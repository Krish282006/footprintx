import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { SMTPServer } from 'smtp-server';
import type { AddressInfo } from 'node:net';
import { connectFixture, loadFixtureBreaches, makeApp, pool, resetDb, signedIn } from './helpers.js';
import { runNotificationJob } from '../src/notifications/service.js';

beforeEach(resetDb);

// A real local SMTP server, so the smtp adapter is exercised end-to-end.
const received: { to: string[]; data: string }[] = [];
let rejectAll = false;
let smtp: SMTPServer;
let port = 0;
beforeAll(async () => {
  smtp = new SMTPServer({
    authOptional: true,
    disabledCommands: ['STARTTLS'],
    onRcptTo(_addr, _session, cb) {
      cb(rejectAll ? Object.assign(new Error('Mailbox unavailable'), { responseCode: 550 }) : undefined);
    },
    onData(stream, session, cb) {
      let data = '';
      stream.on('data', (d) => (data += d));
      stream.on('end', () => {
        received.push({ to: session.envelope.rcptTo.map((r) => r.address), data });
        cb();
      });
    },
  });
  await new Promise<void>((resolve) => smtp.listen(0, '127.0.0.1', resolve));
  port = (smtp.server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((resolve) => smtp.close(() => resolve())));

const smtpEnv = () => ({ EMAIL_PROVIDER: 'smtp', SMTP_HOST: '127.0.0.1', SMTP_PORT: String(port), SMTP_SECURE: 'false' });
const msg = { name: 'Pat', email: 'pat@example.com', subject: 'Question', message: 'Hello, I have a question about DASI.', elapsedMs: 5000 };
const send = (app: Parameters<typeof request>[0], body: object) => request(app).post('/api/contact').set('x-footprintx-client', 'web').send(body);

describe('Contact Us', () => {
  it('delivers through SMTP and says so only after the server accepted it', async () => {
    received.length = 0;
    rejectAll = false;
    const { app } = makeApp(smtpEnv());
    const res = await send(app, msg);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('sent');
    expect(received).toHaveLength(1);
    expect(received[0].to).toEqual(['support@footprintx.test']);
    expect(received[0].data).toContain('Reply-To: pat@example.com');
    expect((await pool().query('SELECT delivery_status FROM contact_messages')).rows[0].delivery_status).toBe('sent');
  });

  it('reports provider failure honestly', async () => {
    rejectAll = true;
    const { app } = makeApp(smtpEnv());
    const res = await send(app, msg);
    rejectAll = false;
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('delivery_failed');
    expect((await pool().query('SELECT delivery_status FROM contact_messages')).rows[0].delivery_status).toBe('failed');
  });

  it('reports missing configuration honestly', async () => {
    const none = await send(makeApp({ EMAIL_PROVIDER: 'none' }).app, msg);
    expect(none.status).toBe(503);
    expect(none.body.message).toMatch(/not sent/);
    const noRecipient = await send(makeApp({ ...smtpEnv(), CONTACT_RECIPIENT: '' }).app, msg);
    expect(noRecipient.status).toBe(503);
    const noHost = await send(makeApp({ EMAIL_PROVIDER: 'smtp', SMTP_HOST: '' }).app, msg);
    expect(noHost.status).toBe(503);
  });

  it('labels development outbox delivery as not emailed', async () => {
    const res = await send(makeApp().app, msg);
    expect(res.body.status).toBe('dev_logged');
    expect(res.body.message).toMatch(/not emailed/);
  });

  it('validates input and blocks simple abuse', async () => {
    const { app } = makeApp();
    expect((await send(app, { ...msg, email: 'bad' })).status).toBe(400);
    expect((await send(app, { ...msg, message: 'short' })).status).toBe(400);
    expect((await send(app, { ...msg, website: 'http://spam' })).status).toBe(400);
    expect((await send(app, { ...msg, elapsedMs: 200 })).status).toBe(400);
    const limited = makeApp({}, { rateLimitScale: 1 }).app;
    const statuses = [];
    for (let i = 0; i < 6; i++) statuses.push((await send(limited, msg)).status);
    expect(statuses.at(-1)).toBe(429);
  });
});

describe('notification preferences and email alerts', () => {
  it('requires separate email consent and keeps in-app alerts when email is off', async () => {
    const { app, ctx } = makeApp();
    await loadFixtureBreaches(ctx);
    const c = await signedIn(app, 'notify@example.com');
    const prefs = (await c.get('/api/notifications/preferences')).body;
    expect(prefs.preferences).toMatchObject({ emailSecurityAlerts: false, emailRemediationReminders: false, emailPeriodicSummary: false });
    const noConsent = await c.put('/api/notifications/preferences', { emailSecurityAlerts: true, emailRemediationReminders: false, emailPeriodicSummary: false });
    expect(noConsent.status).toBe(400);
    expect(noConsent.body.error).toBe('consent_required');
    // Connecting a mailbox does not enable email notifications.
    await connectFixture(c, ctx);
    expect((await c.get('/api/alerts')).body.alerts.length).toBeGreaterThan(0);
    expect((await pool().query('SELECT count(*)::int AS n FROM notification_deliveries')).rows[0].n).toBe(0);
  });

  it('emails new important alerts once to opted-in users (deduplicated)', async () => {
    received.length = 0;
    const { app, ctx } = makeApp(smtpEnv());
    await loadFixtureBreaches(ctx);
    const c = await signedIn(app, 'optin@example.com');
    expect((await c.put('/api/notifications/preferences', { emailSecurityAlerts: true, emailRemediationReminders: true, emailPeriodicSummary: true, emailConsent: true })).status).toBe(200);
    const { connectionId } = await connectFixture(c, ctx);
    const alertMails = received.filter((r) => r.to.includes('optin@example.com'));
    expect(alertMails).toHaveLength(1);
    expect(alertMails[0].data).toContain('new security findings');
    expect(alertMails[0].data).not.toMatch(/password:/i);
    await c.post(`/api/connections/${connectionId}/scan`);
    const { settle } = await import('./helpers.js');
    await settle(ctx);
    expect(received.filter((r) => r.to.includes('optin@example.com'))).toHaveLength(1);
  });

  it('periodic job sends reminders and summaries only when due and only when changed', async () => {
    received.length = 0;
    const { app, ctx, config } = makeApp(smtpEnv());
    await loadFixtureBreaches(ctx);
    const c = await signedIn(app, 'job@example.com');
    await c.put('/api/notifications/preferences', { emailSecurityAlerts: false, emailRemediationReminders: true, emailPeriodicSummary: true, emailConsent: true });
    await connectFixture(c, ctx);
    await pool().query(`UPDATE remediation_items SET created_at = now() - interval '8 days'`);
    const first = await runNotificationJob(config, pool(), ctx.mailer);
    expect(first).toMatchObject({ reminders: 1, summaries: 1 });
    const second = await runNotificationJob(config, pool(), ctx.mailer);
    expect(second).toMatchObject({ reminders: 0, summaries: 0 });
    const later = new Date(Date.now() + 8 * 86400_000);
    const third = await runNotificationJob(config, pool(), ctx.mailer, later);
    expect(third.summaries).toBe(0); // nothing changed → no summary email
    expect(third.reminders).toBe(1); // still-open high priority items → weekly reminder
    const unconfigured = await runNotificationJob(config, pool(), makeApp({ EMAIL_PROVIDER: 'none' }).ctx.mailer);
    expect(unconfigured.note).toMatch(/not configured/);
  });
});

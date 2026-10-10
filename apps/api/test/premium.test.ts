import { beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { Client, connectFixture, makeApp, pool, resetDb, signedIn } from './helpers.js';

beforeEach(resetDb);

async function linkExtension(app: Parameters<typeof request>[0], c: Client) {
  const code = (await c.post('/api/extension/link-code')).body.code;
  const res = await request(app).post('/api/ext/link').send({ code, label: 'Test browser' });
  expect(res.status).toBe(201);
  return res.body.token as string;
}

const ev = (id: string, status = 'red') => ({ clientEventId: id, domain: 'malicious.fixture.test', status, reasons: ['Listed'], action: 'blocked', occurredAt: new Date().toISOString() });

describe('Free / Premium enforcement', () => {
  it('Free users cannot use extension protection, even with forged client claims', async () => {
    const { app } = makeApp();
    const c = await signedIn(app, 'free@example.com');
    const token = await linkExtension(app, c);
    const auth = { Authorization: `Bearer ${token}` };
    const status = await request(app).get('/api/ext/status').set(auth);
    expect(status.body).toMatchObject({ plan: 'free', protectionAvailable: false });
    const check = await request(app).get('/api/ext/check?domain=malicious.fixture.test&plan=premium').set(auth).set('X-Plan', 'premium');
    expect(check.status).toBe(403);
    expect(check.body.error).toBe('premium_required');
    expect((await request(app).put('/api/ext/preferences').set(auth).send({ eventSync: true, plan: 'premium' })).status).toBe(403);
    expect((await request(app).post('/api/ext/events').set(auth).send({ events: [ev('event-0001')] })).status).toBe(403);
    expect((await c.get('/api/security-events')).status).toBe(403);
    expect((await c.put('/api/security-events/sync', { enabled: true })).status).toBe(403);
  });

  it('a user cannot grant themselves Premium by editing profile data', async () => {
    const { app } = makeApp({ ENABLE_DEV_ENTITLEMENTS: 'false' });
    const c = await signedIn(app, 'sneaky@example.com');
    expect((await c.post('/api/dev/plan', { plan: 'premium' })).status).toBe(404);
    const reg = await request(app).post('/api/auth/register').set('x-footprintx-client', 'web').send({ email: 'sneaky2@example.com', password: 'correct-horse-battery-1', acceptPrivacy: true, plan: 'premium' });
    expect(reg.body.user.plan).toBe('free');
    expect((await pool().query(`SELECT count(*)::int AS n FROM users WHERE plan='premium'`)).rows[0].n).toBe(0);
  });

  it('Premium users get protection and keep every Free feature', async () => {
    const { app, ctx } = makeApp();
    const c = await signedIn(app, 'prem@example.com');
    const up = await c.post('/api/dev/plan', { plan: 'premium' });
    expect(up.body).toMatchObject({ plan: 'premium', planSource: 'development' });
    expect(up.body.note).toMatch(/No payment/);
    const token = await linkExtension(app, c);
    const auth = { Authorization: `Bearer ${token}` };
    expect((await request(app).get('/api/ext/check?domain=malicious.fixture.test').set(auth)).body.result.status).toBe('red');
    expect((await request(app).get('/api/ext/check?domain=localhost').set(auth)).body.result.status).toBe('grey');
    // Free features still work for Premium.
    await connectFixture(c, ctx);
    for (const path of ['/api/dashboard', '/api/accounts', '/api/remediation', '/api/alerts', '/api/dasi/history', '/api/notifications/preferences', '/api/reports/security.xlsx', '/api/privacy/export.xlsx']) {
      expect((await c.get(path)).status, path).toBe(200);
    }
    expect((await c.post('/api/domain-check', { domain: 'safe.fixture.test' })).status).toBe(200);
  });

  it('entitlement is re-checked on every request (downgrade takes effect immediately)', async () => {
    const { app } = makeApp();
    const c = await signedIn(app, 'downgrade@example.com');
    await c.post('/api/dev/plan', { plan: 'premium' });
    const token = await linkExtension(app, c);
    const auth = { Authorization: `Bearer ${token}` };
    expect((await request(app).get('/api/ext/check?domain=safe.fixture.test').set(auth)).status).toBe(200);
    await c.post('/api/dev/plan', { plan: 'free' });
    expect((await request(app).get('/api/ext/check?domain=safe.fixture.test').set(auth)).status).toBe(403);
  });

  it('security-event sync requires explicit opt-in and accepts only warning events', async () => {
    const { app } = makeApp();
    const c = await signedIn(app, 'sync@example.com');
    await c.post('/api/dev/plan', { plan: 'premium' });
    const token = await linkExtension(app, c);
    const auth = { Authorization: `Bearer ${token}` };
    const notOptedIn = await request(app).post('/api/ext/events').set(auth).send({ events: [ev('event-0001')] });
    expect(notOptedIn.status).toBe(403);
    expect(notOptedIn.body.error).toBe('sync_disabled');
    expect((await request(app).put('/api/ext/preferences').set(auth).send({ eventSync: true })).status).toBe(200);
    const green = await request(app).post('/api/ext/events').set(auth).send({ events: [ev('event-0002', 'green')] });
    expect(green.status).toBe(400); // routine clean navigation is never accepted
    const ok = await request(app).post('/api/ext/events').set(auth).send({ events: [ev('event-0003'), ev('event-0003')] });
    expect(ok.body.stored).toBe(1); // idempotent by client event id
    const list = (await c.get('/api/security-events')).body;
    expect(list.events).toHaveLength(1);
    expect(list.events[0]).toMatchObject({ domain: 'malicious.fixture.test', status: 'red', action: 'blocked' });
    expect(Object.keys(list.events[0])).not.toContain('url');
  });

  it('link codes are single-use and expire; revoked tokens stop working', async () => {
    const { app } = makeApp();
    const c = await signedIn(app, 'link@example.com');
    const code = (await c.post('/api/extension/link-code')).body.code;
    expect(code).toMatch(/^[A-Z0-9]{5}-[A-Z0-9]{5}$/);
    const first = await request(app).post('/api/ext/link').send({ code });
    expect(first.status).toBe(201);
    expect((await request(app).post('/api/ext/link').send({ code })).status).toBe(400);
    const code2 = (await c.post('/api/extension/link-code')).body.code;
    await pool().query(`UPDATE extension_link_codes SET expires_at = now() - interval '1 minute'`);
    expect((await request(app).post('/api/ext/link').send({ code: code2 })).status).toBe(400);
    const tokens = (await c.get('/api/extension/tokens')).body.tokens;
    expect(tokens).toHaveLength(1);
    expect((await c.delete(`/api/extension/tokens/${tokens[0].id}`)).status).toBe(200);
    expect((await request(app).get('/api/ext/status').set('Authorization', `Bearer ${first.body.token}`)).status).toBe(401);
    expect((await request(app).get('/api/ext/status').set('Authorization', 'Bearer not-a-real-token-value-xxxxxxxx')).status).toBe(401);
    // Tokens are stored hashed.
    const stored = (await pool().query('SELECT token_hash FROM extension_tokens')).rows[0].token_hash as Buffer;
    expect(stored.toString('utf8')).not.toContain(first.body.token);
  });

  it('extension can unlink itself', async () => {
    const { app } = makeApp();
    const c = await signedIn(app, 'unlink@example.com');
    const token = await linkExtension(app, c);
    expect((await request(app).post('/api/ext/unlink').set('Authorization', `Bearer ${token}`)).status).toBe(200);
    expect((await request(app).get('/api/ext/status').set('Authorization', `Bearer ${token}`)).status).toBe(401);
  });

  it('exposes plan information honestly (no billing configured)', async () => {
    const { app } = makeApp();
    const c = await signedIn(app, 'plan@example.com');
    const plan = (await c.get('/api/plan')).body;
    expect(plan.plan).toBe('free');
    expect(plan.billing.configured).toBe(false);
    expect(plan.features.premium).toContain('Everything in Free');
  });
});

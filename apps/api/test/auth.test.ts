import { beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { Client, makeApp, pool, resetDb, PASSWORD } from './helpers.js';

beforeEach(resetDb);

describe('authentication and sessions', () => {
  it('registers, stores an Argon2id hash, and returns a session with CSRF token', async () => {
    const { app } = makeApp();
    const c = new Client(app);
    const res = await c.register('alice@example.com');
    expect(res.body.user).toMatchObject({ email: 'alice@example.com', plan: 'free' });
    expect(res.body.csrfToken).toBeTruthy();
    const cookie = res.headers['set-cookie'][0];
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Lax/);
    const { rows } = await pool().query('SELECT password_hash, privacy_consent_at FROM users WHERE email=$1', ['alice@example.com']);
    expect(rows[0].password_hash).toMatch(/^\$argon2id\$/);
    expect(rows[0].password_hash).not.toContain(PASSWORD);
    expect(rows[0].privacy_consent_at).toBeTruthy();
    const me = await c.get('/api/auth/me');
    expect(me.body.user.email).toBe('alice@example.com');
  });

  it('requires privacy consent and validates input', async () => {
    const { app } = makeApp();
    const noConsent = await request(app).post('/api/auth/register').set('x-footprintx-client', 'web').send({ email: 'b@example.com', password: PASSWORD });
    expect(noConsent.status).toBe(400);
    const short = await request(app).post('/api/auth/register').set('x-footprintx-client', 'web').send({ email: 'b@example.com', password: 'short', acceptPrivacy: true });
    expect(short.status).toBe(400);
    expect(short.body.issues[0].path).toBe('password');
    const badEmail = await request(app).post('/api/auth/register').set('x-footprintx-client', 'web').send({ email: 'nope', password: PASSWORD, acceptPrivacy: true });
    expect(badEmail.status).toBe(400);
  });

  it('rejects duplicate registration case-insensitively', async () => {
    const { app } = makeApp();
    await new Client(app).register('dup@example.com');
    const res = await request(app).post('/api/auth/register').set('x-footprintx-client', 'web').send({ email: 'DUP@example.com', password: PASSWORD, acceptPrivacy: true });
    expect(res.status).toBe(409);
  });

  it('gives a generic error for wrong password and unknown user', async () => {
    const { app } = makeApp();
    await new Client(app).register('carol@example.com');
    const wrong = await new Client(app).login('carol@example.com', 'wrong-password-123');
    const unknown = await new Client(app).login('nobody@example.com', 'wrong-password-123');
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.message).toBe(unknown.body.message);
  });

  it('logs out and invalidates the server-side session', async () => {
    const { app } = makeApp();
    const c = new Client(app);
    await c.register('dave@example.com');
    const cookie = (await c.get('/api/auth/me')).request.cookies;
    expect((await c.post('/api/auth/logout')).status).toBe(200);
    expect((await c.get('/api/auth/me')).body.user).toBeNull();
    expect((await c.get('/api/accounts')).status).toBe(401);
    expect(cookie).toBeDefined();
    const { rows } = await pool().query('SELECT count(*)::int AS n FROM sessions');
    expect(rows[0].n).toBe(0);
  });

  it('a stolen-but-logged-out cookie no longer works', async () => {
    const { app } = makeApp();
    const reg = await new Client(app).register('erin@example.com');
    const rawCookie = reg.headers['set-cookie'][0].split(';')[0];
    const csrf = reg.body.csrfToken;
    expect((await request(app).get('/api/accounts').set('Cookie', rawCookie)).status).toBe(200);
    await request(app).post('/api/auth/logout').set('Cookie', rawCookie).set('x-csrf-token', csrf);
    expect((await request(app).get('/api/accounts').set('Cookie', rawCookie)).status).toBe(401);
  });

  it('enforces CSRF tokens and origin checks on state-changing requests', async () => {
    const { app } = makeApp();
    const c = new Client(app);
    await c.register('frank@example.com');
    const noToken = await c.agent.post('/api/accounts').send({ domain: 'github.com' });
    expect(noToken.status).toBe(403);
    expect(noToken.body.error).toBe('csrf_failed');
    const wrongToken = await c.agent.post('/api/accounts').set('x-csrf-token', 'x'.repeat(32)).send({ domain: 'github.com' });
    expect(wrongToken.status).toBe(403);
    const badOrigin = await c.agent.post('/api/accounts').set('x-csrf-token', c.csrf).set('Origin', 'https://evil.example').send({ domain: 'github.com' });
    expect(badOrigin.status).toBe(403);
    expect(badOrigin.body.error).toBe('bad_origin');
    const ok = await c.agent.post('/api/accounts').set('x-csrf-token', c.csrf).set('Origin', 'http://localhost:5173').send({ domain: 'github.com' });
    expect(ok.status).toBe(201);
    const anonNoHeader = await request(app).post('/api/auth/login').send({ email: 'frank@example.com', password: PASSWORD });
    expect(anonNoHeader.status).toBe(403);
  });

  it('changes password and signs out other sessions', async () => {
    const { app } = makeApp();
    const a = new Client(app);
    await a.register('gina@example.com');
    const b = new Client(app);
    expect((await b.login('gina@example.com')).status).toBe(200);
    const res = await a.post('/api/auth/change-password', { currentPassword: PASSWORD, newPassword: 'a-brand-new-password-9' });
    expect(res.status).toBe(200);
    expect((await b.get('/api/accounts')).status).toBe(401);
    expect((await a.get('/api/accounts')).status).toBe(200);
    expect((await new Client(app).login('gina@example.com', 'a-brand-new-password-9')).status).toBe(200);
  });

  it('password recovery via the development outbox (devlog) resets the password and all sessions', async () => {
    const { app } = makeApp();
    const a = new Client(app);
    await a.register('hank@example.com');
    const res = await request(app).post('/api/auth/forgot-password').set('x-footprintx-client', 'web').send({ email: 'hank@example.com' });
    expect(res.status).toBe(200);
    expect(res.body.devMode).toBe(true);
    expect(res.body.message).toMatch(/No email was sent/);
    const unknown = await request(app).post('/api/auth/forgot-password').set('x-footprintx-client', 'web').send({ email: 'ghost@example.com' });
    expect(unknown.body.message).toBe(res.body.message);
    const { rows } = await pool().query(`SELECT body FROM dev_outbox WHERE to_address='hank@example.com'`);
    expect(rows).toHaveLength(1);
    const token = /token=([A-Za-z0-9_-]+)/.exec(rows[0].body)![1];
    const reset = await request(app).post('/api/auth/reset-password').set('x-footprintx-client', 'web').send({ token, password: 'reset-password-value-1' });
    expect(reset.status).toBe(200);
    expect((await a.get('/api/accounts')).status).toBe(401);
    const reuse = await request(app).post('/api/auth/reset-password').set('x-footprintx-client', 'web').send({ token, password: 'another-password-val-2' });
    expect(reuse.status).toBe(400);
    expect((await new Client(app).login('hank@example.com', 'reset-password-value-1')).status).toBe(200);
  });

  it('reports honestly when password recovery email is not configured', async () => {
    const { app } = makeApp({ EMAIL_PROVIDER: 'none' });
    await new Client(app).register('ivy@example.com');
    const res = await request(app).post('/api/auth/forgot-password').set('x-footprintx-client', 'web').send({ email: 'ivy@example.com' });
    expect(res.status).toBe(503);
    expect(res.body.error).toBe('email_not_configured');
  });

  it('persists users and sessions across application restarts (new app instance)', async () => {
    const first = makeApp();
    const c = new Client(first.app);
    const reg = await c.register('jade@example.com');
    const cookie = reg.headers['set-cookie'][0].split(';')[0];
    const second = makeApp(); // simulates a restarted server against the same database
    const me = await request(second.app).get('/api/auth/me').set('Cookie', cookie);
    expect(me.body.user.email).toBe('jade@example.com');
    expect((await new Client(second.app).login('jade@example.com')).status).toBe(200);
  });

  it('rate-limits repeated login attempts', async () => {
    const { app } = makeApp({}, { rateLimitScale: 1 });
    const statuses: number[] = [];
    for (let i = 0; i < 12; i++) {
      statuses.push((await request(app).post('/api/auth/login').set('x-footprintx-client', 'web').send({ email: 'rl@example.com', password: 'wrong-password-1' })).status);
    }
    expect(statuses.slice(0, 10).every((s) => s === 401)).toBe(true);
    expect(statuses.at(-1)).toBe(429);
  });

  it('sets security headers and never caches API responses', async () => {
    const { app } = makeApp();
    const res = await request(app).get('/api/health');
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('refuses unsafe configuration in production', async () => {
    const { loadConfig } = await import('../src/config.js');
    const base = { DATABASE_URL: 'postgres://x', NODE_ENV: 'production', COOKIE_SECURE: 'true', TOKEN_ENCRYPTION_KEY: Buffer.alloc(32).toString('base64') };
    expect(() => loadConfig({ ...base, ENABLE_DEV_ENTITLEMENTS: 'true' })).toThrow(/ENABLE_DEV_ENTITLEMENTS/);
    expect(() => loadConfig({ ...base, ENABLE_DEV_FIXTURES: 'true' })).toThrow(/ENABLE_DEV_FIXTURES/);
    expect(() => loadConfig({ ...base, EMAIL_PROVIDER: 'devlog' })).toThrow(/devlog/);
    expect(() => loadConfig({ ...base, COOKIE_SECURE: 'false' })).toThrow(/COOKIE_SECURE/);
    expect(() => loadConfig({ ...base, THREAT_PROVIDERS: 'fixture' })).toThrow(/fixture/);
    expect(() => loadConfig(base)).not.toThrow();
  });
});

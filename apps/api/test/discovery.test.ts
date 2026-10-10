import { beforeEach, describe, expect, it } from 'vitest';
import { classifyMessage, accountConfidence } from '../src/discovery/classifier.js';
import { Client, connectFixture, loadFixtureBreaches, makeApp, pool, resetDb, settle, signedIn } from './helpers.js';
import { json, stubFetch } from './stub-fetch.js';
import { sha256 } from '../src/lib/crypto.js';

beforeEach(resetDb);

const m = (from: string, subject: string, date = '2025-03-01T10:00:00Z') => ({ id: 'x', from, subject, date });

describe('email metadata classifier', () => {
  it('recognises account evidence and maps sender domains to services', () => {
    expect(classifyMessage(m('GitHub <noreply@github.com>', 'Welcome to GitHub'))).toMatchObject({ serviceDomain: 'github.com', serviceName: 'GitHub', evidenceType: 'account_creation' });
    expect(classifyMessage(m('Facebook <security@facebookmail.com>', 'New login from Chrome'))).toMatchObject({ serviceDomain: 'facebook.com', evidenceType: 'security_notification', signal: 'new_signin' });
    expect(classifyMessage(m('Shop <x@mail.shop.co.uk>', 'Your order confirmation #5'))).toMatchObject({ serviceDomain: 'shop.co.uk', evidenceType: 'transactional' });
    expect(classifyMessage(m('X <info@x.com>', 'Your password was changed'))).toMatchObject({ signal: 'password_changed' });
    expect(classifyMessage(m('Svc <noreply@svc.example>', 'Two-step verification is now turned on'))).toMatchObject({ signal: 'mfa_enabled' });
  });

  it('ignores personal mail, unknown newsletters and malformed senders', () => {
    expect(classifyMessage(m('Friend <friend@gmail.com>', 'Welcome to my party'))).toBeNull();
    expect(classifyMessage(m('News <news@randomnews.example>', 'Top stories this week'))).toBeNull();
    expect(classifyMessage(m('not an address', 'Welcome to X'))).toBeNull();
    expect(classifyMessage(m('a@b.example', 'Welcome', 'not a date'))).toBeNull();
  });

  it('gives known-service marketing mail only weak confidence', () => {
    expect(classifyMessage(m('Spotify <no-reply@spotify.com>', 'New music for you'))).toMatchObject({ evidenceType: 'marketing', confidence: 0.25 });
  });

  it('computes account confidence from independent evidence types', () => {
    expect(accountConfidence([{ evidenceType: 'marketing', confidence: 0.25 }])).toBe(0.25);
    expect(accountConfidence([{ evidenceType: 'account_creation', confidence: 0.9 }, { evidenceType: 'transactional', confidence: 0.6 }])).toBe(0.95);
    expect(accountConfidence([{ evidenceType: 'account_creation', confidence: 0.9 }, { evidenceType: 'transactional', confidence: 0.6 }, { evidenceType: 'security_notification', confidence: 0.85 }])).toBe(0.99);
  });
});

describe('discovery with the development fixture mailbox', () => {
  it('requires explicit consent before connecting', async () => {
    const { app } = makeApp();
    const c = await signedIn(app, 'u1@example.com');
    const res = await c.post('/api/connections/devfixture', {});
    expect(res.status).toBe(400);
  });

  it('discovers accounts with source, confidence and fixture labels; stores no subjects', async () => {
    const { app, ctx } = makeApp();
    await loadFixtureBreaches(ctx);
    const c = await signedIn(app, 'u2@example.com');
    const { scanId } = await connectFixture(c, ctx);
    const scan = (await c.get(`/api/connections/scans/${scanId}`)).body.scan;
    expect(scan).toMatchObject({ status: 'completed', is_fixture: true, messages_examined: 14 });
    const accounts = (await c.get('/api/accounts')).body.accounts;
    const domains = accounts.map((a: { service_domain: string }) => a.service_domain).sort();
    expect(domains).toEqual(['fixturebank.example', 'fixtureforum.example', 'fixtureshop.example', 'fixturesocial.example', 'github.com', 'google.com', 'spotify.com']);
    expect(accounts.every((a: { is_fixture: boolean }) => a.is_fixture)).toBe(true);
    expect(domains).not.toContain('gmail.com');
    expect(domains).not.toContain('randomnews.example');
    const shop = accounts.find((a: { service_domain: string }) => a.service_domain === 'fixtureshop.example');
    expect(Number(shop.confidence)).toBeGreaterThanOrEqual(0.9);
    const cols = (await pool().query(`SELECT column_name FROM information_schema.columns WHERE table_name='evidence'`)).rows.map((r) => r.column_name);
    expect(cols).not.toContain('subject');
    const dash = (await c.get('/api/dashboard')).body;
    expect(dash.dasi.score).toBeGreaterThan(0);
    expect(dash.dasi.coverage).toBe('complete');
    expect(dash.topFindings.length).toBeGreaterThan(0);
  });

  it('rescanning does not duplicate evidence or accounts', async () => {
    const { app, ctx } = makeApp();
    const c = await signedIn(app, 'u3@example.com');
    const { connectionId } = await connectFixture(c, ctx);
    const before = (await pool().query('SELECT count(*)::int AS n FROM evidence')).rows[0].n;
    const res = await c.post(`/api/connections/${connectionId}/scan`);
    expect(res.status).toBe(202);
    await settle(ctx);
    const after = (await pool().query('SELECT count(*)::int AS n FROM evidence')).rows[0].n;
    expect(after).toBe(before);
    expect((await c.get(`/api/connections/scans/${res.body.scanId}`)).body.scan.evidence_found).toBe(0);
  });

  it('respects "not mine" corrections on later scans', async () => {
    const { app, ctx } = makeApp();
    const c = await signedIn(app, 'u4@example.com');
    const { connectionId } = await connectFixture(c, ctx);
    const spotify = (await c.get('/api/accounts')).body.accounts.find((a: { service_domain: string }) => a.service_domain === 'spotify.com');
    expect((await c.patch(`/api/accounts/${spotify.id}`, { ownership: 'false_positive' })).status).toBe(200);
    await c.post(`/api/connections/${connectionId}/scan`);
    await settle(ctx);
    const after = (await c.get('/api/accounts')).body.accounts.find((a: { service_domain: string }) => a.service_domain === 'spotify.com');
    expect(after.ownership).toBe('false_positive');
    expect(after.risk_score).toBeNull();
    const ev = (await pool().query('SELECT count(*)::int AS n FROM evidence WHERE account_id=$1', [spotify.id])).rows[0].n;
    expect(ev).toBe(1); // no new evidence attached after suppression
  });

  it('disconnecting purges evidence and evidence-only accounts but keeps user-added accounts', async () => {
    const { app, ctx } = makeApp();
    const c = await signedIn(app, 'u5@example.com');
    const { connectionId } = await connectFixture(c, ctx);
    await c.post('/api/accounts', { domain: 'example.org' });
    const res = await c.delete(`/api/connections/${connectionId}`);
    expect(res.status).toBe(200);
    expect(res.body.revocation).toBe('not_applicable');
    expect(res.body.purgedAccounts).toBe(7);
    const accounts = (await c.get('/api/accounts')).body.accounts;
    expect(accounts.map((a: { service_domain: string }) => a.service_domain)).toEqual(['example.org']);
    expect((await pool().query('SELECT count(*)::int AS n FROM evidence')).rows[0].n).toBe(0);
    expect((await c.get('/api/connections')).body.connections).toHaveLength(0);
  });
});

describe('Gmail OAuth integration (stubbed provider endpoints)', () => {
  const env = { GOOGLE_CLIENT_ID: 'cid', GOOGLE_CLIENT_SECRET: 'csecret' };
  const endpoints = {
    googleAuth: 'https://stub-accounts.test/auth',
    googleToken: 'https://stub-oauth.test/token',
    googleRevoke: 'https://stub-oauth.test/revoke',
    gmailApi: 'https://stub-gmail.test/gmail/v1',
  };

  function gmail(opts: { failPage2?: boolean; unauthorized?: boolean } = {}) {
    const msgs: Record<string, { from: string; subject: string; ms: number }> = {
      m1: { from: 'GitHub <noreply@github.com>', subject: 'Welcome to GitHub', ms: Date.parse('2022-01-01') },
      m2: { from: 'Dropbox <no-reply@dropbox.com>', subject: 'Verify your email', ms: Date.parse('2023-01-01') },
      m3: { from: 'Shop <orders@shop.example>', subject: 'Your order confirmation', ms: Date.parse('2024-01-01') },
    };
    return stubFetch([
      [/stub-oauth\.test\/token/, () => json({ access_token: 'at-1', refresh_token: 'rt-1', expires_in: 3600, scope: 'https://www.googleapis.com/auth/gmail.metadata' })],
      [/stub-oauth\.test\/revoke/, () => new Response('', { status: 200 })],
      [/users\/me\/profile/, () => (opts.unauthorized ? new Response('', { status: 401 }) : json({ emailAddress: 'Person@Gmail.com' }))],
      [/users\/me\/messages\?/, (u) => {
        if (opts.unauthorized) return new Response('', { status: 401 });
        if (!u.searchParams.get('pageToken')) return json({ messages: [{ id: 'm1' }, { id: 'm2' }], nextPageToken: 'p2' });
        if (opts.failPage2) return new Response('boom', { status: 500 });
        return json({ messages: [{ id: 'm3' }] });
      }],
      [/users\/me\/messages\/m\d/, (u) => {
        const id = u.pathname.split('/').at(-1)!;
        expect(u.searchParams.get('format')).toBe('metadata');
        const msg = msgs[id];
        return json({ id, internalDate: String(msg.ms), payload: { headers: [{ name: 'From', value: msg.from }, { name: 'Subject', value: msg.subject }] } });
      }],
    ]);
  }

  async function connect(c: Client, fetchStub: ReturnType<typeof stubFetch>) {
    const start = await c.post('/api/connections/oauth/google/start', { consent: true, consentVersion: 'email-discovery-v1' });
    expect(start.status).toBe(200);
    const auth = new URL(start.body.authorizationUrl);
    expect(auth.searchParams.get('scope')).toBe('https://www.googleapis.com/auth/gmail.metadata');
    expect(auth.searchParams.get('code_challenge_method')).toBe('S256');
    const state = auth.searchParams.get('state')!;
    return { state, fetchStub };
  }

  it('reports when OAuth is not configured', async () => {
    const { app } = makeApp();
    const c = await signedIn(app, 'g0@example.com');
    const res = await c.post('/api/connections/oauth/google/start', { consent: true, consentVersion: 'email-discovery-v1' });
    expect(res.status).toBe(503);
    expect(res.body.error).toBe('provider_not_configured');
  });

  it('completes the PKCE flow, encrypts tokens, scans metadata and revokes on disconnect', async () => {
    const f = gmail();
    const { app, ctx } = makeApp(env, { fetchImpl: f.impl, endpoints });
    const c = await signedIn(app, 'g1@example.com');
    const { state } = await connect(c, f);
    const cb = await c.get(`/api/connections/oauth/google/callback?state=${state}&code=authcode`);
    expect(cb.status).toBe(303);
    expect(cb.headers.location).toBe('http://localhost:5173/connections?connected=google');
    await settle(ctx);
    const tokenCall = f.calls.find((x) => x.url.includes('/token'))!;
    expect(tokenCall.body).toContain('code_verifier=');
    const conn = (await pool().query('SELECT * FROM email_connections')).rows[0];
    expect(conn.email_address).toBe('person@gmail.com');
    expect(conn.access_token_enc).toMatch(/^v1\./);
    expect(conn.access_token_enc).not.toContain('at-1');
    expect(conn.refresh_token_enc).not.toContain('rt-1');
    const scan = (await pool().query('SELECT * FROM scans')).rows[0];
    expect(scan).toMatchObject({ status: 'completed', messages_examined: 3, is_fixture: false });
    const accts = (await c.get('/api/accounts')).body.accounts.map((a: { service_domain: string }) => a.service_domain).sort();
    expect(accts).toEqual(['dropbox.com', 'github.com', 'shop.example']);
    const del = await c.delete(`/api/connections/${conn.id}`);
    expect(del.body.revocation).toBe('revoked');
    expect(f.calls.some((x) => x.url.includes('/revoke') && x.url.includes('rt-1'))).toBe(true);
  });

  it('rejects a reused, forged or other-user state', async () => {
    const f = gmail();
    const { app } = makeApp(env, { fetchImpl: f.impl, endpoints });
    const a = await signedIn(app, 'g2@example.com');
    const b = await signedIn(app, 'g3@example.com');
    const { state } = await connect(a, f);
    const forged = await a.get(`/api/connections/oauth/google/callback?state=${'x'.repeat(40)}&code=c`);
    expect(forged.headers.location).toContain('error=invalid_state');
    const otherUser = await b.get(`/api/connections/oauth/google/callback?state=${state}&code=c`);
    expect(otherUser.headers.location).toContain('error=invalid_state');
    // The state was consumed by the failed attempt, so it cannot be replayed.
    const replay = await a.get(`/api/connections/oauth/google/callback?state=${state}&code=c`);
    expect(replay.headers.location).toContain('error=invalid_state');
    expect((await pool().query('SELECT count(*)::int AS n FROM email_connections')).rows[0].n).toBe(0);
    const stored = await pool().query('SELECT 1 FROM oauth_states WHERE state_hash=$1', [sha256(state)]);
    expect(stored.rowCount).toBe(0);
  });

  it('records a partial scan honestly when the provider fails mid-way', async () => {
    const f = gmail({ failPage2: true });
    const { app, ctx } = makeApp(env, { fetchImpl: f.impl, endpoints });
    const c = await signedIn(app, 'g4@example.com');
    const { state } = await connect(c, f);
    await c.get(`/api/connections/oauth/google/callback?state=${state}&code=authcode`);
    await settle(ctx);
    const scan = (await pool().query('SELECT * FROM scans')).rows[0];
    expect(scan.status).toBe('partial');
    expect(scan.messages_examined).toBe(2);
    expect(scan.error_code).toBe('provider_unavailable');
    const dash = (await c.get('/api/dashboard')).body;
    expect(dash.dasi.coverage).toBe('partial');
    expect(dash.dasi.components.some((x: { key: string }) => x.key === 'coverage_uncertainty')).toBe(true);
  });

  it('marks the connection for re-authorisation when the provider rejects the token', async () => {
    const f = gmail();
    const { app, ctx } = makeApp(env, { fetchImpl: f.impl, endpoints });
    const c = await signedIn(app, 'g5@example.com');
    const { state } = await connect(c, f);
    await c.get(`/api/connections/oauth/google/callback?state=${state}&code=authcode`);
    await settle(ctx);
    // Expire the access token; the refresh now fails with invalid_grant.
    await pool().query(`UPDATE email_connections SET token_expires_at = now() - interval '1 hour'`);
    const g2 = stubFetch([[/token/, () => json({ error: 'invalid_grant' }, 400)]]);
    const second = makeApp(env, { fetchImpl: g2.impl, endpoints });
    const conn = (await pool().query('SELECT id FROM email_connections')).rows[0];
    const c2 = new Client(second.app);
    await c2.login('g5@example.com');
    expect((await c2.post(`/api/connections/${conn.id}/scan`)).status).toBe(202);
    await settle(second.ctx);
    const latest = (await pool().query('SELECT status, error_code FROM scans ORDER BY started_at DESC LIMIT 1')).rows[0];
    expect(latest).toEqual({ status: 'failed', error_code: 'reauth_required' });
    expect((await pool().query('SELECT status FROM email_connections')).rows[0].status).toBe('reauth_required');
  });
});

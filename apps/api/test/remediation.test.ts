import { beforeEach, describe, expect, it } from 'vitest';
import { connectFixture, loadFixtureBreaches, makeApp, pool, resetDb, settle, signedIn } from './helpers.js';

beforeEach(resetDb);

async function setup() {
  const { app, ctx } = makeApp();
  await loadFixtureBreaches(ctx);
  const c = await signedIn(app, 'rem@example.com');
  const { connectionId } = await connectFixture(c, ctx);
  const accounts = (await c.get('/api/accounts')).body.accounts as { id: string; service_domain: string; risk_score: number }[];
  const shop = accounts.find((a) => a.service_domain === 'fixtureshop.example')!;
  const items = (await c.get('/api/remediation')).body.items as { id: string; account_id: string; action_type: string; status: string; official_url: string | null; url_kind: string | null }[];
  return { app, ctx, c, connectionId, accounts, shop, items };
}

describe('remediation workflow and recalculation', () => {
  it('produces prioritised recommendations with official or clearly-labelled links', async () => {
    const { items, shop } = await setup();
    expect(items.length).toBeGreaterThan(0);
    const changePw = items.find((i) => i.account_id === shop.id && i.action_type === 'change_password')!;
    expect(changePw.status).toBe('recommended');
    // Unknown service: W3C well-known URL, labelled as such (not presented as verified).
    expect(changePw.official_url).toBe('https://fixtureshop.example/.well-known/change-password');
    expect(changePw.url_kind).toBe('well_known_standard');
    const github = items.find((i) => i.official_url?.startsWith('https://github.com/'));
    expect(github?.url_kind).toBe('curated_official');
  });

  it('records a user-reported password change, recalculates only that account, and preserves other findings', async () => {
    const { c, shop, items, accounts } = await setup();
    const findingsBefore = (await pool().query('SELECT id, account_id, contribution, state, updated_at FROM findings ORDER BY id')).rows;
    const historyBefore = (await c.get('/api/dasi/history')).body.history.length;
    const changePw = items.find((i) => i.account_id === shop.id && i.action_type === 'change_password')!;

    expect((await c.patch(`/api/remediation/${changePw.id}`, { status: 'in_progress' })).status).toBe(200);
    const done = await c.patch(`/api/remediation/${changePw.id}`, { status: 'user_reported_complete' });
    expect(done.status).toBe(200);

    const findingsAfter = (await pool().query('SELECT id, account_id, contribution, state, updated_at FROM findings ORDER BY id')).rows;
    const breachBefore = findingsBefore.find((f) => f.account_id === shop.id && f.state === 'open' && Number(f.contribution) > 20)!;
    const breachAfter = findingsAfter.find((f) => f.id === breachBefore.id)!;
    // The breach finding is kept (not erased), with a documented 50% reduction.
    expect(breachAfter.state).toBe('mitigated_user_reported');
    expect(Number(breachAfter.contribution)).toBeCloseTo(Number(breachBefore.contribution) * 0.5, 1);
    // Findings for other accounts are untouched.
    for (const f of findingsBefore.filter((x) => x.account_id !== shop.id)) {
      const after = findingsAfter.find((x) => x.id === f.id)!;
      expect(after.updated_at.getTime()).toBe(f.updated_at.getTime());
      expect(after.contribution).toBe(f.contribution);
    }
    const shopAfter = (await c.get(`/api/accounts/${shop.id}`)).body.account;
    expect(shopAfter.risk_score).toBeLessThan(accounts.find((a) => a.id === shop.id)!.risk_score);
    const history = (await c.get('/api/dasi/history')).body.history;
    expect(history.length).toBeGreaterThan(historyBefore);
    expect(history[0].reason).toMatch(/user reported complete/);
    expect(history[0].changes.some((ch: { accountId: string }) => ch.accountId === shop.id)).toBe(true);
    const events = (await pool().query('SELECT from_status, to_status FROM remediation_events WHERE item_id=$1 ORDER BY created_at', [changePw.id])).rows;
    expect(events).toEqual([{ from_status: 'recommended', to_status: 'in_progress' }, { from_status: 'in_progress', to_status: 'user_reported_complete' }]);
  });

  it('rejects invalid transitions and system-only statuses', async () => {
    const { c, items } = await setup();
    const item = items[0];
    expect((await c.patch(`/api/remediation/${item.id}`, { status: 'verified_complete' })).status).toBe(409);
    expect((await c.patch(`/api/remediation/${item.id}`, { status: 'verification_pending' })).status).toBe(409);
    expect((await c.post(`/api/remediation/${item.id}/verify`)).status).toBe(409);
    expect((await c.patch(`/api/remediation/${item.id}`, { status: 'bogus' })).status).toBe(400);
  });

  it('verification: no verifier → unable to verify; no evidence → pending, then unable after a completed scan', async () => {
    const { c, ctx, items, connectionId } = await setup();
    const review = items.find((i) => i.action_type === 'review_activity')!;
    await c.patch(`/api/remediation/${review.id}`, { status: 'user_reported_complete' });
    const r1 = await c.post(`/api/remediation/${review.id}/verify`);
    expect(r1.body.status).toBe('unable_to_verify');

    const mfa = items.find((i) => i.action_type === 'enable_mfa')!;
    await c.patch(`/api/remediation/${mfa.id}`, { status: 'user_reported_complete' });
    const r2 = await c.post(`/api/remediation/${mfa.id}/verify`);
    expect(r2.body.status).toBe('verification_pending');
    await c.post(`/api/connections/${connectionId}/scan`);
    await settle(ctx);
    const after = (await c.get('/api/remediation')).body.items.find((i: { id: string }) => i.id === mfa.id);
    expect(after.status).toBe('unable_to_verify');
    expect(after.status_note).toMatch(/no confirmation email/i);
  });

  it('verification succeeds only from real evidence (a password-changed email after the breach)', async () => {
    const { c, shop, items } = await setup();
    const changePw = items.find((i) => i.account_id === shop.id && i.action_type === 'change_password')!;
    await c.patch(`/api/remediation/${changePw.id}`, { status: 'user_reported_complete' });
    await pool().query(
      `INSERT INTO evidence (user_id, account_id, source, evidence_type, signal, confidence, observed_at, is_fixture)
       VALUES ($1,$2,'devfixture','security_notification','password_changed',0.9, now() - interval '1 day', true)`,
      [c.userId, shop.id],
    );
    const res = await c.post(`/api/remediation/${changePw.id}/verify`);
    expect(res.body.status).toBe('verified_complete');
    const finding = (await pool().query(`SELECT state FROM findings WHERE account_id=$1 AND finding_type='service_breach'`, [shop.id])).rows[0];
    expect(finding.state).toBe('mitigated_verified');
  });

  it('marking an account "not mine" removes it from DASI but keeps history; restoring brings it back', async () => {
    const { c, shop } = await setup();
    const before = (await c.get('/api/dashboard')).body.dasi;
    await c.patch(`/api/accounts/${shop.id}`, { ownership: 'false_positive' });
    const mid = (await c.get('/api/dashboard')).body.dasi;
    expect(mid.accountScores.some((a: { accountId: string }) => a.accountId === shop.id)).toBe(false);
    const rem = (await c.get('/api/remediation')).body.items;
    expect(rem.some((i: { account_id: string }) => i.account_id === shop.id)).toBe(false);
    const states = (await pool().query('SELECT DISTINCT state FROM findings WHERE account_id=$1', [shop.id])).rows.map((r) => r.state);
    expect(states).toEqual(['inactive']);
    await c.patch(`/api/accounts/${shop.id}`, { ownership: 'discovered' });
    const restored = (await c.get('/api/dashboard')).body.dasi;
    expect(restored.score).toBe(before.score);
  });

  it('user-reported two-step status lowers risk but is labelled user-reported', async () => {
    const { c, accounts } = await setup();
    const gh = accounts.find((a) => a.service_domain === 'github.com')!;
    await c.patch(`/api/accounts/${gh.id}`, { mfaStatus: 'user_reported_enabled' });
    const detail = (await c.get(`/api/accounts/${gh.id}`)).body;
    expect(detail.account.risk_score).toBeLessThan(gh.risk_score);
    const posture = detail.findings.find((f: { finding_type: string }) => f.finding_type === 'posture_unknown');
    expect(posture.title).toMatch(/reported as enabled/);
    expect(posture.state).toBe('mitigated_user_reported');
  });

  it('creates de-duplicated in-app alerts for important findings', async () => {
    const { c, ctx, connectionId } = await setup();
    const first = (await c.get('/api/alerts')).body.alerts.length;
    expect(first).toBeGreaterThan(0);
    await c.post(`/api/connections/${connectionId}/scan`);
    await settle(ctx);
    expect((await c.get('/api/alerts')).body.alerts.length).toBe(first);
    const a = (await c.get('/api/alerts')).body.alerts[0];
    expect((await c.post(`/api/alerts/${a.id}/read`)).status).toBe(200);
  });

  it('user-added accounts can be added and removed; discovered ones cannot be deleted', async () => {
    const { c, shop } = await setup();
    const add = await c.post('/api/accounts', { domain: 'https://www.Example.org/login' });
    expect(add.status).toBe(201);
    const detail = (await c.get(`/api/accounts/${add.body.id}`)).body.account;
    expect(detail).toMatchObject({ service_domain: 'example.org', ownership: 'user_added' });
    expect((await c.post('/api/accounts', { domain: 'example.org' })).status).toBe(409);
    expect((await c.delete(`/api/accounts/${shop.id}`)).status).toBe(400);
    expect((await c.delete(`/api/accounts/${add.body.id}`)).status).toBe(200);
  });
});

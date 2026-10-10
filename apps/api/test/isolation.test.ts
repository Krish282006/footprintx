import { beforeEach, describe, expect, it } from 'vitest';
import ExcelJS from 'exceljs';
import { connectFixture, loadFixtureBreaches, makeApp, pool, resetDb, signedIn } from './helpers.js';

beforeEach(resetDb);

describe('cross-user isolation (IDOR)', () => {
  it("one user cannot read or modify another user's resources", async () => {
    const { app, ctx } = makeApp();
    await loadFixtureBreaches(ctx);
    const alice = await signedIn(app, 'alice@iso.example');
    const bob = await signedIn(app, 'bob@iso.example');
    const { connectionId, scanId } = await connectFixture(alice, ctx);
    const acct = (await alice.get('/api/accounts')).body.accounts[0];
    const item = (await alice.get('/api/remediation')).body.items[0];
    const alert = (await alice.get('/api/alerts')).body.alerts[0];
    await alice.post('/api/dev/plan', { plan: 'premium' });
    const code = (await alice.post('/api/extension/link-code')).body.code;
    expect(code).toBeTruthy();

    expect((await bob.get(`/api/accounts/${acct.id}`)).status).toBe(404);
    expect((await bob.patch(`/api/accounts/${acct.id}`, { ownership: 'false_positive' })).status).toBe(404);
    expect((await bob.delete(`/api/accounts/${acct.id}`)).status).toBe(404);
    expect((await bob.patch(`/api/remediation/${item.id}`, { status: 'in_progress' })).status).toBe(404);
    expect((await bob.post(`/api/remediation/${item.id}/verify`)).status).toBe(404);
    expect((await bob.post(`/api/alerts/${alert.id}/read`)).status).toBe(404);
    expect((await bob.get(`/api/connections/scans/${scanId}`)).status).toBe(404);
    expect((await bob.post(`/api/connections/${connectionId}/scan`)).status).toBe(404);
    expect((await bob.delete(`/api/connections/${connectionId}`)).status).toBe(404);
    const tokens = (await alice.get('/api/extension/tokens')).body.tokens;
    expect(tokens).toEqual([]);

    expect((await bob.get('/api/accounts')).body.accounts).toEqual([]);
    expect((await bob.get('/api/remediation')).body.items).toEqual([]);
    expect((await bob.get('/api/alerts')).body.alerts).toEqual([]);
    expect((await bob.get('/api/connections')).body.connections).toEqual([]);
    expect((await bob.get('/api/dashboard')).body.dasi.score).toBeNull();

    // Bob's report contains none of Alice's data.
    const res = await bob.get('/api/reports/security.xlsx').buffer(true).parse((r, cb) => {
      const chunks: Buffer[] = [];
      r.on('data', (d: Buffer) => chunks.push(d));
      r.on('end', () => cb(null, Buffer.concat(chunks)));
    });
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(res.body);
    const text = JSON.stringify(wb.worksheets.map((w) => w.getSheetValues()));
    expect(text).not.toContain('alice@iso.example');
    expect(text).not.toContain('fixtureshop.example');

    // Alice's data is unchanged by Bob's attempts.
    expect((await alice.get(`/api/accounts/${acct.id}`)).body.account.ownership).toBe(acct.ownership);
  });

  it('account deletion removes all of the user’s data and only theirs', async () => {
    const { app, ctx } = makeApp();
    const alice = await signedIn(app, 'del-a@iso.example');
    const bob = await signedIn(app, 'del-b@iso.example');
    await connectFixture(alice, ctx);
    await connectFixture(bob, ctx);
    expect((await alice.post('/api/privacy/delete-account', { password: 'wrong', confirm: 'DELETE' })).status).toBe(400);
    expect((await alice.post('/api/privacy/delete-account', { password: 'correct-horse-battery-1', confirm: 'nope' })).status).toBe(400);
    const res = await alice.post('/api/privacy/delete-account', { password: 'correct-horse-battery-1', confirm: 'DELETE' });
    expect(res.status).toBe(200);
    expect(res.body.revocations).toEqual([{ provider: 'devfixture', result: 'not_applicable' }]);
    for (const t of ['users', 'accounts', 'evidence', 'findings', 'remediation_items', 'dasi_snapshots', 'email_connections', 'scans', 'alerts', 'sessions']) {
      const { rows } = await pool().query(`SELECT count(*)::int AS n FROM ${t} WHERE ${t === 'users' ? 'id' : 'user_id'} = $1`, [alice.userId]);
      expect(rows[0].n, t).toBe(0);
    }
    expect((await alice.get('/api/accounts')).status).toBe(401);
    expect((await bob.get('/api/accounts')).body.accounts.length).toBeGreaterThan(0);
  });
});

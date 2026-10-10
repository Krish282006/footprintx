import { beforeEach, describe, expect, it } from 'vitest';
import ExcelJS from 'exceljs';
import request from 'supertest';
import { Client, connectFixture, loadFixtureBreaches, makeApp, pool, resetDb, signedIn } from './helpers.js';
import { safeCell } from '../src/reports/xlsx.js';

beforeEach(resetDb);

const binary = (c: Client, path: string) =>
  c.get(path).buffer(true).parse((r, cb) => {
    const chunks: Buffer[] = [];
    r.on('data', (d: Buffer) => chunks.push(d));
    r.on('end', () => cb(null, Buffer.concat(chunks)));
  });

async function open(buf: Buffer) {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.load(buf);
  return wb;
}

describe('Excel reports', () => {
  it('downloads a valid .xlsx built from the user’s persisted data', async () => {
    const { app, ctx } = makeApp();
    await loadFixtureBreaches(ctx);
    const c = await signedIn(app, 'report@example.com');
    await connectFixture(c, ctx);
    const res = await binary(c, '/api/reports/security.xlsx');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    expect(res.headers['content-disposition']).toMatch(/attachment; filename="footprintx-report-\d{4}-\d{2}-\d{2}\.xlsx"/);
    expect((res.body as Buffer).subarray(0, 2).toString()).toBe('PK'); // zip container, not JSON
    const wb = await open(res.body);
    expect(wb.worksheets.map((w) => w.name)).toEqual(['Summary', 'Accounts', 'Risk Findings', 'Recommendations', 'DASI History', 'Scans']);

    const accounts = wb.getWorksheet('Accounts')!;
    expect(accounts.getRow(1).values).toContain('Service');
    expect(accounts.autoFilter).toBeTruthy();
    expect(accounts.getColumn(1).width).toBeGreaterThan(10);
    const dbCount = (await pool().query('SELECT count(*)::int AS n FROM accounts WHERE user_id=$1', [c.userId])).rows[0].n;
    expect(accounts.rowCount - 1).toBe(dbCount);
    const domains = accounts.getColumn(2).values.slice(2);
    expect(domains).toContain('fixtureshop.example');
    const origin = accounts.getColumn(13).values.slice(2);
    expect(new Set(origin)).toEqual(new Set(['Development fixture']));

    const summary = wb.getWorksheet('Summary')!;
    const summaryText = JSON.stringify(summary.getSheetValues());
    expect(summaryText).toContain('report@example.com');
    expect(summaryText).toContain('synthetic test data');
    const dasi = (await c.get('/api/dashboard')).body.dasi.score;
    expect(summaryText).toContain(`"Digital Attack Surface Index (0–100, higher = more risk)",${dasi}`);

    const findings = wb.getWorksheet('Risk Findings')!;
    expect(findings.rowCount).toBeGreaterThan(1);
    const history = wb.getWorksheet('DASI History')!;
    expect(history.rowCount).toBeGreaterThan(1);
    // Explicit unknown values instead of blanks.
    const mfa = accounts.getColumn(7).values.slice(2);
    expect(mfa).toContain('Unknown');
  });

  it('neutralises spreadsheet formula injection', async () => {
    expect(safeCell('=HYPERLINK("http://evil","x")')).toBe(`'=HYPERLINK("http://evil","x")`);
    expect(safeCell('+1')).toBe("'+1");
    expect(safeCell('-2+3')).toBe("'-2+3");
    expect(safeCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(safeCell(null)).toBe('Unknown');
    expect(safeCell(5)).toBe(5);

    const { app } = makeApp();
    const c = await signedIn(app, 'inject@example.com');
    const add = await c.post('/api/accounts', { domain: 'inject.example', serviceName: '=cmd|"/c calc"!A1' });
    expect(add.status).toBe(201);
    const wb = await open((await binary(c, '/api/reports/security.xlsx')).body);
    const ws = wb.getWorksheet('Accounts')!;
    let sawPayload = false;
    ws.eachRow((row) =>
      row.eachCell((cell) => {
        expect(cell.type).not.toBe(ExcelJS.ValueType.Formula);
        if (String(cell.value).includes('cmd|')) {
          sawPayload = true;
          expect(String(cell.value).startsWith("'")).toBe(true);
        }
      }),
    );
    expect(sawPayload).toBe(true);
  });

  it('requires authentication and includes Security Activity only for Premium', async () => {
    const { app } = makeApp();
    expect((await request(app).get('/api/reports/security.xlsx')).status).toBe(401);
    expect((await request(app).get('/api/privacy/export.xlsx')).status).toBe(401);
    const c = await signedIn(app, 'prem-report@example.com');
    const free = await open((await binary(c, '/api/reports/security.xlsx')).body);
    expect(free.getWorksheet('Security Activity')).toBeUndefined();
    await c.post('/api/dev/plan', { plan: 'premium' });
    const prem = await open((await binary(c, '/api/reports/security.xlsx')).body);
    expect(prem.getWorksheet('Security Activity')).toBeDefined();
  });

  it('exports all personal data as a workbook', async () => {
    const { app, ctx } = makeApp();
    const c = await signedIn(app, 'export@example.com');
    await connectFixture(c, ctx);
    const res = await binary(c, '/api/privacy/export.xlsx');
    expect(res.status).toBe(200);
    const wb = await open(res.body);
    expect(wb.worksheets.map((w) => w.name)).toEqual(expect.arrayContaining(['Profile', 'Email connections', 'Accounts', 'Evidence', 'Findings', 'DASI history']));
    expect(JSON.stringify(wb.getWorksheet('Profile')!.getSheetValues())).toContain('export@example.com');
    expect(JSON.stringify(wb.getWorksheet('Profile')!.getSheetValues())).not.toContain('argon2');
    expect(JSON.stringify(wb.getWorksheet('Email connections')!.getSheetValues())).not.toMatch(/token/i);
  });
});

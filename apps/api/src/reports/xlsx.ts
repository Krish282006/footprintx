import ExcelJS from 'exceljs';
import type { Db } from '../db/pool.js';

const UNKNOWN = 'Unknown';

/**
 * Neutralises spreadsheet formula injection: any text beginning with a formula
 * trigger character is prefixed with an apostrophe so it is displayed as text.
 */
export function safeCell(value: unknown): string | number | Date | boolean {
  if (value === null || value === undefined || value === '') return UNKNOWN;
  if (value instanceof Date || typeof value === 'number' || typeof value === 'boolean') return value;
  const s = String(value);
  return /^[=+\-@\t\r|%]/.test(s) ? `'${s}` : s;
}

type Col = { header: string; key: string; width: number; date?: boolean };

function addSheet(wb: ExcelJS.Workbook, name: string, cols: Col[], rows: Record<string, unknown>[], emptyNote: string) {
  const ws = wb.addWorksheet(name, { views: [{ state: 'frozen', ySplit: 1 }] });
  ws.columns = cols.map((c) => ({ header: c.header, key: c.key, width: c.width, style: c.date ? { numFmt: 'yyyy-mm-dd hh:mm' } : {} }));
  const header = ws.getRow(1);
  header.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  header.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3A5F' } };
  header.alignment = { vertical: 'middle', wrapText: true };
  if (!rows.length) {
    ws.addRow({ [cols[0].key]: emptyNote });
  } else {
    for (const r of rows) {
      const out: Record<string, unknown> = {};
      for (const c of cols) out[c.key] = safeCell(r[c.key]);
      ws.addRow(out);
    }
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: cols.length } };
  }
  ws.eachRow((row, i) => {
    if (i > 1) row.alignment = { vertical: 'top', wrapText: true };
  });
  return ws;
}

const LABEL: Record<string, string> = {
  recommended: 'Recommended', in_progress: 'In progress', user_reported_complete: 'User-reported complete',
  verification_pending: 'Verification pending', verified_complete: 'Verified complete', unable_to_verify: 'Unable to verify', dismissed: 'Dismissed',
  discovered: 'Discovered from email evidence', user_confirmed: 'Confirmed by you', user_added: 'Added by you', false_positive: 'Marked not mine',
  unknown: 'Unknown', user_reported_enabled: 'Enabled (user-reported)', user_reported_disabled: 'Not enabled (user-reported)', evidence_enabled: 'Enabled (confirmation email found)',
  open: 'Open', mitigated_user_reported: 'Mitigated (user-reported)', mitigated_verified: 'Mitigated (verified)', inactive: 'No longer applicable',
  curated_official: 'Official page (curated)', well_known_standard: 'Standard change-password address (unverified)',
};
const label = (v: string | null | undefined) => (v ? (LABEL[v] ?? v) : null);

export async function buildSecurityReport(db: Db, userId: string, opts: { includeSecurityEvents: boolean }): Promise<Buffer> {
  const user = (await db.query<{ email: string; plan: string; plan_source: string }>('SELECT email, plan, plan_source FROM users WHERE id=$1', [userId])).rows[0];
  if (!user) throw new Error('User not found');
  const latest = (await db.query('SELECT score, level, coverage, model_version, created_at FROM dasi_snapshots WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1', [userId])).rows[0];
  const accounts = (await db.query(
    `SELECT a.*, (SELECT string_agg(email_address, ', ') FROM account_identities i WHERE i.account_id=a.id) AS identities,
            (SELECT count(*)::int FROM evidence e WHERE e.account_id=a.id) AS evidence_count
       FROM accounts a WHERE a.user_id=$1 ORDER BY a.risk_score DESC NULLS LAST, a.service_name`, [userId])).rows;
  const findings = (await db.query(
    `SELECT f.*, a.service_name FROM findings f JOIN accounts a ON a.id=f.account_id WHERE f.user_id=$1
      ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.contribution DESC`, [userId])).rows;
  const items = (await db.query(
    `SELECT ri.*, a.service_name FROM remediation_items ri JOIN accounts a ON a.id=ri.account_id WHERE ri.user_id=$1 ORDER BY ri.priority DESC`, [userId])).rows;
  const history = (await db.query('SELECT * FROM dasi_snapshots WHERE user_id=$1 ORDER BY created_at ASC', [userId])).rows;
  const scans = (await db.query('SELECT * FROM scans WHERE user_id=$1 ORDER BY started_at DESC LIMIT 50', [userId])).rows;
  const anyFixture = accounts.some((a) => a.is_fixture);

  const wb = new ExcelJS.Workbook();
  wb.creator = 'FootprintX';
  wb.created = new Date();

  const summary = wb.addWorksheet('Summary');
  summary.columns = [{ header: 'Item', key: 'k', width: 34 }, { header: 'Value', key: 'v', width: 80 }];
  summary.getRow(1).font = { bold: true };
  const openItems = items.filter((i) => ['recommended', 'in_progress'].includes(i.status)).length;
  const summaryRows: [string, unknown][] = [
    ['Report', 'FootprintX security report'],
    ['Generated', new Date()],
    ['Account email', user.email],
    ['Plan', user.plan === 'premium' ? (user.plan_source === 'development' ? 'Premium (development entitlement, no payment)' : 'Premium') : 'Free'],
    ['Digital Attack Surface Index (0–100, higher = more risk)', latest?.score ?? 'Not yet calculated'],
    ['Risk level', latest?.level ?? UNKNOWN],
    ['Discovery coverage', latest?.coverage ?? 'none'],
    ['DASI model version', latest?.model_version ?? UNKNOWN],
    ['Accounts in inventory (excluding "not mine")', accounts.filter((a) => a.ownership !== 'false_positive').length],
    ['Open critical findings', findings.filter((f) => f.severity === 'critical' && f.state === 'open').length],
    ['Open recommended actions', openItems],
    ['Development fixtures included', anyFixture ? 'YES — rows marked "Development fixture" are synthetic test data, not real discoveries' : 'No'],
    ['Important', 'Service-level breaches show that a service was breached, not that your account was included. "Unknown" means FootprintX has no reliable evidence either way.'],
  ];
  for (const [k, v] of summaryRows) summary.addRow({ k, v: safeCell(v) });
  summary.getColumn('v').alignment = { wrapText: true, vertical: 'top' };
  summary.getCell('B3').numFmt = 'yyyy-mm-dd hh:mm';

  addSheet(wb, 'Accounts', [
    { header: 'Service', key: 'service_name', width: 22 },
    { header: 'Domain', key: 'service_domain', width: 26 },
    { header: 'Category', key: 'category', width: 16 },
    { header: 'Source', key: 'ownership', width: 26 },
    { header: 'Existence confidence', key: 'confidence', width: 12 },
    { header: 'Email identities', key: 'identities', width: 34 },
    { header: 'Two-step verification', key: 'mfa_status', width: 26 },
    { header: 'Account risk (0–100)', key: 'risk_score', width: 12 },
    { header: 'Risk level', key: 'risk_level', width: 12 },
    { header: 'Evidence items', key: 'evidence_count', width: 10 },
    { header: 'First seen', key: 'first_seen_at', width: 18, date: true },
    { header: 'Last seen', key: 'last_seen_at', width: 18, date: true },
    { header: 'Data origin', key: 'origin', width: 22 },
  ], accounts.map((a) => ({ ...a, ownership: label(a.ownership), mfa_status: label(a.mfa_status), risk_score: a.risk_score ?? 'Excluded', origin: a.is_fixture ? 'Development fixture' : 'Live' })), 'No accounts discovered yet.');

  addSheet(wb, 'Risk Findings', [
    { header: 'Service', key: 'service_name', width: 22 },
    { header: 'Severity', key: 'severity', width: 10 },
    { header: 'Finding', key: 'title', width: 44 },
    { header: 'Type', key: 'finding_type', width: 18 },
    { header: 'State', key: 'state', width: 22 },
    { header: 'Risk points', key: 'contribution', width: 10 },
    { header: 'Explanation', key: 'explanation', width: 90 },
    { header: 'First detected', key: 'first_detected_at', width: 18, date: true },
    { header: 'Data origin', key: 'origin', width: 22 },
  ], findings.map((f) => ({ ...f, state: label(f.state), origin: f.details?.isFixture ? 'Development fixture' : 'Live' })), 'No findings.');

  addSheet(wb, 'Recommendations', [
    { header: 'Priority', key: 'priority', width: 9 },
    { header: 'Service', key: 'service_name', width: 22 },
    { header: 'Action', key: 'title', width: 44 },
    { header: 'Status', key: 'status', width: 24 },
    { header: 'Status note', key: 'status_note', width: 50 },
    { header: 'Official link', key: 'official_url', width: 50 },
    { header: 'Link type', key: 'url_kind', width: 30 },
    { header: 'User reported at', key: 'user_reported_at', width: 18, date: true },
    { header: 'Verified at', key: 'verified_at', width: 18, date: true },
  ], items.map((i) => ({
    ...i, status: label(i.status), url_kind: label(i.url_kind),
    official_url: i.official_url ?? 'No verified link', status_note: i.status_note ?? '—',
    user_reported_at: i.user_reported_at ?? '—', verified_at: i.verified_at ?? '—',
  })), 'No recommendations.');

  addSheet(wb, 'DASI History', [
    { header: 'Date', key: 'created_at', width: 18, date: true },
    { header: 'DASI', key: 'score', width: 8 },
    { header: 'Level', key: 'level', width: 12 },
    { header: 'Coverage', key: 'coverage', width: 12 },
    { header: 'Model', key: 'model_version', width: 10 },
    { header: 'Reason', key: 'reason', width: 50 },
    { header: 'Changes', key: 'changes_text', width: 80 },
  ], history.map((h) => ({
    ...h,
    score: h.score ?? 'Not calculated',
    changes_text: (h.changes as { serviceName: string; from: number | null; to: number | null; reason: string }[]).length
      ? (h.changes as { serviceName: string; from: number | null; to: number | null; reason: string }[])
          .map((c) => `${c.serviceName}: ${c.from ?? '—'} → ${c.to ?? '—'} (${c.reason})`).join('; ')
      : 'No account-level changes',
  })), 'No score history yet.');

  addSheet(wb, 'Scans', [
    { header: 'Started', key: 'started_at', width: 18, date: true },
    { header: 'Provider', key: 'provider', width: 14 },
    { header: 'Status', key: 'status', width: 12 },
    { header: 'Messages examined', key: 'messages_examined', width: 12 },
    { header: 'Evidence found', key: 'evidence_found', width: 12 },
    { header: 'Error', key: 'error_message', width: 50 },
    { header: 'Data origin', key: 'origin', width: 22 },
  ], scans.map((s) => ({ ...s, error_message: s.error_message ?? '—', origin: s.is_fixture ? 'Development fixture' : 'Live' })), 'No scans yet.');

  if (opts.includeSecurityEvents) {
    const events = (await db.query('SELECT * FROM security_events WHERE user_id=$1 ORDER BY occurred_at DESC LIMIT 1000', [userId])).rows;
    addSheet(wb, 'Security Activity', [
      { header: 'When', key: 'occurred_at', width: 18, date: true },
      { header: 'Domain', key: 'domain', width: 36 },
      { header: 'Status', key: 'status', width: 10 },
      { header: 'Action', key: 'action', width: 14 },
      { header: 'Reasons', key: 'reasons_text', width: 80 },
    ], events.map((e) => ({ ...e, reasons_text: (e.reasons as string[]).join(' ') })), 'No synced security events (sync is opt-in).');
  }

  return Buffer.from(await wb.xlsx.writeBuffer());
}

/** Full personal-data export as a workbook (privacy / portability). */
export async function buildDataExport(db: Db, userId: string): Promise<Buffer> {
  const wb = new ExcelJS.Workbook();
  wb.creator = 'FootprintX';
  const tables: [string, string][] = [
    ['Profile', 'SELECT id, email, display_name, plan, plan_source, privacy_policy_version, privacy_consent_at, created_at FROM users WHERE id=$1'],
    ['Email connections', 'SELECT id, provider, email_address, status, scopes, consent_version, consent_at, last_scan_at, created_at FROM email_connections WHERE user_id=$1'],
    ['Scans', 'SELECT id, provider, is_fixture, status, messages_examined, evidence_found, accounts_new, error_code, started_at, finished_at FROM scans WHERE user_id=$1'],
    ['Accounts', 'SELECT id, service_name, service_domain, category, ownership, confidence, mfa_status, is_fixture, first_seen_at, last_seen_at, risk_score, risk_level FROM accounts WHERE user_id=$1'],
    ['Evidence', 'SELECT id, account_id, source, evidence_type, signal, confidence, sender_domain, identity_email, observed_at, is_fixture FROM evidence WHERE user_id=$1'],
    ['Findings', 'SELECT id, account_id, finding_type, severity, title, state, contribution, first_detected_at, updated_at FROM findings WHERE user_id=$1'],
    ['Remediation', 'SELECT id, account_id, action_type, title, status, status_note, user_reported_at, verified_at, created_at FROM remediation_items WHERE user_id=$1'],
    ['Remediation history', 'SELECT item_id, from_status, to_status, note, created_at FROM remediation_events WHERE user_id=$1'],
    ['DASI history', 'SELECT score, level, coverage, model_version, reason, created_at FROM dasi_snapshots WHERE user_id=$1'],
    ['Alerts', 'SELECT kind, severity, title, read_at, created_at FROM alerts WHERE user_id=$1'],
    ['Notification settings', 'SELECT email_security_alerts, email_remediation_reminders, email_periodic_summary, email_consent_at, security_event_sync, security_event_sync_consent_at FROM notification_preferences WHERE user_id=$1'],
    ['Extension links', 'SELECT label, created_at, last_used_at, revoked_at FROM extension_tokens WHERE user_id=$1'],
    ['Security events', 'SELECT domain, status, action, reasons, occurred_at FROM security_events WHERE user_id=$1'],
    ['Contact messages', 'SELECT subject, delivery_status, created_at FROM contact_messages WHERE user_id=$1'],
  ];
  for (const [name, sql] of tables) {
    const { rows, fields } = await db.query(sql, [userId]);
    const cols = fields.map((f) => ({ header: f.name, key: f.name, width: Math.min(50, Math.max(12, f.name.length + 4)), date: /_at$/.test(f.name) }));
    addSheet(wb, name, cols, rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : v && typeof v === 'object' && !(v instanceof Date) ? JSON.stringify(v) : v]))), 'No data.');
  }
  return Buffer.from(await wb.xlsx.writeBuffer());
}

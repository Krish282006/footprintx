import type { Config } from '../config.js';
import type { Db } from '../db/pool.js';
import type { Mailer, DeliveryStatus } from '../email/mailer.js';
import { sha256Hex } from '../lib/crypto.js';
import type { NewAlert } from '../dasi/risk-service.js';

export type Prefs = {
  email_security_alerts: boolean;
  email_remediation_reminders: boolean;
  email_periodic_summary: boolean;
  email_consent_at: Date | null;
  security_event_sync: boolean;
  security_event_sync_consent_at: Date | null;
  last_summary_sent_at: Date | null;
  last_summary_fingerprint: string | null;
};

export async function getPrefs(db: Db, userId: string): Promise<Prefs> {
  await db.query('INSERT INTO notification_preferences (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);
  const { rows } = await db.query<Prefs>('SELECT * FROM notification_preferences WHERE user_id = $1', [userId]);
  return rows[0];
}

/**
 * Sends one email per (user, kind, fingerprint). A unique index prevents a second
 * successful send of the same notification; failures are recorded and may retry.
 */
export async function deliverOnce(
  db: Db, mailer: Mailer, userId: string, kind: string, fingerprint: string, to: string, subject: string, text: string,
): Promise<DeliveryStatus | 'duplicate'> {
  const existing = await db.query(
    `SELECT 1 FROM notification_deliveries WHERE user_id=$1 AND kind=$2 AND fingerprint=$3 AND status IN ('sent','dev_logged')`,
    [userId, kind, fingerprint],
  );
  if (existing.rowCount) return 'duplicate';
  const result = await mailer.send({ to, subject, text });
  await db.query(
    `INSERT INTO notification_deliveries (user_id, kind, fingerprint, status, error) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
    [userId, kind, fingerprint, result.status, result.error ?? null],
  );
  return result.status;
}

const footer = (config: Config) =>
  `\n\nManage email notifications: ${config.WEB_ORIGIN}/settings#notifications\n` +
  'FootprintX will never ask for your passwords, one-time codes or recovery codes by email.';

/** Emails newly created critical/high alerts to users who opted in. In-app alerts exist regardless. */
export async function notifyNewAlerts(config: Config, db: Db, mailer: Mailer, alerts: NewAlert[]) {
  const byUser = new Map<string, NewAlert[]>();
  for (const a of alerts) byUser.set(a.userId, [...(byUser.get(a.userId) ?? []), a]);
  for (const [userId, list] of byUser) {
    const prefs = await getPrefs(db, userId);
    if (!prefs.email_security_alerts || !prefs.email_consent_at) continue;
    const user = await db.query<{ email: string }>('SELECT email FROM users WHERE id=$1', [userId]);
    if (!user.rows[0]) continue;
    const fingerprint = sha256Hex(list.map((a) => a.id).sort().join(','));
    const text =
      `FootprintX found ${list.length} new important finding${list.length > 1 ? 's' : ''}:\n\n` +
      list.map((a) => `- [${a.severity.toUpperCase()}] ${a.title}`).join('\n') +
      `\n\nReview them: ${config.WEB_ORIGIN}/dashboard` + footer(config);
    await deliverOnce(db, mailer, userId, 'security_alert', fingerprint, user.rows[0].email, 'FootprintX: new security findings', text);
  }
}

/**
 * Periodic job (run daily by a scheduler, e.g. a Render cron job):
 *  - remediation reminders: open items in progress/recommended for 7+ days, at most weekly per item;
 *  - weekly summary: only when the user's DASI or open items changed since the last summary.
 */
export type JobStats = { reminders: number; summaries: number; skipped: number; note?: string };

export async function runNotificationJob(config: Config, db: Db, mailer: Mailer, now = new Date()): Promise<JobStats> {
  const stats: JobStats = { reminders: 0, summaries: 0, skipped: 0 };
  if (!mailer.isConfigured()) return { ...stats, note: 'Email delivery not configured; no emails sent.' };
  const users = await db.query<{ id: string; email: string } & Prefs>(
    `SELECT u.id, u.email, p.* FROM users u JOIN notification_preferences p ON p.user_id = u.id
      WHERE p.email_consent_at IS NOT NULL AND (p.email_remediation_reminders OR p.email_periodic_summary)`,
  );
  for (const u of users.rows) {
    if (u.email_remediation_reminders) {
      const items = await db.query<{ id: string; title: string }>(
        `SELECT ri.id, ri.title FROM remediation_items ri JOIN findings f ON f.id = ri.finding_id
           JOIN accounts a ON a.id = ri.account_id
          WHERE ri.user_id=$1 AND ri.status IN ('recommended','in_progress') AND f.state = 'open'
            AND a.ownership <> 'false_positive' AND f.severity IN ('critical','high')
            AND ri.created_at < $2::timestamptz - interval '7 days'
            AND (ri.last_reminded_at IS NULL OR ri.last_reminded_at < $2::timestamptz - interval '7 days')
          ORDER BY ri.priority DESC LIMIT 5`,
        [u.id, now],
      );
      if (items.rows.length) {
        const week = `${now.getUTCFullYear()}-${Math.floor(now.getTime() / (7 * 86400_000))}`;
        const status = await deliverOnce(
          db, mailer, u.id, 'remediation_reminder', `${week}:${items.rows.map((i) => i.id).join(',')}`, u.email,
          'FootprintX: recommended security actions waiting',
          `These high-priority actions are still open:\n\n${items.rows.map((i) => `- ${i.title}`).join('\n')}\n\n` +
            `Open your remediation list: ${config.WEB_ORIGIN}/remediation` + footer(config),
        );
        if (status === 'sent' || status === 'dev_logged') {
          await db.query('UPDATE remediation_items SET last_reminded_at=$2 WHERE id = ANY($1::uuid[])', [items.rows.map((i) => i.id), now]);
          stats.reminders++;
        } else stats.skipped++;
      }
    }
    if (u.email_periodic_summary) {
      const due = !u.last_summary_sent_at || now.getTime() - new Date(u.last_summary_sent_at).getTime() >= 7 * 86400_000;
      if (!due) continue;
      const snap = await db.query<{ score: number | null; level: string }>(
        'SELECT score, level FROM dasi_snapshots WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1',
        [u.id],
      );
      const open = await db.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM remediation_items ri JOIN findings f ON f.id = ri.finding_id
          WHERE ri.user_id=$1 AND ri.status IN ('recommended','in_progress') AND f.state='open'`,
        [u.id],
      );
      const fingerprint = sha256Hex(`${snap.rows[0]?.score ?? 'none'}:${open.rows[0].n}`);
      if (fingerprint === u.last_summary_fingerprint) {
        stats.skipped++;
        continue; // Nothing changed: no email.
      }
      const score = snap.rows[0]?.score;
      const status = await deliverOnce(
        db, mailer, u.id, 'periodic_summary', `${fingerprint}:${now.toISOString().slice(0, 10)}`, u.email,
        'FootprintX: your weekly security summary',
        `Digital Attack Surface Index: ${score ?? 'not yet calculated'}${snap.rows[0] ? ` (${snap.rows[0].level})` : ''}\n` +
          `Open recommended actions: ${open.rows[0].n}\n\nView details: ${config.WEB_ORIGIN}/dashboard` + footer(config),
      );
      if (status === 'sent' || status === 'dev_logged') {
        await db.query('UPDATE notification_preferences SET last_summary_sent_at=$2, last_summary_fingerprint=$3 WHERE user_id=$1', [u.id, now, fingerprint]);
        stats.summaries++;
      } else stats.skipped++;
    }
  }
  return stats;
}

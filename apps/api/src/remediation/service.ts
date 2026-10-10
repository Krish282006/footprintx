import type { Db } from '../db/pool.js';

export const STATUSES = [
  'recommended', 'in_progress', 'user_reported_complete', 'verification_pending', 'verified_complete', 'unable_to_verify', 'dismissed',
] as const;
export type RemediationStatus = (typeof STATUSES)[number];

/** Transitions a user may request. verification_pending/verified/unable are system-set. */
const USER_TRANSITIONS: Record<RemediationStatus, RemediationStatus[]> = {
  recommended: ['in_progress', 'user_reported_complete', 'dismissed'],
  in_progress: ['recommended', 'user_reported_complete', 'dismissed'],
  user_reported_complete: ['in_progress', 'recommended'],
  verification_pending: ['in_progress', 'recommended'],
  verified_complete: ['recommended'],
  unable_to_verify: ['in_progress', 'user_reported_complete', 'recommended'],
  dismissed: ['recommended'],
};

export function canTransition(from: RemediationStatus, to: RemediationStatus) {
  return USER_TRANSITIONS[from].includes(to);
}

type ItemRow = {
  id: string; user_id: string; account_id: string; action_type: string; status: RemediationStatus;
  finding_details: { breachDate?: string | null }; finding_type: string;
};

/**
 * Evidence-based verifiers. Only actions with a reliable signal can be verified:
 *  - change_password: a "your password was changed" email from the service after the breach date;
 *  - enable_mfa: a "two-step verification turned on" email from the service;
 *  - delete_account: an "account deleted/closed" email from the service.
 * Everything else cannot be verified by FootprintX and is reported honestly as such.
 */
async function findVerifyingEvidence(db: Db, item: ItemRow): Promise<{ observed_at: Date; signal: string } | null> {
  let signal: string | null = null;
  let after: string | null = null;
  if (item.action_type === 'change_password') {
    signal = 'password_changed';
    after = item.finding_details?.breachDate ?? null;
  } else if (item.action_type === 'enable_mfa') signal = 'mfa_enabled';
  else if (item.action_type === 'delete_account') signal = 'account_closed';
  if (!signal) return null;
  const { rows } = await db.query<{ observed_at: Date; signal: string }>(
    `SELECT observed_at, signal FROM evidence WHERE account_id=$1 AND signal=$2 AND ($3::date IS NULL OR observed_at > $3::date)
      ORDER BY observed_at DESC LIMIT 1`,
    [item.account_id, signal, after],
  );
  return rows[0] ?? null;
}

export const HAS_VERIFIER = new Set(['change_password', 'enable_mfa', 'delete_account']);

async function setStatus(db: Db, item: ItemRow, to: RemediationStatus, note: string) {
  await db.query(
    `UPDATE remediation_items SET status=$2, status_note=$3, updated_at=now(),
       verified_at = CASE WHEN $2 = 'verified_complete' THEN now() ELSE verified_at END WHERE id=$1`,
    [item.id, to, note],
  );
  await db.query('INSERT INTO remediation_events (user_id, item_id, from_status, to_status, note) VALUES ($1,$2,$3,$4,$5)', [item.user_id, item.id, item.status, to, note]);
  if (to === 'verified_complete' && item.action_type === 'enable_mfa') {
    await db.query(`UPDATE accounts SET mfa_status='evidence_enabled', updated_at=now() WHERE id=$1`, [item.account_id]);
  }
}

async function loadItem(db: Db, userId: string, itemId: string): Promise<ItemRow | null> {
  const { rows } = await db.query<ItemRow>(
    `SELECT ri.id, ri.user_id, ri.account_id, ri.action_type, ri.status, f.details AS finding_details, f.finding_type
       FROM remediation_items ri JOIN findings f ON f.id = ri.finding_id WHERE ri.id=$1 AND ri.user_id=$2`,
    [itemId, userId],
  );
  return rows[0] ?? null;
}

/** Runs verification for one item the user reported complete. */
export async function requestVerification(db: Db, userId: string, itemId: string): Promise<RemediationStatus | null> {
  const item = await loadItem(db, userId, itemId);
  if (!item) return null;
  if (!['user_reported_complete', 'unable_to_verify'].includes(item.status)) {
    throw Object.assign(new Error('Mark the action as done before requesting verification.'), { status: 409 });
  }
  if (!HAS_VERIFIER.has(item.action_type)) {
    await setStatus(db, item, 'unable_to_verify', 'FootprintX has no reliable way to confirm this action on the external website. Your report is kept as user-reported.');
    return 'unable_to_verify';
  }
  const ev = await findVerifyingEvidence(db, item);
  if (ev) {
    await setStatus(db, item, 'verified_complete', `Verified by a confirmation email from the service dated ${ev.observed_at.toISOString().slice(0, 10)}.`);
    return 'verified_complete';
  }
  const active = await db.query(`SELECT 1 FROM email_connections WHERE user_id=$1 AND status='active' LIMIT 1`, [userId]);
  if (active.rowCount) {
    await setStatus(db, item, 'verification_pending', 'No confirmation email found yet. FootprintX will look again after your next mailbox scan.');
    return 'verification_pending';
  }
  await setStatus(db, item, 'unable_to_verify', 'No connected mailbox is available to look for a confirmation email from the service.');
  return 'unable_to_verify';
}

/** After a scan: resolve pending verifications. Unresolved items become unable_to_verify after a completed scan. */
export async function reverifyPending(db: Db, userId: string, scanCompleted: boolean) {
  const { rows } = await db.query<{ id: string }>(`SELECT id FROM remediation_items WHERE user_id=$1 AND status='verification_pending'`, [userId]);
  for (const r of rows) {
    const item = await loadItem(db, userId, r.id);
    if (!item) continue;
    const ev = await findVerifyingEvidence(db, item);
    if (ev) await setStatus(db, item, 'verified_complete', `Verified by a confirmation email from the service dated ${ev.observed_at.toISOString().slice(0, 10)}.`);
    else if (scanCompleted) await setStatus(db, item, 'unable_to_verify', 'The latest mailbox scan found no confirmation email from the service. Your report is kept as user-reported.');
  }
}

export async function changeStatus(db: Db, userId: string, itemId: string, to: RemediationStatus, note: string | null) {
  const item = await loadItem(db, userId, itemId);
  if (!item) return null;
  if (!canTransition(item.status, to)) {
    throw Object.assign(new Error(`Cannot change status from ${item.status} to ${to}.`), { status: 409 });
  }
  await db.query(
    `UPDATE remediation_items SET status=$2, status_note=$3, updated_at=now(),
       user_reported_at = CASE WHEN $2 = 'user_reported_complete' THEN now() ELSE user_reported_at END WHERE id=$1`,
    [itemId, to, note],
  );
  await db.query('INSERT INTO remediation_events (user_id, item_id, from_status, to_status, note) VALUES ($1,$2,$3,$4,$5)', [userId, itemId, item.status, to, note]);
  // Keep the account's reported two-step status consistent with the user's report.
  if (item.action_type === 'enable_mfa' && to === 'user_reported_complete') {
    await db.query(`UPDATE accounts SET mfa_status='user_reported_enabled', updated_at=now() WHERE id=$1 AND mfa_status IN ('unknown','user_reported_disabled')`, [item.account_id]);
  }
  return { accountId: item.account_id, from: item.status };
}

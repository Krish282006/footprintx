import type pg from 'pg';
import type { Db } from '../db/pool.js';
import { securityLink } from '../catalog/services.js';
import { breachCatalogStatus } from '../breach/catalog.js';
import {
  assessAccount, computeDasi, explainChanges, levelFor, MODEL_VERSION,
  type AccountInput, type Coverage, type DasiResult, type FindingCandidate, type MitigationState, type Severity,
} from './model.js';

const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 100, high: 70, medium: 40, low: 20, info: 5 };
const USER_REPORTED = new Set(['user_reported_complete', 'verification_pending', 'unable_to_verify']);

export type NewAlert = { id: string; userId: string; severity: Severity; title: string; body: string; kind: string };
export type RecalcResult = { dasi: DasiResult; snapshotCreated: boolean; newAlerts: NewAlert[] };

export async function discoveryCoverage(q: Db | pg.PoolClient, userId: string): Promise<Coverage> {
  const { rows } = await q.query<{ latest: string | null }>(
    `SELECT (SELECT s.status FROM scans s WHERE s.connection_id = c.id AND s.status <> 'running'
             ORDER BY s.started_at DESC LIMIT 1) AS latest
       FROM email_connections c WHERE c.user_id = $1`,
    [userId],
  );
  if (!rows.length) return 'none';
  if (rows.every((r) => r.latest === 'completed')) return 'complete';
  if (rows.some((r) => r.latest === 'completed' || r.latest === 'partial')) return 'partial';
  return 'none';
}

type AccountRow = {
  id: string; service_name: string; service_domain: string; category: string; ownership: AccountInput['ownership'];
  confidence: number; mfa_status: AccountInput['mfaStatus']; risk_score: number | null;
  earliest: Date | null; earliest_creation: Date | null; last_seen: Date | null;
};

async function loadAccountInputs(client: pg.PoolClient, userId: string, accountIds: string[] | null): Promise<AccountInput[]> {
  const { rows } = await client.query<AccountRow>(
    `SELECT a.id, a.service_name, a.service_domain, a.category, a.ownership, a.confidence, a.mfa_status, a.risk_score,
            (SELECT min(observed_at) FROM evidence e WHERE e.account_id = a.id AND e.source <> 'hibp') AS earliest,
            (SELECT min(observed_at) FROM evidence e WHERE e.account_id = a.id AND e.evidence_type = 'account_creation') AS earliest_creation,
            (SELECT max(observed_at) FROM evidence e WHERE e.account_id = a.id AND e.source <> 'hibp') AS last_seen
       FROM accounts a
      WHERE a.user_id = $1 AND ($2::uuid[] IS NULL OR a.id = ANY($2::uuid[]))`,
    [userId, accountIds],
  );
  const inputs: AccountInput[] = [];
  for (const r of rows) {
    const breaches = await client.query<{ id: string; title: string; breach_date: string | null; data_classes: string[]; source: string; email_confirmed: boolean; item_status: string | null }>(
      `SELECT b.id, b.title, b.breach_date, b.data_classes, b.source,
              EXISTS (SELECT 1 FROM evidence e WHERE e.account_id = $1 AND e.source = 'hibp' AND e.signal = 'hibp:' || b.id) AS email_confirmed,
              (SELECT ri.status FROM remediation_items ri JOIN findings f ON f.id = ri.finding_id
                WHERE f.account_id = $1 AND f.breach_id = b.id AND ri.action_type = 'change_password' LIMIT 1) AS item_status
         FROM breach_catalog b
        WHERE (b.domain = $2 OR EXISTS (SELECT 1 FROM evidence e WHERE e.account_id = $1 AND e.source = 'hibp' AND e.signal = 'hibp:' || b.id))
          AND NOT b.is_fabricated AND NOT b.is_spam_list
        ORDER BY b.breach_date NULLS LAST, b.id`,
      [r.id, r.service_domain],
    );
    const alerts = await client.query<{ observed_at: Date; signal: string }>(
      `SELECT observed_at, signal FROM evidence WHERE account_id = $1 AND evidence_type = 'security_notification'
         AND signal IN ('new_signin', 'suspicious_activity', 'security_alert_generic')`,
      [r.id],
    );
    const review = await client.query<{ user_reported_at: Date | null }>(
      `SELECT ri.user_reported_at FROM remediation_items ri JOIN findings f ON f.id = ri.finding_id
        WHERE f.account_id = $1 AND ri.action_type = 'review_activity' AND ri.status = ANY($2::text[]) LIMIT 1`,
      [r.id, [...USER_REPORTED, 'verified_complete']],
    );
    inputs.push({
      id: r.id,
      serviceName: r.service_name,
      serviceDomain: r.service_domain,
      category: r.category,
      ownership: r.ownership,
      confidence: r.confidence,
      mfaStatus: r.mfa_status,
      earliestEvidenceAt: r.earliest?.toISOString() ?? null,
      earliestCreationEvidenceAt: r.earliest_creation?.toISOString() ?? null,
      lastSeenAt: r.last_seen?.toISOString() ?? null,
      breaches: breaches.rows.map((b) => ({
        id: b.id,
        title: b.title,
        breachDate: b.breach_date,
        dataClasses: b.data_classes,
        isFixture: b.source === 'fixture',
        emailConfirmed: b.email_confirmed,
        passwordChange: (b.item_status === 'verified_complete' ? 'verified' : b.item_status && USER_REPORTED.has(b.item_status) ? 'user_reported' : 'none') as MitigationState,
      })),
      securityAlerts: alerts.rows.map((a) => ({ observedAt: a.observed_at.toISOString(), signal: a.signal })),
      activityReviewedAt: review.rows[0]?.user_reported_at?.toISOString() ?? null,
    });
  }
  return inputs;
}

type ActionSpec = { action: 'change_password' | 'enable_mfa' | 'review_activity' | 'delete_account' | 'review_account'; title: string; description: string; link: ReturnType<typeof securityLink> };

function actionsFor(f: FindingCandidate, a: AccountInput): ActionSpec[] {
  const name = a.serviceName;
  switch (f.type) {
    case 'service_breach':
    case 'email_breach': {
      const kind = (f.details as { dataKind?: string }).dataKind;
      if (kind === 'credentials' || kind === 'authSecrets') {
        return [{
          action: 'change_password',
          title: `Change your ${name} password`,
          description: `Set a new, unique password for ${name} from its official website. If you used the same password anywhere else, change it there too. A password manager makes unique passwords easy. FootprintX never asks for or stores your passwords.`,
          link: securityLink(a.serviceDomain, 'password'),
        }];
      }
      return [{
        action: 'review_account',
        title: `Review your ${name} account`,
        description: `Check the personal details stored in your ${name} account and be wary of emails or calls that mention this breach — attackers use leaked details to make phishing convincing.`,
        link: securityLink(a.serviceDomain, 'security'),
      }];
    }
    case 'security_alert':
      return [{
        action: 'review_activity',
        title: `Review recent sign-ins on ${name}`,
        description: `Open ${name}'s security page and check recent sign-ins and devices. If anything is unfamiliar, change your password and sign out other sessions.`,
        link: securityLink(a.serviceDomain, 'activity'),
      }];
    case 'posture_unknown':
      if (a.mfaStatus === 'user_reported_enabled' || a.mfaStatus === 'evidence_enabled') return [];
      return [{
        action: 'enable_mfa',
        title: `Turn on two-step verification for ${name}`,
        description: `Two-step verification stops most account takeovers even when a password leaks. Prefer an authenticator app or security key over SMS where ${name} offers it.`,
        link: securityLink(a.serviceDomain, 'mfa'),
      }];
    case 'dormant_account': {
      const link = securityLink(a.serviceDomain, 'delete');
      return [{
        action: 'delete_account',
        title: `Consider deleting your unused ${name} account`,
        description: link
          ? `If you no longer use ${name}, deleting the account removes data that could leak in a future breach.`
          : `If you no longer use ${name}, use its account settings or help pages to close the account. FootprintX does not have a verified deletion link for this service.`,
        link,
      }];
    }
  }
}

/**
 * Recalculates risk for the given accounts (or all of a user's accounts), persists
 * findings and remediation items, then recomputes the overall DASI and stores a
 * history snapshot when anything changed. Findings for other accounts are untouched.
 */
export async function recalculate(db: Db, userId: string, opts: { accountIds?: string[] | null; reason: string; now?: Date }): Promise<RecalcResult> {
  const now = opts.now ?? new Date();
  const breachStatus = await breachCatalogStatus(db);
  const client = await db.connect();
  const newAlerts: NewAlert[] = [];
  const reasons = new Map<string, string>();
  try {
    await client.query('BEGIN');
    // Serialise recalculations for the same user.
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [userId]);
    const inputs = await loadAccountInputs(client, userId, opts.accountIds ?? null);

    for (const input of inputs) {
      const assessment = assessAccount(input, now);
      const keptIds: string[] = [];
      for (const f of assessment.findings) {
        const fingerprint = `${input.id}:${f.key}`;
        const prev = await client.query<{ id: string; severity: Severity; contribution: number; state: string }>(
          'SELECT id, severity, contribution, state FROM findings WHERE user_id = $1 AND fingerprint = $2',
          [userId, fingerprint],
        );
        let findingId: string;
        if (prev.rows[0]) {
          findingId = prev.rows[0].id;
          const p = prev.rows[0];
          if (p.severity !== f.severity || Number(p.contribution) !== f.contribution || p.state !== f.state) {
            await client.query(
              `UPDATE findings SET severity=$2, title=$3, explanation=$4, contribution=$5, details=$6, state=$7, updated_at=now() WHERE id=$1`,
              [findingId, f.severity, f.title, f.explanation, f.contribution, JSON.stringify(f.details), f.state],
            );
          } else {
            // Keep explanatory text current without touching updated_at.
            await client.query(`UPDATE findings SET title=$2, explanation=$3, details=$4 WHERE id=$1`, [findingId, f.title, f.explanation, JSON.stringify(f.details)]);
          }
        } else {
          const ins = await client.query<{ id: string }>(
            `INSERT INTO findings (user_id, account_id, finding_type, fingerprint, breach_id, severity, title, explanation, contribution, details, state)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
            [userId, input.id, f.type, fingerprint, f.breachId ?? null, f.severity, f.title, f.explanation, f.contribution, JSON.stringify(f.details), f.state],
          );
          findingId = ins.rows[0].id;
        }
        keptIds.push(findingId);

        // In-app alerts for important findings, deduplicated by fingerprint + what changed.
        if ((f.severity === 'critical' || f.severity === 'high') && f.state === 'open') {
          const alertKey = `finding:${fingerprint}:${f.type === 'security_alert' ? (f.details as { latest: string }).latest : f.severity}`;
          const alert = await client.query<{ id: string }>(
            `INSERT INTO alerts (user_id, kind, severity, title, body, fingerprint, account_id) VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (user_id, fingerprint) DO NOTHING RETURNING id`,
            [userId, f.type, f.severity, f.title, f.explanation, alertKey, input.id],
          );
          if (alert.rows[0]) newAlerts.push({ id: alert.rows[0].id, userId, severity: f.severity, title: f.title, body: f.explanation, kind: f.type });
        }

        for (const spec of actionsFor(f, input)) {
          const priority = SEVERITY_WEIGHT[f.severity] + Math.round(f.contribution);
          await client.query(
            `INSERT INTO remediation_items (user_id, account_id, finding_id, action_type, title, description, priority, official_url, url_kind)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (finding_id, action_type) DO UPDATE SET title=$5, description=$6, priority=$7, official_url=$8, url_kind=$9`,
            [userId, input.id, findingId, spec.action, spec.title, spec.description, priority, spec.link?.url ?? null, spec.link?.kind ?? null],
          );
        }
      }
      // Findings no longer produced become inactive (history preserved). Breach findings
      // are historical facts and stay as they are unless the account is excluded.
      await client.query(
        `UPDATE findings SET state='inactive', updated_at=now()
          WHERE account_id=$1 AND state <> 'inactive' AND NOT (id = ANY($2::uuid[]))
            AND (finding_type NOT IN ('service_breach','email_breach') OR $3)`,
        [input.id, keptIds, input.ownership === 'false_positive'],
      );
      const prevScore = (await client.query<{ risk_score: number | null }>('SELECT risk_score FROM accounts WHERE id=$1', [input.id])).rows[0]?.risk_score ?? null;
      await client.query(
        `UPDATE accounts SET risk_score=$2, risk_level=$3, risk_components=$4, risk_updated_at=now() WHERE id=$1`,
        [
          input.id, assessment.score, levelFor(assessment.score),
          JSON.stringify(assessment.findings.map((f) => ({ key: f.key, type: f.type, contribution: f.contribution, severity: f.severity }))),
        ],
      );
      if (prevScore !== assessment.score) reasons.set(input.id, opts.reason);
    }

    // Overall DASI from the stored per-account scores of ALL the user's accounts.
    const all = await client.query<{ id: string; service_name: string; risk_score: number | null; critical: number }>(
      `SELECT a.id, a.service_name, a.risk_score,
              (SELECT count(*)::int FROM findings f WHERE f.account_id = a.id AND f.severity = 'critical' AND f.state = 'open') AS critical
         FROM accounts a WHERE a.user_id = $1 AND a.ownership <> 'false_positive'`,
      [userId],
    );
    const coverage = await discoveryCoverage(client, userId);
    const dasi = computeDasi({
      accounts: all.rows.map((r) => ({ accountId: r.id, serviceName: r.service_name, score: r.risk_score, criticalFindings: r.critical })),
      coverage,
      breachDataAvailable: breachStatus.available,
    });
    const last = await client.query<{ score: number | null; level: string; coverage: Coverage; components: { result: DasiResult } }>(
      'SELECT score, level, coverage, components FROM dasi_snapshots WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1',
      [userId],
    );
    const prev = last.rows[0]?.components?.result ?? null;
    const changes = explainChanges(prev, dasi, reasons);
    const changed =
      !last.rows[0] ||
      last.rows[0].score !== dasi.score ||
      last.rows[0].coverage !== dasi.coverage ||
      JSON.stringify(prev?.accountScores ?? []) !== JSON.stringify(dasi.accountScores) ||
      JSON.stringify(prev?.components ?? []) !== JSON.stringify(dasi.components);
    if (changed) {
      await client.query(
        `INSERT INTO dasi_snapshots (user_id, score, level, coverage, model_version, components, changes, reason)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [userId, dasi.score, dasi.level, dasi.coverage, MODEL_VERSION, JSON.stringify({ result: dasi }), JSON.stringify(changes), opts.reason],
      );
    }
    await client.query('COMMIT');
    return { dasi, snapshotCreated: changed, newAlerts };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

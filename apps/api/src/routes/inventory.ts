import { Router } from 'express';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { parse, requireAuth } from '../middleware.js';
import { HttpError, notFound } from '../lib/errors.js';
import { normalizeDomain } from '../lib/domain.js';
import { lookupService, fallbackServiceName } from '../catalog/services.js';
import { recalculate, discoveryCoverage } from '../dasi/risk-service.js';
import { notifyNewAlerts } from '../notifications/service.js';
import { changeStatus, requestVerification, STATUSES, HAS_VERIFIER } from '../remediation/service.js';
import { breachCatalogStatus, ensureBreachCatalogFresh } from '../breach/catalog.js';
import * as model from '../dasi/model.js';

const uuid = z.string().uuid();

export function inventoryRouter(ctx: AppContext) {
  const r = Router();
  const { db } = ctx;
  r.use(requireAuth);

  const recalc = async (userId: string, reason: string, accountIds?: string[]) => {
    const result = await recalculate(db, userId, { reason, accountIds });
    if (result.newAlerts.length) await notifyNewAlerts(ctx.config, db, ctx.mailer, result.newAlerts);
    return result;
  };

  // ---- Dashboard ---------------------------------------------------------------
  r.get('/dashboard', async (req, res) => {
    const uid = req.user!.id;
    const latest = (await db.query('SELECT score, level, coverage, model_version, components, changes, reason, created_at FROM dasi_snapshots WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1', [uid])).rows[0];
    const recent = (await db.query(`SELECT score, level, changes, reason, created_at FROM dasi_snapshots WHERE user_id=$1 ORDER BY created_at DESC LIMIT 6`, [uid])).rows;
    const topFindings = (await db.query(
      `SELECT f.id, f.account_id, f.finding_type, f.severity, f.title, f.explanation, f.state, f.contribution, a.service_name, a.is_fixture
         FROM findings f JOIN accounts a ON a.id = f.account_id
        WHERE f.user_id=$1 AND f.state='open' AND a.ownership <> 'false_positive' AND f.severity IN ('critical','high','medium')
        ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, f.contribution DESC LIMIT 5`,
      [uid],
    )).rows;
    const nextActions = (await db.query(
      `SELECT ri.id, ri.title, ri.description, ri.status, ri.official_url, ri.url_kind, ri.action_type, a.service_name
         FROM remediation_items ri JOIN findings f ON f.id = ri.finding_id JOIN accounts a ON a.id = ri.account_id
        WHERE ri.user_id=$1 AND ri.status IN ('recommended','in_progress') AND f.state <> 'inactive' AND a.ownership <> 'false_positive'
        ORDER BY ri.priority DESC, ri.created_at LIMIT 3`,
      [uid],
    )).rows;
    const counts = (await db.query(
      `SELECT (SELECT count(*)::int FROM accounts WHERE user_id=$1 AND ownership <> 'false_positive') AS accounts,
              (SELECT count(*)::int FROM accounts WHERE user_id=$1 AND is_fixture) AS fixture_accounts,
              (SELECT count(*)::int FROM remediation_items ri JOIN findings f ON f.id=ri.finding_id JOIN accounts a ON a.id=ri.account_id
                 WHERE ri.user_id=$1 AND ri.status IN ('recommended','in_progress') AND f.state <> 'inactive' AND a.ownership <> 'false_positive') AS open_actions,
              (SELECT count(*)::int FROM alerts WHERE user_id=$1 AND read_at IS NULL) AS unread_alerts,
              (SELECT count(*)::int FROM email_connections WHERE user_id=$1) AS connections,
              (SELECT count(*)::int FROM scans WHERE user_id=$1 AND status='running') AS running_scans`,
      [uid],
    )).rows[0];
    res.json({
      dasi: latest
        ? { ...latest.components.result, createdAt: latest.created_at, reason: latest.reason }
        : { modelVersion: model.MODEL_VERSION, score: null, level: 'unknown', coverage: await discoveryCoverage(db, uid), components: [], notes: ['Not enough information yet. Connect a mailbox or add accounts to calculate your DASI.'], criticalFindingCount: 0, accountScores: [] },
      topFindings,
      nextActions,
      recentChanges: recent.filter((s) => (s.changes as unknown[]).length).slice(0, 5),
      counts,
      breachData: await breachCatalogStatus(db),
    });
  });

  r.get('/dasi/history', async (req, res) => {
    const { rows } = await db.query(
      'SELECT id, score, level, coverage, model_version, changes, reason, created_at FROM dasi_snapshots WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200',
      [req.user!.id],
    );
    res.json({ history: rows });
  });

  r.get('/dasi/model', (_req, res) => {
    res.json({
      version: model.MODEL_VERSION,
      scale: '0–100; higher means more observed risk',
      levels: { low: '0–24', moderate: '25–49', high: '50–74', critical: '75–100', unknown: 'not enough information' },
      breachBase: model.BREACH_BASE,
      relevance: model.RELEVANCE,
      freshness: { '≤1 year': 1, '≤3 years': 0.85, '≤6 years': 0.7, older: 0.55, unknownDate: 0.7 },
      confidence: 'factor = 0.4 + 0.6 × account-existence confidence',
      mitigation: model.MITIGATION,
      securityAlert: model.SECURITY_ALERT,
      posture: model.POSTURE,
      dormant: model.DORMANT,
      categoryImpact: model.CATEGORY_IMPACT,
      aggregate: { ...model.AGGREGATE, formula: 'DASI = 0.6 × highest account risk + 0.4 × 100 × (1 − Π(1 − riskᵢ/200)) + uncertainty' },
      uncertainty: model.UNCERTAINTY,
      documentation: 'docs/DASI.md',
    });
  });

  r.post('/dasi/recalculate', async (req, res) => {
    await ensureBreachCatalogFresh(ctx.config, db, ctx.fetchImpl);
    const result = await recalc(req.user!.id, 'Manual rescore');
    res.json({ dasi: result.dasi, snapshotCreated: result.snapshotCreated });
  });

  // ---- Accounts ----------------------------------------------------------------
  r.get('/accounts', async (req, res) => {
    const { rows } = await db.query(
      `SELECT a.id, a.service_name, a.service_domain, a.category, a.ownership, a.confidence, a.mfa_status, a.is_fixture,
              a.first_seen_at, a.last_seen_at, a.risk_score, a.risk_level,
              (SELECT array_agg(email_address ORDER BY email_address) FROM account_identities i WHERE i.account_id=a.id) AS identities,
              (SELECT count(*)::int FROM evidence e WHERE e.account_id=a.id) AS evidence_count,
              (SELECT array_agg(DISTINCT e.source) FROM evidence e WHERE e.account_id=a.id) AS sources,
              (SELECT count(*)::int FROM findings f WHERE f.account_id=a.id AND f.state='open' AND f.severity IN ('critical','high')) AS serious_findings
         FROM accounts a WHERE a.user_id=$1 ORDER BY (a.ownership = 'false_positive'), a.risk_score DESC NULLS LAST, a.service_name`,
      [req.user!.id],
    );
    res.json({ accounts: rows });
  });

  r.get('/accounts/:id', async (req, res) => {
    const id = parse(uuid, req.params.id);
    const account = (await db.query('SELECT * FROM accounts WHERE id=$1 AND user_id=$2', [id, req.user!.id])).rows[0];
    if (!account) throw notFound('Account');
    const [identities, evidence, findings, items] = await Promise.all([
      db.query('SELECT email_address FROM account_identities WHERE account_id=$1', [id]),
      db.query('SELECT id, source, evidence_type, signal, confidence, sender_domain, identity_email, observed_at, is_fixture FROM evidence WHERE account_id=$1 ORDER BY observed_at DESC LIMIT 100', [id]),
      db.query(`SELECT id, finding_type, breach_id, severity, title, explanation, contribution, details, state, first_detected_at, updated_at FROM findings WHERE account_id=$1
                 ORDER BY (state='inactive'), contribution DESC`, [id]),
      db.query('SELECT id, finding_id, action_type, title, description, priority, official_url, url_kind, status, status_note, user_reported_at, verified_at FROM remediation_items WHERE account_id=$1 ORDER BY priority DESC', [id]),
    ]);
    const service = lookupService(account.service_domain);
    res.json({
      account,
      identities: identities.rows.map((i) => i.email_address),
      evidence: evidence.rows,
      findings: findings.rows,
      remediation: items.rows.map((i) => ({ ...i, verifiable: HAS_VERIFIER.has(i.action_type) })),
      catalog: service ? { name: service.name, securityUrl: service.securityUrl } : null,
    });
  });

  r.post('/accounts', async (req, res) => {
    const body = parse(z.object({ domain: z.string().min(3).max(253), serviceName: z.string().trim().min(1).max(80).optional() }), req.body);
    const d = normalizeDomain(body.domain);
    if (!d.ok || !d.value.registrableDomain) throw new HttpError(400, 'invalid_domain', 'Enter a valid website domain, such as example.com');
    const domain = lookupService(d.value.registrableDomain)?.domain ?? d.value.registrableDomain;
    const service = lookupService(domain);
    const ins = await db.query<{ id: string }>(
      `INSERT INTO accounts (user_id, service_domain, service_name, category, ownership, confidence)
       VALUES ($1,$2,$3,$4,'user_added',1) ON CONFLICT (user_id, service_domain) DO NOTHING RETURNING id`,
      [req.user!.id, domain, body.serviceName ?? service?.name ?? fallbackServiceName(domain), service?.category ?? 'other'],
    );
    if (!ins.rows[0]) throw new HttpError(409, 'account_exists', 'This service is already in your inventory');
    await db.query('INSERT INTO account_identities (account_id, email_address) VALUES ($1,$2)', [ins.rows[0].id, req.user!.email]);
    await db.query('DELETE FROM discovery_suppressions WHERE user_id=$1 AND service_domain=$2', [req.user!.id, domain]);
    const result = await recalc(req.user!.id, `Account added by you (${domain})`, [ins.rows[0].id]);
    res.status(201).json({ id: ins.rows[0].id, dasi: result.dasi });
  });

  r.patch('/accounts/:id', async (req, res) => {
    const id = parse(uuid, req.params.id);
    const body = parse(
      z.object({
        ownership: z.enum(['user_confirmed', 'false_positive', 'discovered']).optional(),
        mfaStatus: z.enum(['unknown', 'user_reported_enabled', 'user_reported_disabled']).optional(),
      }).refine((b) => b.ownership || b.mfaStatus, 'Nothing to update'),
      req.body,
    );
    const acct = (await db.query('SELECT id, ownership, service_domain, service_name FROM accounts WHERE id=$1 AND user_id=$2', [id, req.user!.id])).rows[0];
    if (!acct) throw notFound('Account');
    const reasons: string[] = [];
    if (body.ownership && body.ownership !== acct.ownership) {
      if (acct.ownership === 'user_added' && body.ownership !== 'user_confirmed') {
        throw new HttpError(400, 'invalid_change', 'Accounts you added yourself can be removed instead');
      }
      await db.query('UPDATE accounts SET ownership=$2, updated_at=now() WHERE id=$1', [id, body.ownership]);
      if (body.ownership === 'false_positive') {
        await db.query('INSERT INTO discovery_suppressions (user_id, service_domain) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user!.id, acct.service_domain]);
        reasons.push(`${acct.service_name} marked as not yours`);
      } else {
        await db.query('DELETE FROM discovery_suppressions WHERE user_id=$1 AND service_domain=$2', [req.user!.id, acct.service_domain]);
        reasons.push(body.ownership === 'user_confirmed' ? `${acct.service_name} confirmed as yours` : `${acct.service_name} restored`);
      }
    }
    if (body.mfaStatus) {
      await db.query('UPDATE accounts SET mfa_status=$2, updated_at=now() WHERE id=$1', [id, body.mfaStatus]);
      reasons.push(`Two-step verification status for ${acct.service_name} updated (user-reported)`);
    }
    const result = await recalc(req.user!.id, reasons.join('; ') || 'Account updated', [id]);
    res.json({ ok: true, dasi: result.dasi });
  });

  r.delete('/accounts/:id', async (req, res) => {
    const id = parse(uuid, req.params.id);
    const del = await db.query(`DELETE FROM accounts WHERE id=$1 AND user_id=$2 AND ownership='user_added' RETURNING service_name`, [id, req.user!.id]);
    if (!del.rows[0]) {
      const exists = await db.query('SELECT 1 FROM accounts WHERE id=$1 AND user_id=$2', [id, req.user!.id]);
      if (!exists.rowCount) throw notFound('Account');
      throw new HttpError(400, 'invalid_change', 'Discovered accounts cannot be deleted; mark them as "not mine" so future scans skip them.');
    }
    const result = await recalc(req.user!.id, `Account removed (${del.rows[0].service_name})`, []);
    res.json({ ok: true, dasi: result.dasi });
  });

  // ---- Remediation -------------------------------------------------------------------
  r.get('/remediation', async (req, res) => {
    const { rows } = await db.query(
      `SELECT ri.id, ri.account_id, ri.action_type, ri.title, ri.description, ri.priority, ri.official_url, ri.url_kind, ri.status, ri.status_note,
              ri.user_reported_at, ri.verified_at, ri.updated_at, a.service_name, a.is_fixture, f.severity, f.title AS finding_title, f.state AS finding_state
         FROM remediation_items ri JOIN accounts a ON a.id = ri.account_id JOIN findings f ON f.id = ri.finding_id
        WHERE ri.user_id=$1 AND a.ownership <> 'false_positive' AND f.state <> 'inactive'
        ORDER BY CASE WHEN ri.status IN ('recommended','in_progress') THEN 0 ELSE 1 END, ri.priority DESC, ri.created_at`,
      [req.user!.id],
    );
    res.json({ items: rows.map((i) => ({ ...i, verifiable: HAS_VERIFIER.has(i.action_type) })) });
  });

  r.patch('/remediation/:id', async (req, res) => {
    const id = parse(uuid, req.params.id);
    const body = parse(z.object({ status: z.enum(STATUSES), note: z.string().trim().max(500).optional() }), req.body);
    let changed;
    try {
      changed = await changeStatus(db, req.user!.id, id, body.status, body.note ?? null);
    } catch (err) {
      if ((err as { status?: number }).status === 409) throw new HttpError(409, 'invalid_transition', (err as Error).message);
      throw err;
    }
    if (!changed) throw notFound('Recommendation');
    const result = await recalc(req.user!.id, `Remediation updated: ${body.status.replace(/_/g, ' ')}`, [changed.accountId]);
    res.json({ ok: true, dasi: result.dasi });
  });

  r.post('/remediation/:id/verify', async (req, res) => {
    const id = parse(uuid, req.params.id);
    let status;
    try {
      status = await requestVerification(db, req.user!.id, id);
    } catch (err) {
      if ((err as { status?: number }).status === 409) throw new HttpError(409, 'invalid_transition', (err as Error).message);
      throw err;
    }
    if (!status) throw notFound('Recommendation');
    const acct = (await db.query('SELECT account_id FROM remediation_items WHERE id=$1', [id])).rows[0];
    const result = await recalc(req.user!.id, `Verification: ${status.replace(/_/g, ' ')}`, [acct.account_id]);
    res.json({ status, dasi: result.dasi });
  });

  // ---- Alerts & notification preferences ------------------------------------------------
  r.get('/alerts', async (req, res) => {
    const { rows } = await db.query(
      'SELECT id, kind, severity, title, body, account_id, read_at, created_at FROM alerts WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',
      [req.user!.id],
    );
    res.json({ alerts: rows });
  });

  r.post('/alerts/:id/read', async (req, res) => {
    const id = parse(uuid, req.params.id);
    const upd = await db.query('UPDATE alerts SET read_at=COALESCE(read_at, now()) WHERE id=$1 AND user_id=$2', [id, req.user!.id]);
    if (!upd.rowCount) throw notFound('Alert');
    res.json({ ok: true });
  });

  r.post('/alerts/read-all', async (req, res) => {
    await db.query('UPDATE alerts SET read_at=now() WHERE user_id=$1 AND read_at IS NULL', [req.user!.id]);
    res.json({ ok: true });
  });

  return r;
}

import { Router } from 'express';
import argon2 from 'argon2';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { parse, requireAuth, requirePremium, sessionCookieName } from '../middleware.js';
import { HttpError } from '../lib/errors.js';
import { decrypt } from '../lib/crypto.js';
import { limiter } from '../lib/ratelimit.js';
import { getPrefs } from '../notifications/service.js';
import { buildDataExport, buildSecurityReport } from '../reports/xlsx.js';
import type { ProviderId } from '../discovery/providers.js';
import { PRIVACY_POLICY_VERSION } from './auth.js';

const XLSX = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

export const PLAN_FEATURES = {
  free: [
    'Account discovery from connected mailboxes', 'Account inventory and corrections', 'Service breach checks',
    'DASI score, explanations and history', 'Prioritised remediation with official links', 'Remediation tracking',
    'In-app alerts and optional email notifications', 'Manual domain reputation checks', 'Excel reports and data export',
    'Privacy controls and account deletion',
  ],
  premium: [
    'Everything in Free', 'Browser extension protection with automatic domain checks', 'Warnings for known-malicious and suspicious sites',
    'Security event history from the extension', 'Optional security-event synchronisation (opt-in)',
  ],
};

export function settingsRouter(ctx: AppContext) {
  const r = Router();
  const { db, config } = ctx;
  r.use(requireAuth);
  const reportLimit = limiter({ windowMs: 60_000, limit: 10, scale: ctx.rateLimitScale });

  // ---- Notification preferences (separate from mailbox-connection consent) ----------
  r.get('/notifications/preferences', async (req, res) => {
    const p = await getPrefs(db, req.user!.id);
    res.json({
      preferences: {
        emailSecurityAlerts: p.email_security_alerts,
        emailRemediationReminders: p.email_remediation_reminders,
        emailPeriodicSummary: p.email_periodic_summary,
        emailConsentAt: p.email_consent_at,
        securityEventSync: p.security_event_sync,
      },
      emailDelivery: { configured: ctx.mailer.isConfigured(), mode: ctx.mailer.mode },
    });
  });

  r.put('/notifications/preferences', async (req, res) => {
    const body = parse(
      z.object({
        emailSecurityAlerts: z.boolean(),
        emailRemediationReminders: z.boolean(),
        emailPeriodicSummary: z.boolean(),
        emailConsent: z.boolean().optional(),
      }),
      req.body,
    );
    const anyOn = body.emailSecurityAlerts || body.emailRemediationReminders || body.emailPeriodicSummary;
    const prev = await getPrefs(db, req.user!.id);
    if (anyOn && !prev.email_consent_at && body.emailConsent !== true) {
      throw new HttpError(400, 'consent_required', `Confirm that FootprintX may email ${req.user!.email} about your security`);
    }
    await db.query(
      `UPDATE notification_preferences SET email_security_alerts=$2, email_remediation_reminders=$3, email_periodic_summary=$4,
         email_consent_at = CASE WHEN $5 THEN COALESCE(email_consent_at, now()) ELSE NULL END, updated_at=now() WHERE user_id=$1`,
      [req.user!.id, body.emailSecurityAlerts, body.emailRemediationReminders, body.emailPeriodicSummary, anyOn],
    );
    res.json({ ok: true, emailDeliveryConfigured: ctx.mailer.isConfigured() });
  });

  // ---- Plan / entitlements --------------------------------------------------------------
  r.get('/plan', (req, res) => {
    res.json({
      plan: req.user!.plan,
      planSource: req.user!.planSource,
      features: PLAN_FEATURES,
      billing: { configured: false, message: 'Online payments are not available yet. No payment is taken by this build.' },
      devEntitlementsEnabled: config.ENABLE_DEV_ENTITLEMENTS && config.NODE_ENV !== 'production',
    });
  });

  r.post('/dev/plan', async (req, res) => {
    if (!config.ENABLE_DEV_ENTITLEMENTS || config.NODE_ENV === 'production') {
      throw new HttpError(404, 'not_available', 'Development entitlements are disabled on this server');
    }
    const body = parse(z.object({ plan: z.enum(['free', 'premium']) }), req.body);
    await db.query(`UPDATE users SET plan=$2, plan_source=$3, plan_updated_at=now() WHERE id=$1`, [
      req.user!.id, body.plan, body.plan === 'premium' ? 'development' : 'default',
    ]);
    res.json({ plan: body.plan, planSource: body.plan === 'premium' ? 'development' : 'default', note: 'Development entitlement only. No payment was made.' });
  });

  // ---- Reports ---------------------------------------------------------------------------
  r.get('/reports/security.xlsx', reportLimit, async (req, res) => {
    const buf = await buildSecurityReport(db, req.user!.id, { includeSecurityEvents: req.user!.plan === 'premium' });
    res.setHeader('Content-Type', XLSX);
    res.setHeader('Content-Disposition', `attachment; filename="footprintx-report-${new Date().toISOString().slice(0, 10)}.xlsx"`);
    res.setHeader('Cache-Control', 'no-store');
    res.send(buf);
  });

  r.get('/privacy/export.xlsx', reportLimit, async (req, res) => {
    const buf = await buildDataExport(db, req.user!.id);
    res.setHeader('Content-Type', XLSX);
    res.setHeader('Content-Disposition', `attachment; filename="footprintx-data-export-${new Date().toISOString().slice(0, 10)}.xlsx"`);
    res.setHeader('Cache-Control', 'no-store');
    res.send(buf);
  });

  r.get('/privacy', (_req, res) => {
    res.json({ policyVersion: PRIVACY_POLICY_VERSION });
  });

  // ---- Account deletion ---------------------------------------------------------------------
  r.post('/privacy/delete-account', async (req, res) => {
    const body = parse(z.object({ password: z.string().min(1).max(128), confirm: z.literal('DELETE') }), req.body);
    const u = (await db.query('SELECT password_hash FROM users WHERE id=$1', [req.user!.id])).rows[0];
    if (!(await argon2.verify(u.password_hash, body.password).catch(() => false))) {
      throw new HttpError(400, 'invalid_credentials', 'Password is incorrect');
    }
    const conns = (await db.query('SELECT provider, access_token_enc, refresh_token_enc FROM email_connections WHERE user_id=$1', [req.user!.id])).rows;
    const revocations: { provider: string; result: string }[] = [];
    for (const c of conns) {
      const token = c.refresh_token_enc ?? c.access_token_enc;
      if (c.provider === 'devfixture' || !token || !config.encryptionKey) {
        revocations.push({ provider: c.provider, result: 'not_applicable' });
        continue;
      }
      revocations.push({ provider: c.provider, result: await ctx.providers[c.provider as ProviderId].revoke(decrypt(token, config.encryptionKey)) });
    }
    // ON DELETE CASCADE removes every user-owned row in one statement.
    await db.query('DELETE FROM users WHERE id=$1', [req.user!.id]);
    res.clearCookie(sessionCookieName(config), { path: '/', httpOnly: true, secure: config.COOKIE_SECURE, sameSite: config.COOKIE_SAMESITE });
    res.json({ ok: true, deleted: true, revocations });
  });

  // ---- Premium: security events ------------------------------------------------------------
  r.get('/security-events', requirePremium, async (req, res) => {
    const { rows } = await db.query(
      'SELECT id, domain, status, reasons, action, occurred_at FROM security_events WHERE user_id=$1 ORDER BY occurred_at DESC LIMIT 500',
      [req.user!.id],
    );
    const prefs = await getPrefs(db, req.user!.id);
    res.json({ events: rows, syncEnabled: prefs.security_event_sync });
  });

  r.delete('/security-events', requirePremium, async (req, res) => {
    const del = await db.query('DELETE FROM security_events WHERE user_id=$1', [req.user!.id]);
    res.json({ ok: true, deleted: del.rowCount });
  });

  r.put('/security-events/sync', requirePremium, async (req, res) => {
    const body = parse(z.object({ enabled: z.boolean() }), req.body);
    await getPrefs(db, req.user!.id);
    await db.query(
      `UPDATE notification_preferences SET security_event_sync=$2,
         security_event_sync_consent_at = CASE WHEN $2 THEN now() ELSE NULL END, updated_at=now() WHERE user_id=$1`,
      [req.user!.id, body.enabled],
    );
    res.json({ ok: true, enabled: body.enabled });
  });

  return r;
}

import { Router } from 'express';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { extensionAuth, parse, requireAuth, requirePremium } from '../middleware.js';
import { linkCode, randomToken, sha256 } from '../lib/crypto.js';
import { HttpError, notFound } from '../lib/errors.js';
import { ipKey, limiter } from '../lib/ratelimit.js';
import { getPrefs } from '../notifications/service.js';
import { normalizeDomain } from '../lib/domain.js';

/** Web-app side (cookie session): create link codes, list and revoke linked extensions. */
export function extensionWebRouter(ctx: AppContext) {
  const r = Router();
  const { db } = ctx;
  r.use(requireAuth);

  r.post('/link-code', async (req, res) => {
    const code = linkCode();
    await db.query('DELETE FROM extension_link_codes WHERE user_id=$1 OR expires_at < now()', [req.user!.id]);
    const { rows } = await db.query<{ expires_at: Date }>(
      `INSERT INTO extension_link_codes (code_hash, user_id, expires_at) VALUES ($1,$2, now() + interval '10 minutes') RETURNING expires_at`,
      [sha256(code), req.user!.id],
    );
    res.json({ code, expiresAt: rows[0].expires_at });
  });

  r.get('/tokens', async (req, res) => {
    const { rows } = await db.query(
      'SELECT id, label, created_at, last_used_at FROM extension_tokens WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC',
      [req.user!.id],
    );
    res.json({ tokens: rows });
  });

  r.delete('/tokens/:id', async (req, res) => {
    const id = parse(z.string().uuid(), req.params.id);
    const upd = await db.query('UPDATE extension_tokens SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL', [id, req.user!.id]);
    if (!upd.rowCount) throw notFound('Extension link');
    res.json({ ok: true });
  });

  return r;
}

const eventSchema = z.object({
  clientEventId: z.string().regex(/^[A-Za-z0-9-]{8,64}$/),
  domain: z.string().min(1).max(253),
  status: z.enum(['red', 'amber']), // routine/clean navigation is never accepted
  reasons: z.array(z.string().max(300)).max(10),
  action: z.enum(['warned', 'blocked', 'proceeded', 'went_back']),
  occurredAt: z.string().datetime(),
});

/** Extension side (bearer token). Every protection request re-checks Premium server-side. */
export function extensionApiRouter(ctx: AppContext) {
  const r = Router();
  const { db } = ctx;
  const linkLimit = limiter({ windowMs: 15 * 60_000, limit: 10, scale: ctx.rateLimitScale, key: ipKey, message: 'Too many linking attempts. Wait a few minutes.' });
  const checkLimit = limiter({ windowMs: 60_000, limit: 120, scale: ctx.rateLimitScale, key: (req) => `ext:${req.extensionTokenId}` });

  r.post('/link', linkLimit, async (req, res) => {
    const body = parse(z.object({ code: z.string().trim().toUpperCase().regex(/^[A-Z0-9]{5}-[A-Z0-9]{5}$/, 'Enter the code shown in FootprintX'), label: z.string().trim().max(60).optional() }), req.body);
    const { rows } = await db.query<{ user_id: string }>(
      'UPDATE extension_link_codes SET used_at=now() WHERE code_hash=$1 AND used_at IS NULL AND expires_at > now() RETURNING user_id',
      [sha256(body.code)],
    );
    if (!rows[0]) throw new HttpError(400, 'invalid_code', 'This code is invalid or expired. Create a new code in FootprintX → Extension.');
    const token = randomToken(32);
    await db.query('INSERT INTO extension_tokens (user_id, token_hash, label) VALUES ($1,$2,$3)', [rows[0].user_id, sha256(token), body.label || 'Browser extension']);
    const u = (await db.query('SELECT email, plan FROM users WHERE id=$1', [rows[0].user_id])).rows[0];
    res.status(201).json({ token, email: u.email, plan: u.plan });
  });

  r.use(extensionAuth(db));

  r.get('/status', async (req, res) => {
    const prefs = await getPrefs(db, req.user!.id);
    res.json({
      email: req.user!.email,
      plan: req.user!.plan,
      planSource: req.user!.planSource,
      protectionAvailable: req.user!.plan === 'premium',
      eventSync: prefs.security_event_sync,
      sources: ctx.reputation.providerSummary,
    });
  });

  r.post('/unlink', async (req, res) => {
    await db.query('UPDATE extension_tokens SET revoked_at=now() WHERE id=$1', [req.extensionTokenId]);
    res.json({ ok: true });
  });

  r.get('/check', requirePremium, checkLimit, async (req, res) => {
    const domain = parse(z.string().min(1).max(253), req.query.domain);
    const result = await ctx.reputation.check(domain);
    if ('error' in result) {
      return res.json({ result: { domain, status: 'grey', summary: 'Not checked', reasons: [result.error === 'local_or_private' ? 'Local and private addresses are not checked.' : 'This address cannot be checked.'], nextSteps: [], providers: [], confidence: 'none' } });
    }
    res.json({ result });
  });

  r.put('/preferences', requirePremium, async (req, res) => {
    const body = parse(z.object({ eventSync: z.boolean() }), req.body);
    await getPrefs(db, req.user!.id);
    await db.query(
      `UPDATE notification_preferences SET security_event_sync=$2,
         security_event_sync_consent_at = CASE WHEN $2 THEN now() ELSE NULL END, updated_at=now() WHERE user_id=$1`,
      [req.user!.id, body.eventSync],
    );
    res.json({ ok: true, eventSync: body.eventSync });
  });

  r.post('/events', requirePremium, async (req, res) => {
    const body = parse(z.object({ events: z.array(eventSchema).min(1).max(50) }), req.body);
    const prefs = await getPrefs(db, req.user!.id);
    if (!prefs.security_event_sync) {
      throw new HttpError(403, 'sync_disabled', 'Security-event sync is off. Turn it on in the extension or in FootprintX settings first.');
    }
    let stored = 0;
    for (const e of body.events) {
      const d = normalizeDomain(e.domain);
      if (!d.ok) continue;
      const ins = await db.query(
        `INSERT INTO security_events (user_id, source, domain, status, reasons, action, client_event_id, occurred_at)
         VALUES ($1,'extension',$2,$3,$4,$5,$6,$7) ON CONFLICT (user_id, client_event_id) DO NOTHING`,
        [req.user!.id, d.value.host, e.status, JSON.stringify(e.reasons), e.action, e.clientEventId, e.occurredAt],
      );
      stored += ins.rowCount ?? 0;
    }
    res.json({ ok: true, stored });
  });

  return r;
}

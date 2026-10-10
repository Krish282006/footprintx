import { Router, type Response } from 'express';
import argon2 from 'argon2';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { parse, requireAuth, sessionCookieName } from '../middleware.js';
import { randomToken, sha256 } from '../lib/crypto.js';
import { HttpError } from '../lib/errors.js';
import { ipKey, limiter } from '../lib/ratelimit.js';

export const PRIVACY_POLICY_VERSION = '2026-10-01';

// OWASP-recommended Argon2id parameters (19 MiB, t=2, p=1).
const ARGON = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;
let dummyHash: Promise<string> | null = null;

const email = z.string().trim().toLowerCase().email('Enter a valid email address').max(254);
const password = z.string().min(12, 'Use at least 12 characters').max(128, 'Use at most 128 characters');

export async function hashPassword(pw: string) {
  return argon2.hash(pw, ARGON);
}

export function publicUser(u: { id: string; email: string; plan: string; planSource: string; displayName: string | null }) {
  return { id: u.id, email: u.email, displayName: u.displayName, plan: u.plan, planSource: u.planSource };
}

export async function createSession(ctx: AppContext, res: Response, userId: string) {
  const token = randomToken(32);
  const csrfToken = randomToken(24);
  const expires = new Date(Date.now() + ctx.config.SESSION_TTL_HOURS * 3600_000);
  await ctx.db.query('INSERT INTO sessions (user_id, token_hash, csrf_token, expires_at) VALUES ($1,$2,$3,$4)', [userId, sha256(token), csrfToken, expires]);
  res.cookie(sessionCookieName(ctx.config), token, {
    httpOnly: true,
    secure: ctx.config.COOKIE_SECURE,
    sameSite: ctx.config.COOKIE_SAMESITE,
    path: '/',
    expires,
  });
  return csrfToken;
}

export function authRouter(ctx: AppContext) {
  const r = Router();
  const { db, config } = ctx;
  const authLimit = limiter({ windowMs: 15 * 60_000, limit: 10, scale: ctx.rateLimitScale, key: (req) => `${ipKey(req)}:${String(req.body?.email ?? '').toLowerCase()}`, message: 'Too many attempts. Please wait 15 minutes and try again.' });
  const registerLimit = limiter({ windowMs: 60 * 60_000, limit: 20, scale: ctx.rateLimitScale, key: ipKey });
  const recoveryLimit = limiter({ windowMs: 60 * 60_000, limit: 5, scale: ctx.rateLimitScale, key: (req) => `${ipKey(req)}:${String(req.body?.email ?? '')}` });

  r.post('/register', registerLimit, async (req, res) => {
    const body = parse(
      z.object({
        email,
        password,
        displayName: z.string().trim().max(80).optional(),
        acceptPrivacy: z.literal(true, { message: 'You must accept the privacy notice to create an account' }),
      }),
      req.body,
    );
    if (body.password.toLowerCase().includes(body.email.split('@')[0]) && body.email.split('@')[0].length >= 4) {
      throw new HttpError(400, 'weak_password', 'Your password must not contain your email name');
    }
    const hash = await hashPassword(body.password);
    const ins = await db.query<{ id: string; plan: string; plan_source: string }>(
      `INSERT INTO users (email, password_hash, display_name, privacy_policy_version, privacy_consent_at)
       VALUES ($1,$2,$3,$4,now()) ON CONFLICT (email) DO NOTHING RETURNING id, plan, plan_source`,
      [body.email, hash, body.displayName || null, PRIVACY_POLICY_VERSION],
    );
    if (!ins.rows[0]) throw new HttpError(409, 'email_taken', 'An account with this email already exists. Try signing in or resetting your password.');
    await db.query('INSERT INTO notification_preferences (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [ins.rows[0].id]);
    const csrfToken = await createSession(ctx, res, ins.rows[0].id);
    res.status(201).json({
      user: publicUser({ id: ins.rows[0].id, email: body.email, plan: 'free', planSource: 'default', displayName: body.displayName || null }),
      csrfToken,
    });
  });

  r.post('/login', authLimit, async (req, res) => {
    const body = parse(z.object({ email, password: z.string().min(1).max(128) }), req.body);
    const { rows } = await db.query('SELECT id, email, password_hash, plan, plan_source, display_name FROM users WHERE email=$1', [body.email]);
    const u = rows[0];
    // Verify against a dummy hash for unknown users so timing does not reveal account existence.
    dummyHash ??= hashPassword(randomToken(16));
    const ok = await argon2.verify(u?.password_hash ?? (await dummyHash), body.password).catch(() => false);
    if (!u || !ok) throw new HttpError(401, 'invalid_credentials', 'Invalid email or password');
    if (argon2.needsRehash(u.password_hash, ARGON)) {
      await db.query('UPDATE users SET password_hash=$2 WHERE id=$1', [u.id, await hashPassword(body.password)]);
    }
    const csrfToken = await createSession(ctx, res, u.id);
    res.json({ user: publicUser({ id: u.id, email: u.email, plan: u.plan, planSource: u.plan_source, displayName: u.display_name }), csrfToken });
  });

  r.post('/logout', async (req, res) => {
    if (req.session) await db.query('DELETE FROM sessions WHERE id=$1', [req.session.id]);
    res.clearCookie(sessionCookieName(config), { path: '/', httpOnly: true, secure: config.COOKIE_SECURE, sameSite: config.COOKIE_SAMESITE });
    res.json({ ok: true });
  });

  r.get('/me', (req, res) => {
    if (!req.user || !req.session) return res.json({ user: null, csrfToken: null });
    res.json({ user: publicUser(req.user), csrfToken: req.session.csrfToken });
  });

  r.post('/forgot-password', recoveryLimit, async (req, res) => {
    const body = parse(z.object({ email }), req.body);
    if (!ctx.mailer.isConfigured()) {
      throw new HttpError(503, 'email_not_configured', 'Password reset by email is unavailable because email delivery is not configured on this server. Contact the administrator.');
    }
    const { rows } = await db.query<{ id: string }>('SELECT id FROM users WHERE email=$1', [body.email]);
    let delivery: string | null = null;
    if (rows[0]) {
      const token = randomToken(32);
      await db.query(`INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1,$2, now() + interval '1 hour')`, [rows[0].id, sha256(token)]);
      const link = `${config.WEB_ORIGIN}/reset-password#token=${token}`;
      const result = await ctx.mailer.send({
        to: body.email,
        subject: 'Reset your FootprintX password',
        text: `Someone (hopefully you) asked to reset your FootprintX password.\n\nReset it within 1 hour: ${link}\n\nIf you did not ask for this, ignore this email; your password stays the same.`,
      });
      delivery = result.status;
      if (result.status === 'failed') {
        throw new HttpError(502, 'delivery_failed', 'We could not send the reset email right now. Please try again later.');
      }
    }
    // Same response whether or not the account exists (prevents account enumeration).
    res.json({
      ok: true,
      devMode: ctx.mailer.mode === 'devlog',
      message:
        ctx.mailer.mode === 'devlog'
          ? 'Development mode: if an account exists, the reset link was written to the local development outbox (dev_outbox table / server log). No email was sent.'
          : 'If an account exists for that address, we have emailed a reset link. It expires in 1 hour.',
      ...(config.NODE_ENV === 'test' ? { _delivery: delivery } : {}),
    });
  });

  r.post('/reset-password', recoveryLimit, async (req, res) => {
    const body = parse(z.object({ token: z.string().min(20).max(200), password }), req.body);
    const { rows } = await db.query<{ id: string; user_id: string }>(
      'SELECT id, user_id FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now()',
      [sha256(body.token)],
    );
    if (!rows[0]) throw new HttpError(400, 'invalid_token', 'This reset link is invalid or has expired. Request a new one.');
    await db.query('UPDATE password_reset_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL', [rows[0].user_id]);
    await db.query('UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1', [rows[0].user_id, await hashPassword(body.password)]);
    // Invalidate every existing session after a password reset.
    await db.query('DELETE FROM sessions WHERE user_id=$1', [rows[0].user_id]);
    res.json({ ok: true, message: 'Password updated. Please sign in with your new password.' });
  });

  r.post('/change-password', requireAuth, authLimit, async (req, res) => {
    const body = parse(z.object({ currentPassword: z.string().min(1).max(128), newPassword: password }), req.body);
    const { rows } = await db.query('SELECT password_hash FROM users WHERE id=$1', [req.user!.id]);
    if (!(await argon2.verify(rows[0].password_hash, body.currentPassword).catch(() => false))) {
      throw new HttpError(400, 'invalid_credentials', 'Current password is incorrect');
    }
    await db.query('UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1', [req.user!.id, await hashPassword(body.newPassword)]);
    await db.query('DELETE FROM sessions WHERE user_id=$1 AND id <> $2', [req.user!.id, req.session!.id]);
    res.json({ ok: true, message: 'Password changed. Other sessions were signed out.' });
  });

  return r;
}

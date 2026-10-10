import type { NextFunction, Request, Response } from 'express';
import { ZodError, type ZodType } from 'zod';
import type { Config } from './config.js';
import type { Db } from './db/pool.js';
import { safeEqual, sha256 } from './lib/crypto.js';
import { HttpError, premiumRequired } from './lib/errors.js';
import { logger } from './lib/logger.js';

export const sessionCookieName = (config: Config) => (config.COOKIE_SECURE ? '__Host-fx_session' : 'fx_session');

export function parse<T>(schema: ZodType<T>, data: unknown): T {
  return schema.parse(data);
}

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** Loads the cookie session (if any). Sliding expiry is not used: sessions have a fixed lifetime. */
export function loadSession(config: Config, db: Db) {
  return async (req: Request, _res: Response, next: NextFunction) => {
    const token = req.cookies?.[sessionCookieName(config)];
    if (typeof token === 'string' && token.length >= 20 && token.length <= 200) {
      const { rows } = await db.query(
        `SELECT s.id AS session_id, s.csrf_token, u.id, u.email, u.plan, u.plan_source, u.display_name
           FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.token_hash = $1 AND s.expires_at > now()`,
        [sha256(token)],
      );
      const r = rows[0];
      if (r) {
        req.user = { id: r.id, email: r.email, plan: r.plan, planSource: r.plan_source, displayName: r.display_name };
        req.session = { id: r.session_id, csrfToken: r.csrf_token };
        db.query('UPDATE sessions SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval \'5 minutes\'', [r.session_id]).catch(() => undefined);
      }
    }
    next();
  };
}

/**
 * CSRF defence for cookie-authenticated requests:
 *  1. Origin (when sent) must be an allowed web origin.
 *  2. Authenticated unsafe requests must echo the per-session token in X-CSRF-Token.
 *  3. Unauthenticated unsafe requests must send X-FootprintX-Client, a custom header
 *     that forces a CORS preflight, which only allowed origins pass.
 * Bearer-token (extension) routes are exempt because they do not use cookies.
 */
export function csrfProtection(config: Config) {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!UNSAFE.has(req.method)) return next();
    if (req.path.startsWith('/api/ext/')) return next();
    const origin = req.get('origin');
    if (origin && !config.corsOrigins.includes(origin) && origin !== new URL(config.API_PUBLIC_URL).origin) {
      return next(new HttpError(403, 'bad_origin', 'Request origin is not allowed'));
    }
    if (req.session) {
      const sent = req.get('x-csrf-token') ?? '';
      if (!sent || !safeEqual(sent, req.session.csrfToken)) return next(new HttpError(403, 'csrf_failed', 'Missing or invalid CSRF token. Reload the page and try again.'));
    } else if (!req.get('x-footprintx-client')) {
      return next(new HttpError(403, 'csrf_failed', 'Missing client header'));
    }
    next();
  };
}

export function requireAuth(req: Request, _res: Response, next: NextFunction) {
  if (!req.user) return next(new HttpError(401, 'unauthenticated', 'Please sign in'));
  next();
}

/** Entitlement is always read from the database row loaded for this request, never from the client. */
export function requirePremium(req: Request, _res: Response, next: NextFunction) {
  if (!req.user) return next(new HttpError(401, 'unauthenticated', 'Please sign in'));
  if (req.user.plan !== 'premium') return next(premiumRequired());
  next();
}

export function extensionAuth(db: Db) {
  return async (req: Request, _res: Response, next: NextFunction) => {
    const header = req.get('authorization') ?? '';
    const m = /^Bearer ([A-Za-z0-9_-]{20,200})$/.exec(header);
    if (!m) return next(new HttpError(401, 'unauthenticated', 'Extension is not linked'));
    const { rows } = await db.query(
      `SELECT t.id AS token_id, u.id, u.email, u.plan, u.plan_source, u.display_name
         FROM extension_tokens t JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = $1 AND t.revoked_at IS NULL`,
      [sha256(m[1])],
    );
    const r = rows[0];
    if (!r) return next(new HttpError(401, 'unauthenticated', 'Extension link is invalid or was revoked'));
    req.user = { id: r.id, email: r.email, plan: r.plan, planSource: r.plan_source, displayName: r.display_name };
    req.extensionTokenId = r.token_id;
    db.query('UPDATE extension_tokens SET last_used_at = now() WHERE id = $1', [r.token_id]).catch(() => undefined);
    next();
  };
}

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
  if (err instanceof ZodError) {
    return res.status(400).json({
      error: 'validation_error',
      message: 'Some fields are invalid',
      issues: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    });
  }
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) });
  }
  const e = err as { status?: number; type?: string; message?: string };
  if (e?.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid_json', message: 'Request body is not valid JSON' });
  if (e?.type === 'entity.too.large') return res.status(413).json({ error: 'too_large', message: 'Request body is too large' });
  if (typeof e?.status === 'number' && e.status >= 400 && e.status < 500) {
    return res.status(e.status).json({ error: 'request_error', message: e.message ?? 'Request failed' });
  }
  logger.error({ err: e?.message, path: req.path, method: req.method }, 'unhandled error');
  res.status(500).json({ error: 'internal_error', message: 'Something went wrong. Please try again.' });
}

import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import type { Request } from 'express';

export function limiter(opts: { windowMs: number; limit: number; scale: number; key?: (req: Request) => string; message?: string }) {
  return rateLimit({
    windowMs: opts.windowMs,
    limit: Math.max(1, Math.round(opts.limit * opts.scale)),
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    keyGenerator: (req) => (opts.key ? opts.key(req) : req.user ? `u:${req.user.id}` : `ip:${ipKeyGenerator(req.ip ?? '0.0.0.0')}`),
    handler: (_req, res) =>
      res.status(429).json({ error: 'rate_limited', message: opts.message ?? 'Too many requests. Please wait a moment and try again.' }),
  });
}

export const ipKey = (req: Request) => ipKeyGenerator(req.ip ?? '0.0.0.0');

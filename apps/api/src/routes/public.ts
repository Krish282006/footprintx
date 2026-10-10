import { Router } from 'express';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { parse, requireAuth } from '../middleware.js';
import { HttpError } from '../lib/errors.js';
import { ipKey, limiter } from '../lib/ratelimit.js';
import { LIMITATIONS } from '../threat/service.js';

export function publicRouter(ctx: AppContext) {
  const r = Router();
  const { db, config } = ctx;
  const contactLimit = limiter({ windowMs: 60 * 60_000, limit: 5, scale: ctx.rateLimitScale, key: ipKey, message: 'You have sent several messages recently. Please try again later.' });
  const checkLimit = limiter({ windowMs: 60_000, limit: 20, scale: ctx.rateLimitScale });

  r.get('/health', async (_req, res) => {
    try {
      await db.query('SELECT 1');
      res.json({ status: 'ok', database: 'ok' });
    } catch {
      res.status(503).json({ status: 'degraded', database: 'unavailable' });
    }
  });

  r.get('/status', async (_req, res) => {
    const feeds = (await db.query('SELECT feed_id, last_success, last_status, entry_count FROM threat_feeds ORDER BY feed_id')).rows;
    const breach = (await db.query(`SELECT last_success, last_status, item_count FROM source_status WHERE source='breach_catalog'`)).rows[0] ?? null;
    res.json({
      emailDelivery: { configured: ctx.mailer.isConfigured(), mode: ctx.mailer.mode },
      contactConfigured: ctx.mailer.isConfigured() && Boolean(config.CONTACT_RECIPIENT),
      threatSources: ctx.reputation.providerSummary,
      feeds,
      breachCatalog: breach ? { ...breach, source: config.BREACH_SOURCE } : { source: config.BREACH_SOURCE, last_success: null },
      devFixtures: config.ENABLE_DEV_FIXTURES && config.NODE_ENV !== 'production',
    });
  });

  // ---- Contact Us ---------------------------------------------------------------------
  r.post('/contact', contactLimit, async (req, res) => {
    const body = parse(
      z.object({
        name: z.string().trim().min(1, 'Enter your name').max(100),
        email: z.string().trim().toLowerCase().email('Enter a valid email address').max(254),
        subject: z.string().trim().min(3, 'Enter a subject').max(150),
        message: z.string().trim().min(10, 'Message must be at least 10 characters').max(5000),
        website: z.string().max(0, 'Message rejected').optional(), // honeypot: must stay empty
        elapsedMs: z.number().int().min(0).optional(),
      }),
      req.body,
    );
    if (body.elapsedMs !== undefined && body.elapsedMs < 1500) {
      throw new HttpError(400, 'too_fast', 'That was quick! Please review your message and send it again.');
    }
    const clean = (s: string) => s.replace(/[\r\n]+/g, ' ');
    let status: 'sent' | 'failed' | 'not_configured' | 'dev_logged';
    let error: string | undefined;
    if (!config.CONTACT_RECIPIENT || !ctx.mailer.isConfigured()) {
      status = 'not_configured';
      error = !config.CONTACT_RECIPIENT ? 'CONTACT_RECIPIENT not set' : 'Email delivery not configured';
    } else {
      const result = await ctx.mailer.send({
        to: config.CONTACT_RECIPIENT,
        replyTo: body.email,
        subject: `[FootprintX contact] ${clean(body.subject)}`,
        text: `From: ${clean(body.name)} <${body.email}>\nSigned-in user: ${req.user ? req.user.id : 'no'}\n\n${body.message}`,
      });
      status = result.status;
      error = result.error;
    }
    await db.query(
      'INSERT INTO contact_messages (user_id, name, email, subject, message, delivery_status, delivery_error) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [req.user?.id ?? null, body.name, body.email, body.subject, body.message, status, error ?? null],
    );
    if (status === 'sent') return res.json({ status, message: 'Thanks — your message was sent. We usually reply within a few working days.' });
    if (status === 'dev_logged') {
      return res.json({ status, message: 'Development mode: your message was saved to the local development outbox. It was not emailed.' });
    }
    if (status === 'not_configured') {
      throw new HttpError(503, 'contact_unavailable', 'Your message was not sent: email delivery is not configured on this server.');
    }
    throw new HttpError(502, 'delivery_failed', 'Your message could not be sent because the email service failed. Please try again later.');
  });

  // ---- Manual domain reputation check (Free) ------------------------------------------------
  r.post('/domain-check', requireAuth, checkLimit, async (req, res) => {
    const body = parse(z.object({ domain: z.string().trim().min(1).max(2048) }), req.body);
    const result = await ctx.reputation.check(body.domain);
    if ('error' in result) {
      const message =
        result.error === 'local_or_private'
          ? 'Local and private network addresses are not checked.'
          : result.error === 'unsupported_scheme'
            ? 'Only web addresses (http/https) can be checked.'
            : 'Enter a valid domain or web address, such as example.com';
      throw new HttpError(400, `domain_${result.error}`, message);
    }
    res.json({ result });
  });

  r.get('/domain-check/limitations', (_req, res) => res.json({ limitations: LIMITATIONS, sources: ctx.reputation.providerSummary }));

  return r;
}

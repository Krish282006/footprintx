import { Router } from 'express';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { track } from '../context.js';
import { parse, requireAuth } from '../middleware.js';
import { withTransaction } from '../db/pool.js';
import { decrypt, encrypt, randomToken, sha256 } from '../lib/crypto.js';
import { HttpError, notFound } from '../lib/errors.js';
import { ProviderError } from '../lib/http.js';
import { logger } from '../lib/logger.js';
import { limiter } from '../lib/ratelimit.js';
import { startScan, type ScanDeps } from '../discovery/service.js';
import type { ProviderId } from '../discovery/providers.js';
import { recalculate } from '../dasi/risk-service.js';
import { notifyNewAlerts } from '../notifications/service.js';

export const EMAIL_CONSENT_VERSION = 'email-discovery-v1';

export const CONSENT_TEXT = {
  version: EMAIL_CONSENT_VERSION,
  accessed: 'Sender address, subject line and date of messages (message metadata). FootprintX does not request access to message bodies or attachments.',
  why: 'To find evidence of online accounts (for example welcome, verification, receipt and security emails) so you can see and secure your accounts.',
  stored: 'Only the conclusion: the service domain, the type of evidence, its date, and a one-way hash of the message ID for de-duplication. Subject lines and message content are not stored. Access tokens are encrypted at rest.',
  limits: 'Up to the most recent N messages per scan. Discovery can miss accounts and can mistake newsletters for accounts; you can correct results.',
  disconnect: 'Disconnect at any time from the Connected mailboxes page. FootprintX revokes the token where the provider supports it and deletes the evidence gathered from that mailbox.',
  notEmailNotifications: 'Connecting a mailbox does not sign you up for email notifications; those are a separate choice.',
} as const;

const consentSchema = z.object({ consent: z.literal(true, { message: 'Consent is required to connect a mailbox' }), consentVersion: z.literal(EMAIL_CONSENT_VERSION) });

function pkce() {
  const verifier = randomToken(48);
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export function scanDeps(ctx: AppContext): ScanDeps {
  return {
    config: ctx.config,
    db: ctx.db,
    providers: ctx.providers,
    fetchImpl: ctx.fetchImpl,
    onAlerts: (alerts) => notifyNewAlerts(ctx.config, ctx.db, ctx.mailer, alerts),
  };
}

const redirectUri = (ctx: AppContext, provider: string) => `${ctx.config.API_PUBLIC_URL.replace(/\/$/, '')}/api/connections/oauth/${provider}/callback`;

export function connectionsRouter(ctx: AppContext) {
  const r = Router();
  const { db, config } = ctx;
  const scanLimit = limiter({ windowMs: 60 * 60_000, limit: 20, scale: ctx.rateLimitScale });

  r.get('/providers', requireAuth, (_req, res) => {
    res.json({
      consent: { ...CONSENT_TEXT, limits: CONSENT_TEXT.limits.replace('N', String(config.DISCOVERY_MAX_MESSAGES)) },
      tokenEncryptionConfigured: Boolean(config.encryptionKey),
      providers: Object.values(ctx.providers)
        .filter((p) => !p.isFixture || p.isConfigured())
        .map((p) => ({ id: p.id, label: p.label, scopes: p.scopes, configured: p.isConfigured() && (p.isFixture || Boolean(config.encryptionKey)), isFixture: p.isFixture })),
    });
  });

  r.get('/', requireAuth, async (req, res) => {
    const { rows } = await db.query(
      `SELECT c.id, c.provider, c.email_address, c.status, c.scopes, c.consent_at, c.last_scan_at, c.created_at,
              (SELECT row_to_json(s) FROM (SELECT id, status, messages_examined, evidence_found, accounts_new, error_code, error_message,
                       started_at, finished_at, is_fixture FROM scans WHERE connection_id = c.id ORDER BY started_at DESC LIMIT 1) s) AS latest_scan
         FROM email_connections c WHERE c.user_id = $1 ORDER BY c.created_at`,
      [req.user!.id],
    );
    res.json({ connections: rows });
  });

  r.post('/oauth/:provider/start', requireAuth, async (req, res) => {
    const providerId = req.params.provider as ProviderId;
    const provider = ctx.providers[providerId];
    if (!provider || provider.isFixture) throw notFound('Provider');
    parse(consentSchema, req.body);
    if (!provider.isConfigured() || !config.encryptionKey) {
      throw new HttpError(503, 'provider_not_configured', `${provider.label} sign-in is not configured on this server. See README → "Email OAuth setup".`);
    }
    const state = randomToken(32);
    const { verifier, challenge } = pkce();
    await db.query('DELETE FROM oauth_states WHERE expires_at < now()');
    await db.query(
      `INSERT INTO oauth_states (state_hash, user_id, provider, code_verifier_enc, expires_at) VALUES ($1,$2,$3,$4, now() + interval '10 minutes')`,
      [sha256(state), req.user!.id, providerId, encrypt(verifier, config.encryptionKey)],
    );
    res.json({ authorizationUrl: provider.authorizationUrl({ state, codeChallenge: challenge, redirectUri: redirectUri(ctx, providerId) }) });
  });

  // OAuth redirect target. Always redirects to a fixed page on the web app (no open redirect).
  r.get('/oauth/:provider/callback', async (req, res) => {
    const back = (q: string) => res.redirect(303, `${config.WEB_ORIGIN}/connections?${q}`);
    const providerId = req.params.provider as ProviderId;
    const provider = ctx.providers[providerId];
    const q = z.object({ state: z.string().min(20).max(200), code: z.string().min(1).max(2048).optional(), error: z.string().max(200).optional() }).safeParse(req.query);
    if (!provider || provider.isFixture || !q.success) return back('error=invalid_callback');
    const stateRow = (await db.query<{ user_id: string; provider: string; code_verifier_enc: string; expires_at: Date }>(
      'DELETE FROM oauth_states WHERE state_hash=$1 RETURNING user_id, provider, code_verifier_enc, expires_at',
      [sha256(q.data.state)],
    )).rows[0];
    // The state must exist, be unexpired, match the provider and belong to the signed-in user.
    if (!stateRow || stateRow.expires_at < new Date() || stateRow.provider !== providerId || !req.user || req.user.id !== stateRow.user_id) {
      return back('error=invalid_state');
    }
    if (q.data.error || !q.data.code) return back(`error=${q.data.error === 'access_denied' ? 'access_denied' : 'provider_error'}`);
    try {
      const key = config.encryptionKey!;
      const tokens = await provider.exchangeCode({ code: q.data.code, codeVerifier: decrypt(stateRow.code_verifier_enc, key), redirectUri: redirectUri(ctx, providerId) });
      const emailAddress = await provider.profileEmail(tokens.accessToken);
      const { rows } = await db.query<{ id: string }>(
        `INSERT INTO email_connections (user_id, provider, email_address, status, scopes, access_token_enc, refresh_token_enc, token_expires_at, consent_version, consent_at)
         VALUES ($1,$2,$3,'active',$4,$5,$6,$7,$8,now())
         ON CONFLICT (user_id, provider, email_address) DO UPDATE SET status='active', scopes=$4, access_token_enc=$5,
           refresh_token_enc=COALESCE($6, email_connections.refresh_token_enc), token_expires_at=$7, consent_version=$8, consent_at=now()
         RETURNING id`,
        [stateRow.user_id, providerId, emailAddress, tokens.scopes, encrypt(tokens.accessToken, key), tokens.refreshToken ? encrypt(tokens.refreshToken, key) : null, tokens.expiresAt, EMAIL_CONSENT_VERSION],
      );
      const { done } = await startScan(scanDeps(ctx), stateRow.user_id, rows[0].id);
      track(ctx, done);
      return back(`connected=${providerId}`);
    } catch (err) {
      logger.warn({ provider: providerId, code: (err as ProviderError).code }, 'oauth callback failed');
      return back('error=connection_failed');
    }
  });

  // DEVELOPMENT FIXTURE mailbox: no OAuth; clearly labelled everywhere it appears.
  r.post('/devfixture', requireAuth, async (req, res) => {
    parse(consentSchema, req.body);
    const provider = ctx.providers.devfixture;
    if (!provider.isConfigured()) throw new HttpError(404, 'not_available', 'Development fixtures are disabled on this server');
    const email = await provider.profileEmail('fixture');
    const { rows } = await db.query<{ id: string }>(
      `INSERT INTO email_connections (user_id, provider, email_address, status, scopes, consent_version, consent_at)
       VALUES ($1,'devfixture',$2,'active',$3,$4,now())
       ON CONFLICT (user_id, provider, email_address) DO UPDATE SET status='active' RETURNING id`,
      [req.user!.id, email, provider.scopes, EMAIL_CONSENT_VERSION],
    );
    const { scanId, done } = await startScan(scanDeps(ctx), req.user!.id, rows[0].id);
    track(ctx, done);
    res.status(202).json({ connectionId: rows[0].id, scanId, isFixture: true });
  });

  r.post('/:id/scan', requireAuth, scanLimit, async (req, res) => {
    const id = parse(z.string().uuid(), req.params.id);
    try {
      const { scanId, done } = await startScan(scanDeps(ctx), req.user!.id, id);
      track(ctx, done);
      res.status(202).json({ scanId });
    } catch (err) {
      const e = err as { status?: number; scanId?: string };
      if (e.status === 404) throw notFound('Connection');
      if (e.status === 409) throw new HttpError(409, 'scan_in_progress', 'A scan is already running for this mailbox', { scanId: e.scanId });
      throw err;
    }
  });

  r.get('/scans/:scanId', requireAuth, async (req, res) => {
    const id = parse(z.string().uuid(), req.params.scanId);
    const { rows } = await db.query(
      `SELECT id, connection_id, provider, is_fixture, status, messages_examined, messages_limit, evidence_found, accounts_new,
              error_code, error_message, started_at, finished_at FROM scans WHERE id=$1 AND user_id=$2`,
      [id, req.user!.id],
    );
    if (!rows[0]) throw notFound('Scan');
    res.json({ scan: rows[0] });
  });

  r.delete('/:id', requireAuth, async (req, res) => {
    const id = parse(z.string().uuid(), req.params.id);
    const purge = req.query.purge !== 'false';
    const conn = (await db.query('SELECT * FROM email_connections WHERE id=$1 AND user_id=$2', [id, req.user!.id])).rows[0];
    if (!conn) throw notFound('Connection');
    let revocation: string = 'not_applicable';
    if (conn.provider !== 'devfixture' && config.encryptionKey) {
      const token = conn.refresh_token_enc ?? conn.access_token_enc;
      revocation = token ? await ctx.providers[conn.provider as ProviderId].revoke(decrypt(token, config.encryptionKey)) : 'not_applicable';
    }
    const purgedAccounts = await withTransaction(db, async (tx) => {
      if (purge) await tx.query('DELETE FROM evidence WHERE connection_id=$1 AND user_id=$2', [id, req.user!.id]);
      await tx.query('DELETE FROM email_connections WHERE id=$1 AND user_id=$2', [id, req.user!.id]);
      if (!purge) return 0;
      // Remove discovered accounts that no longer have any supporting evidence.
      const del = await tx.query(
        `DELETE FROM accounts a WHERE a.user_id=$1 AND a.ownership IN ('discovered','false_positive')
           AND NOT EXISTS (SELECT 1 FROM evidence e WHERE e.account_id=a.id)`,
        [req.user!.id],
      );
      return del.rowCount ?? 0;
    });
    const result = await recalculate(db, req.user!.id, { reason: `Mailbox disconnected (${conn.email_address})` });
    res.json({
      ok: true,
      revocation,
      purgedAccounts,
      dasi: result.dasi,
      note:
        revocation === 'not_supported'
          ? 'Microsoft does not offer token revocation for this sign-in type. FootprintX deleted its tokens; you can also remove app access at https://account.live.com/consent/Manage.'
          : revocation === 'failed'
            ? 'FootprintX deleted its tokens but the provider did not confirm revocation. You can remove access in your provider account settings.'
            : undefined,
    });
  });

  return r;
}

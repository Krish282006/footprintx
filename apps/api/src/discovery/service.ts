import type { Config } from '../config.js';
import type { Db } from '../db/pool.js';
import { decrypt, encrypt, sha256Hex } from '../lib/crypto.js';
import { ProviderError } from '../lib/http.js';
import { logger } from '../lib/logger.js';
import { accountConfidence, classifyMessage } from './classifier.js';
import type { MailboxProvider, ProviderId } from './providers.js';
import { recalculate, type NewAlert } from '../dasi/risk-service.js';
import { lookupEmailBreaches } from '../breach/catalog.js';
import type { FetchLike } from '../lib/http.js';
import { reverifyPending } from '../remediation/service.js';

export type ConnectionRow = {
  id: string; user_id: string; provider: ProviderId; email_address: string; status: string; scopes: string[];
  access_token_enc: string | null; refresh_token_enc: string | null; token_expires_at: Date | null;
};

export type ScanDeps = {
  config: Config;
  db: Db;
  providers: Record<ProviderId, MailboxProvider>;
  fetchImpl: FetchLike;
  onAlerts: (alerts: NewAlert[]) => Promise<void>;
};

const STALE_SCAN_MINUTES = 15;

function key(config: Config): Buffer {
  if (!config.encryptionKey) throw new ProviderError('not_configured', 'TOKEN_ENCRYPTION_KEY is not configured');
  return config.encryptionKey;
}

async function accessTokenFor(deps: ScanDeps, conn: ConnectionRow, provider: MailboxProvider): Promise<string> {
  if (provider.isFixture) return 'fixture';
  const k = key(deps.config);
  const valid = conn.access_token_enc && conn.token_expires_at && conn.token_expires_at.getTime() > Date.now() + 60_000;
  if (valid) return decrypt(conn.access_token_enc!, k);
  if (!conn.refresh_token_enc) throw new ProviderError('reauth_required', 'No refresh token; reconnect the mailbox');
  const tokens = await provider.refresh(decrypt(conn.refresh_token_enc, k));
  await deps.db.query(
    `UPDATE email_connections SET access_token_enc=$2, token_expires_at=$3, refresh_token_enc=COALESCE($4, refresh_token_enc), status='active' WHERE id=$1`,
    [conn.id, encrypt(tokens.accessToken, k), tokens.expiresAt, tokens.refreshToken ? encrypt(tokens.refreshToken, k) : null],
  );
  return tokens.accessToken;
}

/** Creates a scan row and runs it. Returns the scan id and a promise for completion. */
export async function startScan(deps: ScanDeps, userId: string, connectionId: string): Promise<{ scanId: string; done: Promise<void> }> {
  const { db } = deps;
  const conn = (await db.query<ConnectionRow>('SELECT * FROM email_connections WHERE id=$1 AND user_id=$2', [connectionId, userId])).rows[0];
  if (!conn) throw Object.assign(new Error('not_found'), { status: 404 });
  await db.query(
    `UPDATE scans SET status='failed', error_code='abandoned', error_message='Scan did not finish', finished_at=now()
      WHERE connection_id=$1 AND status='running' AND started_at < now() - ($2 || ' minutes')::interval`,
    [connectionId, String(STALE_SCAN_MINUTES)],
  );
  const running = await db.query('SELECT id FROM scans WHERE connection_id=$1 AND status=$2', [connectionId, 'running']);
  if (running.rowCount) throw Object.assign(new Error('scan_in_progress'), { status: 409, scanId: running.rows[0].id });
  const provider = deps.providers[conn.provider];
  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO scans (user_id, connection_id, provider, is_fixture, status, messages_limit) VALUES ($1,$2,$3,$4,'running',$5) RETURNING id`,
    [userId, connectionId, conn.provider, provider.isFixture, deps.config.DISCOVERY_MAX_MESSAGES],
  );
  const scanId = rows[0].id;
  const done = runScan(deps, conn, provider, scanId).catch((err) => logger.error({ err: (err as Error).message, scanId }, 'scan crashed'));
  return { scanId, done };
}

async function runScan(deps: ScanDeps, conn: ConnectionRow, provider: MailboxProvider, scanId: string) {
  const { db, config } = deps;
  let examined = 0;
  let evidenceFound = 0;
  const touched = new Set<string>();
  let accountsNew = 0;
  let failure: ProviderError | null = null;
  const suppressed = new Set(
    (await db.query<{ service_domain: string }>('SELECT service_domain FROM discovery_suppressions WHERE user_id=$1', [conn.user_id])).rows.map((r) => r.service_domain),
  );

  try {
    const token = await accessTokenFor(deps, conn, provider);
    for await (const page of provider.listMessages(token, config.DISCOVERY_MAX_MESSAGES)) {
      for (const msg of page) {
        examined++;
        const c = classifyMessage(msg);
        if (!c || suppressed.has(c.serviceDomain)) continue;
        const acct = await db.query<{ id: string; inserted: boolean }>(
          `INSERT INTO accounts (user_id, service_domain, service_name, category, is_fixture, first_seen_at, last_seen_at)
           VALUES ($1,$2,$3,$4,$5,$6,$6)
           ON CONFLICT (user_id, service_domain) DO UPDATE SET
             first_seen_at = LEAST(accounts.first_seen_at, EXCLUDED.first_seen_at),
             last_seen_at = GREATEST(accounts.last_seen_at, EXCLUDED.last_seen_at),
             updated_at = now()
           RETURNING id, (xmax = 0) AS inserted`,
          [conn.user_id, c.serviceDomain, c.serviceName, c.category, provider.isFixture, c.observedAt],
        );
        const accountId = acct.rows[0].id;
        if (acct.rows[0].inserted) accountsNew++;
        await db.query('INSERT INTO account_identities (account_id, email_address) VALUES ($1,$2) ON CONFLICT DO NOTHING', [accountId, conn.email_address]);
        const ev = await db.query(
          `INSERT INTO evidence (user_id, account_id, connection_id, scan_id, source, evidence_type, signal, confidence, sender_domain,
             identity_email, message_ref_hash, observed_at, is_fixture)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT DO NOTHING`,
          [
            conn.user_id, accountId, conn.id, scanId, conn.provider, c.evidenceType, c.signal, c.confidence, c.senderDomain,
            conn.email_address, sha256Hex(`${conn.provider}:${conn.id}:${msg.id}`), c.observedAt, provider.isFixture,
          ],
        );
        if (ev.rowCount) evidenceFound++;
        touched.add(accountId);
      }
      await db.query('UPDATE scans SET messages_examined=$2, evidence_found=$3 WHERE id=$1', [scanId, examined, evidenceFound]);
    }
  } catch (err) {
    failure = err instanceof ProviderError ? err : new ProviderError('provider_unavailable', 'Unexpected error during scan');
    if (!(err instanceof ProviderError)) logger.error({ err: (err as Error).message }, 'unexpected scan error');
    if (failure.code === 'reauth_required') await db.query(`UPDATE email_connections SET status='reauth_required' WHERE id=$1`, [conn.id]);
  }

  // Recompute account confidence from all evidence for touched accounts.
  for (const accountId of touched) {
    const items = await db.query<{ evidence_type: string; confidence: number }>('SELECT evidence_type, confidence FROM evidence WHERE account_id=$1', [accountId]);
    await db.query('UPDATE accounts SET confidence=$2 WHERE id=$1', [
      accountId,
      accountConfidence(items.rows.map((r) => ({ evidenceType: r.evidence_type, confidence: Number(r.confidence) }))),
    ]);
  }

  // Optional per-email breach lookup (only with a configured HIBP key).
  if (!failure && config.HIBP_API_KEY && !provider.isFixture) {
    const names = await lookupEmailBreaches(config, deps.fetchImpl, conn.email_address);
    if (names?.length) {
      const matches = await db.query<{ id: string; domain: string | null; title: string }>('SELECT id, domain, title FROM breach_catalog WHERE id = ANY($1::text[])', [names]);
      for (const b of matches.rows) {
        if (!b.domain || suppressed.has(b.domain)) continue;
        const acct = await db.query<{ id: string }>(
          `INSERT INTO accounts (user_id, service_domain, service_name, category) VALUES ($1,$2,$3,'other')
           ON CONFLICT (user_id, service_domain) DO UPDATE SET updated_at=now() RETURNING id`,
          [conn.user_id, b.domain, b.title],
        );
        await db.query(
          `INSERT INTO evidence (user_id, account_id, connection_id, scan_id, source, evidence_type, signal, confidence, identity_email, message_ref_hash, observed_at)
           VALUES ($1,$2,$3,$4,'hibp','breach_record',$5,0.9,$6,$7,now()) ON CONFLICT DO NOTHING`,
          [conn.user_id, acct.rows[0].id, conn.id, scanId, `hibp:${b.id}`, conn.email_address, sha256Hex(`hibp:${conn.email_address}:${b.id}`)],
        );
        await db.query('UPDATE accounts SET confidence=GREATEST(confidence, 0.9) WHERE id=$1', [acct.rows[0].id]);
        touched.add(acct.rows[0].id);
      }
    }
  }

  const status = failure ? (examined > 0 ? 'partial' : 'failed') : 'completed';
  await db.query(
    `UPDATE scans SET status=$2, messages_examined=$3, evidence_found=$4, accounts_new=$5, error_code=$6, error_message=$7, finished_at=now() WHERE id=$1`,
    [scanId, status, examined, evidenceFound, accountsNew, failure?.code ?? null, failure ? failure.message.slice(0, 300) : null],
  );
  await db.query('UPDATE email_connections SET last_scan_at=now() WHERE id=$1', [conn.id]);

  await reverifyPending(db, conn.user_id, status === 'completed');
  const reason =
    status === 'completed'
      ? `Mailbox scan completed (${conn.email_address})`
      : status === 'partial'
        ? `Mailbox scan partially completed (${conn.email_address})`
        : `Mailbox scan failed (${conn.email_address})`;
  // Recalculate the whole user so coverage changes are reflected; unrelated findings
  // keep their identity and history because recalculation upserts by fingerprint.
  const result = await recalculate(db, conn.user_id, { reason });
  if (result.newAlerts.length) await deps.onAlerts(result.newAlerts);
}

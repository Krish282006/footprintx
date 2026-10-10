import type { Config } from '../config.js';
import type { Db } from '../db/pool.js';
import { fetchJson, ProviderError, type FetchLike } from '../lib/http.js';
import { logger } from '../lib/logger.js';
import { FIXTURE_BREACHES } from '../discovery/fixtures.js';

/**
 * Breach catalogue: the public Have I Been Pwned breach list (no API key needed,
 * licensed CC BY 4.0, attribution shown in the UI). This is SERVICE-LEVEL data:
 * a match means the service had a breach, not that the user's account was in it.
 */
export const HIBP_BREACHES_URL = 'https://haveibeenpwned.com/api/v3/breaches';
const SOURCE_KEY = 'breach_catalog';
const USER_AGENT = 'FootprintX-breach-catalog/1.0';

type HibpBreach = {
  Name: string; Title: string; Domain: string; BreachDate: string; AddedDate: string; PwnCount: number;
  DataClasses: string[]; IsVerified: boolean; IsSensitive: boolean; IsFabricated: boolean; IsSpamList: boolean;
};

export type BreachSyncResult = { ok: boolean; count: number; error?: string };

async function recordStatus(db: Db, ok: boolean, count: number | null, error: string | null) {
  await db.query(
    `INSERT INTO source_status (source, last_attempt, last_success, last_status, last_error, item_count)
     VALUES ($1, now(), CASE WHEN $2 THEN now() END, $3, $4, $5)
     ON CONFLICT (source) DO UPDATE SET last_attempt = now(),
       last_success = CASE WHEN $2 THEN now() ELSE source_status.last_success END,
       last_status = $3, last_error = $4, item_count = COALESCE($5, source_status.item_count)`,
    [SOURCE_KEY, ok, ok ? 'ok' : 'error', error, count],
  );
}

export async function syncBreachCatalog(config: Config, db: Db, fetchImpl: FetchLike, url = HIBP_BREACHES_URL): Promise<BreachSyncResult> {
  if (config.BREACH_SOURCE === 'none') return { ok: false, count: 0, error: 'Breach source disabled' };
  if (config.BREACH_SOURCE === 'fixture') {
    // DEVELOPMENT FIXTURE catalogue.
    for (const b of FIXTURE_BREACHES) {
      await db.query(
        `INSERT INTO breach_catalog (id, title, domain, breach_date, pwn_count, data_classes, is_verified, source, fetched_at)
         VALUES ($1,$2,$3,$4,$5,$6,true,'fixture',now())
         ON CONFLICT (id) DO UPDATE SET title=$2, domain=$3, breach_date=$4, pwn_count=$5, data_classes=$6, fetched_at=now()`,
        [b.id, b.title, b.domain, b.breachDate, b.pwnCount, b.dataClasses],
      );
    }
    await recordStatus(db, true, FIXTURE_BREACHES.length, null);
    return { ok: true, count: FIXTURE_BREACHES.length };
  }
  try {
    const list = await fetchJson<HibpBreach[]>(fetchImpl, url, { headers: { 'user-agent': USER_AGENT, accept: 'application/json' }, timeoutMs: 20_000 });
    if (!Array.isArray(list)) throw new ProviderError('invalid_response', 'Breach list is not an array');
    const client = await db.connect();
    try {
      await client.query('BEGIN');
      for (const b of list) {
        if (!b?.Name || typeof b.Name !== 'string') continue;
        await client.query(
          `INSERT INTO breach_catalog (id, title, domain, breach_date, added_date, pwn_count, data_classes, is_verified,
             is_sensitive, is_fabricated, is_spam_list, source, fetched_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'hibp',now())
           ON CONFLICT (id) DO UPDATE SET title=$2, domain=$3, breach_date=$4, added_date=$5, pwn_count=$6, data_classes=$7,
             is_verified=$8, is_sensitive=$9, is_fabricated=$10, is_spam_list=$11, fetched_at=now()`,
          [
            b.Name, String(b.Title ?? b.Name).slice(0, 200), b.Domain ? String(b.Domain).toLowerCase() : null,
            /^\d{4}-\d{2}-\d{2}$/.test(b.BreachDate) ? b.BreachDate : null, b.AddedDate ?? null, b.PwnCount ?? null,
            Array.isArray(b.DataClasses) ? b.DataClasses.map(String) : [], Boolean(b.IsVerified), Boolean(b.IsSensitive),
            Boolean(b.IsFabricated), Boolean(b.IsSpamList),
          ],
        );
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    await recordStatus(db, true, list.length, null);
    return { ok: true, count: list.length };
  } catch (err) {
    const error = err instanceof ProviderError ? `${err.code}: ${err.message}` : (err as Error).message;
    logger.warn({ error }, 'breach catalogue sync failed');
    await recordStatus(db, false, null, error.slice(0, 300));
    return { ok: false, count: 0, error };
  }
}

export async function breachCatalogStatus(db: Db) {
  const { rows } = await db.query(`SELECT last_attempt, last_success, last_status, last_error, item_count FROM source_status WHERE source = $1`, [SOURCE_KEY]);
  const r = rows[0];
  return {
    available: Boolean(r?.last_success),
    lastSuccess: r?.last_success ?? null,
    lastAttempt: r?.last_attempt ?? null,
    lastError: r?.last_status === 'error' ? r.last_error : null,
    itemCount: r?.item_count ?? 0,
  };
}

/** Sync if the catalogue has never loaded or is older than 24 hours. Never throws. */
export async function ensureBreachCatalogFresh(config: Config, db: Db, fetchImpl: FetchLike) {
  const status = await breachCatalogStatus(db);
  const stale = !status.lastSuccess || Date.now() - new Date(status.lastSuccess).getTime() > 24 * 3600_000;
  const recentlyTried = status.lastAttempt && Date.now() - new Date(status.lastAttempt).getTime() < 10 * 60_000;
  if (stale && !recentlyTried) await syncBreachCatalog(config, db, fetchImpl).catch(() => undefined);
}

/**
 * Optional per-email lookup (paid HIBP key). Returns breach names, [] when none,
 * or null when the lookup is unavailable — never a false "clean" result.
 */
export async function lookupEmailBreaches(config: Config, fetchImpl: FetchLike, email: string, baseUrl = 'https://haveibeenpwned.com/api/v3'): Promise<string[] | null> {
  if (!config.HIBP_API_KEY) return null;
  try {
    const res = await fetchImpl(`${baseUrl}/breachedaccount/${encodeURIComponent(email)}?truncateResponse=true`, {
      headers: { 'hibp-api-key': config.HIBP_API_KEY, 'user-agent': USER_AGENT },
      signal: AbortSignal.timeout(10_000),
    });
    if (res.status === 404) return [];
    if (!res.ok) return null;
    const body = (await res.json()) as { Name: string }[];
    return Array.isArray(body) ? body.map((b) => b.Name) : null;
  } catch {
    return null;
  }
}

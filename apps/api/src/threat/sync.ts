import type { Db } from '../db/pool.js';
import { normalizeDomain } from '../lib/domain.js';
import type { FetchLike } from '../lib/http.js';
import { logger } from '../lib/logger.js';

const MAX_BYTES = 60 * 1024 * 1024;

export function feedIdFor(url: string): string {
  const u = new URL(url);
  const last = u.pathname.split('/').filter(Boolean).at(-1) ?? u.hostname;
  return `${u.hostname.replace(/^www\./, '')}:${last.replace(/\.(txt|csv|list)$/i, '')}`.slice(0, 120);
}

/** Parses plain domain lists and hosts-file style lists; ignores comments and invalid lines. */
export function parseFeed(text: string): string[] {
  const out = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.replace(/#.*/, '').trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    const candidate = parts.length > 1 && /^(0\.0\.0\.0|127\.0\.0\.1)$/.test(parts[0]) ? parts[1] : parts[0];
    const parsed = normalizeDomain(candidate);
    if (parsed.ok && !parsed.value.isIp) out.add(parsed.value.host);
  }
  return [...out];
}

export async function syncFeed(db: Db, fetchImpl: FetchLike, url: string): Promise<{ feedId: string; ok: boolean; count: number; error?: string }> {
  const feedId = feedIdFor(url);
  await db.query(
    `INSERT INTO threat_feeds (feed_id, url, last_attempt) VALUES ($1,$2,now())
     ON CONFLICT (feed_id) DO UPDATE SET url=$2, last_attempt=now()`,
    [feedId, url],
  );
  try {
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(60_000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const len = Number(res.headers.get('content-length') ?? 0);
    if (len > MAX_BYTES) throw new Error('Feed too large');
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error('Feed too large');
    const domains = parseFeed(text);
    if (!domains.length) throw new Error('Feed contained no valid domains');
    const client = await db.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM threat_feed_entries WHERE feed_id = $1', [feedId]);
      for (let i = 0; i < domains.length; i += 5000) {
        await client.query(
          `INSERT INTO threat_feed_entries (feed_id, domain) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING`,
          [feedId, domains.slice(i, i + 5000)],
        );
      }
      await client.query(
        `UPDATE threat_feeds SET last_success=now(), last_status='ok', last_error=NULL, entry_count=$2 WHERE feed_id=$1`,
        [feedId, domains.length],
      );
      // Results computed from the previous feed version are no longer trustworthy.
      await client.query('DELETE FROM domain_reputation_cache');
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    return { feedId, ok: true, count: domains.length };
  } catch (err) {
    const error = (err as Error).message.slice(0, 300);
    logger.warn({ feedId, error }, 'threat feed sync failed');
    await db.query(`UPDATE threat_feeds SET last_status='error', last_error=$2 WHERE feed_id=$1`, [feedId, error]);
    return { feedId, ok: false, count: 0, error };
  }
}

export async function syncAllFeeds(db: Db, fetchImpl: FetchLike, urls: string[]) {
  const results = [];
  for (const url of urls) results.push(await syncFeed(db, fetchImpl, url));
  return results;
}

/** Syncs feeds that have never synced or are older than maxAgeHours. Never throws. */
export async function ensureFeedsFresh(db: Db, fetchImpl: FetchLike, urls: string[], maxAgeHours: number) {
  for (const url of urls) {
    const { rows } = await db.query<{ last_success: Date | null; last_attempt: Date | null }>(
      'SELECT last_success, last_attempt FROM threat_feeds WHERE feed_id = $1',
      [feedIdFor(url)],
    );
    const r = rows[0];
    const stale = !r?.last_success || Date.now() - r.last_success.getTime() > maxAgeHours * 3600_000;
    const recentlyTried = r?.last_attempt && Date.now() - r.last_attempt.getTime() < 10 * 60_000;
    if (stale && !recentlyTried) await syncFeed(db, fetchImpl, url).catch(() => undefined);
  }
}

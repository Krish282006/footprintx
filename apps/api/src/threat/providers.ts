import type { Db } from '../db/pool.js';
import type { FetchLike } from '../lib/http.js';
import type { ThreatProvider } from './types.js';

/**
 * Local blocklist feed provider. Domains are synced from configured public feeds into
 * PostgreSQL (see sync.ts) and looked up locally, so checked domains never leave the server.
 */
export function feedProvider(db: Db, maxAgeHours: number): ThreatProvider {
  return {
    id: 'feed',
    kind: 'threat_intel',
    label: 'Public phishing/malware domain feeds',
    async check(d) {
      const feeds = await db.query<{ feed_id: string; last_success: Date | null }>('SELECT feed_id, last_success FROM threat_feeds');
      const fresh = feeds.rows.filter((f) => f.last_success && Date.now() - f.last_success.getTime() < maxAgeHours * 3 * 3600_000);
      if (!fresh.length) {
        return { outcome: 'error', reasons: [], confidence: 'low', error: feeds.rows.length ? 'feed_stale' : 'feed_not_synced' };
      }
      const { rows } = await db.query<{ domain: string; feed_id: string }>(
        'SELECT domain, feed_id FROM threat_feed_entries WHERE domain = ANY($1::text[]) AND feed_id = ANY($2::text[]) LIMIT 5',
        [d.candidates, fresh.map((f) => f.feed_id)],
      );
      if (rows.length) {
        const exact = rows.find((r) => r.domain === d.host) ?? rows[0];
        return {
          outcome: 'malicious',
          confidence: exact.domain === d.host ? 'high' : 'medium',
          matchedDomain: exact.domain,
          reasons: [
            exact.domain === d.host
              ? `This site is listed in the "${exact.feed_id}" phishing/malware feed.`
              : `The parent domain ${exact.domain} is listed in the "${exact.feed_id}" phishing/malware feed.`,
          ],
        };
      }
      return { outcome: 'no_match', reasons: [], confidence: 'medium' };
    },
  };
}

/** abuse.ch URLhaus host lookup (free Auth-Key required: https://auth.abuse.ch/). */
export function urlhausProvider(authKey: string, fetchImpl: FetchLike, endpoint = 'https://urlhaus-api.abuse.ch/v1/host/'): ThreatProvider {
  return {
    id: 'urlhaus',
    kind: 'threat_intel',
    label: 'abuse.ch URLhaus',
    async check(d, signal) {
      if (!authKey) return { outcome: 'error', reasons: [], confidence: 'low', error: 'not_configured' };
      const res = await fetchImpl(endpoint, {
        method: 'POST',
        headers: { 'Auth-Key': authKey, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ host: d.host }).toString(),
        signal,
      });
      if (!res.ok) return { outcome: 'error', reasons: [], confidence: 'low', error: `http_${res.status}` };
      const body = (await res.json()) as { query_status?: string; url_count?: string | number; urls?: { url_status?: string }[] };
      if (body.query_status === 'no_results') return { outcome: 'no_match', reasons: [], confidence: 'medium' };
      if (body.query_status === 'ok') {
        const online = (body.urls ?? []).filter((u) => u.url_status === 'online').length;
        return online
          ? { outcome: 'malicious', confidence: 'high', matchedDomain: d.host, reasons: [`URLhaus lists ${online} active malware URL(s) on this host.`] }
          : { outcome: 'suspicious', confidence: 'medium', matchedDomain: d.host, reasons: ['URLhaus has previously listed malware URLs on this host (currently offline).'] };
      }
      return { outcome: 'error', reasons: [], confidence: 'low', error: `urlhaus_${body.query_status ?? 'unknown'}` };
    },
  };
}

/** Google Safe Browsing v4 Lookup API (free key; non-commercial terms apply). */
export function safeBrowsingProvider(apiKey: string, fetchImpl: FetchLike, endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'): ThreatProvider {
  return {
    id: 'safebrowsing',
    kind: 'threat_intel',
    label: 'Google Safe Browsing',
    async check(d, signal) {
      if (!apiKey) return { outcome: 'error', reasons: [], confidence: 'low', error: 'not_configured' };
      const res = await fetchImpl(`${endpoint}?key=${encodeURIComponent(apiKey)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'footprintx', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: `http://${d.host}/` }, { url: `https://${d.host}/` }],
          },
        }),
        signal,
      });
      if (!res.ok) return { outcome: 'error', reasons: [], confidence: 'low', error: `http_${res.status}` };
      const body = (await res.json()) as { matches?: { threatType: string }[] };
      if (body.matches?.length) {
        const types = Array.from(new Set(body.matches.map((m) => m.threatType.toLowerCase().replace(/_/g, ' '))));
        return { outcome: 'malicious', confidence: 'high', matchedDomain: d.host, reasons: [`Google Safe Browsing flags this site for: ${types.join(', ')}.`] };
      }
      return { outcome: 'no_match', reasons: [], confidence: 'medium' };
    },
  };
}

/**
 * DEVELOPMENT/TEST FIXTURE provider. Recognises reserved *.fixture.test names only,
 * so tests never need to visit or query real malicious sites.
 */
export const fixtureProvider: ThreatProvider = {
  id: 'fixture',
  kind: 'threat_intel',
  label: 'Development fixture threat source',
  isFixture: true,
  async check(d, signal) {
    const h = d.host;
    if (!h.endsWith('.fixture.test') && h !== 'fixture.test') return { outcome: 'no_match', reasons: [], confidence: 'medium' };
    if (h.startsWith('malicious.') || h.includes('.malicious.')) {
      return { outcome: 'malicious', confidence: 'high', matchedDomain: h, reasons: ['Listed as phishing in the development fixture source.'] };
    }
    if (h.startsWith('suspicious.')) return { outcome: 'suspicious', confidence: 'medium', matchedDomain: h, reasons: ['Flagged as suspicious in the development fixture source.'] };
    if (h.startsWith('timeout.')) {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, 60_000);
        signal.addEventListener('abort', () => {
          clearTimeout(t);
          reject(Object.assign(new Error('aborted'), { name: 'TimeoutError' }));
        });
      });
    }
    if (h.startsWith('error.')) throw new Error('Fixture provider failure');
    return { outcome: 'no_match', reasons: [], confidence: 'medium' };
  },
};

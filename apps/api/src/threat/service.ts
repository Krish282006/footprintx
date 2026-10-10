import type { Config } from '../config.js';
import type { Db } from '../db/pool.js';
import { normalizeDomain } from '../lib/domain.js';
import type { FetchLike } from '../lib/http.js';
import { heuristicsProvider } from './heuristics.js';
import { feedProvider, fixtureProvider, safeBrowsingProvider, urlhausProvider } from './providers.js';
import type { ProviderResult, ReputationResult, ReputationStatus, ThreatProvider } from './types.js';

export const LIMITATIONS =
  'FootprintX checks domains against the configured threat sources only. "No known threat" means none of those sources ' +
  'listed the site at check time; it does not guarantee the site is safe. FootprintX is not antivirus software.';

const TTL_MS: Record<ReputationStatus, number> = { green: 6 * 3600_000, red: 12 * 3600_000, amber: 3600_000, grey: 0 };

const NEXT_STEPS: Record<ReputationStatus, string[]> = {
  red: [
    'Do not enter passwords, payment details or personal information on this site.',
    'Close the tab or go back to the previous page.',
    'If you already entered a password here, change it from the official website and turn on two-step verification.',
  ],
  amber: [
    'Check the address carefully before entering any information.',
    'Reach the service by typing its known address or using a saved bookmark instead of a link.',
    'Avoid signing in or paying unless you are sure the site is genuine.',
  ],
  green: ['No known threat was found. Stay alert for unexpected sign-in prompts or urgent requests.'],
  grey: ['The check could not be completed. Be cautious, and try again later.'],
};

export function buildProviders(config: Config, db: Db, fetchImpl: FetchLike): ThreatProvider[] {
  const out: ThreatProvider[] = [];
  for (const id of config.THREAT_PROVIDERS) {
    if (id === 'feed') out.push(feedProvider(db, config.THREAT_FEED_MAX_AGE_HOURS));
    else if (id === 'heuristics') out.push(heuristicsProvider);
    else if (id === 'urlhaus' && config.URLHAUS_AUTH_KEY) out.push(urlhausProvider(config.URLHAUS_AUTH_KEY, fetchImpl));
    else if (id === 'safebrowsing' && config.GOOGLE_SAFE_BROWSING_KEY) out.push(safeBrowsingProvider(config.GOOGLE_SAFE_BROWSING_KEY, fetchImpl));
    else if (id === 'fixture' && config.NODE_ENV !== 'production') out.push(fixtureProvider);
  }
  return out;
}

/** Combines provider results. A failed lookup can never produce green. */
export function aggregate(results: ProviderResult[]): Pick<ReputationResult, 'status' | 'summary' | 'reasons' | 'confidence'> {
  const intel = results.filter((r) => r.kind === 'threat_intel');
  const malicious = intel.filter((r) => r.outcome === 'malicious');
  if (malicious.length) {
    return {
      status: 'red',
      summary: 'Known malicious site',
      reasons: malicious.flatMap((r) => r.reasons),
      confidence: malicious.some((r) => r.confidence === 'high') ? 'high' : 'medium',
    };
  }
  const suspicious = results.filter((r) => r.outcome === 'suspicious');
  if (suspicious.length) {
    return { status: 'amber', summary: 'Suspicious site', reasons: suspicious.flatMap((r) => r.reasons), confidence: suspicious.some((r) => r.kind === 'threat_intel') ? 'medium' : 'low' };
  }
  const failed = intel.filter((r) => r.outcome === 'error');
  const clean = intel.filter((r) => r.outcome === 'no_match');
  if (!intel.length) {
    return { status: 'grey', summary: 'Not checked', reasons: ['No threat-intelligence source is configured or available.'], confidence: 'none' };
  }
  if (failed.length) {
    return {
      status: 'grey',
      summary: clean.length ? 'Check incomplete' : 'Check unavailable',
      reasons: [
        clean.length
          ? `${failed.length} of ${intel.length} threat sources could not be reached; the others found no known threat.`
          : 'The threat sources could not be reached, so this site was not checked.',
      ],
      confidence: 'none',
    };
  }
  return { status: 'green', summary: 'No known threat detected', reasons: ['None of the configured threat sources list this site.'], confidence: 'medium' };
}

export type CheckOptions = { bypassCache?: boolean };

export class ReputationService {
  constructor(
    private db: Db,
    private providers: ThreatProvider[],
    private timeoutMs: number,
  ) {}

  get providerSummary() {
    return this.providers.map((p) => ({ id: p.id, label: p.label, kind: p.kind, isFixture: Boolean(p.isFixture) }));
  }

  async check(input: string, opts: CheckOptions = {}): Promise<ReputationResult | { error: 'invalid' | 'local_or_private' | 'unsupported_scheme' }> {
    const parsed = normalizeDomain(input);
    if (!parsed.ok) return { error: parsed.reason };
    const d = parsed.value;

    if (!opts.bypassCache) {
      const cached = await this.db.query<{ result: ReputationResult; expires_at: Date }>(
        'SELECT result, expires_at FROM domain_reputation_cache WHERE domain = $1 AND expires_at > now()',
        [d.host],
      );
      if (cached.rows[0]) return { ...cached.rows[0].result, fromCache: true };
    }

    const results = await Promise.all(this.providers.map((p) => this.runProvider(p, d)));
    const agg = aggregate(results);
    const checkedAt = new Date();
    const ttl = TTL_MS[agg.status];
    const result: ReputationResult = {
      domain: d.host,
      displayDomain: d.unicodeHost,
      ...agg,
      nextSteps: NEXT_STEPS[agg.status],
      providers: results,
      checkedAt: checkedAt.toISOString(),
      expiresAt: ttl ? new Date(checkedAt.getTime() + ttl).toISOString() : null,
      fromCache: false,
      limitations: LIMITATIONS,
    };
    if (ttl) {
      await this.db.query(
        `INSERT INTO domain_reputation_cache (domain, status, result, checked_at, expires_at) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (domain) DO UPDATE SET status=$2, result=$3, checked_at=$4, expires_at=$5`,
        [d.host, agg.status, JSON.stringify(result), checkedAt, result.expiresAt],
      );
    }
    return result;
  }

  private async runProvider(p: ThreatProvider, d: Parameters<ThreatProvider['check']>[0]): Promise<ProviderResult> {
    const base = { provider: p.id, kind: p.kind } as const;
    const signal = AbortSignal.timeout(this.timeoutMs);
    try {
      const r = await Promise.race([
        p.check(d, signal),
        new Promise<never>((_, reject) =>
          signal.addEventListener('abort', () => reject(Object.assign(new Error('timeout'), { name: 'TimeoutError' }))),
        ),
      ]);
      return { ...base, ...r, checkedAt: new Date().toISOString() };
    } catch (err) {
      const name = (err as Error).name;
      return {
        ...base,
        outcome: 'error',
        reasons: [],
        confidence: 'low',
        error: name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'provider_error',
        checkedAt: new Date().toISOString(),
      };
    }
  }
}

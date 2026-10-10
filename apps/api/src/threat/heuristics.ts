import { BRAND_DOMAINS, BRAND_LABELS } from '../catalog/services.js';
import type { ThreatProvider } from './types.js';

function levenshtein(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length][b.length];
}

const SCRIPT_TESTS: [string, RegExp][] = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Armenian', /\p{Script=Armenian}/u],
];

/** Normalises common digit/letter swaps used in look-alike domains. */
const deconfuse = (s: string) => s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/rn/g, 'm').replace(/vv/g, 'w');

/**
 * Local heuristics. These never produce "malicious" — only "suspicious" (amber) with
 * an explanation — because look-alike signals have false positives.
 */
export const heuristicsProvider: ThreatProvider = {
  id: 'heuristics',
  kind: 'heuristic',
  label: 'FootprintX look-alike heuristics',
  async check(d) {
    const reasons: string[] = [];
    if (d.isIp) reasons.push('The site is addressed by a raw IP address instead of a domain name.');
    if (d.registrableDomain && !BRAND_DOMAINS.has(d.registrableDomain)) {
      const label = d.registrableDomain.split('.')[0];
      if (d.isIdn) {
        const unicodeLabel = d.unicodeHost.split('.').slice(-2)[0] ?? '';
        const scripts = SCRIPT_TESTS.filter(([, re]) => re.test(unicodeLabel)).map(([n]) => n);
        if (scripts.length > 1) reasons.push(`The domain mixes ${scripts.join(' and ')} characters, a common look-alike technique.`);
      }
      for (const brand of BRAND_LABELS) {
        const plain = label.replace(/-/g, '');
        if (plain === brand) continue;
        if (levenshtein(deconfuse(plain), brand) <= 1 && plain.length >= 5) {
          reasons.push(`"${d.registrableDomain}" closely resembles ${brand}, but is a different domain.`);
          break;
        }
      }
      const sub = d.host.slice(0, Math.max(0, d.host.length - d.registrableDomain.length - 1));
      const brandInSub = BRAND_LABELS.find((b) => sub.split(/[.-]/).includes(b));
      if (brandInSub) reasons.push(`The address contains "${brandInSub}" but the site actually belongs to ${d.registrableDomain}.`);
    }
    return reasons.length
      ? { outcome: 'suspicious', reasons, confidence: 'low' }
      : { outcome: 'no_match', reasons: [], confidence: 'low' };
  },
};

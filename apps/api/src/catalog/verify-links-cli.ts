/**
 * Checks that every curated official link is reachable (HTTP status < 400 after
 * redirects, or 401/403 which indicates a sign-in wall on a live page).
 * Usage: npm run links:verify -w apps/api
 */
import { SERVICE_CATALOG } from './services.js';

const urls = new Set<string>();
for (const s of SERVICE_CATALOG) {
  for (const u of [s.securityUrl, s.passwordUrl, s.mfaUrl, s.activityUrl, s.deleteUrl]) if (u) urls.add(u);
}
let failures = 0;
for (const url of urls) {
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow', signal: AbortSignal.timeout(10_000) });
    const ok = res.status < 400 || res.status === 401 || res.status === 403;
    if (!ok) failures++;
    console.log(`${ok ? 'OK  ' : 'FAIL'} ${res.status} ${url}`);
  } catch (err) {
    failures++;
    console.log(`FAIL ---  ${url} (${(err as Error).message})`);
  }
}
console.log(`${urls.size - failures}/${urls.size} links reachable on ${new Date().toISOString()}`);
process.exitCode = failures ? 1 : 0;

/**
 * Pure extension logic (no chrome.* calls) so it can be unit-tested.
 * Privacy rule: only the hostname of a top-level http(s) navigation is ever sent,
 * never paths, query strings, page content, form data, cookies or credentials.
 */
export type Status = 'green' | 'red' | 'amber' | 'grey';

export type CheckResult = {
  host: string;
  status: Status;
  summary: string;
  reasons: string[];
  nextSteps: string[];
  checkedAt: string;
  source: 'server' | 'cache' | 'local';
  /** Why the result is grey, when it is. */
  greyReason?: 'offline' | 'timeout' | 'server_error' | 'premium_required' | 'not_linked' | 'not_checked' | 'local_address' | 'disabled' | 'unavailable';
};

const PRIVATE_V4 = [/^10\./, /^127\./, /^0\./, /^169\.254\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./];

/** Returns the hostname to check for a URL, or null when the URL must not be checked or sent. */
export function hostToCheck(rawUrl: string, apiHost: string): { host: string } | { skip: 'not_web' | 'local_address' | 'own_service' } {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return { skip: 'not_web' };
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { skip: 'not_web' };
  const host = u.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (!host) return { skip: 'not_web' };
  if (host === apiHost) return { skip: 'own_service' };
  if (
    host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.lan') ||
    !host.includes('.') && !host.includes(':') || PRIVATE_V4.some((r) => r.test(host)) || host === '::1' || /^f[cd]/.test(host) || host.startsWith('fe80')
  ) {
    return { skip: 'local_address' };
  }
  return { host };
}

/** Cache lifetime per status. Grey results are cached only briefly so recovery is quick. */
export const CACHE_TTL_MS: Record<Status, number> = { green: 6 * 3600_000, red: 12 * 3600_000, amber: 3600_000, grey: 60_000 };

export function isFresh(r: CheckResult, now = Date.now()): boolean {
  return now - new Date(r.checkedAt).getTime() < CACHE_TTL_MS[r.status];
}

export const BADGE: Record<Status, { text: string; color: string; title: string }> = {
  green: { text: '✓', color: '#067647', title: 'No known threat detected by FootprintX sources' },
  red: { text: '!', color: '#b42318', title: 'Known malicious site' },
  amber: { text: '?', color: '#b54708', title: 'Suspicious or uncertain site' },
  grey: { text: '–', color: '#667085', title: 'Not checked' },
};

const GREY_TEXT: Record<NonNullable<CheckResult['greyReason']>, string> = {
  offline: 'You appear to be offline, so this site was not checked.',
  timeout: 'The check took too long and was stopped, so this site was not checked.',
  server_error: 'FootprintX could not complete the check.',
  premium_required: 'Automatic protection requires a Premium plan.',
  not_linked: 'Link the extension to your FootprintX account to enable checks.',
  not_checked: 'This page was not checked.',
  local_address: 'Local and private network addresses are not checked.',
  disabled: 'Protection is turned off in the extension settings.',
  unavailable: 'Threat sources were unavailable, so this site was not fully checked.',
};

export function greyResult(host: string, reason: NonNullable<CheckResult['greyReason']>, source: CheckResult['source'] = 'local'): CheckResult {
  return {
    host,
    status: 'grey',
    summary: reason === 'premium_required' ? 'Premium required' : reason === 'not_linked' ? 'Not linked' : reason === 'disabled' ? 'Protection off' : 'Not checked',
    reasons: [GREY_TEXT[reason]],
    nextSteps: reason === 'offline' || reason === 'timeout' || reason === 'server_error' || reason === 'unavailable' ? ['Be cautious with sign-in or payment pages until the site can be checked.'] : [],
    checkedAt: new Date().toISOString(),
    source,
    greyReason: reason,
  };
}

type ServerResult = { status: Status; summary: string; reasons: string[]; nextSteps: string[] };

/**
 * Asks the FootprintX API about one host. Every failure maps to grey — a failed
 * check is never reported as safe.
 */
export async function checkHost(opts: {
  apiBase: string;
  token: string | null;
  host: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  online?: boolean;
}): Promise<CheckResult> {
  const { apiBase, token, host, fetchImpl = fetch, timeoutMs = 5000, online = true } = opts;
  if (!token) return greyResult(host, 'not_linked');
  if (!online) return greyResult(host, 'offline');
  let res: Response;
  try {
    res = await fetchImpl(`${apiBase}/api/ext/check?domain=${encodeURIComponent(host)}`, {
      headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
      credentials: 'omit',
      cache: 'no-store',
    });
  } catch (err) {
    const name = (err as Error)?.name;
    return greyResult(host, name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'offline');
  }
  if (res.status === 401) return greyResult(host, 'not_linked');
  if (res.status === 403) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    return greyResult(host, body.error === 'premium_required' ? 'premium_required' : 'server_error');
  }
  if (!res.ok) return greyResult(host, 'server_error');
  let body: { result?: ServerResult };
  try {
    body = await res.json();
  } catch {
    return greyResult(host, 'server_error');
  }
  const r = body.result;
  if (!r || !['green', 'red', 'amber', 'grey'].includes(r.status)) return greyResult(host, 'server_error');
  return {
    host,
    status: r.status,
    summary: String(r.summary ?? ''),
    reasons: Array.isArray(r.reasons) ? r.reasons.map(String).slice(0, 10) : [],
    nextSteps: Array.isArray(r.nextSteps) ? r.nextSteps.map(String).slice(0, 10) : [],
    checkedAt: new Date().toISOString(),
    source: 'server',
    ...(r.status === 'grey' ? { greyReason: 'unavailable' as const } : {}),
  };
}

export type Settings = { protection: boolean; blockMalicious: boolean; eventSync: boolean };
export const DEFAULT_SETTINGS: Settings = { protection: true, blockMalicious: true, eventSync: false };

/** Validates messages arriving from extension pages; anything else is ignored. */
export type Message =
  | { type: 'get-tab-result'; tabId: number }
  | { type: 'proceed'; host: string; tabId: number; url: string }
  | { type: 'go-back'; host: string; tabId: number }
  | { type: 'settings-changed' }
  | { type: 'clear-cache' };

export function parseMessage(m: unknown): Message | null {
  if (!m || typeof m !== 'object') return null;
  const o = m as Record<string, unknown>;
  const int = (v: unknown) => typeof v === 'number' && Number.isInteger(v) && v >= 0;
  const hostOk = (v: unknown) => typeof v === 'string' && /^[a-z0-9.-]{1,253}$/.test(v);
  switch (o.type) {
    case 'get-tab-result':
      return int(o.tabId) ? { type: 'get-tab-result', tabId: o.tabId as number } : null;
    case 'proceed':
      return hostOk(o.host) && int(o.tabId) && typeof o.url === 'string' && /^https?:\/\//.test(o.url) ? { type: 'proceed', host: o.host as string, tabId: o.tabId as number, url: o.url } : null;
    case 'go-back':
      return hostOk(o.host) && int(o.tabId) ? { type: 'go-back', host: o.host as string, tabId: o.tabId as number } : null;
    case 'settings-changed':
    case 'clear-cache':
      return { type: o.type };
    default:
      return null;
  }
}

/// <reference types="chrome" />
import { BADGE, checkHost, DEFAULT_SETTINGS, greyResult, hostToCheck, isFresh, parseMessage, type CheckResult, type Settings } from './lib';

declare const __API_BASE__: string;
const API_BASE = __API_BASE__;
const API_HOST = new URL(API_BASE).hostname;
const MAX_CACHE = 500;

type Account = { email: string; plan: string };

async function local<T>(key: string, fallback: T): Promise<T> {
  const v = await chrome.storage.local.get(key);
  return (v[key] as T) ?? fallback;
}

async function getSettings(): Promise<Settings> {
  return { ...DEFAULT_SETTINGS, ...(await local<Partial<Settings>>('settings', {})) };
}

async function setTabResult(tabId: number, r: CheckResult) {
  await chrome.storage.session.set({ [`tab:${tabId}`]: r });
  await paintBadge(tabId, r);
}

async function paintBadge(tabId: number, r: CheckResult | null) {
  try {
    if (!r) {
      await chrome.action.setBadgeText({ tabId, text: '' });
      return;
    }
    const b = BADGE[r.status];
    await chrome.action.setBadgeText({ tabId, text: b.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
    await chrome.action.setTitle({ tabId, title: `FootprintX: ${r.summary || b.title} (${r.host})` });
  } catch {
    // Tab closed while checking.
  }
}

async function readCache(host: string): Promise<CheckResult | null> {
  const cache = await local<Record<string, CheckResult>>('cache', {});
  const hit = cache[host];
  return hit && isFresh(hit) ? { ...hit, source: 'cache' } : null;
}

async function writeCache(r: CheckResult) {
  // Only real server answers are cached; "not linked"/"premium required" are not.
  if (r.source !== 'server') return;
  const cache = await local<Record<string, CheckResult>>('cache', {});
  cache[r.host] = r;
  const entries = Object.entries(cache).filter(([, v]) => isFresh(v));
  entries.sort((a, b) => b[1].checkedAt.localeCompare(a[1].checkedAt));
  await chrome.storage.local.set({ cache: Object.fromEntries(entries.slice(0, MAX_CACHE)) });
}

/** Opt-in only: sends warning events (never clean navigations) to the user's FootprintX account. */
async function syncEvent(r: CheckResult, action: 'warned' | 'blocked' | 'proceeded' | 'went_back') {
  if (r.status !== 'red' && r.status !== 'amber') return;
  const [settings, token, account] = await Promise.all([getSettings(), local<string | null>('token', null), local<Account | null>('account', null)]);
  if (!settings.eventSync || !token || account?.plan !== 'premium') return;
  try {
    await fetch(`${API_BASE}/api/ext/events`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      credentials: 'omit',
      body: JSON.stringify({
        events: [{ clientEventId: crypto.randomUUID(), domain: r.host, status: r.status, reasons: r.reasons.slice(0, 10), action, occurredAt: new Date().toISOString() }],
      }),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    // Best effort; the warning itself never depends on sync.
  }
}

const inflight = new Map<number, string>();

async function handleNavigation(tabId: number, url: string) {
  if (url.startsWith(chrome.runtime.getURL(''))) return;
  const target = hostToCheck(url, API_HOST);
  if ('skip' in target) {
    if (target.skip === 'local_address') await setTabResult(tabId, greyResult(new URL(url).hostname, 'local_address'));
    else {
      await chrome.storage.session.remove(`tab:${tabId}`);
      await paintBadge(tabId, null);
    }
    return;
  }
  const { host } = target;
  const settings = await getSettings();
  if (!settings.protection) return setTabResult(tabId, greyResult(host, 'disabled'));
  const token = await local<string | null>('token', null);
  if (!token) return setTabResult(tabId, greyResult(host, 'not_linked'));

  inflight.set(tabId, host);
  let result = await readCache(host);
  if (!result) {
    await paintBadge(tabId, { ...greyResult(host, 'not_checked'), summary: 'Checking…' });
    result = await checkHost({ apiBase: API_BASE, token, host, online: navigator.onLine });
    await writeCache(result);
    if (result.greyReason === 'not_linked') await chrome.storage.local.remove(['token', 'account']);
  }
  // Ignore stale answers if the tab has already moved on to another site.
  if (inflight.get(tabId) !== host) return;
  inflight.delete(tabId);
  await setTabResult(tabId, result);

  if (result.status === 'red') {
    const allowed = (await chrome.storage.session.get(`allow:${host}`))[`allow:${host}`];
    if (settings.blockMalicious && !allowed) {
      const warning = chrome.runtime.getURL(`warning.html?host=${encodeURIComponent(host)}&url=${encodeURIComponent(url)}`);
      await chrome.tabs.update(tabId, { url: warning });
      await syncEvent(result, 'blocked');
    } else if (!allowed) {
      await syncEvent(result, 'warned');
    }
  } else if (result.status === 'amber') {
    await syncEvent(result, 'warned');
  }
}

chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId === 0) void handleNavigation(d.tabId, d.url);
});

// Tab-specific badges are reset by Chrome on navigation; repaint once the page commits,
// but only with a result that belongs to the committed page (or its warning page).
chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0) return;
  const r = (await chrome.storage.session.get(`tab:${d.tabId}`))[`tab:${d.tabId}`] as CheckResult | undefined;
  if (!r) return;
  let host = '';
  try {
    const u = new URL(d.url);
    host = d.url.startsWith(chrome.runtime.getURL('warning.html')) ? (u.searchParams.get('host') ?? '') : u.hostname.toLowerCase();
  } catch {
    return;
  }
  if (host === r.host) await paintBadge(d.tabId, r);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove(`tab:${tabId}`);
});

chrome.runtime.onMessage.addListener((raw, sender, sendResponse) => {
  // Accept messages only from this extension's own pages.
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL(''))) return false;
  const msg = parseMessage(raw);
  if (!msg) return false;
  (async () => {
    switch (msg.type) {
      case 'proceed': {
        await chrome.storage.session.set({ [`allow:${msg.host}`]: true });
        const r = (await chrome.storage.session.get(`tab:${msg.tabId}`))[`tab:${msg.tabId}`] as CheckResult | undefined;
        if (r) await syncEvent(r, 'proceeded');
        await chrome.tabs.update(msg.tabId, { url: msg.url });
        return { ok: true };
      }
      case 'go-back': {
        const r = (await chrome.storage.session.get(`tab:${msg.tabId}`))[`tab:${msg.tabId}`] as CheckResult | undefined;
        if (r) await syncEvent(r, 'went_back');
        return { ok: true };
      }
      case 'clear-cache':
        await chrome.storage.local.set({ cache: {} });
        return { ok: true };
      case 'get-tab-result':
        return (await chrome.storage.session.get(`tab:${msg.tabId}`))[`tab:${msg.tabId}`] ?? null;
      case 'settings-changed':
        return { ok: true };
    }
  })().then(sendResponse, () => sendResponse(null));
  return true;
});

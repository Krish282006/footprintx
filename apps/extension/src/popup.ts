/// <reference types="chrome" />
import { DEFAULT_SETTINGS, type CheckResult, type Settings } from './lib';

declare const __API_BASE__: string;
declare const __WEB_BASE__: string;
const API = __API_BASE__;
const WEB = __WEB_BASE__;

type Account = { email: string; plan: string };
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

function setText(id: string, text: string) {
  $(id).textContent = text;
}

function show(id: string, visible: boolean) {
  $(id).hidden = !visible;
}

function message(text: string, kind: 'error' | 'info' | 'success' = 'info') {
  const el = $('message');
  el.textContent = text;
  el.className = `notice ${kind}`;
  el.hidden = !text;
}

async function api<T>(path: string, init: RequestInit = {}): Promise<{ status: number; body: T | null }> {
  const { token } = await chrome.storage.local.get('token');
  try {
    const res = await fetch(`${API}${path}`, {
      ...init,
      credentials: 'omit',
      headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...(init.headers ?? {}) },
      signal: AbortSignal.timeout(6000),
    });
    return { status: res.status, body: (await res.json().catch(() => null)) as T | null };
  } catch {
    return { status: 0, body: null };
  }
}

async function activeTabId(): Promise<number | null> {
  const fromQuery = new URLSearchParams(location.search).get('tabId'); // used by automated tests
  if (fromQuery) return Number(fromQuery);
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id ?? null;
}

function renderResult(r: CheckResult | null) {
  const box = $('site');
  if (!r) {
    box.className = 'site grey';
    setText('site-status', 'Not checked');
    setText('site-host', 'This page is not a website FootprintX checks.');
    $('site-reasons').replaceChildren();
    $('site-steps').replaceChildren();
    setText('site-meta', '');
    return;
  }
  box.className = `site ${r.status}`;
  box.dataset.status = r.status;
  const label = { green: 'No known threat', red: 'Known malicious', amber: 'Suspicious', grey: r.summary || 'Not checked' }[r.status];
  setText('site-status', label);
  setText('site-host', r.host);
  $('site-reasons').replaceChildren(...r.reasons.map((x) => Object.assign(document.createElement('li'), { textContent: x })));
  $('site-steps').replaceChildren(...r.nextSteps.map((x) => Object.assign(document.createElement('li'), { textContent: x })));
  setText('site-meta', `Checked ${new Date(r.checkedAt).toLocaleTimeString()}${r.source === 'cache' ? ' (cached)' : ''}. No known threat is not a guarantee of safety.`);
}

async function render() {
  const { token, account, settings } = await chrome.storage.local.get(['token', 'account', 'settings']);
  const s: Settings = { ...DEFAULT_SETTINGS, ...(settings ?? {}) };
  show('linked', Boolean(token));
  show('unlinked', !token);
  if (!token) return;
  const acct = account as Account | undefined;
  setText('account-email', acct?.email ?? '');
  setText('account-plan', acct?.plan === 'premium' ? 'Premium' : 'Free');
  show('premium-note', acct?.plan !== 'premium');
  ($('opt-protection') as HTMLInputElement).checked = s.protection;
  ($('opt-block') as HTMLInputElement).checked = s.blockMalicious;
  const sync = $('opt-sync') as HTMLInputElement;
  sync.checked = s.eventSync;
  sync.disabled = acct?.plan !== 'premium';
  const tabId = await activeTabId();
  const r = tabId === null ? null : ((await chrome.storage.session.get(`tab:${tabId}`))[`tab:${tabId}`] as CheckResult | undefined) ?? null;
  renderResult(r);
}

async function refreshStatus() {
  const res = await api<{ email: string; plan: string; eventSync: boolean }>('/api/ext/status');
  if (res.status === 401) {
    await chrome.storage.local.remove(['token', 'account']);
    message('This browser was unlinked from FootprintX. Link it again to continue.', 'error');
  } else if (res.status === 200 && res.body) {
    const { settings } = await chrome.storage.local.get('settings');
    await chrome.storage.local.set({ account: { email: res.body.email, plan: res.body.plan }, settings: { ...DEFAULT_SETTINGS, ...(settings ?? {}), eventSync: res.body.eventSync } });
  } else if (res.status === 0) {
    message('FootprintX is unreachable. Showing saved information.', 'info');
  }
  await render();
}

$('link-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = ($('link-code') as HTMLInputElement).value.trim();
  const btn = $('link-btn') as HTMLButtonElement;
  btn.disabled = true;
  message('Linking…');
  const res = await api<{ token: string; email: string; plan: string; message?: string }>('/api/ext/link', {
    method: 'POST',
    body: JSON.stringify({ code, label: navigator.userAgent.includes('Edg/') ? 'Microsoft Edge' : 'Chrome' }),
  });
  btn.disabled = false;
  if (res.status === 201 && res.body?.token) {
    await chrome.storage.local.set({ token: res.body.token, account: { email: res.body.email, plan: res.body.plan }, cache: {} });
    message('Linked to your FootprintX account.', 'success');
    await refreshStatus();
  } else {
    message(res.status === 0 ? 'Could not reach FootprintX. Check your connection.' : (res.body?.message ?? 'Linking failed.'), 'error');
  }
});

async function saveSetting(key: keyof Settings, value: boolean) {
  const { settings } = await chrome.storage.local.get('settings');
  await chrome.storage.local.set({ settings: { ...DEFAULT_SETTINGS, ...(settings ?? {}), [key]: value } });
}

$('opt-protection').addEventListener('change', (e) => void saveSetting('protection', (e.target as HTMLInputElement).checked));
$('opt-block').addEventListener('change', (e) => void saveSetting('blockMalicious', (e.target as HTMLInputElement).checked));
$('opt-sync').addEventListener('change', async (e) => {
  const input = e.target as HTMLInputElement;
  const wanted = input.checked;
  const res = await api<{ eventSync: boolean; message?: string }>('/api/ext/preferences', { method: 'PUT', body: JSON.stringify({ eventSync: wanted }) });
  if (res.status === 200) {
    await saveSetting('eventSync', wanted);
    message(wanted ? 'Warning events will be synced to your account.' : 'Event sync turned off.', 'success');
  } else {
    input.checked = !wanted;
    message(res.body?.message ?? 'Could not change sync setting.', 'error');
  }
});
$('clear-cache').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'clear-cache' });
  message('Saved results cleared. Sites will be checked again on your next visit.', 'success');
});
$('unlink').addEventListener('click', async () => {
  await api('/api/ext/unlink', { method: 'POST' });
  await chrome.storage.local.remove(['token', 'account']);
  await chrome.storage.local.set({ cache: {} });
  message('Unlinked. Protection is off until you link again.', 'info');
  await render();
});
for (const a of document.querySelectorAll<HTMLAnchorElement>('a[data-web]')) a.href = `${WEB}${a.dataset.web}`;

void render().then(refreshStatus);

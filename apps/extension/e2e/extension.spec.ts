import { chromium, expect, test, type BrowserContext, type Page, type Worker } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtempSync } from 'node:fs';
import os from 'node:os';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const API = 'http://localhost:4200';

let context: BrowserContext;
let sw: Worker;
let extId: string;
let site: http.Server;
let sitePort: number;

/** Minimal API client that keeps the session cookie and CSRF token. */
async function webUser(email: string, premium: boolean) {
  const reg = await fetch(`${API}/api/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-footprintx-client': 'web' },
    body: JSON.stringify({ email, password: 'extension-e2e-password-1', acceptPrivacy: true }),
  });
  expect(reg.status).toBe(201);
  const cookie = reg.headers.get('set-cookie')!.split(';')[0];
  const { csrfToken } = await reg.json();
  const call = (p: string, method = 'GET', body?: unknown) =>
    fetch(`${API}${p}`, { method, headers: { cookie, 'x-csrf-token': csrfToken, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  if (premium) expect((await call('/api/dev/plan', 'POST', { plan: 'premium' })).status).toBe(200);
  const code = (await (await call('/api/extension/link-code', 'POST')).json()).code as string;
  return { call, code };
}

const siteUrl = (host: string) => `http://${host}:${sitePort}/page?secret=should-not-be-sent`;

async function tabResult(host: string) {
  return sw.evaluate(async (h) => {
    const all = await chrome.storage.session.get(null);
    const entry = Object.entries(all).find(([k, v]) => k.startsWith('tab:') && (v as { host: string }).host === h);
    if (!entry) return null;
    const tabId = Number(entry[0].slice(4));
    return { tabId, ...(entry[1] as { status: string; greyReason?: string; reasons: string[] }), badge: await chrome.action.getBadgeText({ tabId }) };
  }, host);
}

async function waitForResult(host: string) {
  let r: Awaited<ReturnType<typeof tabResult>> = null;
  await expect.poll(async () => (r = await tabResult(host))?.status ?? null, { timeout: 15_000 }).not.toBeNull();
  return r!;
}

async function popup(): Promise<Page> {
  const p = await context.newPage();
  await p.goto(`chrome-extension://${extId}/popup.html`);
  return p;
}

test.beforeAll(async () => {
  execFileSync('node', ['build.mjs'], { cwd: root, env: { ...process.env, FOOTPRINTX_API_URL: API, FOOTPRINTX_WEB_URL: 'http://localhost:5175' }, stdio: 'inherit' });
  // A local stand-in for every *.fixture.test site. No real (malicious) site is ever visited.
  site = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<!doctype html><title>Fixture</title><h1>Fixture site ${req.headers.host}</h1>`);
  });
  await new Promise<void>((r) => site.listen(0, '127.0.0.1', r));
  sitePort = (site.address() as AddressInfo).port;
  const dist = path.join(root, 'dist');
  context = await chromium.launchPersistentContext(mkdtempSync(path.join(os.tmpdir(), 'fx-ext-')), {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${dist}`, `--load-extension=${dist}`, '--host-resolver-rules=MAP *.fixture.test 127.0.0.1'],
  });
  sw = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  extId = new URL(sw.url()).host;
});

test.afterAll(async () => {
  await context?.close();
  site?.close();
});

test('manifest requests minimal permissions', async () => {
  const manifest = await sw.evaluate(() => chrome.runtime.getManifest());
  expect(manifest.manifest_version).toBe(3);
  expect(manifest.permissions).toEqual(['storage', 'webNavigation']);
  expect(manifest.host_permissions).toEqual([`${API}/*`]);
});

test('unlinked extension does not check sites', async () => {
  const page = await context.newPage();
  await page.goto(siteUrl('before-link.fixture.test'));
  const r = await waitForResult('before-link.fixture.test');
  expect(r).toMatchObject({ status: 'grey', greyReason: 'not_linked' });
  await page.close();
});

test('Premium: link, block known-malicious, warn suspicious, green for clean, grey on timeout, settings, opt-in sync', async () => {
  const user = await webUser(`ext-premium-${Date.now()}@e2e.example`, true);
  const p = await popup();
  await expect(p.getByText('Link this browser')).toBeVisible();
  await p.getByLabel('Link code').fill('WRONG-CODE1');
  await p.getByRole('button', { name: 'Link' }).click();
  await expect(p.locator('#message')).toContainText('invalid or expired');
  await p.getByLabel('Link code').fill(user.code);
  await p.getByRole('button', { name: 'Link' }).click();
  await expect(p.locator('#account-plan')).toHaveText('Premium');

  // Known-malicious: blocked with a warning page that explains why.
  const tab = await context.newPage();
  await tab.goto(siteUrl('malicious.fixture.test')).catch(() => undefined);
  await expect(tab).toHaveURL(new RegExp(`^chrome-extension://${extId}/warning.html`), { timeout: 15_000 });
  await expect(tab.getByRole('heading', { name: 'Warning: known malicious site' })).toBeVisible();
  await expect(tab.locator('#reasons')).toContainText('development fixture source');
  await expect(tab.locator('#steps')).toContainText('Do not enter passwords');
  await tab.screenshot({ path: test.info().outputPath('warning-page.png') });
  const red = await waitForResult('malicious.fixture.test');
  expect(red.badge).toBe('!');
  await tab.getByRole('button', { name: 'Continue anyway (not recommended)' }).click();
  await expect(tab.getByRole('heading', { name: /Fixture site malicious\.fixture\.test/ })).toBeVisible();

  // Clean site: green, badge ✓, popup explains limits.
  await tab.goto(siteUrl('safe.fixture.test'));
  const green = await waitForResult('safe.fixture.test');
  expect(green).toMatchObject({ status: 'green', badge: '✓' });
  const p2 = await context.newPage();
  await p2.goto(`chrome-extension://${extId}/popup.html?tabId=${green.tabId}`);
  await expect(p2.locator('#site-status')).toHaveText('No known threat');
  await expect(p2.locator('#site-meta')).toContainText('not a guarantee');
  await p2.setViewportSize({ width: 360, height: 640 });
  await p2.screenshot({ path: test.info().outputPath('popup-green.png') });

  // Suspicious: amber; look-alike heuristic: amber.
  await tab.goto(siteUrl('suspicious.fixture.test'));
  expect(await waitForResult('suspicious.fixture.test')).toMatchObject({ status: 'amber', badge: '?' });

  // Provider timeout on the server: grey (never green).
  await tab.goto(siteUrl('timeout.fixture.test'));
  expect(await waitForResult('timeout.fixture.test')).toMatchObject({ status: 'grey', greyReason: 'unavailable' });
  await tab.goto(siteUrl('error.fixture.test'));
  expect(await waitForResult('error.fixture.test')).toMatchObject({ status: 'grey' });

  // Cache: a repeat visit is served from the extension cache.
  await tab.goto(siteUrl('safe.fixture.test'));
  await expect.poll(async () => (await sw.evaluate(async () => {
    const all = await chrome.storage.session.get(null);
    return Object.values(all).find((v) => (v as { host: string }).host === 'safe.fixture.test') as { source: string } | undefined;
  }))?.source).toBe('cache');

  // Settings persist; protection off means no check.
  await p2.reload();
  await p2.getByLabel('Check sites automatically').uncheck();
  await p2.reload();
  await expect(p2.getByLabel('Check sites automatically')).not.toBeChecked();
  await tab.goto(siteUrl('while-off.fixture.test'));
  expect(await waitForResult('while-off.fixture.test')).toMatchObject({ status: 'grey', greyReason: 'disabled' });
  await p2.getByLabel('Check sites automatically').check();

  // Opt-in security-event sync: nothing is synced until enabled; then only the warning.
  expect((await (await user.call('/api/security-events')).json()).events).toHaveLength(0);
  await p2.getByLabel(/Sync warning events/).check();
  await expect(p2.locator('#message')).toContainText('will be synced');
  await tab.goto(siteUrl('a.malicious.fixture.test')).catch(() => undefined);
  await expect(tab).toHaveURL(/warning\.html/, { timeout: 15_000 });
  await tab.goto(siteUrl('safe-again.fixture.test'));
  await waitForResult('safe-again.fixture.test');
  await expect.poll(async () => (await (await user.call('/api/security-events')).json()).events.map((e: { domain: string }) => e.domain), { timeout: 10_000 }).toEqual(['a.malicious.fixture.test']);

  // Unlink: protection stops.
  await p2.getByRole('button', { name: 'Unlink' }).click();
  await expect(p2.getByText('Link this browser')).toBeVisible();
  for (const pg of [p, p2, tab]) await pg.close();
});

test('Free user: linked but protection is refused server-side (Premium required)', async () => {
  const user = await webUser(`ext-free-${Date.now()}@e2e.example`, false);
  const p = await popup();
  await p.getByLabel('Link code').fill(user.code);
  await p.getByRole('button', { name: 'Link' }).click();
  await expect(p.locator('#account-plan')).toHaveText('Free');
  await expect(p.locator('#premium-note')).toBeVisible();
  // Even if local storage is tampered with to claim Premium, the server refuses.
  await sw.evaluate(() => chrome.storage.local.set({ account: { email: 'x', plan: 'premium' } }));
  const tab = await context.newPage();
  await tab.goto(siteUrl('malicious.fixture.test'));
  const r = await waitForResult('malicious.fixture.test');
  expect(r).toMatchObject({ status: 'grey', greyReason: 'premium_required' });
  await expect(tab.getByRole('heading', { name: /Fixture site/ })).toBeVisible(); // not blocked: no entitlement
});

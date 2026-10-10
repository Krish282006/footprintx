import { describe, expect, it } from 'vitest';
import { checkHost, CACHE_TTL_MS, greyResult, hostToCheck, isFresh, parseMessage } from '../src/lib';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const base = { apiBase: 'https://api.example', token: 't'.repeat(40), host: 'site.example' };

describe('hostToCheck (privacy: hostname only)', () => {
  it('extracts only the hostname from web URLs', () => {
    expect(hostToCheck('https://Login.Example.com:8443/path?session=secret#frag', 'api.example')).toEqual({ host: 'login.example.com' });
  });
  it('skips non-web, local/private and the FootprintX API itself', () => {
    expect(hostToCheck('chrome://settings', 'api.example')).toEqual({ skip: 'not_web' });
    expect(hostToCheck('file:///etc/passwd', 'api.example')).toEqual({ skip: 'not_web' });
    expect(hostToCheck('http://localhost:5173/', 'api.example')).toEqual({ skip: 'local_address' });
    expect(hostToCheck('http://192.168.0.1/', 'api.example')).toEqual({ skip: 'local_address' });
    expect(hostToCheck('http://intranet/', 'api.example')).toEqual({ skip: 'local_address' });
    expect(hostToCheck('http://printer.local/', 'api.example')).toEqual({ skip: 'local_address' });
    expect(hostToCheck('https://api.example/api/x', 'api.example')).toEqual({ skip: 'own_service' });
  });
});

describe('checkHost status mapping', () => {
  it('maps server results and sends only the hostname with a bearer token', async () => {
    const calls: string[] = [];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      calls.push(url);
      expect((init.headers as Record<string, string>).authorization).toMatch(/^Bearer /);
      expect(init.credentials).toBe('omit');
      return json({ result: { status: 'red', summary: 'Known malicious site', reasons: ['Listed'], nextSteps: ['Leave'] } });
    }) as typeof fetch;
    const r = await checkHost({ ...base, fetchImpl });
    expect(r).toMatchObject({ status: 'red', reasons: ['Listed'], source: 'server' });
    expect(calls).toEqual(['https://api.example/api/ext/check?domain=site.example']);
  });
  it('green only when the server says green', async () => {
    expect((await checkHost({ ...base, fetchImpl: (async () => json({ result: { status: 'green', summary: '', reasons: [], nextSteps: [] } })) as typeof fetch })).status).toBe('green');
  });
  it('offline → grey', async () => {
    expect(await checkHost({ ...base, online: false })).toMatchObject({ status: 'grey', greyReason: 'offline' });
    const fail = (async () => { throw new TypeError('Failed to fetch'); }) as typeof fetch;
    expect(await checkHost({ ...base, fetchImpl: fail })).toMatchObject({ status: 'grey', greyReason: 'offline' });
  });
  it('timeout → grey', async () => {
    const slow = ((_u: string, init: RequestInit) => new Promise((_, reject) => init.signal!.addEventListener('abort', () => reject(Object.assign(new Error('t'), { name: 'TimeoutError' }))))) as typeof fetch;
    expect(await checkHost({ ...base, fetchImpl: slow, timeoutMs: 50 })).toMatchObject({ status: 'grey', greyReason: 'timeout' });
  });
  it('server error, bad JSON and unknown status → grey', async () => {
    expect(await checkHost({ ...base, fetchImpl: (async () => new Response('x', { status: 500 })) as typeof fetch })).toMatchObject({ status: 'grey', greyReason: 'server_error' });
    expect(await checkHost({ ...base, fetchImpl: (async () => new Response('not json')) as typeof fetch })).toMatchObject({ status: 'grey' });
    expect(await checkHost({ ...base, fetchImpl: (async () => json({ result: { status: 'purple' } })) as typeof fetch })).toMatchObject({ status: 'grey' });
  });
  it('entitlement and linking failures → grey with a clear reason', async () => {
    expect(await checkHost({ ...base, fetchImpl: (async () => json({ error: 'premium_required' }, 403)) as typeof fetch })).toMatchObject({ status: 'grey', greyReason: 'premium_required', summary: 'Premium required' });
    expect(await checkHost({ ...base, fetchImpl: (async () => json({}, 401)) as typeof fetch })).toMatchObject({ greyReason: 'not_linked' });
    expect(await checkHost({ ...base, token: null })).toMatchObject({ greyReason: 'not_linked' });
  });
  it('server grey (sources unavailable) stays grey', async () => {
    const r = await checkHost({ ...base, fetchImpl: (async () => json({ result: { status: 'grey', summary: 'Check unavailable', reasons: [], nextSteps: [] } })) as typeof fetch });
    expect(r).toMatchObject({ status: 'grey', greyReason: 'unavailable' });
  });
});

describe('cache expiry', () => {
  it('expires per status', () => {
    const now = Date.now();
    const at = (ms: number) => new Date(now - ms).toISOString();
    expect(isFresh({ ...greyResult('a.example', 'offline'), status: 'green', checkedAt: at(CACHE_TTL_MS.green - 1000) }, now)).toBe(true);
    expect(isFresh({ ...greyResult('a.example', 'offline'), status: 'green', checkedAt: at(CACHE_TTL_MS.green + 1000) }, now)).toBe(false);
    expect(isFresh({ ...greyResult('a.example', 'offline'), checkedAt: at(61_000) }, now)).toBe(false);
  });
});

describe('message validation', () => {
  it('accepts only well-formed messages', () => {
    expect(parseMessage({ type: 'proceed', host: 'bad.example', tabId: 3, url: 'https://bad.example/x' })).toBeTruthy();
    expect(parseMessage({ type: 'proceed', host: 'bad.example', tabId: 3, url: 'javascript:alert(1)' })).toBeNull();
    expect(parseMessage({ type: 'proceed', host: '<script>', tabId: 3, url: 'https://x' })).toBeNull();
    expect(parseMessage({ type: 'get-tab-result', tabId: -1 })).toBeNull();
    expect(parseMessage({ type: 'set-plan', plan: 'premium' })).toBeNull();
    expect(parseMessage('clear-cache')).toBeNull();
  });
});

import { beforeEach, describe, expect, it } from 'vitest';
import { normalizeDomain } from '../src/lib/domain.js';
import { aggregate, ReputationService } from '../src/threat/service.js';
import { fixtureProvider, feedProvider, urlhausProvider, safeBrowsingProvider } from '../src/threat/providers.js';
import { heuristicsProvider } from '../src/threat/heuristics.js';
import { parseFeed, syncFeed } from '../src/threat/sync.js';
import type { ProviderResult, ThreatProvider } from '../src/threat/types.js';
import { makeApp, pool, resetDb, signedIn } from './helpers.js';
import { json, stubFetch } from './stub-fetch.js';

beforeEach(resetDb);

const pr = (over: Partial<ProviderResult>): ProviderResult => ({ provider: 'p', kind: 'threat_intel', outcome: 'no_match', reasons: [], confidence: 'medium', checkedAt: '', ...over });

describe('domain normalisation', () => {
  it('normalises URLs, case, trailing dots and keeps only the host', () => {
    const r = normalizeDomain('HTTPS://Login.Example.co.uk./path?q=secret#x');
    expect(r.ok && r.value).toMatchObject({ host: 'login.example.co.uk', registrableDomain: 'example.co.uk', candidates: ['login.example.co.uk', 'example.co.uk'] });
  });
  it('converts internationalised domains to punycode and back for display', () => {
    const r = normalizeDomain('аpple.com'); // Cyrillic "а"
    expect(r.ok && r.value.host).toBe('xn--pple-43d.com');
    expect(r.ok && r.value.isIdn).toBe(true);
    expect(r.ok && r.value.unicodeHost).toBe('аpple.com');
  });
  it('rejects invalid, local, private and non-web inputs', () => {
    expect(normalizeDomain('').ok).toBe(false);
    expect(normalizeDomain('localhost')).toEqual({ ok: false, reason: 'local_or_private' });
    expect(normalizeDomain('192.168.1.1')).toEqual({ ok: false, reason: 'local_or_private' });
    expect(normalizeDomain('http://[::1]/')).toEqual({ ok: false, reason: 'local_or_private' });
    expect(normalizeDomain('printer.local')).toEqual({ ok: false, reason: 'local_or_private' });
    expect(normalizeDomain('ftp://example.com')).toEqual({ ok: false, reason: 'unsupported_scheme' });
    expect(normalizeDomain('javascript:alert(1)').ok).toBe(false);
    expect(normalizeDomain('nodot').ok).toBe(false);
    expect(normalizeDomain('exa mple.com').ok).toBe(false);
  });
});

describe('aggregation rules', () => {
  it('green only when every threat source succeeded without a match', () => {
    expect(aggregate([pr({}), pr({ provider: 'q' })]).status).toBe('green');
  });
  it('red for a credible known-malicious match, even if another source failed', () => {
    expect(aggregate([pr({ outcome: 'malicious', reasons: ['listed'], confidence: 'high' }), pr({ outcome: 'error' })]).status).toBe('red');
  });
  it('amber for suspicious or heuristic signals', () => {
    expect(aggregate([pr({}), pr({ kind: 'heuristic', outcome: 'suspicious', reasons: ['lookalike'] })]).status).toBe('amber');
  });
  it('a failed lookup can never be green', () => {
    expect(aggregate([pr({ outcome: 'error' })]).status).toBe('grey');
    expect(aggregate([pr({}), pr({ outcome: 'error' })])).toMatchObject({ status: 'grey', summary: 'Check incomplete' });
    expect(aggregate([pr({ kind: 'heuristic' })]).status).toBe('grey'); // heuristics alone are not threat intel
    expect(aggregate([]).status).toBe('grey');
  });
});

describe('reputation service with controlled fixtures', () => {
  const svc = (providers: ThreatProvider[], timeout = 200) => new ReputationService(pool(), providers, timeout);

  it('safe result: green with limitations, cached', async () => {
    const s = svc([fixtureProvider, heuristicsProvider]);
    const r = await s.check('https://safe.fixture.test/login');
    expect('status' in r && r.status).toBe('green');
    expect('limitations' in r && r.limitations).toMatch(/does not guarantee/);
    const again = await s.check('safe.fixture.test');
    expect('fromCache' in again && again.fromCache).toBe(true);
  });

  it('known threat: red with reasons and next steps', async () => {
    const r = await svc([fixtureProvider]).check('malicious.fixture.test');
    expect(r).toMatchObject({ status: 'red', summary: 'Known malicious site', confidence: 'high' });
    expect('nextSteps' in r && r.nextSteps[0]).toMatch(/Do not enter passwords/);
  });

  it('suspicious result: amber', async () => {
    expect(await svc([fixtureProvider]).check('suspicious.fixture.test')).toMatchObject({ status: 'amber' });
  });

  it('timeout: grey, and not cached', async () => {
    const started = Date.now();
    const r = await svc([fixtureProvider], 150).check('timeout.fixture.test');
    expect(Date.now() - started).toBeLessThan(2000);
    expect(r).toMatchObject({ status: 'grey' });
    expect('providers' in r && r.providers[0].error).toBe('timeout');
    expect((await pool().query('SELECT count(*)::int AS n FROM domain_reputation_cache')).rows[0].n).toBe(0);
  });

  it('provider failure: grey', async () => {
    const r = await svc([fixtureProvider]).check('error.fixture.test');
    expect(r).toMatchObject({ status: 'grey', summary: 'Check unavailable' });
  });

  it('offline (network error) for remote providers: grey, never green', async () => {
    const offline = stubFetch([]); // every request throws "fetch failed"
    const r = await svc([urlhausProvider('key', offline.impl), safeBrowsingProvider('key', offline.impl)]).check('example.com');
    expect(r).toMatchObject({ status: 'grey' });
  });

  it('URLhaus and Safe Browsing adapters map provider responses correctly', async () => {
    const f = stubFetch([
      [/urlhaus/, (_u, init) => (String(init.body).includes('bad.example') ? json({ query_status: 'ok', urls: [{ url_status: 'online' }] }) : json({ query_status: 'no_results' }))],
      [/safebrowsing/, (_u, init) => (String(init.body).includes('bad.example') ? json({ matches: [{ threatType: 'SOCIAL_ENGINEERING' }] }) : json({}))],
    ]);
    const s = svc([urlhausProvider('k', f.impl, 'https://urlhaus.test/v1/host/'), safeBrowsingProvider('k', f.impl, 'https://safebrowsing.test/find')]);
    expect(await s.check('bad.example')).toMatchObject({ status: 'red' });
    expect(await s.check('good.example')).toMatchObject({ status: 'green' });
    expect(f.calls.find((c) => c.url.includes('urlhaus'))!.headers['auth-key']).toBe('k');
  });

  it('look-alike heuristics flag brand impersonation as amber, not red', async () => {
    const s = svc([fixtureProvider, heuristicsProvider]);
    expect(await s.check('paypa1.com')).toMatchObject({ status: 'amber' });
    expect(await s.check('github.com.account-verify.example')).toMatchObject({ status: 'amber' });
    const homograph = await s.check('xn--pple-43d.com'); // "аpple.com" with a Cyrillic "а"
    expect(homograph).toMatchObject({ status: 'amber' });
    expect('reasons' in homograph && homograph.reasons.join(' ')).toMatch(/mixes Latin and Cyrillic/);
    expect(await s.check('github.com')).toMatchObject({ status: 'green' });
  });
});

describe('blocklist feed provider', () => {
  it('parses plain and hosts-file feeds, ignoring comments and junk', () => {
    expect(parseFeed('# c\nbad.example\n0.0.0.0 worse.example\n\nnot a domain\n127.0.0.1 localhost\n1.2.3.4\n')).toEqual(['bad.example', 'worse.example']);
  });

  it('syncs a feed, matches exact and parent domains, and reports unsynced feeds as errors', async () => {
    const provider = feedProvider(pool(), 24);
    const s = new ReputationService(pool(), [provider], 1000);
    expect(await s.check('anything.example')).toMatchObject({ status: 'grey' }); // never synced
    const f = stubFetch([[/feed\.test/, () => new Response('phish.example\nevil-login.example\n')]]);
    const res = await syncFeed(pool(), f.impl, 'https://feed.test/list.txt');
    expect(res).toMatchObject({ ok: true, count: 2 });
    expect(await s.check('phish.example')).toMatchObject({ status: 'red', confidence: 'high' });
    expect(await s.check('login.evil-login.example')).toMatchObject({ status: 'red', confidence: 'medium' });
    expect(await s.check('fine.example')).toMatchObject({ status: 'green' });
    const broken = stubFetch([[/feed\.test/, () => new Response('', { status: 500 })]]);
    expect((await syncFeed(pool(), broken.impl, 'https://feed.test/list.txt')).ok).toBe(false);
    // A failed refresh keeps the last good data.
    expect((await pool().query('SELECT count(*)::int AS n FROM threat_feed_entries')).rows[0].n).toBe(2);
  });
});

describe('manual domain check endpoint (Free)', () => {
  it('requires sign-in, validates input and returns results', async () => {
    const { app } = makeApp();
    const c = await signedIn(app, 'check@example.com');
    expect((await c.post('/api/domain-check', { domain: 'localhost' })).status).toBe(400);
    expect((await c.post('/api/domain-check', { domain: 'malicious.fixture.test' })).body.result.status).toBe('red');
    const anon = await (await import('supertest')).default(app).post('/api/domain-check').set('x-footprintx-client', 'web').send({ domain: 'x.com' });
    expect(anon.status).toBe(401);
  });
});

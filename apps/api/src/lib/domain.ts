import { domainToUnicode } from 'node:url';
import { isIP } from 'node:net';
import { parse } from 'tldts';

export type NormalizedDomain = {
  host: string; // ASCII (punycode) lower-case hostname
  unicodeHost: string; // display form
  registrableDomain: string | null; // e.g. example.co.uk
  isIp: boolean;
  isIdn: boolean;
  candidates: string[]; // host and parent domains down to the registrable domain
};

export type DomainParseResult =
  | { ok: true; value: NormalizedDomain }
  | { ok: false; reason: 'invalid' | 'local_or_private' | 'unsupported_scheme' };

const PRIVATE_SUFFIXES = ['.local', '.localhost', '.internal', '.lan', '.home.arpa', '.intranet', '.corp'];

function isPrivateIp(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  const v6 = ip.toLowerCase();
  return v6 === '::1' || v6 === '::' || v6.startsWith('fc') || v6.startsWith('fd') || v6.startsWith('fe80');
}

/**
 * Normalises user- or extension-supplied input (a hostname or URL) into a canonical
 * ASCII hostname. Only the hostname is retained; paths and queries are discarded.
 * Nothing here performs network access, so this cannot be used for SSRF.
 */
export function normalizeDomain(input: string): DomainParseResult {
  const raw = String(input ?? '').trim();
  if (!raw || raw.length > 2048) return { ok: false, reason: 'invalid' };
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`);
  } catch {
    return { ok: false, reason: 'invalid' };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return { ok: false, reason: 'unsupported_scheme' };
  let host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (!host || host.length > 253) return { ok: false, reason: 'invalid' };

  const ipVersion = isIP(host);
  if (ipVersion) {
    if (isPrivateIp(host)) return { ok: false, reason: 'local_or_private' };
    return {
      ok: true,
      value: { host, unicodeHost: host, registrableDomain: null, isIp: true, isIdn: false, candidates: [host] },
    };
  }
  if (host === 'localhost' || PRIVATE_SUFFIXES.some((s) => host.endsWith(s))) {
    return { ok: false, reason: 'local_or_private' };
  }
  const labels = host.split('.');
  if (labels.length < 2) return { ok: false, reason: 'invalid' };
  if (!labels.every((l) => /^[a-z0-9_]([a-z0-9-_]{0,61}[a-z0-9_])?$/.test(l))) return { ok: false, reason: 'invalid' };

  const parsed = parse(host, { allowPrivateDomains: false });
  const registrable = parsed.domain ?? null;
  const candidates: string[] = [];
  if (registrable) {
    let current = host;
    while (current.length >= registrable.length) {
      candidates.push(current);
      if (current === registrable) break;
      current = current.slice(current.indexOf('.') + 1);
    }
  } else {
    candidates.push(host);
  }
  return {
    ok: true,
    value: {
      host,
      unicodeHost: domainToUnicode(host) || host,
      registrableDomain: registrable,
      isIp: false,
      isIdn: labels.some((l) => l.startsWith('xn--')),
      candidates,
    },
  };
}

/** Registrable domain (eTLD+1) for an email sender domain, or null. */
export function registrableDomainOf(host: string): string | null {
  const parsed = parse(host.toLowerCase(), { allowPrivateDomains: false });
  return parsed.domain ?? null;
}

import type { Config } from '../config.js';
import { fetchJson, ProviderError, type FetchLike } from '../lib/http.js';
import type { MessageMeta } from './classifier.js';
import { fixtureMessages, FIXTURE_MAILBOX_ADDRESS } from './fixtures.js';

export type ProviderId = 'google' | 'microsoft' | 'devfixture';
export type TokenSet = { accessToken: string; refreshToken?: string; expiresAt: Date | null; scopes: string[] };

export type ProviderEndpoints = {
  googleAuth: string;
  googleToken: string;
  googleRevoke: string;
  gmailApi: string;
  microsoftAuthority: string; // e.g. https://login.microsoftonline.com/common
  graphApi: string;
};

export const DEFAULT_ENDPOINTS = (tenant: string): ProviderEndpoints => ({
  googleAuth: 'https://accounts.google.com/o/oauth2/v2/auth',
  googleToken: 'https://oauth2.googleapis.com/token',
  googleRevoke: 'https://oauth2.googleapis.com/revoke',
  gmailApi: 'https://gmail.googleapis.com/gmail/v1',
  microsoftAuthority: `https://login.microsoftonline.com/${encodeURIComponent(tenant)}`,
  graphApi: 'https://graph.microsoft.com/v1.0',
});

export interface MailboxProvider {
  id: ProviderId;
  label: string;
  /** Least-privilege scopes requested. */
  scopes: string[];
  isFixture: boolean;
  isConfigured(): boolean;
  authorizationUrl(p: { state: string; codeChallenge: string; redirectUri: string }): string;
  exchangeCode(p: { code: string; codeVerifier: string; redirectUri: string }): Promise<TokenSet>;
  refresh(refreshToken: string): Promise<TokenSet>;
  profileEmail(accessToken: string): Promise<string>;
  /** Yields pages of message metadata, newest first, until `limit` messages have been yielded. */
  listMessages(accessToken: string, limit: number): AsyncGenerator<MessageMeta[]>;
  revoke(token: string): Promise<'revoked' | 'not_supported' | 'failed'>;
}

type TokenResponse = { access_token: string; refresh_token?: string; expires_in?: number; scope?: string; error?: string };

function toTokenSet(t: TokenResponse, fallbackScopes: string[]): TokenSet {
  if (!t.access_token) throw new ProviderError('invalid_response', 'Token response missing access_token');
  return {
    accessToken: t.access_token,
    refreshToken: t.refresh_token,
    expiresAt: t.expires_in ? new Date(Date.now() + t.expires_in * 1000) : null,
    scopes: t.scope ? t.scope.split(' ') : fallbackScopes,
  };
}

async function postForm(fetchImpl: FetchLike, url: string, body: Record<string, string>): Promise<TokenResponse> {
  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams(body).toString(),
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    throw new ProviderError('provider_unavailable', `Token endpoint unreachable: ${(err as Error).message}`);
  }
  const json = (await res.json().catch(() => ({}))) as TokenResponse;
  if (!res.ok) {
    // invalid_grant = refresh token revoked/expired: the user must reconnect.
    if (json.error === 'invalid_grant' || res.status === 401) throw new ProviderError('reauth_required', 'Authorization expired or was revoked');
    throw new ProviderError('provider_unavailable', `Token endpoint returned HTTP ${res.status}`);
  }
  return json;
}

function headerValue(headers: { name: string; value: string }[] | undefined, name: string): string {
  return headers?.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? '';
}

export function googleProvider(config: Config, endpoints: ProviderEndpoints, fetchImpl: FetchLike): MailboxProvider {
  // gmail.metadata: headers and labels only — no message bodies or attachments.
  const scopes = ['https://www.googleapis.com/auth/gmail.metadata'];
  return {
    id: 'google',
    label: 'Gmail',
    scopes,
    isFixture: false,
    isConfigured: () => Boolean(config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET),
    authorizationUrl({ state, codeChallenge, redirectUri }) {
      const u = new URL(endpoints.googleAuth);
      u.search = new URLSearchParams({
        client_id: config.GOOGLE_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: scopes.join(' '),
        access_type: 'offline',
        prompt: 'consent',
        include_granted_scopes: 'false',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      }).toString();
      return u.toString();
    },
    async exchangeCode({ code, codeVerifier, redirectUri }) {
      return toTokenSet(
        await postForm(fetchImpl, endpoints.googleToken, {
          code, code_verifier: codeVerifier, redirect_uri: redirectUri, grant_type: 'authorization_code',
          client_id: config.GOOGLE_CLIENT_ID, client_secret: config.GOOGLE_CLIENT_SECRET,
        }),
        scopes,
      );
    },
    async refresh(refreshToken) {
      const t = await postForm(fetchImpl, endpoints.googleToken, {
        refresh_token: refreshToken, grant_type: 'refresh_token',
        client_id: config.GOOGLE_CLIENT_ID, client_secret: config.GOOGLE_CLIENT_SECRET,
      });
      return toTokenSet(t, scopes);
    },
    async profileEmail(accessToken) {
      const p = await fetchJson<{ emailAddress?: string }>(fetchImpl, `${endpoints.gmailApi}/users/me/profile`, {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      if (!p.emailAddress) throw new ProviderError('invalid_response', 'Profile has no email address');
      return p.emailAddress.toLowerCase();
    },
    async *listMessages(accessToken, limit) {
      const auth = { authorization: `Bearer ${accessToken}` };
      let pageToken: string | undefined;
      let yielded = 0;
      while (yielded < limit) {
        const u = new URL(`${endpoints.gmailApi}/users/me/messages`);
        u.searchParams.set('maxResults', String(Math.min(100, limit - yielded)));
        if (pageToken) u.searchParams.set('pageToken', pageToken);
        const page = await fetchJson<{ messages?: { id: string }[]; nextPageToken?: string }>(fetchImpl, u.toString(), { headers: auth });
        const ids = (page.messages ?? []).map((m) => m.id);
        const metas: MessageMeta[] = [];
        // Fetch metadata in small parallel batches to respect Gmail quotas.
        for (let i = 0; i < ids.length; i += 10) {
          const batch = await Promise.all(
            ids.slice(i, i + 10).map((id) => {
              const mu = new URL(`${endpoints.gmailApi}/users/me/messages/${encodeURIComponent(id)}`);
              mu.searchParams.set('format', 'metadata');
              for (const h of ['From', 'Subject', 'Date']) mu.searchParams.append('metadataHeaders', h);
              return fetchJson<{ id: string; internalDate?: string; payload?: { headers?: { name: string; value: string }[] } }>(
                fetchImpl, mu.toString(), { headers: auth },
              );
            }),
          );
          for (const m of batch) {
            const date = m.internalDate ? new Date(Number(m.internalDate)).toISOString() : headerValue(m.payload?.headers, 'Date');
            metas.push({ id: m.id, from: headerValue(m.payload?.headers, 'From'), subject: headerValue(m.payload?.headers, 'Subject'), date });
          }
        }
        yielded += metas.length;
        if (metas.length) yield metas;
        pageToken = page.nextPageToken;
        if (!pageToken || !ids.length) break;
      }
    },
    async revoke(token) {
      try {
        const res = await fetchImpl(`${endpoints.googleRevoke}?token=${encodeURIComponent(token)}`, {
          method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, signal: AbortSignal.timeout(10_000),
        });
        return res.ok ? 'revoked' : 'failed';
      } catch {
        return 'failed';
      }
    },
  };
}

export function microsoftProvider(config: Config, endpoints: ProviderEndpoints, fetchImpl: FetchLike): MailboxProvider {
  // Mail.ReadBasic: sender, subject and dates only — no bodies or attachments.
  const scopes = ['offline_access', 'User.Read', 'Mail.ReadBasic'];
  return {
    id: 'microsoft',
    label: 'Outlook / Microsoft 365',
    scopes,
    isFixture: false,
    isConfigured: () => Boolean(config.MICROSOFT_CLIENT_ID && config.MICROSOFT_CLIENT_SECRET),
    authorizationUrl({ state, codeChallenge, redirectUri }) {
      const u = new URL(`${endpoints.microsoftAuthority}/oauth2/v2.0/authorize`);
      u.search = new URLSearchParams({
        client_id: config.MICROSOFT_CLIENT_ID, redirect_uri: redirectUri, response_type: 'code', response_mode: 'query',
        scope: scopes.join(' '), state, code_challenge: codeChallenge, code_challenge_method: 'S256', prompt: 'consent',
      }).toString();
      return u.toString();
    },
    async exchangeCode({ code, codeVerifier, redirectUri }) {
      return toTokenSet(
        await postForm(fetchImpl, `${endpoints.microsoftAuthority}/oauth2/v2.0/token`, {
          code, code_verifier: codeVerifier, redirect_uri: redirectUri, grant_type: 'authorization_code',
          client_id: config.MICROSOFT_CLIENT_ID, client_secret: config.MICROSOFT_CLIENT_SECRET, scope: scopes.join(' '),
        }),
        scopes,
      );
    },
    async refresh(refreshToken) {
      return toTokenSet(
        await postForm(fetchImpl, `${endpoints.microsoftAuthority}/oauth2/v2.0/token`, {
          refresh_token: refreshToken, grant_type: 'refresh_token', scope: scopes.join(' '),
          client_id: config.MICROSOFT_CLIENT_ID, client_secret: config.MICROSOFT_CLIENT_SECRET,
        }),
        scopes,
      );
    },
    async profileEmail(accessToken) {
      const me = await fetchJson<{ mail?: string | null; userPrincipalName?: string }>(
        fetchImpl, `${endpoints.graphApi}/me?$select=mail,userPrincipalName`, { headers: { authorization: `Bearer ${accessToken}` } },
      );
      const email = me.mail || me.userPrincipalName;
      if (!email) throw new ProviderError('invalid_response', 'Profile has no email address');
      return email.toLowerCase();
    },
    async *listMessages(accessToken, limit) {
      let url: string | undefined =
        `${endpoints.graphApi}/me/messages?$select=id,from,subject,receivedDateTime&$orderby=receivedDateTime%20desc&$top=${Math.min(100, limit)}`;
      let yielded = 0;
      while (url && yielded < limit) {
        const page: { value?: { id: string; subject?: string; receivedDateTime?: string; from?: { emailAddress?: { name?: string; address?: string } } }[]; '@odata.nextLink'?: string } =
          await fetchJson(fetchImpl, url, { headers: { authorization: `Bearer ${accessToken}` } });
        const metas = (page.value ?? []).slice(0, limit - yielded).map((m) => ({
          id: m.id,
          from: m.from?.emailAddress?.address ? `${m.from.emailAddress.name ?? ''} <${m.from.emailAddress.address}>` : '',
          subject: m.subject ?? '',
          date: m.receivedDateTime ?? '',
        }));
        yielded += metas.length;
        if (metas.length) yield metas;
        url = page['@odata.nextLink'];
        // Only follow nextLink on the configured Graph host (defence against a tampered response).
        if (url && !url.startsWith(endpoints.graphApi)) throw new ProviderError('invalid_response', 'Unexpected pagination host');
      }
    },
    async revoke() {
      // Microsoft identity platform has no per-token revocation endpoint for this flow.
      // Tokens are deleted locally; the user can remove app consent at https://account.live.com/consent/Manage
      return 'not_supported';
    },
  };
}

/** DEVELOPMENT FIXTURE mailbox. Clearly labelled; only available when ENABLE_DEV_FIXTURES=true. */
export function devFixtureProvider(config: Config): MailboxProvider {
  return {
    id: 'devfixture',
    label: 'Development fixture mailbox (not a real mailbox)',
    scopes: ['fixture:metadata'],
    isFixture: true,
    isConfigured: () => config.ENABLE_DEV_FIXTURES && config.NODE_ENV !== 'production',
    authorizationUrl: () => {
      throw new ProviderError('not_configured', 'Fixture mailbox does not use OAuth');
    },
    exchangeCode: async () => {
      throw new ProviderError('not_configured', 'Fixture mailbox does not use OAuth');
    },
    refresh: async () => ({ accessToken: 'fixture', expiresAt: null, scopes: ['fixture:metadata'] }),
    profileEmail: async () => FIXTURE_MAILBOX_ADDRESS,
    async *listMessages(_token, limit) {
      const all = fixtureMessages(new Date()).slice(0, limit);
      for (let i = 0; i < all.length; i += 5) yield all.slice(i, i + 5);
    },
    revoke: async () => 'revoked',
  };
}

export type FetchLike = typeof fetch;

export class ProviderError extends Error {
  constructor(
    public code: 'reauth_required' | 'rate_limited' | 'provider_unavailable' | 'invalid_response' | 'timeout' | 'not_configured',
    message: string,
    public status?: number,
  ) {
    super(message);
  }
}

/** fetch + JSON with a hard timeout. Never returns a "successful" value on failure. */
export async function fetchJson<T>(
  fetchImpl: FetchLike,
  url: string,
  init: RequestInit & { timeoutMs?: number } = {},
): Promise<T> {
  const { timeoutMs = 10_000, ...rest } = init;
  let res: Response;
  try {
    res = await fetchImpl(url, { ...rest, signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    const name = (err as Error).name;
    if (name === 'TimeoutError' || name === 'AbortError') throw new ProviderError('timeout', `Request timed out after ${timeoutMs}ms`);
    throw new ProviderError('provider_unavailable', `Network error: ${(err as Error).message}`);
  }
  if (res.status === 401 || res.status === 403) {
    throw new ProviderError('reauth_required', `Provider rejected credentials (${res.status})`, res.status);
  }
  if (res.status === 429) throw new ProviderError('rate_limited', 'Provider rate limit reached', 429);
  if (!res.ok) throw new ProviderError('provider_unavailable', `Provider returned HTTP ${res.status}`, res.status);
  try {
    return (await res.json()) as T;
  } catch {
    throw new ProviderError('invalid_response', 'Provider returned invalid JSON');
  }
}

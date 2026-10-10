type Handler = (url: URL, init: RequestInit) => Response | Promise<Response>;

/** A fetch replacement that routes requests to in-test handlers (no real network). */
export function stubFetch(routes: [RegExp, Handler][]) {
  const calls: { url: string; method: string; body?: string; headers: Record<string, string> }[] = [];
  const impl = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    calls.push({ url: url.href, method: init.method ?? 'GET', body: typeof init.body === 'string' ? init.body : undefined, headers: Object.fromEntries(new Headers(init.headers).entries()) });
    for (const [re, h] of routes) if (re.test(url.href)) return h(url, init);
    throw new TypeError(`fetch failed: no stub for ${url.href}`);
  }) as typeof fetch;
  return { impl, calls };
}

export const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

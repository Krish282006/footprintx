/** Small typed client for the FootprintX API. Never stores secrets in localStorage. */
const BASE = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');

let csrfToken: string | null = null;
export const setCsrf = (t: string | null) => {
  csrfToken = t;
};

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public issues: { path: string; message: string }[] = [],
  ) {
    super(message);
  }
}

async function handle(res: Response) {
  if (res.ok) return res.status === 204 ? null : res.json();
  let body: { error?: string; message?: string; issues?: { path: string; message: string }[] } = {};
  try {
    body = await res.json();
  } catch {
    /* non-JSON error */
  }
  throw new ApiError(res.status, body.error ?? 'error', body.message ?? `Request failed (${res.status})`, body.issues ?? []);
}

export async function api<T = unknown>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { accept: 'application/json', 'x-footprintx-client': 'web' };
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET' && csrfToken) headers['x-csrf-token'] = csrfToken;
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      credentials: 'include',
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  } catch {
    throw new ApiError(0, 'network_error', 'Could not reach FootprintX. Check your connection and try again.');
  }
  return handle(res) as Promise<T>;
}

/**
 * Downloads a file from the API. Only reports success when a real workbook arrived;
 * a JSON error or network failure surfaces as an error instead.
 */
export async function download(path: string, fallbackName: string): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, { credentials: 'include' });
  } catch {
    throw new ApiError(0, 'network_error', 'Could not reach FootprintX. Check your connection and try again.');
  }
  if (!res.ok) await handle(res);
  const type = res.headers.get('content-type') ?? '';
  if (!type.includes('spreadsheetml')) throw new ApiError(500, 'bad_file', 'The server did not return a valid Excel file.');
  const blob = await res.blob();
  const name = /filename="([^"]+)"/.exec(res.headers.get('content-disposition') ?? '')?.[1] ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---- Types shared by pages -------------------------------------------------------------
export type User = { id: string; email: string; displayName: string | null; plan: 'free' | 'premium'; planSource: string };
export type Level = 'low' | 'moderate' | 'high' | 'critical' | 'unknown';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DasiComponent = { key: string; label: string; value: number; weight: number; points: number; explanation: string };
export type Dasi = {
  modelVersion: string; score: number | null; level: Level; coverage: 'none' | 'partial' | 'complete'; components: DasiComponent[];
  notes: string[]; criticalFindingCount: number; accountScores: { accountId: string; serviceName: string; score: number }[];
  createdAt?: string; reason?: string;
};
export type Change = { accountId: string | null; serviceName: string; from: number | null; to: number | null; reason: string };
export type Finding = {
  id: string; account_id: string; finding_type: string; severity: Severity; title: string; explanation: string; state: string;
  contribution: number; service_name?: string; is_fixture?: boolean; details?: Record<string, unknown>; first_detected_at?: string;
};
export type RemediationStatus = 'recommended' | 'in_progress' | 'user_reported_complete' | 'verification_pending' | 'verified_complete' | 'unable_to_verify' | 'dismissed';
export type RemediationItem = {
  id: string; account_id: string; action_type: string; title: string; description: string; priority: number; official_url: string | null;
  url_kind: 'curated_official' | 'well_known_standard' | null; status: RemediationStatus; status_note: string | null; service_name: string;
  is_fixture?: boolean; severity?: Severity; verifiable: boolean; user_reported_at?: string | null; verified_at?: string | null;
};
export type Account = {
  id: string; service_name: string; service_domain: string; category: string; ownership: 'discovered' | 'user_confirmed' | 'user_added' | 'false_positive';
  confidence: number; mfa_status: string; is_fixture: boolean; first_seen_at: string | null; last_seen_at: string | null; risk_score: number | null;
  risk_level: Level | null; identities: string[] | null; evidence_count: number; sources: string[] | null; serious_findings: number;
};
export type Reputation = {
  domain: string; displayDomain?: string; status: 'green' | 'red' | 'amber' | 'grey'; summary: string; reasons: string[]; nextSteps: string[];
  confidence: string; checkedAt?: string; fromCache?: boolean; limitations?: string;
  providers: { provider: string; kind: string; outcome: string; error?: string }[];
};

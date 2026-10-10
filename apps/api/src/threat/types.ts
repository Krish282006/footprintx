export type ReputationStatus = 'green' | 'red' | 'amber' | 'grey';

export type ProviderOutcome =
  | 'malicious' // credible known-malicious match
  | 'suspicious' // heuristic or low-confidence signal
  | 'no_match' // lookup succeeded, nothing found
  | 'error' // lookup failed (timeout, offline, provider error)
  | 'not_applicable'; // provider cannot assess this input

export type ProviderResult = {
  provider: string;
  kind: 'threat_intel' | 'heuristic';
  outcome: ProviderOutcome;
  reasons: string[];
  confidence: 'high' | 'medium' | 'low';
  matchedDomain?: string;
  error?: string;
  checkedAt: string;
};

export type ReputationResult = {
  domain: string;
  displayDomain: string;
  status: ReputationStatus;
  summary: string;
  reasons: string[];
  nextSteps: string[];
  confidence: 'high' | 'medium' | 'low' | 'none';
  providers: ProviderResult[];
  checkedAt: string;
  expiresAt: string | null;
  fromCache: boolean;
  limitations: string;
};

export interface ThreatProvider {
  id: string;
  kind: 'threat_intel' | 'heuristic';
  label: string;
  isFixture?: boolean;
  check(domain: { host: string; candidates: string[]; registrableDomain: string | null; isIp: boolean; isIdn: boolean; unicodeHost: string }, signal: AbortSignal): Promise<Omit<ProviderResult, 'checkedAt' | 'provider' | 'kind'>>;
}

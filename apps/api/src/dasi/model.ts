/**
 * Digital Attack Surface Index (DASI) — model dasi-1.0.
 *
 * Pure and deterministic: given the same inputs and `now`, it returns the same output.
 * Scale 0–100, higher = more observed risk. The full rationale for every weight is in
 * docs/DASI.md; keep that document in sync with the constants below.
 */

export const MODEL_VERSION = 'dasi-1.0';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Level = 'low' | 'moderate' | 'high' | 'critical' | 'unknown';
export type Coverage = 'none' | 'partial' | 'complete';
export type MitigationState = 'none' | 'user_reported' | 'verified';

// --- Weights and thresholds -------------------------------------------------

/** Base points for a breach, by the most sensitive data class exposed. */
export const BREACH_BASE = { credentials: 45, authSecrets: 40, financialOrId: 35, contactOrProfile: 15 } as const;
const CREDENTIAL_CLASSES = ['passwords'];
const AUTH_SECRET_CLASSES = ['security questions and answers', 'auth tokens', 'password hints', 'historical passwords'];
const FINANCIAL_ID_CLASSES = [
  'credit cards', 'partial credit card data', 'bank account numbers', 'government issued ids',
  'social security numbers', 'passport numbers', 'credit card cvv',
];

/** How strongly the evidence ties this user's account to the breach. */
export const RELEVANCE = {
  email_confirmed: 1.0, // the user's address appears in the breach (per-email lookup)
  account_predates_breach: 0.9, // evidence of the account dated on/before the breach
  timing_unknown: 0.5, // account exists, but we cannot tell whether it existed at breach time
  created_after_breach: 0.15, // account-creation evidence dated after the breach
} as const;

/** Older breaches matter less, but never zero (old passwords are often still reused). */
export function freshnessFactor(breachDate: string | null, now: Date): number {
  if (!breachDate) return 0.7;
  const years = (now.getTime() - new Date(`${breachDate}T00:00:00Z`).getTime()) / (365.25 * 86400_000);
  if (years <= 1) return 1.0;
  if (years <= 3) return 0.85;
  if (years <= 6) return 0.7;
  return 0.55;
}

/** Account-existence confidence dampens, but never removes, risk (unknown is not safe). */
export const confidenceFactor = (confidence: number) => 0.4 + 0.6 * clamp01(confidence);

/** Mitigation multipliers. User reports are recorded honestly and only partially reduce risk. */
export const MITIGATION = { none: 1, user_reported: 0.5, verified: 0.2 } as const;

export const SECURITY_ALERT = { windowDays: 90, base: 20, suspiciousBase: 25 } as const;
export const POSTURE = { unknown: 8, user_reported_disabled: 12, user_reported_enabled: 2, evidence_enabled: 1 } as const;
export const DORMANT = { afterDays: 730, base: 6 } as const;

export const CATEGORY_IMPACT: Record<string, number> = {
  email_identity: 1.3, financial: 1.25, developer: 1.1, social: 1.0, shopping: 1.0,
  productivity: 1.0, travel: 0.95, entertainment: 0.9, other: 0.9,
};

export const AGGREGATE = { peakWeight: 0.6, breadthWeight: 0.4, breadthDivisor: 200 } as const;
export const UNCERTAINTY = { coverage_none: 10, coverage_partial: 5, breach_data_unavailable: 5 } as const;

export function levelFor(score: number | null): Level {
  if (score === null) return 'unknown';
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'moderate';
  return 'low';
}

export function severityFor(contribution: number): Severity {
  if (contribution >= 30) return 'critical';
  if (contribution >= 18) return 'high';
  if (contribution >= 8) return 'medium';
  if (contribution > 2) return 'low';
  return 'info';
}

// --- Inputs ------------------------------------------------------------------

export type BreachInput = {
  id: string;
  title: string;
  breachDate: string | null; // YYYY-MM-DD
  dataClasses: string[];
  isFixture: boolean;
  emailConfirmed: boolean;
  passwordChange: MitigationState; // state of the change_password remediation for this breach
};

export type AlertEvidence = { observedAt: string; signal: string };

export type AccountInput = {
  id: string;
  serviceName: string;
  serviceDomain: string;
  category: string;
  ownership: 'discovered' | 'user_confirmed' | 'user_added' | 'false_positive';
  confidence: number;
  mfaStatus: 'unknown' | 'user_reported_enabled' | 'user_reported_disabled' | 'evidence_enabled';
  earliestEvidenceAt: string | null;
  earliestCreationEvidenceAt: string | null;
  lastSeenAt: string | null;
  breaches: BreachInput[];
  securityAlerts: AlertEvidence[];
  activityReviewedAt: string | null; // user-reported review of a security alert
};

export type FindingCandidate = {
  key: string; // stable per account, e.g. "breach:Adobe"
  type: 'service_breach' | 'email_breach' | 'security_alert' | 'posture_unknown' | 'dormant_account';
  breachId?: string;
  severity: Severity;
  title: string;
  explanation: string;
  contribution: number;
  state: 'open' | 'mitigated_user_reported' | 'mitigated_verified';
  details: Record<string, unknown>;
};

export type AccountAssessment = {
  accountId: string;
  serviceName: string;
  score: number | null; // null when excluded (false positive)
  level: Level;
  impact: number;
  findings: FindingCandidate[];
};

// --- Account assessment ------------------------------------------------------------

const round2 = (n: number) => Math.round(n * 100) / 100;
function clamp01(n: number) {
  return Math.max(0, Math.min(1, n));
}

export function breachBase(dataClasses: string[]): { base: number; kind: keyof typeof BREACH_BASE } {
  const lc = dataClasses.map((c) => c.toLowerCase());
  if (lc.some((c) => CREDENTIAL_CLASSES.includes(c))) return { base: BREACH_BASE.credentials, kind: 'credentials' };
  if (lc.some((c) => AUTH_SECRET_CLASSES.includes(c))) return { base: BREACH_BASE.authSecrets, kind: 'authSecrets' };
  if (lc.some((c) => FINANCIAL_ID_CLASSES.includes(c))) return { base: BREACH_BASE.financialOrId, kind: 'financialOrId' };
  return { base: BREACH_BASE.contactOrProfile, kind: 'contactOrProfile' };
}

export function breachRelevance(account: AccountInput, breach: BreachInput): keyof typeof RELEVANCE {
  if (breach.emailConfirmed) return 'email_confirmed';
  if (!breach.breachDate) return 'timing_unknown';
  const breachAt = new Date(`${breach.breachDate}T23:59:59Z`).getTime();
  if (account.earliestEvidenceAt && new Date(account.earliestEvidenceAt).getTime() <= breachAt) return 'account_predates_breach';
  if (account.earliestCreationEvidenceAt && new Date(account.earliestCreationEvidenceAt).getTime() > breachAt) {
    return 'created_after_breach';
  }
  return 'timing_unknown';
}

const RELEVANCE_TEXT: Record<keyof typeof RELEVANCE, string> = {
  email_confirmed: 'Your email address appears in this breach.',
  account_predates_breach: 'Evidence shows your account existed before the breach date.',
  timing_unknown: 'We could not determine whether your account existed when the breach happened.',
  created_after_breach: 'Your account appears to have been created after the breach, so it was probably not affected.',
};

export function assessAccount(a: AccountInput, now: Date): AccountAssessment {
  if (a.ownership === 'false_positive') {
    return { accountId: a.id, serviceName: a.serviceName, score: null, level: 'unknown', impact: 0, findings: [] };
  }
  const impact = CATEGORY_IMPACT[a.category] ?? CATEGORY_IMPACT.other;
  const confidence = a.ownership === 'discovered' ? a.confidence : 1;
  const cf = confidenceFactor(confidence);
  const findings: FindingCandidate[] = [];

  // Each breach is counted once per account, regardless of how many evidence items point to it.
  const seen = new Set<string>();
  for (const b of a.breaches) {
    if (seen.has(b.id)) continue;
    seen.add(b.id);
    const { base, kind } = breachBase(b.dataClasses);
    const relevanceKey = breachRelevance(a, b);
    const relevance = RELEVANCE[relevanceKey];
    const freshness = freshnessFactor(b.breachDate, now);
    // A password change only mitigates credential exposure; exposed personal data stays exposed.
    const credentialRelated = kind === 'credentials' || kind === 'authSecrets';
    const mitigationState: MitigationState = credentialRelated ? b.passwordChange : 'none';
    const mitigation = MITIGATION[mitigationState];
    const contribution = round2(base * relevance * freshness * cf * mitigation);
    const exposure = b.emailConfirmed ? 'email_breach' : 'service_breach';
    findings.push({
      key: `breach:${b.id}`,
      type: exposure,
      breachId: b.id,
      severity: severityFor(contribution),
      title: b.emailConfirmed
        ? `Your email address was found in the ${b.title} breach`
        : `${a.serviceName} had a data breach${b.breachDate ? ` (${b.breachDate.slice(0, 4)})` : ''}`,
      explanation: [
        b.emailConfirmed
          ? `A breach lookup found your email address in the ${b.title} breach.`
          : `${b.title} is a service-level breach. This does not prove that your own account was included.`,
        RELEVANCE_TEXT[relevanceKey],
        `Exposed data: ${b.dataClasses.length ? b.dataClasses.join(', ') : 'not published'}.`,
        mitigationState === 'user_reported'
          ? 'You reported changing your password after this breach (user-reported, not independently verified); risk from this breach is reduced by half.'
          : mitigationState === 'verified'
            ? 'A password-change confirmation from this service was found after the breach date; risk from this breach is reduced.'
            : credentialRelated
              ? 'Passwords or similar secrets were exposed. If you reused this password elsewhere, those accounts are at risk too.'
              : 'Changing your password does not undo exposure of this data; watch for phishing that references it.',
      ].join(' '),
      contribution,
      state: mitigationState === 'verified' ? 'mitigated_verified' : mitigationState === 'user_reported' ? 'mitigated_user_reported' : 'open',
      details: {
        breachDate: b.breachDate,
        dataClasses: b.dataClasses,
        dataKind: kind,
        base,
        relevance: relevanceKey,
        relevanceFactor: relevance,
        freshnessFactor: freshness,
        confidenceFactor: round2(cf),
        mitigation: mitigationState,
        mitigationFactor: mitigation,
        isFixture: b.isFixture,
      },
    });
  }

  // Recent security notifications (new sign-in, suspicious activity) — one finding per account.
  const windowStart = now.getTime() - SECURITY_ALERT.windowDays * 86400_000;
  const recent = a.securityAlerts.filter((e) => new Date(e.observedAt).getTime() >= windowStart);
  if (recent.length) {
    const latest = recent.map((e) => e.observedAt).sort().at(-1)!;
    const suspicious = recent.some((e) => e.signal === 'suspicious_activity');
    const reviewedAfterLatest = Boolean(a.activityReviewedAt && a.activityReviewedAt >= latest);
    const mitigation = reviewedAfterLatest ? MITIGATION.user_reported : 1;
    const contribution = round2((suspicious ? SECURITY_ALERT.suspiciousBase : SECURITY_ALERT.base) * cf * mitigation);
    findings.push({
      key: 'security_alert',
      type: 'security_alert',
      severity: severityFor(contribution),
      title: `${recent.length} recent security notification${recent.length > 1 ? 's' : ''} from ${a.serviceName}`,
      explanation:
        `${a.serviceName} sent ${suspicious ? 'a suspicious-activity warning' : 'sign-in or security notifications'} in the last ` +
        `${SECURITY_ALERT.windowDays} days (latest ${latest.slice(0, 10)}). If you do not recognise this activity, secure the account.` +
        (reviewedAfterLatest ? ' You reported reviewing this activity (user-reported).' : ''),
      contribution,
      state: reviewedAfterLatest ? 'mitigated_user_reported' : 'open',
      details: { count: recent.length, latest, suspicious, windowDays: SECURITY_ALERT.windowDays },
    });
  }

  // Two-step verification posture: unknown is never treated as safe.
  const postureBase = POSTURE[a.mfaStatus];
  const postureContribution = round2(postureBase * cf);
  const POSTURE_TEXT = {
    unknown: ['Two-step verification status unknown', 'FootprintX cannot see whether two-step verification is enabled on this account. Unknown is not treated as safe.'],
    user_reported_disabled: ['Two-step verification reported as not enabled', 'You reported that two-step verification is off. Turning it on is one of the most effective protections against account takeover.'],
    user_reported_enabled: ['Two-step verification reported as enabled', 'You reported that two-step verification is on. FootprintX cannot confirm this independently, so a small residual risk remains.'],
    evidence_enabled: ['Two-step verification confirmation found', 'An email from this service confirmed that two-step verification was turned on. It could have been turned off since, so a small residual risk remains.'],
  } as const;
  findings.push({
    key: 'posture',
    type: 'posture_unknown',
    severity: a.mfaStatus === 'user_reported_enabled' || a.mfaStatus === 'evidence_enabled' ? 'info' : severityFor(postureContribution),
    title: POSTURE_TEXT[a.mfaStatus][0],
    explanation: POSTURE_TEXT[a.mfaStatus][1],
    contribution: postureContribution,
    state: a.mfaStatus === 'user_reported_enabled' ? 'mitigated_user_reported' : a.mfaStatus === 'evidence_enabled' ? 'mitigated_verified' : 'open',
    details: { mfaStatus: a.mfaStatus, base: postureBase },
  });

  // Dormant accounts are forgotten attack surface.
  if (a.lastSeenAt && now.getTime() - new Date(a.lastSeenAt).getTime() > DORMANT.afterDays * 86400_000) {
    const contribution = round2(DORMANT.base * cf);
    findings.push({
      key: 'dormant',
      type: 'dormant_account',
      severity: severityFor(contribution),
      title: `No activity seen from ${a.serviceName} in over two years`,
      explanation:
        'Unused accounts are often forgotten and keep old passwords. If you no longer need this account, consider deleting it.',
      contribution,
      state: 'open',
      details: { lastSeenAt: a.lastSeenAt, afterDays: DORMANT.afterDays },
    });
  }

  const raw = findings.reduce((s, f) => s + f.contribution, 0) * impact;
  const score = Math.min(100, Math.round(raw));
  return { accountId: a.id, serviceName: a.serviceName, score, level: levelFor(score), impact, findings };
}

// --- Overall DASI --------------------------------------------------------------

export type DasiComponent = { key: string; label: string; value: number; weight: number; points: number; explanation: string };

export type DasiResult = {
  modelVersion: string;
  score: number | null;
  level: Level;
  coverage: Coverage;
  components: DasiComponent[];
  accountScores: { accountId: string; serviceName: string; score: number }[];
  criticalFindingCount: number;
  notes: string[];
};

export type DasiInput = {
  accounts: { accountId: string; serviceName: string; score: number | null; criticalFindings: number }[];
  coverage: Coverage;
  breachDataAvailable: boolean;
};

export function computeDasi(input: DasiInput): DasiResult {
  const active = input.accounts.filter((a): a is typeof a & { score: number } => a.score !== null);
  const notes: string[] = [];
  if (!active.length && input.coverage !== 'complete') {
    return {
      modelVersion: MODEL_VERSION,
      score: null,
      level: 'unknown',
      coverage: input.coverage,
      components: [],
      accountScores: [],
      criticalFindingCount: 0,
      notes: [
        input.coverage === 'none'
          ? 'Not enough information yet. Connect a mailbox or add accounts to calculate your DASI.'
          : 'Discovery has not completed successfully, so no score can be calculated yet.',
      ],
    };
  }
  const peak = active.reduce((m, a) => Math.max(m, a.score), 0);
  const breadth = 100 * (1 - active.reduce((p, a) => p * (1 - a.score / AGGREGATE.breadthDivisor), 1));
  const components: DasiComponent[] = [
    {
      key: 'peak_account',
      label: 'Highest-risk account',
      value: peak,
      weight: AGGREGATE.peakWeight,
      points: round2(peak * AGGREGATE.peakWeight),
      explanation: 'Your single riskiest account matters most: one compromised account can unlock others.',
    },
    {
      key: 'breadth',
      label: 'Overall exposure across accounts',
      value: round2(breadth),
      weight: AGGREGATE.breadthWeight,
      points: round2(breadth * AGGREGATE.breadthWeight),
      explanation: 'Every additional account with risk increases your attack surface, with diminishing returns.',
    },
  ];
  if (input.coverage !== 'complete') {
    const pts = input.coverage === 'none' ? UNCERTAINTY.coverage_none : UNCERTAINTY.coverage_partial;
    components.push({
      key: 'coverage_uncertainty',
      label: input.coverage === 'none' ? 'No completed mailbox scan' : 'Discovery partially complete',
      value: pts,
      weight: 1,
      points: pts,
      explanation: 'Accounts we have not been able to discover may carry risk; unknown is not treated as safe.',
    });
    notes.push(input.coverage === 'none' ? 'No mailbox has been fully scanned, so some accounts are likely missing.' : 'At least one mailbox scan was partial or failed.');
  }
  if (!input.breachDataAvailable) {
    components.push({
      key: 'breach_data_uncertainty',
      label: 'Breach data unavailable',
      value: UNCERTAINTY.breach_data_unavailable,
      weight: 1,
      points: UNCERTAINTY.breach_data_unavailable,
      explanation: 'The breach catalogue could not be loaded, so breach exposure could not be checked.',
    });
    notes.push('Breach exposure could not be checked because the breach catalogue is unavailable.');
  }
  if (!active.length) notes.push('Discovery completed and found no accounts. This reflects only the evidence available to FootprintX.');
  const score = Math.min(100, Math.round(components.reduce((s, c) => s + c.points, 0)));
  return {
    modelVersion: MODEL_VERSION,
    score,
    level: levelFor(score),
    coverage: input.coverage,
    components,
    accountScores: active.map((a) => ({ accountId: a.accountId, serviceName: a.serviceName, score: a.score })),
    criticalFindingCount: input.accounts.reduce((s, a) => s + a.criticalFindings, 0),
    notes,
  };
}

export type DasiChange = { accountId: string | null; serviceName: string; from: number | null; to: number | null; reason: string };

/** Explains what moved between two results (used for score history). */
export function explainChanges(prev: DasiResult | null, next: DasiResult, reasons: Map<string, string> = new Map()): DasiChange[] {
  const changes: DasiChange[] = [];
  const before = new Map((prev?.accountScores ?? []).map((a) => [a.accountId, a]));
  const after = new Map(next.accountScores.map((a) => [a.accountId, a]));
  for (const [id, a] of after) {
    const b = before.get(id);
    if (!b) changes.push({ accountId: id, serviceName: a.serviceName, from: null, to: a.score, reason: reasons.get(id) ?? 'Account added to your inventory' });
    else if (b.score !== a.score) changes.push({ accountId: id, serviceName: a.serviceName, from: b.score, to: a.score, reason: reasons.get(id) ?? 'Account risk changed' });
  }
  for (const [id, b] of before) {
    if (!after.has(id)) changes.push({ accountId: id, serviceName: b.serviceName, from: b.score, to: null, reason: reasons.get(id) ?? 'Account removed or marked as not yours' });
  }
  if (prev && prev.coverage !== next.coverage) {
    changes.push({ accountId: null, serviceName: 'Discovery coverage', from: null, to: null, reason: `Coverage changed from ${prev.coverage} to ${next.coverage}` });
  }
  return changes;
}

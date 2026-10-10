import { describe, expect, it } from 'vitest';
import { assessAccount, computeDasi, explainChanges, levelFor, type AccountInput, type BreachInput } from '../src/dasi/model.js';

const NOW = new Date('2026-06-01T00:00:00Z');

const breach = (over: Partial<BreachInput> = {}): BreachInput => ({
  id: 'ShopBreach', title: 'Shop', breachDate: '2024-01-15', dataClasses: ['Email addresses', 'Passwords'],
  isFixture: true, emailConfirmed: false, passwordChange: 'none', ...over,
});

const account = (over: Partial<AccountInput> = {}): AccountInput => ({
  id: 'a1', serviceName: 'Shop', serviceDomain: 'shop.example', category: 'shopping', ownership: 'discovered',
  confidence: 0.9, mfaStatus: 'unknown', earliestEvidenceAt: '2020-01-01T00:00:00Z', earliestCreationEvidenceAt: '2020-01-01T00:00:00Z',
  lastSeenAt: '2026-05-01T00:00:00Z', breaches: [], securityAlerts: [], activityReviewedAt: null, ...over,
});

describe('DASI account assessment (dasi-1.0)', () => {
  it('computes a deterministic breach contribution from documented factors', () => {
    const a = assessAccount(account({ breaches: [breach()] }), NOW);
    const f = a.findings.find((x) => x.type === 'service_breach')!;
    // 45 (passwords) × 0.9 (predates) × 0.85 (2.4 years) × (0.4 + 0.6 × 0.9 = 0.94) × 1 = 32.36
    expect(f.contribution).toBe(32.36);
    expect(f.severity).toBe('critical');
    expect(f.details).toMatchObject({ relevance: 'account_predates_breach', freshnessFactor: 0.85, base: 45 });
    // posture unknown: 8 × 0.94 = 7.52 ; total (32.36 + 7.52) × 1.0 impact = 39.88 → 40
    expect(a.score).toBe(40);
    expect(a.level).toBe('moderate');
    // Same inputs, same output.
    expect(assessAccount(account({ breaches: [breach()] }), NOW)).toEqual(a);
  });

  it('labels service-level breaches as not proof of personal compromise', () => {
    const f = assessAccount(account({ breaches: [breach()] }), NOW).findings[0];
    expect(f.explanation).toMatch(/does not prove that your own account was included/);
    const confirmed = assessAccount(account({ breaches: [breach({ emailConfirmed: true })] }), NOW).findings[0];
    expect(confirmed.type).toBe('email_breach');
  });

  it('lowers relevance for accounts created after the breach and for unknown timing', () => {
    const after = assessAccount(account({ earliestEvidenceAt: '2025-01-01T00:00:00Z', earliestCreationEvidenceAt: '2025-01-01T00:00:00Z', breaches: [breach()] }), NOW);
    const unknown = assessAccount(account({ earliestEvidenceAt: '2025-01-01T00:00:00Z', earliestCreationEvidenceAt: null, breaches: [breach()] }), NOW);
    expect(after.findings[0].details.relevance).toBe('created_after_breach');
    expect(unknown.findings[0].details.relevance).toBe('timing_unknown');
    expect(after.findings[0].contribution).toBeLessThan(unknown.findings[0].contribution);
  });

  it('applies a user-reported password change as a documented 50% reduction, never removing the finding', () => {
    const before = assessAccount(account({ breaches: [breach()] }), NOW).findings[0];
    const after = assessAccount(account({ breaches: [breach({ passwordChange: 'user_reported' })] }), NOW).findings[0];
    expect(after.contribution).toBe(Math.round(before.contribution * 0.5 * 100) / 100);
    expect(after.state).toBe('mitigated_user_reported');
    expect(after.explanation).toMatch(/user-reported, not independently verified/);
    const verified = assessAccount(account({ breaches: [breach({ passwordChange: 'verified' })] }), NOW).findings[0];
    expect(verified.contribution).toBeLessThan(after.contribution);
  });

  it('does not let a password change mitigate exposure of non-credential data', () => {
    const b = breach({ dataClasses: ['Email addresses', 'Names'], passwordChange: 'user_reported' });
    const f = assessAccount(account({ breaches: [b] }), NOW).findings[0];
    expect(f.details.mitigation).toBe('none');
    expect(f.state).toBe('open');
  });

  it('counts the same breach once per account (overlap handling)', () => {
    const a = assessAccount(account({ breaches: [breach(), breach()] }), NOW);
    expect(a.findings.filter((f) => f.type === 'service_breach')).toHaveLength(1);
  });

  it('never treats unknown two-step status as safe', () => {
    const unknown = assessAccount(account(), NOW);
    const enabled = assessAccount(account({ mfaStatus: 'user_reported_enabled' }), NOW);
    expect(unknown.score).toBeGreaterThan(enabled.score!);
    expect(enabled.score).toBeGreaterThan(0);
    expect(unknown.findings.find((f) => f.key === 'posture')!.title).toMatch(/unknown/);
  });

  it('only counts security notifications from the last 90 days and honours review after the latest alert', () => {
    const old = assessAccount(account({ securityAlerts: [{ observedAt: '2025-01-01T00:00:00Z', signal: 'new_signin' }] }), NOW);
    expect(old.findings.some((f) => f.type === 'security_alert')).toBe(false);
    const recent = assessAccount(account({ securityAlerts: [{ observedAt: '2026-05-20T00:00:00Z', signal: 'suspicious_activity' }] }), NOW);
    const alert = recent.findings.find((f) => f.type === 'security_alert')!;
    expect(alert.contribution).toBe(23.5); // 25 × 0.94
    const reviewedBefore = assessAccount(account({ activityReviewedAt: '2026-05-01T00:00:00Z', securityAlerts: [{ observedAt: '2026-05-20T00:00:00Z', signal: 'suspicious_activity' }] }), NOW);
    expect(reviewedBefore.findings.find((f) => f.type === 'security_alert')!.state).toBe('open');
  });

  it('flags dormant accounts and excludes false positives', () => {
    const dormant = assessAccount(account({ lastSeenAt: '2023-01-01T00:00:00Z' }), NOW);
    expect(dormant.findings.some((f) => f.type === 'dormant_account')).toBe(true);
    const fp = assessAccount(account({ ownership: 'false_positive', breaches: [breach()] }), NOW);
    expect(fp.score).toBeNull();
    expect(fp.findings).toHaveLength(0);
  });

  it('weights high-impact categories more', () => {
    const shop = assessAccount(account({ breaches: [breach()] }), NOW).score!;
    const email = assessAccount(account({ category: 'email_identity', breaches: [breach()] }), NOW).score!;
    expect(email).toBeGreaterThan(shop);
  });
});

describe('overall DASI', () => {
  it('returns unknown (not zero) when there is no information', () => {
    const r = computeDasi({ accounts: [], coverage: 'none', breachDataAvailable: true });
    expect(r.score).toBeNull();
    expect(r.level).toBe('unknown');
  });

  it('combines peak and breadth deterministically, plus uncertainty for partial coverage', () => {
    const accounts = [
      { accountId: 'a', serviceName: 'A', score: 60, criticalFindings: 1 },
      { accountId: 'b', serviceName: 'B', score: 20, criticalFindings: 0 },
    ];
    const complete = computeDasi({ accounts, coverage: 'complete', breachDataAvailable: true });
    // peak 60×0.6 = 36 ; breadth 100×(1 − 0.7×0.9) = 37 → ×0.4 = 14.8 ; total 50.8 → 51
    expect(complete.score).toBe(51);
    expect(complete.level).toBe('high');
    const partial = computeDasi({ accounts, coverage: 'partial', breachDataAvailable: true });
    expect(partial.score).toBe(56);
    const noBreach = computeDasi({ accounts, coverage: 'complete', breachDataAvailable: false });
    expect(noBreach.score).toBe(56);
    expect(noBreach.notes.join(' ')).toMatch(/breach catalogue is unavailable/);
  });

  it('keeps critical findings visible when the aggregate is moderate', () => {
    const r = computeDasi({ accounts: [{ accountId: 'a', serviceName: 'A', score: 40, criticalFindings: 1 }], coverage: 'complete', breachDataAvailable: true });
    expect(r.score).toBe(32);
    expect(r.level).toBe('moderate');
    expect(r.criticalFindingCount).toBe(1);
  });

  it('explains score changes between snapshots', () => {
    const prev = computeDasi({ accounts: [{ accountId: 'a', serviceName: 'A', score: 40, criticalFindings: 0 }], coverage: 'partial', breachDataAvailable: true });
    const next = computeDasi({ accounts: [{ accountId: 'a', serviceName: 'A', score: 20, criticalFindings: 0 }, { accountId: 'b', serviceName: 'B', score: 10, criticalFindings: 0 }], coverage: 'complete', breachDataAvailable: true });
    const changes = explainChanges(prev, next, new Map([['a', 'Password change reported']]));
    expect(changes).toEqual([
      { accountId: 'a', serviceName: 'A', from: 40, to: 20, reason: 'Password change reported' },
      { accountId: 'b', serviceName: 'B', from: null, to: 10, reason: 'Account added to your inventory' },
      { accountId: null, serviceName: 'Discovery coverage', from: null, to: null, reason: 'Coverage changed from partial to complete' },
    ]);
  });

  it('maps levels at documented thresholds', () => {
    expect([0, 24, 25, 49, 50, 74, 75, 100].map(levelFor)).toEqual(['low', 'low', 'moderate', 'moderate', 'high', 'high', 'critical', 'critical']);
  });
});

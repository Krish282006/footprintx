# Digital Attack Surface Index (DASI) — model `dasi-1.0`

DASI is a 0–100 score where **higher means more observed risk**. It is computed by pure, deterministic code in [`apps/api/src/dasi/model.ts`](../apps/api/src/dasi/model.ts) and is unit-tested against hand-calculated values (`apps/api/test/dasi-model.test.ts`). Every component is shown to the user.

## Principles

1. **Unknown is not safe.** No evidence → score `null` ("unknown"), not 0. Unknown two-step status adds risk. Incomplete discovery or unavailable breach data adds an explicit uncertainty allowance.
2. **Evidence, not assumption.** A breach of a *service* is weighted by how strongly evidence ties *your* account to it; it is never described as proof of compromise.
3. **User reports are honoured but labelled.** They reduce risk partially; only evidence-based verification reduces it further. Historical findings are never deleted.
4. **Critical findings stay visible** in their own list even when the aggregate is moderate.

## Account score

`account_risk = min(100, round( Σ finding_points × category_impact ))`

### Breach finding (one per breach per account — overlap is de-duplicated)

`points = base × relevance × freshness × confidence_factor × mitigation`

| Factor | Values |
|---|---|
| base (most sensitive data class) | Passwords 45 · security Q&A / auth tokens / password hints 40 · financial or government ID 35 · contact/profile data 15 |
| relevance | email found in breach (per-email lookup) 1.0 · account evidence on/before breach date 0.9 · timing unknown 0.5 · account-creation evidence after breach 0.15 |
| freshness (breach age) | ≤1 y 1.0 · ≤3 y 0.85 · ≤6 y 0.7 · older 0.55 · unknown date 0.7 |
| confidence_factor | 0.4 + 0.6 × account-existence confidence (1.0 for confirmed/added accounts) |
| mitigation (credential breaches only) | none 1.0 · user-reported password change 0.5 · verified (password-changed email after breach) 0.2 |

A password change does **not** mitigate exposure of non-credential data (names, addresses, card data).

### Other findings
| Finding | Points |
|---|---|
| Security notifications (new sign-in, suspicious activity) in the last 90 days — one finding per account | 20 (25 if suspicious) × confidence_factor; × 0.5 if the user reported reviewing activity after the latest alert |
| Two-step verification | unknown 8 · user-reported off 12 · user-reported on 2 · confirmation email found 1 (× confidence_factor) |
| Dormant (no evidence for > 730 days) | 6 × confidence_factor |

### Category impact
email/identity 1.3 · financial 1.25 · developer 1.1 · social, shopping, productivity 1.0 · travel 0.95 · entertainment 0.9 · other 0.9.

### Severity of a finding
critical ≥ 30 points · high ≥ 18 · medium ≥ 8 · low > 2 · info otherwise.

### Account-existence confidence
Strongest evidence item + 0.05 per additional independent evidence type, capped at 0.99. Evidence confidences: account creation/verification 0.85–0.9, security notifications 0.75–0.9, password reset 0.7, receipts/notices 0.55–0.6, other mail from a known service 0.25. Accounts the user marks "not mine" are excluded (score `null`) and suppressed in future scans.

## Overall DASI

```
peak     = max(account_risk)
breadth  = 100 × (1 − Π (1 − account_risk_i / 200))
DASI     = min(100, round( 0.6 × peak + 0.4 × breadth + uncertainty ))
```

Uncertainty: no completed mailbox scan +10 · a partial/failed latest scan +5 · breach catalogue unavailable +5.

Levels: 0–24 low · 25–49 moderate · 50–74 high · 75–100 critical · `null` unknown.

Worked example (unit-tested): accounts at 60 and 20, complete coverage → peak 36 + breadth 0.4 × 37 = 14.8 → **51 (high)**; with partial coverage → **56**.

## Recalculation and history

- Triggers: scan completion, account corrections, two-step status reports, remediation status changes, verification, account add/remove, mailbox disconnect, manual rescore.
- Only the affected accounts are reassessed; others keep their stored scores and their findings are untouched (verified by test). Findings are upserted by a stable fingerprint, so history and first-detected dates persist; findings no longer produced become `inactive` (breach findings remain unless the account is excluded).
- A snapshot is stored only when the score, coverage, components or per-account scores change, with the reason and per-account deltas (`dasi_snapshots.changes`).

## Remediation verification

| Action | Verified when |
|---|---|
| Change password | a "your password was changed" email from the service is found, dated after the breach |
| Turn on two-step verification | a "two-step verification turned on" email from the service is found |
| Delete account | an "account deleted/closed" email from the service is found |
| Review activity / review account | no reliable verifier → `unable_to_verify`, the user report is kept |

If no evidence exists yet and a mailbox is connected, the item is `verification_pending` and is resolved after the next scan (`verified_complete` or `unable_to_verify`). FootprintX never claims to have detected a password change by itself.

# FootprintX API

Base path `/api`. JSON in and out (except `.xlsx` downloads). All request bodies are validated with Zod; invalid input returns `400 {error:"validation_error", issues:[{path,message}]}`. Errors always have the shape `{ "error": "<code>", "message": "<human text>" }`.

## Authentication model

| Client | Credential | CSRF |
|---|---|---|
| Web app | `HttpOnly` session cookie (`fx_session`, or `__Host-fx_session` when `COOKIE_SECURE=true`), 7-day fixed lifetime, server-side session row (SHA-256 of the token) | Unsafe methods need `X-CSRF-Token` (per-session token from `/auth/me`, `/auth/login`, `/auth/register`). Unauthenticated unsafe requests need `X-FootprintX-Client: web`. A present `Origin` must be an allowed origin. |
| Extension | `Authorization: Bearer <token>` (hashed in DB, revocable) | Not cookie-based; exempt |

Ownership: every user-owned query is scoped with `user_id = <session user>`; a resource of another user returns `404`. Premium is checked server-side from the database on every request.

Rate limits (per IP or user, in-memory): global 300/min; login 10/15 min per IP+email; register 20/h per IP; password recovery 5/h; contact 5/h per IP; manual domain checks 20/min; extension checks 120/min per token; extension linking 10/15 min per IP; reports 10/min; scans 20/h.

## Endpoints

### Public / auth
| Method | Path | Notes |
|---|---|---|
| GET | `/health` | `{status, database}` |
| GET | `/status` | Configured sources, feed/breach freshness, whether email is configured |
| POST | `/auth/register` | `{email, password(12–128), displayName?, acceptPrivacy:true}` → `201 {user, csrfToken}` |
| POST | `/auth/login` | `{email, password}` → `{user, csrfToken}`; generic `401 invalid_credentials` |
| POST | `/auth/logout` | Deletes the session |
| GET | `/auth/me` | `{user|null, csrfToken|null}` |
| POST | `/auth/forgot-password` | `{email}`; same response whether or not the account exists; `503 email_not_configured` when email is off |
| POST | `/auth/reset-password` | `{token, password}`; single use, 1 h; signs out all sessions |
| POST | `/auth/change-password` | `{currentPassword, newPassword}`; signs out other sessions |
| POST | `/contact` | `{name, email, subject, message, website(honeypot, empty), elapsedMs}` → `200 {status:"sent"|"dev_logged"}`, `503 contact_unavailable`, `502 delivery_failed` |

### Mailboxes and discovery (signed in)
| Method | Path | Notes |
|---|---|---|
| GET | `/connections/providers` | Consent text, provider list and whether each is configured |
| GET | `/connections` | Connections with latest scan |
| POST | `/connections/oauth/:provider/start` | `provider` = `google`/`microsoft`; body `{consent:true, consentVersion:"email-discovery-v1"}` → `{authorizationUrl}` (PKCE S256, state stored hashed, 10 min) |
| GET | `/connections/oauth/:provider/callback` | Provider redirect; validates state/user/provider, exchanges code, encrypts tokens, starts a scan, redirects to `WEB_ORIGIN/connections?...` |
| POST | `/connections/devfixture` | Development fixture mailbox (only with `ENABLE_DEV_FIXTURES`) → `202 {connectionId, scanId}` |
| POST | `/connections/:id/scan` | `202 {scanId}`; `409 scan_in_progress` |
| GET | `/connections/scans/:scanId` | Status `running|completed|partial|failed`, counts, error code |
| DELETE | `/connections/:id?purge=true` | Revokes (Google) / deletes tokens; purges evidence and evidence-only accounts; returns `revocation` |

### Inventory, DASI, remediation, alerts (signed in)
| Method | Path | Notes |
|---|---|---|
| GET | `/dashboard` | Latest DASI (score may be `null` = unknown), top findings, next 3 actions, recent changes, counts, breach-data status |
| GET | `/dasi/history` | Snapshots with reasons and per-account changes |
| GET | `/dasi/model` | Model constants (see [DASI.md](DASI.md)) |
| POST | `/dasi/recalculate` | Refresh breach catalogue if stale and rescore |
| GET | `/accounts` | Inventory with risk, source, confidence |
| GET | `/accounts/:id` | Account, evidence (no subjects), findings, remediation |
| POST | `/accounts` | `{domain, serviceName?}` add manually |
| PATCH | `/accounts/:id` | `{ownership?: user_confirmed|false_positive|discovered, mfaStatus?: unknown|user_reported_enabled|user_reported_disabled}` |
| DELETE | `/accounts/:id` | Only accounts you added |
| GET | `/remediation` | Items with status, official link and link kind |
| PATCH | `/remediation/:id` | `{status, note?}`; only valid user transitions (`409 invalid_transition`) |
| POST | `/remediation/:id/verify` | Evidence-based verification → `verified_complete`, `verification_pending` or `unable_to_verify` |
| GET | `/alerts`; POST `/alerts/:id/read`; POST `/alerts/read-all` | In-app alerts |
| GET/PUT | `/notifications/preferences` | `{emailSecurityAlerts, emailRemediationReminders, emailPeriodicSummary, emailConsent?}` (consent required to enable) |
| POST | `/domain-check` | `{domain}` → reputation result (Free) |

### Reports, privacy, plan (signed in)
| Method | Path | Notes |
|---|---|---|
| GET | `/reports/security.xlsx` | Summary, Accounts, Risk Findings, Recommendations, DASI History, Scans, + Security Activity (Premium) |
| GET | `/privacy/export.xlsx` | Full personal-data export |
| POST | `/privacy/delete-account` | `{password, confirm:"DELETE"}`; revokes mailbox tokens; cascades all data |
| GET | `/plan` | Plan, features, billing status (not configured) |
| POST | `/dev/plan` | `{plan}` development entitlement; `404` unless `ENABLE_DEV_ENTITLEMENTS` and not production |
| GET/DELETE | `/security-events` | Premium; synced warning events |
| PUT | `/security-events/sync` | Premium; `{enabled}` opt-in |

### Extension
| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/extension/link-code` | cookie | One-time `XXXXX-XXXXX` code, 10 min |
| GET | `/extension/tokens`; DELETE `/extension/tokens/:id` | cookie | List / revoke linked browsers |
| POST | `/ext/link` | — | `{code, label?}` → `201 {token, email, plan}` |
| GET | `/ext/status` | bearer | Plan, `protectionAvailable`, `eventSync` |
| POST | `/ext/check` | bearer + Premium | `{domain}` (POST keeps hostnames out of URLs/access logs) → reputation result; `403 premium_required` for Free |
| PUT | `/ext/preferences` | bearer + Premium | `{eventSync}` |
| POST | `/ext/events` | bearer + Premium + opt-in | `{events:[{clientEventId, domain, status:"red"|"amber", reasons, action, occurredAt}]}`; idempotent |
| POST | `/ext/unlink` | bearer | Revokes the calling token |

## Reputation result

```json
{ "domain": "xn--pple-43d.com", "displayDomain": "аpple.com", "status": "amber", "summary": "Suspicious site",
  "reasons": ["The domain mixes Latin and Cyrillic characters, a common look-alike technique."],
  "nextSteps": ["Check the address carefully before entering any information.", "..."],
  "confidence": "low", "providers": [{"provider":"feed","kind":"threat_intel","outcome":"no_match"}],
  "checkedAt": "...", "expiresAt": "...", "fromCache": false, "limitations": "..." }
```

`status`: `green` only if every configured threat-intelligence source succeeded without a match; `red` for a credible known-malicious match; `amber` for suspicious/heuristic signals; `grey` when any source failed and nothing matched, or no source is available. Failed lookups are never cached.

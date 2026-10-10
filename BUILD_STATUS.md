# FootprintX — build status

Last full verification: 2026-10-10, on a clean clone following only the README (Node 22.22, PostgreSQL 16.15, Chromium 141 via Playwright 1.56.1).

Legend: **PASS** implemented and tested · **PARTIAL** implemented, not fully verified · **BLOCKED** external dependency · **FAIL** not met.

## Summary

| Checkpoint | Status | Evidence |
|---|---|---|
| A. Project foundation | PASS | `npm ci`, migrations, seed, typecheck and builds succeed on a clean clone |
| B. Authentication and privacy | PASS | `apps/api/test/auth.test.ts`, `isolation.test.ts`; e2e auth flows |
| C. Email consent and account discovery | PARTIAL (live OAuth BLOCKED) | Gmail + Microsoft adapters tested against stubbed provider endpoints; fixture mailbox end-to-end; no OAuth credentials were available |
| D. All Free features | PASS | e2e "Free user" flow (desktop + mobile); API suites |
| E. DASI and remediation engine | PASS | `dasi-model.test.ts` (hand-calculated values), `remediation.test.ts` |
| F. Threat intelligence | PASS (paid/keyed providers PARTIAL) | `threat.test.ts`; live public feed verified (386,610 domains); URLhaus/Safe Browsing adapters tested with stubs only |
| G. Premium browser extension | PASS | Built, loaded into Chromium, driven end-to-end (`apps/extension/e2e`); unit tests |
| H. Free/Premium enforcement | PASS | `premium.test.ts`; extension e2e with tampered local plan |
| I. Contact Us and notifications | PASS | Real SMTP delivery to a local SMTP server, provider failure, missing configuration |
| J. Excel reports | PASS | `reports.test.ts` opens and validates workbooks; e2e downloads real `.xlsx` |
| K. Uncluttered UI | PASS | Playwright e2e on desktop and mobile; axe-core WCAG 2.1 AA scan of 18 screens (0 serious/critical) |
| L. Security and data integrity | PASS (with documented open items) | Tests above; `npm audit` 0 vulnerabilities; [SECURITY.md](docs/SECURITY.md) |
| M. Local execution and future deployment | PASS (local) · PARTIAL (deployment) | Clean-clone setup, restart persistence verified; Vercel/Render/Neon config written but not deployed (as instructed) |

## Test inventory (all passing in the final run)

| Suite | Command | Result |
|---|---|---|
| API (Vitest + Supertest + real PostgreSQL) | `npm test -w apps/api` | 93 tests, 9 files |
| Web unit (Vitest + Testing Library) | `npm test -w apps/web` | 8 tests |
| Extension unit | `npm test -w apps/extension` | 11 tests |
| Web e2e (Playwright, desktop + Pixel 7) | `npm run test:e2e` | 10 tests (4 flows + accessibility scan, × 2 viewports) |
| Extension e2e (real extension in Chromium + real API) | `npm run test:extension:e2e` | 4 tests |
| Typecheck / build / audit | `npm run typecheck`, `npm run build`, `npm audit` | clean / OK / 0 vulnerabilities |

## Checkpoint details

### A. Project foundation — PASS
npm-workspaces monorepo (`apps/api`, `apps/web`, `apps/extension`), `.env.example` files without secrets, `.gitignore`, SQL migration with constraints, development-fixture seed (refuses production), README with exact commands, Docker Compose PostgreSQL, CI workflow, Render blueprint and Vercel config.

### B. Authentication and privacy — PASS
Implemented and tested: registration with privacy consent, Argon2id hashing, login with generic errors and timing equalisation, server-side sessions (hashed token, HttpOnly, SameSite, `__Host-`/Secure in production — verified by running the production build), logout, password change (revokes other sessions), password recovery (single-use 1 h token in URL fragment; honest `email_not_configured`), CSRF tokens + Origin checks, rate limiting, ownership checks on every resource (IDOR suite), data export (.xlsx), account deletion (cascade verified across 10 tables), mailbox disconnection with revocation, log redaction. Never collects external passwords, OTPs, MFA secrets, recovery codes, cookies or vault contents.
Open (documented): FootprintX's own logins have no MFA; registration email is not verified.

### C. Email consent and account discovery — PARTIAL (live provider access BLOCKED)
- Implemented: Gmail (`gmail.metadata`) and Microsoft Graph (`Mail.ReadBasic`) OAuth with PKCE, hashed single-use state bound to user and provider, encrypted token storage, refresh, `reauth_required` handling, Google revocation, metadata-only scanning with a message cap, partial/failed scan states, evidence classification with source/timestamp/confidence, de-duplication across scans and mailboxes, multi-mailbox identities, "not mine" corrections that persist across scans, user-added accounts, minimum retention (no subjects/bodies stored), separate consent from email notifications.
- Tested: full Gmail flow (authorize URL, code exchange, profile, paginated metadata fetch, partial failure, token rejection, revocation) and Microsoft flow (scopes, pagination, revocation not supported) against **stubbed provider endpoints**; the **development fixture mailbox** end-to-end in API and browser tests.
- BLOCKED: no Google/Microsoft OAuth client credentials or verified apps exist for this project, so no live mailbox was scanned. Gmail's restricted-scope verification is required before public launch (see DEPLOYMENT.md). Fixture data is labelled everywhere it appears.

### D. All Free features — PASS
Inventory, service-level breach checks, account explanations, DASI with history and rescans, prioritised remediation with links, status tracking, in-app alerts, notification preferences, manual domain checks, privacy controls, `.xlsx` reports and export, Contact Us. No account or scan limits. The e2e Free flow completes discovery → assessment → correction → remediation → history → Excel report without Premium.
Note: official security links are curated from vendor documentation; they could not be network-verified from this build environment (most vendor sites were blocked by the egress proxy). `npm run links:verify -w apps/api` checks them from an unrestricted network. Unknown services use the W3C `/.well-known/change-password` address, labelled as possibly unsupported.

### E. DASI and remediation engine — PASS
Documented model `dasi-1.0` ([DASI.md](docs/DASI.md)) with weights, thresholds, relevance, freshness, confidence, overlap handling, explicit unknowns and uncertainty allowances. Tests verify exact values, determinism, recalculation of only the affected account, preservation of unrelated findings (unchanged `updated_at`), history snapshots with reasons, the 50% user-reported rule, evidence-based verification (`verified_complete` only from a password-changed / 2FA-enabled / account-closed email), and all seven remediation states. The dashboard updates without a page reload (React Query invalidation; polling while scans run).

### F. Threat intelligence — PASS (keyed providers PARTIAL)
Adapters: local blocklist feed (default; live Phishing.Database feed synced and queried — a listed domain returned red, `github.com` green, `paypa1.com` amber, without visiting any site), look-alike heuristics (mixed-script IDN, typo-squats, brand in subdomain; amber only), URLhaus, Google Safe Browsing, and a development fixture source. Safe normalisation (punycode, subdomain→registrable matching, private/local rejection), per-status cache expiry, failed checks never cached, per-provider timeouts, rate limits. Tests cover safe, known-threat, suspicious, timeout, offline and provider-failure cases. URLhaus and Safe Browsing need free keys that were not available; they are tested against stubs only.
BLOCKED in this environment: the HIBP public breach list (the egress proxy returned 403). The integration is implemented and records the failure honestly; the dashboard shows "Breach data unavailable" and the DASI adds +5 uncertainty. Local development used the labelled fixture catalogue.

### G. Premium browser extension — PASS
Manifest V3, permissions `storage` + `webNavigation` + the API origin only. Toolbar badge per tab, popup (link, status, reasons, next steps, settings, clear cache, unlink), warning page with go-back / continue-anyway, persistent settings, cache with expiry, timeouts/offline/server-error → grey, bearer-token linking with single-use codes, server-side entitlement on every check, opt-in warning-event sync, hostname-only POST requests. Reproducible build and zip packaging. Verified by loading the built extension into Chromium (new headless) against a real API: red block + continue, green, amber, grey (timeout/error), cache, settings persistence, protection off, opt-in sync, unlink, and Free-user refusal even with tampered local storage.
Not done: Chrome Web Store/Edge Add-ons submission; testing in Edge or Firefox.

### H. Free/Premium enforcement — PASS
Plan read from the database per request; forged headers/body fields ignored; downgrade takes effect immediately; Premium retains every Free endpoint (tested). Development entitlement is clearly labelled "no payment" and refused in production. No billing is implemented and none is simulated.

### I. Contact Us and notifications — PASS
Contact form with validation, honeypot, timing check and rate limit; SMTP adapter tested end-to-end against a local SMTP server (delivered), a rejecting server (502, recorded as failed) and missing configuration (503, not sent); development outbox mode is labelled "not emailed". Optional email notifications (security alerts, reminders, weekly summaries) need separate consent, are de-duplicated, skip unchanged summaries, and never email after every scan; in-app alerts and extension warnings work without them. No external SMTP provider credentials were available, so real-internet delivery was not tested.

### J. Excel reports — PASS
ExcelJS workbooks (Summary, Accounts, Risk Findings, Recommendations, DASI History, Scans, Security Activity for Premium) from persisted data with headers, widths, filters, date formats, explicit "Unknown", fixture labelling, formula-injection neutralisation, auth and ownership checks. Tests open and validate the workbook contents; the web client rejects non-workbook responses.

### K. Uncluttered UI — PASS
Dashboard prioritises DASI + meaning, top findings, next three actions, recent changes; advanced detail in expandable sections. Loading/empty/partial/error/success states; consistent status colours always paired with text; skip link, focus styles, keyboard navigation, responsive layout with no horizontal scroll at 390 px. Verified with Playwright on desktop and mobile and axe-core (0 serious/critical WCAG 2.1 AA violations on 18 screens).

### L. Security and data integrity — PASS (open items documented)
See [SECURITY.md](docs/SECURITY.md) for the threat model, controls, retention policy, deletion workflow, backup/recovery and the 11 open findings (in-memory rate limiting, no FootprintX MFA, no email verification, Microsoft revocation, Gmail restricted-scope verification, unverified curated links, OAuth codes in access logs, heuristic false positives, dev-server CSP, SMTP dependency). Dependency audit: 0 vulnerabilities (uuid override for exceljs).

### M. Local execution and future deployment — PASS (local) · PARTIAL (deployment)
Clean clone → README commands → migrations, seed, `dev:api` + `dev:web`, sign-in through the Vite proxy: verified. Data and sessions persisted across a real API process restart. The compiled production build was started with production settings (HSTS, `__Host-` Secure cookie, dev switches refused). Vercel (`apps/web/vercel.json` with `/api` rewrite and security headers), Render (`render.yaml`), Neon (SSL connection, automatic migrations) and OAuth/extension-store/billing/hosting-limit guidance are in [DEPLOYMENT.md](docs/DEPLOYMENT.md). Not deployed, per instructions, so the hosting configuration is unverified against live services.

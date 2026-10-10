# Security, privacy and data handling

## Threat model (concise)

**Assets:** FootprintX credentials and sessions; mailbox OAuth tokens; the account inventory, findings and history (sensitive: it maps a person's online life); extension tokens; contact messages.

**Actors:** anonymous internet attackers; a signed-in user attacking other users (IDOR, entitlement bypass); malicious websites interacting with the browser or extension; a compromised/curious third-party provider; an operator with database access; an attacker with a stolen database backup.

| Threat | Controls (implemented and tested unless noted) |
|---|---|
| Credential stuffing / brute force | Argon2id (19 MiB, t=2, p=1, OWASP); generic login errors; dummy hash for unknown users (timing); login rate limit 10/15 min per IP+email |
| Session theft / fixation | 256-bit random token in `HttpOnly`, `SameSite=Lax`, `Secure` + `__Host-` prefix in production; only SHA-256 stored; new session on login; logout deletes server row; password change/reset revokes sessions; fixed 7-day expiry |
| CSRF | Per-session CSRF token header on all unsafe requests; custom header for unauthenticated unsafe requests (forces CORS preflight); Origin allow-list; `SameSite=Lax` |
| XSS | React escaping; no `dangerouslySetInnerHTML`; extension uses `textContent`; strict CSP for web (`vercel.json`), API (`default-src 'none'`) and extension pages (`script-src 'self'`) |
| SQL injection | Parameterised queries only (no string-built SQL with user input) |
| SSRF | The API never fetches user-supplied URLs. Outbound calls go only to fixed provider endpoints and operator-configured feed URLs; Graph pagination links must stay on the Graph host |
| IDOR / cross-user access | Every query is scoped by `user_id`; foreign IDs return 404; tested for accounts, findings, remediation, alerts, connections, scans, extension tokens and reports |
| Entitlement spoofing | Plan read from the DB per request; client fields/headers ignored; dev entitlement endpoint disabled unless explicitly enabled and refused in production; extension checks re-verified per request; tested with forged headers and tampered extension storage |
| OAuth abuse | PKCE (S256); 256-bit `state` stored hashed, bound to user + provider, single-use, 10 min; fixed redirect URIs from config; post-callback redirect to a fixed web path (no open redirect) |
| Token exposure | Mailbox tokens AES-256-GCM encrypted with `TOKEN_ENCRYPTION_KEY`; extension tokens, reset tokens, link codes and OAuth states stored as SHA-256 hashes; Google tokens revoked on disconnect/deletion |
| Over-collection | Gmail `gmail.metadata` / Microsoft `Mail.ReadBasic` (no bodies); only sender domain, evidence type, date and a message-ID hash are stored; extension sends hostnames only (POST body, not URL); clean navigation is never uploaded; event sync is opt-in |
| Malicious extension messages | Background accepts messages only from its own pages and validates their shape; red/amber decisions come only from the server |
| Spreadsheet formula injection | Cells starting with `= + - @ \t \r | %` are prefixed with `'`; tested |
| Abuse of contact form | Validation, honeypot field, minimum fill time, 5 messages/h per IP, header-injection-safe subject |
| Sensitive logging | No request-body or access logging in the API; pino redaction of cookies, authorization, CSRF, passwords and tokens; provider errors sanitised before storage |
| Misconfiguration | Production start refuses dev fixtures, dev entitlements, devlog email, insecure cookies, missing encryption key and fixture threat/breach sources |
| Dependency vulnerabilities | `npm audit` clean at build time (an `uuid` override patches exceljs's transitive dependency); CI runs `npm audit --omit=dev` |
| Data integrity | Foreign keys with `ON DELETE CASCADE`; CHECK constraints for every status enum; unique constraints for de-duplication (evidence, findings, remediation items, alerts, notification deliveries, events); transactions for disconnect/purge, feed replacement and recalculation (with a per-user advisory lock); migrations transactional and advisory-locked |

## Data retention policy

| Data | Retention |
|---|---|
| FootprintX account, inventory, findings, remediation, DASI history, alerts | Until the user deletes their account |
| Sessions | 7 days (expired rows are ignored; deleted on logout/password change) |
| Password reset tokens | 1 hour, single use |
| OAuth state | 10 minutes, single use |
| Extension link codes | 10 minutes, single use |
| Mailbox tokens and evidence | Until the mailbox is disconnected (evidence purged by default) or the account is deleted |
| Message subjects / bodies | Never stored |
| Domain reputation cache | Up to 12 h; not linked to any user |
| Security events (Premium, opt-in) | Until the user deletes them or the account |
| Contact messages | Kept to answer the request; `user_id` is cleared on account deletion; delete on request |
| Notification delivery records | Until account deletion (used for de-duplication) |

## Deletion workflow

1. User confirms with their password and the word `DELETE` (Settings → Your data).
2. The API attempts token revocation for every connected mailbox (Google: revoke endpoint; Microsoft: not supported by the platform — user is told how to remove consent).
3. `DELETE FROM users` cascades to every user-owned table in one statement (verified by test: no rows remain in 10 tables, other users unaffected).
4. The session cookie is cleared and the user sees a confirmation.

Backups (e.g. Neon point-in-time restore) still contain deleted data until the backup window expires; disclose this window in the production privacy notice.

## Backup and recovery guidance

- **Neon:** enable point-in-time restore (the free plan keeps a short history window; paid plans are longer). Test restoring into a branch before relying on it.
- **Logical backups:** `pg_dump --format=custom "$DATABASE_URL" > footprintx-$(date +%F).dump`; restore with `pg_restore --clean --no-owner -d "$DATABASE_URL" file.dump`. Encrypt backups at rest and restrict access.
- **Key management:** `TOKEN_ENCRYPTION_KEY` is required to read mailbox tokens. Store it in the hosting secret store and in a separate secure location; without it, users must reconnect mailboxes (no other data is lost). Rotation: deploy a new key and ask users to reconnect, or add a re-encryption migration.
- Migrations are forward-only; take a backup before deploying a release with a new migration.

## Unresolved findings and risks

| # | Finding | Severity | Notes / mitigation path |
|---|---|---|---|
| 1 | Rate limits use an in-memory store | Medium | Fine for one instance; limits reset on restart and are not shared across instances. Use a PostgreSQL/Redis store before scaling out. |
| 2 | FootprintX's own login has no MFA | Medium | Add TOTP/WebAuthn for FootprintX accounts. |
| 3 | Registration does not verify email ownership | Medium | Opt-in notification emails could be sent to an address the registrant does not own. Add verification before enabling email notifications in production. |
| 4 | No "sign out other devices" button | Low | Password change/reset already revokes other sessions. |
| 5 | Microsoft tokens cannot be revoked by API | Low | Platform limitation; tokens are deleted locally and the user is shown the consent-management link. |
| 6 | Gmail `gmail.metadata` is a restricted scope | Process | Google app verification (and possibly a paid third-party security assessment) is required before public launch. |
| 7 | Curated security links were not network-verified in this build environment | Low | Run `npm run links:verify -w apps/api` from an unrestricted network before release. |
| 8 | OAuth callback query (`code`, `state`) may appear in hosting access logs | Low | Codes are single-use and PKCE-bound; consider `response_mode=form_post` for Microsoft. |
| 9 | Look-alike heuristics can produce false positives | Low | Always amber with an explanation, never red. |
| 10 | Dev server (Vite) does not send the production CSP | Info | CSP is applied by Vercel headers in production. |
| 11 | Contact/notification delivery depends on an SMTP provider | Info | Honest `not_configured`/`failed` states are implemented. |

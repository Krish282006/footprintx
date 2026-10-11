# FootprintX


**Secure Your Digital Past. Protect Your Online Future.**

FootprintX finds online accounts from email evidence you explicitly authorise, checks those services against public breach data, scores your exposure with an explainable **Digital Attack Surface Index (DASI)**, prioritises remediation with links to each service's own security pages, and tracks your progress. Premium adds a browser extension that warns about known-malicious and suspicious sites.

What FootprintX does **not** claim: it cannot find every account, a breached *service* is not proof that *your* account was exposed, it cannot see your passwords or two-step settings (so your reports are labelled "user-reported"), and "no known threat" is not a guarantee that a site is safe.

Current state of every requirement: [BUILD_STATUS.md](BUILD_STATUS.md).

## Repository layout

| Path | What |
|---|---|
| `apps/api` | Node.js 22 + Express 5 + TypeScript API, PostgreSQL (`pg`), SQL migrations, Vitest suites |
| `apps/web` | React 19 + Vite + TypeScript single-page app, Vitest + Playwright e2e |
| `apps/extension` | Chrome/Edge Manifest V3 extension (esbuild), Vitest + Playwright e2e that loads the real extension |
| `docs/` | [API](docs/API.md), [DASI model](docs/DASI.md), [security & privacy](docs/SECURITY.md), [deployment](docs/DEPLOYMENT.md) |
| `render.yaml`, `apps/web/vercel.json` | Future deployment configuration (Render API, Vercel web, Neon PostgreSQL) |
| `docker-compose.yml` | Optional local PostgreSQL |

## Requirements

- Node.js **22** (20.11+ works) and npm 10
- PostgreSQL **16** (native install or `docker compose up -d`)
- For browser tests only: Chromium via Playwright (`npx playwright install chromium`)

Everything is free/open source. No paid API is needed to run locally.

## Quick start (local)

```bash
# 1. Install dependencies (all workspaces)
npm ci

# 2. Start PostgreSQL — EITHER Docker:
docker compose up -d
#    OR a native PostgreSQL 16 (as a superuser):
#    psql -c "CREATE ROLE footprintx LOGIN PASSWORD 'footprintx_dev_password' CREATEDB;"
#    createdb -O footprintx footprintx_dev && createdb -O footprintx footprintx_test && createdb -O footprintx footprintx_e2e

# 3. Configure the API
cp apps/api/.env.example apps/api/.env
KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
sed -i.bak "s|^TOKEN_ENCRYPTION_KEY=.*|TOKEN_ENCRYPTION_KEY=$KEY|" apps/api/.env && rm apps/api/.env.bak

# 4. Migrate and load clearly labelled development fixtures (two demo users)
npm run db:migrate
npm run db:seed

# 5. Run the API (http://localhost:4000) and the web app (http://localhost:5173) in two terminals
npm run dev:api
npm run dev:web
```

Open http://localhost:5173 and either create an account or sign in with a seeded **development fixture** user:

| Email | Password | Plan |
|---|---|---|
| `free-demo@footprintx.test` | `FootprintX-demo-2026!` | Free |
| `premium-demo@footprintx.test` | `FootprintX-demo-2026!` | Premium (development entitlement — no payment) |

Seeded users have the **development fixture mailbox** connected: synthetic messages from fictional `*.example` services plus a few well-known services. Everything derived from it is labelled "Development fixture" in the UI and in Excel reports. It is never presented as real discovery.

The Vite dev server proxies `/api` to the API, so cookies are first-party and no CORS is involved.

### Data sources in local development

- **Threat feed (live, free):** the default `THREAT_FEED_URLS` (Phishing.Database active phishing domains) is downloaded at API start and hourly, or on demand with `npm run threat:sync -w apps/api`. Domains are looked up locally; checked hostnames are never sent to the feed provider.
- **Breach catalogue:** `BREACH_SOURCE=hibp` loads the public Have I Been Pwned breach list (no key). If that host is unreachable from your network, set `BREACH_SOURCE=fixture` for the labelled fictional catalogue; the dashboard says when breach data is unavailable and the DASI adds an uncertainty allowance.
- **Development fixture threat source:** add `fixture` to `THREAT_PROVIDERS` to make `malicious.fixture.test`, `suspicious.fixture.test`, `timeout.fixture.test` and `error.fixture.test` return controlled results. Tests use only these; no real malicious site is ever visited.
- **Behind an HTTP proxy:** Node's `fetch` ignores `HTTPS_PROXY` unless you start the API with `NODE_USE_ENV_PROXY=1` (Node 22.21+).

## Tests and builds

```bash
npm run typecheck            # all workspaces
npm test                     # API (needs PostgreSQL db footprintx_test), web, extension unit tests
npm run build                # API (tsc), web (vite), extension (dist/)
npm run test:e2e             # web app e2e, desktop + mobile (needs db footprintx_e2e + Chromium)
npm run test:extension:e2e   # loads the built extension into Chromium against a real API
npm run audit:deps           # npm audit of production dependencies
```

Test databases: `footprintx_test` (API suite; schema is dropped and re-migrated each run) and `footprintx_e2e` (Playwright; reset on each run). The scripts refuse to reset a database whose name does not contain `test`/`e2e`. Override with `TEST_DATABASE_URL` / `E2E_DATABASE_URL`.

## Browser extension

```bash
# Build against your API (defaults: API http://localhost:4000, web http://localhost:5173)
FOOTPRINTX_API_URL=http://localhost:4000 FOOTPRINTX_WEB_URL=http://localhost:5173 npm run build -w apps/extension
# Optional: reproducible zip for store upload -> apps/extension/packages/footprintx-extension-1.0.0.zip
npm run package -w apps/extension
```

Install: open `chrome://extensions` (or `edge://extensions`), enable **Developer mode**, click **Load unpacked**, select `apps/extension/dist`. Then in the web app go to **Extension → Create link code** and enter the code in the extension popup.

Permissions: `storage`, `webNavigation`, and host access to the FootprintX API origin only. The extension sends only the hostname of top-level navigations (never paths, queries, page content, forms, cookies or credentials). Results: **green** = checked, no known threat from configured sources; **red** = credible known-malicious match (warning page before load); **amber** = suspicious/uncertain; **grey** = pending, offline, failed, not linked, Premium required, or not checked. Warning-event sync is off by default and needs explicit opt-in.

## Configuration

All API settings are environment variables documented in [`apps/api/.env.example`](apps/api/.env.example). Highlights:

| Variable | Purpose |
|---|---|
| `DATABASE_URL`, `DATABASE_SSL` | PostgreSQL (use `DATABASE_SSL=true` for Neon) |
| `WEB_ORIGIN`, `API_PUBLIC_URL` | Web origin (CORS, email links) and public API base (OAuth redirect URIs) |
| `TOKEN_ENCRYPTION_KEY` | 32-byte base64 key for AES-256-GCM encryption of mailbox tokens (required in production) |
| `EMAIL_PROVIDER` | `none`, `smtp` (real delivery) or `devlog` (development outbox; refused in production) |
| `GOOGLE_*`, `MICROSOFT_*` | Email OAuth apps (see [deployment guide](docs/DEPLOYMENT.md#email-oauth-setup)) |
| `THREAT_PROVIDERS` | `feed,heuristics` plus optional `urlhaus`, `safebrowsing` (free keys) or `fixture` (dev only) |
| `ENABLE_DEV_FIXTURES`, `ENABLE_DEV_ENTITLEMENTS` | Development-only switches; the API refuses to start in production if either is on |

The web app needs no configuration (`apps/web/.env.example`): it calls same-origin `/api`.

## Scheduled jobs

- `npm run jobs:notify -w apps/api` — remediation reminders and weekly summaries for users who opted in (deduplicated; nothing is sent when nothing changed). Run daily.
- `npm run threat:sync -w apps/api` — refresh threat feeds and the breach catalogue (the API also does this hourly).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Invalid configuration: DATABASE_URL` | Create `apps/api/.env` from `.env.example`. |
| `ECONNREFUSED 127.0.0.1:5432` | PostgreSQL is not running (`docker compose up -d` or start the native service). |
| `password authentication failed for user "footprintx"` | Create the role/databases as in step 2, or point `DATABASE_URL` at your own. |
| "Gmail/Outlook not configured on this server" | Expected without OAuth credentials. Use the development fixture mailbox or follow the OAuth setup guide. |
| Dashboard says "Breach data unavailable" | The HIBP list could not be downloaded. Check network/proxy, or use `BREACH_SOURCE=fixture` for development. |
| Domain checks are grey "Check unavailable" | No threat feed has synced yet. Run `npm run threat:sync -w apps/api` (use `NODE_USE_ENV_PROXY=1` behind a proxy). |
| Password reset says email is not configured | Set `EMAIL_PROVIDER=smtp` with `SMTP_*`, or `devlog` locally (link appears in the `dev_outbox` table and API log). |
| Extension popup: "Could not reach FootprintX" | Rebuild the extension with the correct `FOOTPRINTX_API_URL` and reload it in `chrome://extensions`. |
| Playwright: "Executable doesn't exist" | `npx playwright install chromium` (the repo pins `@playwright/test` 1.56.1). |
| Port 4000/5173 in use | Change `PORT` in `apps/api/.env`; for the web app set `FOOTPRINTX_API_PROXY` and run `npx vite --port <n>`. |

## Licence and attribution

Breach data: [Have I Been Pwned](https://haveibeenpwned.com) breach list, CC BY 4.0. Default threat feed: [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (MIT).

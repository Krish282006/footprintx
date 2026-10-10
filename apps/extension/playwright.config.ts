import { defineConfig } from '@playwright/test';

/** Loads the built extension into Chromium and drives it against a real API (fixture threat source only). */
export const API_PORT = 4200;
export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  workers: 1,
  reporter: [['list']],
  webServer: {
    command: 'node ../web/e2e/reset-db.mjs && npm run --prefix ../api dev:e2e',
    url: `http://localhost:${API_PORT}/api/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      NODE_ENV: 'development',
      PORT: String(API_PORT),
      DATABASE_URL: process.env.E2E_DATABASE_URL ?? 'postgres://footprintx:footprintx_dev_password@localhost:5432/footprintx_e2e',
      WEB_ORIGIN: 'http://localhost:5175',
      API_PUBLIC_URL: `http://localhost:${API_PORT}`,
      TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 5).toString('base64'),
      EMAIL_PROVIDER: 'devlog',
      BREACH_SOURCE: 'fixture',
      THREAT_PROVIDERS: 'fixture,heuristics',
      THREAT_LOOKUP_TIMEOUT_MS: '500',
      ENABLE_DEV_FIXTURES: 'true',
      ENABLE_DEV_ENTITLEMENTS: 'true',
      LOG_LEVEL: 'warn',
    },
  },
});

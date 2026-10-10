import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end tests run the real API (against a dedicated PostgreSQL database
 * "footprintx_e2e") and the real web app, using development fixtures only.
 */
const API_PORT = 4100;
const WEB_PORT = 5174;
const e2eEnv = {
  NODE_ENV: 'development',
  PORT: String(API_PORT),
  DATABASE_URL: process.env.E2E_DATABASE_URL ?? 'postgres://footprintx:footprintx_dev_password@localhost:5432/footprintx_e2e',
  WEB_ORIGIN: `http://localhost:${WEB_PORT}`,
  API_PUBLIC_URL: `http://localhost:${WEB_PORT}`,
  TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString('base64'),
  EMAIL_PROVIDER: 'devlog',
  CONTACT_RECIPIENT: 'support@footprintx.test',
  BREACH_SOURCE: 'fixture',
  THREAT_PROVIDERS: 'fixture,heuristics',
  ENABLE_DEV_FIXTURES: 'true',
  ENABLE_DEV_ENTITLEMENTS: 'true',
  LOG_LEVEL: 'warn',
};

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: { baseURL: `http://localhost:${WEB_PORT}`, trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 900 } } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: [
    {
      command: 'node e2e/reset-db.mjs && npm run --prefix ../api dev:e2e',
      url: `http://localhost:${API_PORT}/api/health`,
      env: e2eEnv,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `npx vite --port ${WEB_PORT} --strictPort`,
      url: `http://localhost:${WEB_PORT}`,
      env: { FOOTPRINTX_API_PROXY: `http://localhost:${API_PORT}` },
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});

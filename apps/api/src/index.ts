import { loadConfig } from './config.js';
import { createPool } from './db/pool.js';
import { migrate } from './db/migrate.js';
import { createApp } from './app.js';
import { logger } from './lib/logger.js';
import { ensureBreachCatalogFresh } from './breach/catalog.js';
import { ensureFeedsFresh } from './threat/sync.js';

const config = loadConfig();
const pool = createPool(config.DATABASE_URL, config.DATABASE_SSL);

await migrate(pool, (m) => logger.info(m));
const { app, ctx } = createApp({ config, db: pool });

const server = app.listen(config.PORT, () => {
  logger.info({ port: config.PORT, env: config.NODE_ENV, email: ctx.mailer.mode, threat: config.THREAT_PROVIDERS }, 'FootprintX API listening');
});

// Background refresh of public data sources. Failures are recorded, never fatal.
const refresh = async () => {
  await ensureBreachCatalogFresh(config, pool, fetch);
  if (config.THREAT_PROVIDERS.includes('feed')) await ensureFeedsFresh(pool, fetch, config.THREAT_FEED_URLS, config.THREAT_FEED_MAX_AGE_HOURS);
};
refresh().catch((err) => logger.warn({ err: (err as Error).message }, 'initial data refresh failed'));
const timer = setInterval(() => refresh().catch(() => undefined), 60 * 60_000);
timer.unref();

const shutdown = (signal: string) => {
  logger.info({ signal }, 'shutting down');
  server.close(() => pool.end().finally(() => process.exit(0)));
  setTimeout(() => process.exit(1), 10_000).unref();
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

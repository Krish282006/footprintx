import { loadConfig } from '../config.js';
import { createPool } from '../db/pool.js';
import { syncBreachCatalog } from '../breach/catalog.js';
import { syncAllFeeds } from './sync.js';

const config = loadConfig();
const pool = createPool(config.DATABASE_URL, config.DATABASE_SSL);
try {
  const feeds = await syncAllFeeds(pool, fetch, config.THREAT_FEED_URLS);
  for (const f of feeds) console.log(`${f.ok ? 'OK  ' : 'FAIL'} feed ${f.feedId}: ${f.ok ? `${f.count} domains` : f.error}`);
  const b = await syncBreachCatalog(config, pool, fetch);
  console.log(`${b.ok ? 'OK  ' : 'FAIL'} breach catalogue (${config.BREACH_SOURCE}): ${b.ok ? `${b.count} breaches` : b.error}`);
  if (feeds.some((f) => !f.ok) || !b.ok) process.exitCode = 1;
} finally {
  await pool.end();
}

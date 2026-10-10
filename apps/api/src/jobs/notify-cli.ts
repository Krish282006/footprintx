import { loadConfig } from '../config.js';
import { createPool } from '../db/pool.js';
import { createMailer } from '../email/mailer.js';
import { runNotificationJob } from '../notifications/service.js';

const config = loadConfig();
const pool = createPool(config.DATABASE_URL, config.DATABASE_SSL);
try {
  const result = await runNotificationJob(config, pool, createMailer(config, pool));
  console.log(JSON.stringify(result));
} finally {
  await pool.end();
}

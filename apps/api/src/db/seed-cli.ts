/**
 * DEVELOPMENT FIXTURE SEED. Creates two clearly labelled demo users and runs the
 * development fixture mailbox scan for one of them. Refuses to run in production.
 *
 *   free-demo@footprintx.test     / FootprintX-demo-2026!   (Free plan)
 *   premium-demo@footprintx.test  / FootprintX-demo-2026!   (Premium via development entitlement, no payment)
 */
import { loadConfig } from '../config.js';
import { createPool } from './pool.js';
import { migrate } from './migrate.js';
import { hashPassword, PRIVACY_POLICY_VERSION } from '../routes/auth.js';
import { syncBreachCatalog } from '../breach/catalog.js';
import { createApp } from '../app.js';
import { startScan } from '../discovery/service.js';
import { scanDeps, EMAIL_CONSENT_VERSION } from '../routes/connections.js';
import { FIXTURE_MAILBOX_ADDRESS } from '../discovery/fixtures.js';

const config = loadConfig();
if (config.NODE_ENV === 'production') {
  console.error('Refusing to seed development fixtures in production.');
  process.exit(1);
}
const pool = createPool(config.DATABASE_URL, config.DATABASE_SSL);
try {
  await migrate(pool);
  if (config.BREACH_SOURCE === 'fixture') await syncBreachCatalog(config, pool, fetch);
  const password = 'FootprintX-demo-2026!';
  const users = [
    { email: 'free-demo@footprintx.test', plan: 'free', source: 'default', name: 'Free demo (fixture)' },
    { email: 'premium-demo@footprintx.test', plan: 'premium', source: 'development', name: 'Premium demo (fixture)' },
  ];
  const { ctx } = createApp({ config: { ...config, ENABLE_DEV_FIXTURES: true }, db: pool });
  for (const u of users) {
    const { rows } = await pool.query<{ id: string }>(
      `INSERT INTO users (email, password_hash, display_name, plan, plan_source, privacy_policy_version, privacy_consent_at)
       VALUES ($1,$2,$3,$4,$5,$6,now())
       ON CONFLICT (email) DO UPDATE SET plan=$4, plan_source=$5 RETURNING id`,
      [u.email, await hashPassword(password), u.name, u.plan, u.source, PRIVACY_POLICY_VERSION],
    );
    await pool.query('INSERT INTO notification_preferences (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [rows[0].id]);
    const conn = await pool.query<{ id: string }>(
      `INSERT INTO email_connections (user_id, provider, email_address, status, scopes, consent_version, consent_at)
       VALUES ($1,'devfixture',$2,'active','{fixture:metadata}',$3,now())
       ON CONFLICT (user_id, provider, email_address) DO UPDATE SET status='active' RETURNING id`,
      [rows[0].id, FIXTURE_MAILBOX_ADDRESS, EMAIL_CONSENT_VERSION],
    );
    const running = await pool.query(`SELECT 1 FROM scans WHERE connection_id=$1 AND status='running'`, [conn.rows[0].id]);
    if (!running.rowCount) {
      const { done } = await startScan(scanDeps(ctx), rows[0].id, conn.rows[0].id);
      await done;
    }
    console.log(`Seeded ${u.email} (${u.plan}${u.source === 'development' ? ', development entitlement' : ''}) — password: ${password}`);
  }
  console.log('All seeded data is DEVELOPMENT FIXTURE data and is labelled as such in the app.');
} finally {
  await pool.end();
}

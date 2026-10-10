import pg from 'pg';
import { migrate } from '../src/db/migrate.js';

export default async function setup() {
  const url = process.env.TEST_DATABASE_URL ?? 'postgres://footprintx:footprintx_dev_password@localhost:5432/footprintx_test';
  if (!/test/.test(url)) throw new Error('Refusing to run tests against a database whose name does not contain "test"');
  const pool = new pg.Pool({ connectionString: url });
  // Fresh schema for every test run, then apply the real migrations.
  await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  await migrate(pool);
  await pool.end();
}

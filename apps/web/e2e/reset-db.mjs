// Resets the dedicated end-to-end database. Refuses any database without "e2e" in its name.
import pg from 'pg';

const url = process.env.DATABASE_URL ?? '';
if (!/e2e/.test(url)) throw new Error('Refusing to reset a database whose name does not contain "e2e"');
const pool = new pg.Pool({ connectionString: url });
await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
await pool.end();
console.log('e2e database reset');

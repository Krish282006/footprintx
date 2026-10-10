import request from 'supertest';
import type { Express } from 'express';
import { loadConfig } from '../src/config.js';
import { createPool, type Db } from '../src/db/pool.js';
import { createApp, type AppOptions } from '../src/app.js';
import { syncBreachCatalog } from '../src/breach/catalog.js';
import type { AppContext } from '../src/context.js';

let sharedPool: Db | null = null;
export function pool(): Db {
  sharedPool ??= createPool(process.env.DATABASE_URL!, false);
  return sharedPool;
}

export async function resetDb() {
  const db = pool();
  const { rows } = await db.query<{ tablename: string }>(
    `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'schema_migrations'`,
  );
  await db.query(`TRUNCATE ${rows.map((r) => `"${r.tablename}"`).join(', ')} RESTART IDENTITY CASCADE`);
}

export function makeApp(env: Record<string, string> = {}, opts: Partial<AppOptions> = {}) {
  const config = loadConfig({ ...process.env, ...env });
  const { app, ctx } = createApp({ config, db: pool(), rateLimitScale: 1000, ...opts });
  return { app, ctx, config };
}

export async function loadFixtureBreaches(ctx: AppContext) {
  await syncBreachCatalog(ctx.config, ctx.db, fetch);
}

/** Waits for background work (scans) started by requests. */
export async function settle(ctx: AppContext) {
  while (ctx.background.size) await Promise.all([...ctx.background]);
}

export const PASSWORD = 'correct-horse-battery-1';

/** A signed-in client: keeps the cookie and sends the CSRF token automatically. */
export class Client {
  agent: ReturnType<typeof request.agent>;
  csrf = '';
  userId = '';
  constructor(public app: Express) {
    this.agent = request.agent(app);
  }
  async register(email: string, password = PASSWORD) {
    const res = await this.agent
      .post('/api/auth/register')
      .set('x-footprintx-client', 'web')
      .send({ email, password, acceptPrivacy: true });
    if (res.status !== 201) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);
    this.csrf = res.body.csrfToken;
    this.userId = res.body.user.id;
    return res;
  }
  async login(email: string, password = PASSWORD) {
    const res = await this.agent.post('/api/auth/login').set('x-footprintx-client', 'web').send({ email, password });
    if (res.status === 200) {
      this.csrf = res.body.csrfToken;
      this.userId = res.body.user.id;
    }
    return res;
  }
  get(path: string) {
    return this.agent.get(path);
  }
  post(path: string, body: unknown = {}) {
    return this.agent.post(path).set('x-csrf-token', this.csrf).send(body as object);
  }
  put(path: string, body: unknown = {}) {
    return this.agent.put(path).set('x-csrf-token', this.csrf).send(body as object);
  }
  patch(path: string, body: unknown = {}) {
    return this.agent.patch(path).set('x-csrf-token', this.csrf).send(body as object);
  }
  delete(path: string) {
    return this.agent.delete(path).set('x-csrf-token', this.csrf);
  }
}

export async function signedIn(app: Express, email: string) {
  const c = new Client(app);
  await c.register(email);
  return c;
}

export async function connectFixture(c: Client, ctx: AppContext) {
  const res = await c.post('/api/connections/devfixture', { consent: true, consentVersion: 'email-discovery-v1' });
  if (res.status !== 202) throw new Error(`fixture connect failed ${res.status} ${JSON.stringify(res.body)}`);
  await settle(ctx);
  return res.body as { connectionId: string; scanId: string };
}

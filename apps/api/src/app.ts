import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import type { Config } from './config.js';
import type { Db } from './db/pool.js';
import type { AppContext } from './context.js';
import { createMailer, type Mailer } from './email/mailer.js';
import { csrfProtection, errorHandler, loadSession } from './middleware.js';
import { limiter } from './lib/ratelimit.js';
import type { FetchLike } from './lib/http.js';
import { DEFAULT_ENDPOINTS, devFixtureProvider, googleProvider, microsoftProvider, type ProviderEndpoints, type MailboxProvider, type ProviderId } from './discovery/providers.js';
import { buildProviders, ReputationService } from './threat/service.js';
import type { ThreatProvider } from './threat/types.js';
import { authRouter } from './routes/auth.js';
import { connectionsRouter } from './routes/connections.js';
import { inventoryRouter } from './routes/inventory.js';
import { settingsRouter } from './routes/account-settings.js';
import { publicRouter } from './routes/public.js';
import { extensionApiRouter, extensionWebRouter } from './routes/extension.js';

export type AppOptions = {
  config: Config;
  db: Db;
  fetchImpl?: FetchLike;
  mailer?: Mailer;
  endpoints?: Partial<ProviderEndpoints>;
  threatProviders?: ThreatProvider[];
  rateLimitScale?: number;
};

export function createApp(opts: AppOptions) {
  const { config, db } = opts;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const endpoints = { ...DEFAULT_ENDPOINTS(config.MICROSOFT_TENANT), ...opts.endpoints };
  const providers: Record<ProviderId, MailboxProvider> = {
    google: googleProvider(config, endpoints, fetchImpl),
    microsoft: microsoftProvider(config, endpoints, fetchImpl),
    devfixture: devFixtureProvider(config),
  };
  const ctx: AppContext = {
    config,
    db,
    fetchImpl,
    mailer: opts.mailer ?? createMailer(config, db),
    providers,
    reputation: new ReputationService(db, opts.threatProviders ?? buildProviders(config, db, fetchImpl), config.THREAT_LOOKUP_TIMEOUT_MS),
    rateLimitScale: opts.rateLimitScale ?? 1,
    background: new Set(),
  };

  const app = express();
  app.disable('x-powered-by');
  if (config.TRUST_PROXY) app.set('trust proxy', 1);
  app.use(
    helmet({
      // The API serves JSON and file downloads only.
      contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
      crossOriginResourcePolicy: { policy: 'same-site' },
      strictTransportSecurity: config.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false,
    }),
  );
  app.use(
    '/api',
    cors({
      origin: (origin, cb) => cb(null, !origin || config.corsOrigins.includes(origin)),
      credentials: true,
      allowedHeaders: ['content-type', 'x-csrf-token', 'x-footprintx-client', 'authorization'],
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
      maxAge: 600,
    }),
  );
  app.use(express.json({ limit: '100kb' }));
  app.use(cookieParser());
  app.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use('/api', limiter({ windowMs: 60_000, limit: 300, scale: ctx.rateLimitScale }));
  app.use(loadSession(config, db));
  app.use(csrfProtection(config));

  app.use('/api/auth', authRouter(ctx));
  app.use('/api/connections', connectionsRouter(ctx));
  app.use('/api/extension', extensionWebRouter(ctx));
  app.use('/api/ext', extensionApiRouter(ctx));
  app.use('/api', publicRouter(ctx));
  app.use('/api', settingsRouter(ctx));
  app.use('/api', inventoryRouter(ctx));
  app.use('/api', (_req, res) => res.status(404).json({ error: 'not_found', message: 'Not found' }));
  app.use(errorHandler);
  return { app, ctx };
}

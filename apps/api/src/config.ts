import { z } from 'zod';

const bool = (def: boolean) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? def : ['1', 'true', 'yes'].includes(v.toLowerCase())));

const list = (def: string) =>
  z
    .string()
    .optional()
    .transform((v) =>
      (v === undefined ? def : v)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    );

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().default(4000),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  DATABASE_SSL: bool(false),
  WEB_ORIGIN: z.string().url().default('http://localhost:5173'),
  EXTRA_CORS_ORIGINS: list(''),
  API_PUBLIC_URL: z.string().url().default('http://localhost:4000'),
  COOKIE_SECURE: bool(false),
  COOKIE_SAMESITE: z.enum(['lax', 'strict', 'none']).default('lax'),
  SESSION_TTL_HOURS: z.coerce.number().positive().default(168),
  TOKEN_ENCRYPTION_KEY: z.string().optional().default(''),
  TRUST_PROXY: bool(false),
  EMAIL_PROVIDER: z.enum(['none', 'smtp', 'devlog']).default('none'),
  EMAIL_FROM: z.string().default('FootprintX <no-reply@footprintx.local>'),
  CONTACT_RECIPIENT: z.string().optional().default(''),
  SMTP_HOST: z.string().optional().default(''),
  SMTP_PORT: z.coerce.number().int().default(587),
  SMTP_SECURE: bool(false),
  SMTP_USER: z.string().optional().default(''),
  SMTP_PASS: z.string().optional().default(''),
  GOOGLE_CLIENT_ID: z.string().optional().default(''),
  GOOGLE_CLIENT_SECRET: z.string().optional().default(''),
  MICROSOFT_CLIENT_ID: z.string().optional().default(''),
  MICROSOFT_CLIENT_SECRET: z.string().optional().default(''),
  MICROSOFT_TENANT: z.string().default('common'),
  DISCOVERY_MAX_MESSAGES: z.coerce.number().int().positive().max(5000).default(500),
  BREACH_SOURCE: z.enum(['hibp', 'fixture', 'none']).default('hibp'),
  HIBP_API_KEY: z.string().optional().default(''),
  THREAT_PROVIDERS: list('feed,heuristics'),
  THREAT_FEED_URLS: list(''),
  THREAT_FEED_MAX_AGE_HOURS: z.coerce.number().positive().default(24),
  URLHAUS_AUTH_KEY: z.string().optional().default(''),
  GOOGLE_SAFE_BROWSING_KEY: z.string().optional().default(''),
  THREAT_LOOKUP_TIMEOUT_MS: z.coerce.number().int().positive().default(4000),
  ENABLE_DEV_FIXTURES: bool(false),
  ENABLE_DEV_ENTITLEMENTS: bool(false),
  LOG_LEVEL: z.string().default('info'),
});

export type Config = z.infer<typeof schema> & { corsOrigins: string[]; encryptionKey: Buffer | null };

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration: ${issues}`);
  }
  const c = parsed.data;
  let encryptionKey: Buffer | null = null;
  if (c.TOKEN_ENCRYPTION_KEY) {
    encryptionKey = Buffer.from(c.TOKEN_ENCRYPTION_KEY, 'base64');
    if (encryptionKey.length !== 32) throw new Error('TOKEN_ENCRYPTION_KEY must be 32 bytes, base64 encoded');
  }
  if (c.NODE_ENV === 'production') {
    // Development-only switches are refused in production rather than silently ignored.
    if (c.ENABLE_DEV_FIXTURES) throw new Error('ENABLE_DEV_FIXTURES must be false in production');
    if (c.ENABLE_DEV_ENTITLEMENTS) throw new Error('ENABLE_DEV_ENTITLEMENTS must be false in production');
    if (c.EMAIL_PROVIDER === 'devlog') throw new Error('EMAIL_PROVIDER=devlog is not allowed in production');
    if (!c.COOKIE_SECURE) throw new Error('COOKIE_SECURE must be true in production');
    if (!encryptionKey) throw new Error('TOKEN_ENCRYPTION_KEY is required in production');
    if (c.THREAT_PROVIDERS.includes('fixture')) throw new Error('The fixture threat provider is not allowed in production');
    if (c.BREACH_SOURCE === 'fixture') throw new Error('BREACH_SOURCE=fixture is not allowed in production');
  }
  if (c.COOKIE_SAMESITE === 'none' && !c.COOKIE_SECURE) {
    throw new Error('COOKIE_SAMESITE=none requires COOKIE_SECURE=true');
  }
  const corsOrigins = [c.WEB_ORIGIN, ...c.EXTRA_CORS_ORIGINS].map((o) => o.replace(/\/$/, ''));
  return { ...c, corsOrigins, encryptionKey };
}

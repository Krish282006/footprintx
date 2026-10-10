// Test configuration. Uses a dedicated PostgreSQL database (never the dev database).
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgres://footprintx:footprintx_dev_password@localhost:5432/footprintx_test';
process.env.TOKEN_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64');
process.env.EMAIL_PROVIDER = 'devlog';
process.env.CONTACT_RECIPIENT = 'support@footprintx.test';
process.env.BREACH_SOURCE = 'fixture';
process.env.THREAT_PROVIDERS = 'fixture,heuristics';
process.env.THREAT_LOOKUP_TIMEOUT_MS = '300';
process.env.ENABLE_DEV_FIXTURES = 'true';
process.env.ENABLE_DEV_ENTITLEMENTS = 'true';
process.env.WEB_ORIGIN = 'http://localhost:5173';
process.env.API_PUBLIC_URL = 'http://localhost:4000';
process.env.GOOGLE_CLIENT_ID = '';
process.env.GOOGLE_CLIENT_SECRET = '';
process.env.HIBP_API_KEY = '';

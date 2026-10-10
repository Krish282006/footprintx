import pino from 'pino';

// Sensitive fields are redacted from every log line. Request bodies are never logged.
export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  redact: {
    paths: [
      'req.headers.cookie',
      'req.headers.authorization',
      'req.headers["x-csrf-token"]',
      '*.password',
      '*.token',
      '*.accessToken',
      '*.refreshToken',
      '*.access_token',
      '*.refresh_token',
      '*.code',
      '*.secret',
    ],
    censor: '[REDACTED]',
  },
  enabled: process.env.NODE_ENV !== 'test' || process.env.LOG_IN_TESTS === 'true',
});

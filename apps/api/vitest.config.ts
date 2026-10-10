import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    globalSetup: ['test/global-setup.ts'],
    setupFiles: ['test/setup-env.ts'],
    // Tests share one PostgreSQL test database; run files serially for isolation.
    fileParallelism: false,
    testTimeout: 20000,
    hookTimeout: 30000,
  },
});

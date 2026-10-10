import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// In development the API is proxied so the app and API share one origin
// (first-party cookies, no CORS). Production uses the same layout via vercel.json rewrites.
const apiTarget = process.env.FOOTPRINTX_API_PROXY ?? 'http://localhost:4000';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: { '/api': { target: apiTarget, changeOrigin: false } },
  },
  preview: {
    port: 4173,
    proxy: { '/api': { target: apiTarget, changeOrigin: false } },
  },
  build: { sourcemap: false, target: 'es2022' },
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.test.tsx', 'src/**/*.test.ts'],
    setupFiles: ['src/test-setup.ts'],
  },
});

// frontend/vitest.config.ts
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// https://vitest.dev/config/
export default defineConfig({
  plugins: [react()],
  test: {
    // Enable global APIs (describe, it, expect)
    globals: true,
    // Simulate browser environment
    environment: 'jsdom',
    // Run setup file before tests
    setupFiles: './src/setupTests.ts',
    // Optimization: We don't need CSS processing for these logic tests
    css: false,
  },
  // Keep proxy settings if needed for integration tests that might hit the actual backend proxy
  server: {
    proxy: {
      '/ws': {
        target: 'ws://127.0.0.1:8080',
        ws: true,
        changeOrigin: true,
      },
    }
  }
});
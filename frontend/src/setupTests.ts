// src/setupTests.ts
// 4. Add a Testing Strategy: Setup file for Vitest

// Extend expect with jest-dom matchers (e.g., .toBeInTheDocument())
import '@testing-library/jest-dom';

// Mock crypto.randomUUID for the test environment (JSDOM).
// The application relies on this for generating request IDs.
if (!global.crypto || !global.crypto.randomUUID) {
  Object.defineProperty(global, 'crypto', {
    value: {
      ...global.crypto,
      // A simple mock implementation sufficient for testing ID generation
      randomUUID: () => `mock-uuid-${Math.random()}-${Date.now()}`,
    },
    writable: true,
    configurable: true,
  });
}
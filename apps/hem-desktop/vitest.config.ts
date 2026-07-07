import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['tests/unit/**/*.test.ts', 'tests/renderer/**/*.test.ts'],
          environment: 'node',
        },
      },
      {
        test: {
          name: 'integration',
          include: ['tests/integration/**/*.itest.ts'],
          environment: 'node',
          testTimeout: 120_000,
          hookTimeout: 120_000,
          // One daemon, sequential drive of the handler surface.
          fileParallelism: false,
        },
      },
    ],
  },
});

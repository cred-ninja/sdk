import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const packageDir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@credninja/protocol': resolve(packageDir, '../protocol/src/index.ts'),
      '@credninja/link': resolve(packageDir, '../link/src/index.ts'),
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/__tests__/**/*.test.ts'],
  },
});

// Flat ESLint config for cred-ninja/sdk.
//
// This is a deliberately small, high-signal baseline. Its primary jobs are to
// give *authoritative* answers where heuristic scanners get confused:
//   - `@typescript-eslint/no-unused-vars` is real dead-code detection. It
//     understands default-parameter usage, so helpers used only as defaults
//     (e.g. the `default*` functions in guard's express middleware) are
//     correctly seen as USED, not flagged as dead code.
//   - `no-console` keeps stray debug logging out of library code while allowing
//     it where it is intentional (CLIs, server entrypoints, examples, scripts).
//
// Keep it lean. Add rules deliberately; a noisy linter gets ignored.

import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/*.d.ts',
      '**/coverage/**',
      'package-lock.json',
      // The scaffold template ships as-is to end users; lint it in its own repo.
      'packages/create-cred-app/template/**',
    ],
  },
  {
    files: ['**/*.ts', '**/*.mts', '**/*.cts', '**/*.mjs', '**/*.js'],
    languageOptions: {
      parser: tseslint.parser,
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    plugins: { '@typescript-eslint': tseslint.plugin },
    rules: {
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrors: 'none',
        },
      ],
      'no-console': ['error', { allow: ['warn', 'error'] }],
    },
  },
  {
    // Places where writing to stdout is the intended behavior.
    files: [
      '**/*.mjs',
      '**/cli.ts',
      'packages/server/src/server.ts',
      'packages/mcp/src/server.ts',
      'examples/**/*.ts',
      'scripts/**',
    ],
    rules: { 'no-console': 'off' },
  },
  {
    // Test fixtures often define intentionally-unused scaffolding and log freely.
    files: ['**/*.test.ts', '**/__tests__/**'],
    rules: {
      '@typescript-eslint/no-unused-vars': 'off',
      'no-console': 'off',
    },
  },
);

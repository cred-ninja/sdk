#!/usr/bin/env node
// Runs the #419 http-signature-08 vectors against Cred's verifier and writes
// conformance/wimse-419/results-<date>.json. Usage: node scripts/conformance/run-wimse-419.mjs
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const date = new Date().toISOString().slice(0, 10);
const out = path.join(root, 'conformance/wimse-419', `results-${date}.json`);
const run = spawnSync('npx', ['vitest', 'run', 'src/__tests__/conformance-wimse-419.test.ts'], {
  cwd: path.join(root, 'packages/server'),
  env: { ...process.env, WIMSE419_RESULTS: out },
  stdio: 'inherit',
});
if (fs.existsSync(out)) console.log(`${JSON.parse(fs.readFileSync(out, 'utf8')).summary} -> ${path.relative(root, out)}`);
process.exit(run.status ?? 1);

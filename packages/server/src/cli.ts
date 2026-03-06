#!/usr/bin/env node
/**
 * @credninja/server — CLI entry point
 *
 * Loads .env, validates config, initializes vault, starts server.
 */

import fs from 'fs';
import path from 'path';

// Load .env file if present (zero-dep dotenv)
const envPath = path.resolve(process.cwd(), '.env');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let value = trimmed.slice(eqIdx + 1).trim();
    // Strip surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

import { loadConfig } from './config.js';
import { createServer } from './server.js';

async function main() {
  console.log('🔐 Cred Server — credential delegation for AI agents');
  console.log('');

  // Load and validate config
  const config = loadConfig();

  // Ensure data directory exists
  const dataDir = path.dirname(path.resolve(config.vaultPath));
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
    console.log(`📁 Created data directory: ${dataDir}`);
  }

  // Create server and initialize vault
  const { app, vault } = createServer(config);
  await vault.init();

  // Start listening
  app.listen(config.port, config.host, () => {
    console.log(`🚀 Listening on http://${config.host}:${config.port}`);
    console.log('');
    console.log('Configured providers:');
    if (config.providers.length === 0) {
      console.log('  (none) — add provider credentials to .env');
    }
    for (const p of config.providers) {
      console.log(`  ✓ ${p.slug}`);
    }
    console.log('');
    console.log('Endpoints:');
    console.log(`  GET  /health                       — liveness check`);
    console.log(`  GET  /providers                    — list providers + status`);
    console.log(`  GET  /connect/:provider            — start OAuth flow (browser)`);
    console.log(`  GET  /connect/:provider/callback   — OAuth callback`);
    console.log(`  GET  /api/token/:provider          — get delegated token (Bearer auth)`);
    console.log(`  DELETE /api/token/:provider        — revoke token (Bearer auth)`);
    console.log('');
    if (config.host === '127.0.0.1' || config.host === 'localhost') {
      console.log('⚠️  Listening on localhost only. For remote access, set HOST=0.0.0.0');
      console.log('   and place behind a TLS reverse proxy (Caddy recommended).');
    }
  });
}

main().catch((err) => {
  console.error('❌ Failed to start:', err.message ?? err);
  process.exit(1);
});

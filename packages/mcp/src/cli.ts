#!/usr/bin/env node
/**
 * Cred MCP Server — CLI Entry Point
 *
 * Usage: npx @credninja/mcp
 *        npx @credninja/mcp --local
 *
 * Cloud mode (default):
 *   CRED_AGENT_TOKEN   - Agent token for Cred API authentication
 *   CRED_APP_CLIENT_ID - App client ID for delegation requests
 *   CRED_BASE_URL      - Override API base URL (default: https://api.cred.ninja)
 *
 * Local mode (--local flag or CRED_MODE=local):
 *   CRED_VAULT_PASSPHRASE - Passphrase for vault encryption
 *   CRED_VAULT_PATH       - Path to vault file (default: ./cred-vault.json)
 *   CRED_VAULT_STORAGE    - Storage backend: 'sqlite' or 'file' (default: file)
 *   CRED_PROVIDERS        - Provider credentials: "google:clientId:secret,github:clientId:secret"
 */

import { loadConfig } from './config.js';
import { startServer } from './server.js';

async function main(): Promise<void> {
  try {
    const config = loadConfig(process.argv);
    await startServer(config);
  } catch (error) {
    console.error('Failed to start Cred MCP server:', error);
    process.exit(1);
  }
}

main();

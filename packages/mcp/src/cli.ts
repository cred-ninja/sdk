#!/usr/bin/env node
/**
 * Cred MCP Server — CLI Entry Point
 *
 * Usage: npx @credninja/mcp
 *
 * Required environment variables:
 *   CRED_AGENT_TOKEN   - Agent token for Cred API authentication
 *   CRED_APP_CLIENT_ID - App client ID for delegation requests
 *
 * Optional:
 *   CRED_BASE_URL      - Override API base URL (default: https://api.cred.ninja)
 */

import { loadConfig } from './config.js';
import { startServer } from './server.js';

async function main(): Promise<void> {
  try {
    const config = loadConfig();
    await startServer(config);
  } catch (error) {
    console.error('Failed to start Cred MCP server:', error);
    process.exit(1);
  }
}

main();

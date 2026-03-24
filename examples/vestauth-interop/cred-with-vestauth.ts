// Demonstrates: Cred delegation with VestAuth-managed transport signing.
//
// Verified VestAuth commands as of March 23, 2026:
//   vestauth agent init
//   vestauth agent curl <url>
//
// Prerequisites:
//   1. Install and initialize VestAuth:
//      curl -sSf https://vestauth.sh | sh
//      vestauth agent init
//   2. Set CRED_SERVER_URL and CRED_AGENT_TOKEN
//   3. A Google connection already established in Cred
//
// Run:
//   npx tsx examples/vestauth-interop/cred-with-vestauth.ts

import { spawnSync } from 'node:child_process';
import { Cred } from '@credninja/sdk';

async function main() {
  const baseUrl = process.env.CRED_SERVER_URL;
  if (!baseUrl) {
    throw new Error('Set CRED_SERVER_URL to your Cred server URL');
  }

  const agentToken = process.env.CRED_AGENT_TOKEN;
  if (!agentToken) {
    throw new Error('Set CRED_AGENT_TOKEN to a valid Cred agent token');
  }

  const cred = new Cred({ baseUrl, agentToken });
  const delegated = await cred.delegate({
    service: 'google',
    userId: 'default',
    scopes: ['calendar.readonly'],
  });

  const targetUrl = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
  const result = spawnSync(
    'vestauth',
    [
      'agent',
      'curl',
      targetUrl,
      '-H',
      `Authorization: Bearer ${delegated.accessToken}`,
      '-H',
      'Accept: application/json',
    ],
    { stdio: 'inherit' }
  );

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`vestauth agent curl exited with status ${result.status ?? 'unknown'}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

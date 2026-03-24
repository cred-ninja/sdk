// Demonstrates: Cred-native Web Bot Auth plus delegated OAuth access.
//
// Prerequisites:
//   1. A running Cred server with native Web Bot Auth enabled
//   2. CRED_SERVER_URL and CRED_AGENT_TOKEN set
//   3. A Web Bot Auth key registered via POST /api/v1/web-bot-auth/keys
//   4. A Google connection already established in Cred
//
// Run:
//   npx tsx examples/vestauth-interop/cred-native-web-bot-auth.ts

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

  console.log(`Delegated token expires in ${delegated.expiresIn}s`);
  console.log(`Signature-Agent directory: ${new URL('/.well-known/http-message-signatures-directory', baseUrl).toString()}`);
  console.log('Use @credninja/mcp cred_use to send the actual signed outbound request.');
  console.log('This example focuses on the Cred-native identity + delegation setup.');
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

// TODO(aspirational): This example demonstrates only the delegate() half of
// the Web Bot Auth + delegation flow. The outbound signed request is not yet
// implemented here — once @credninja/mcp exposes a programmatic signer, swap
// the final console.log for an actual signed fetch using the directory URL
// printed below. See packages/mcp for the current cred_use surface.
//
// Demonstrates: Cred-native Web Bot Auth plus delegated OAuth access.
//
// Prerequisites:
//   1. A running Cred server with native Web Bot Auth enabled
//   2. CRED_BASE_URL, CRED_AGENT_TOKEN, and CRED_APP_CLIENT_ID set
//   3. A Web Bot Auth key registered via POST /api/v1/web-bot-auth/keys
//   4. A Google connection already established in Cred
//
// Run:
//   npx tsx examples/vestauth-interop/cred-native-web-bot-auth.ts

import { Cred } from '@credninja/sdk';

async function main() {
  const baseUrl = process.env.CRED_BASE_URL;
  if (!baseUrl) {
    throw new Error('Set CRED_BASE_URL to your Cred server URL');
  }

  const agentToken = process.env.CRED_AGENT_TOKEN;
  if (!agentToken) {
    throw new Error('Set CRED_AGENT_TOKEN to a valid Cred agent token');
  }

  const appClientId = process.env.CRED_APP_CLIENT_ID;
  if (!appClientId) {
    throw new Error('Set CRED_APP_CLIENT_ID to your Cred app client ID');
  }

  const cred = new Cred({ baseUrl, agentToken });
  const delegated = await cred.delegate({
    service: 'google',
    userId: 'default',
    appClientId,
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

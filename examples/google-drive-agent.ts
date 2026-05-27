// Demonstrates: agent receives a scoped Google delegation handle via Cred.
// Raw OAuth credentials and provider access tokens never touch the agent host.
//
// Prerequisites:
//   1. A running Cred server (npx @credninja/server) with Google configured
//   2. Google connected via the server's /connect/google endpoint
//   3. CRED_BASE_URL, CRED_AGENT_TOKEN, and CRED_APP_CLIENT_ID environment variables set
//
// Run: npx tsx examples/google-drive-agent.ts

import { Cred } from "@credninja/sdk";

async function main() {
  const baseUrl = process.env.CRED_BASE_URL;
  if (!baseUrl) {
    throw new Error("Set CRED_BASE_URL to your Cred server (e.g. http://localhost:3456)");
  }

  const agentToken = process.env.CRED_AGENT_TOKEN;
  if (!agentToken) {
    throw new Error("Set CRED_AGENT_TOKEN to your agent token (starts with cred_at_)");
  }

  const appClientId = process.env.CRED_APP_CLIENT_ID;
  if (!appClientId) {
    throw new Error("Set CRED_APP_CLIENT_ID to your Cred app client ID");
  }

  const cred = new Cred({
    baseUrl,
    agentToken,
  });

  // Delegate to Google. The returned handle is used through Cred's broker.
  const credential = await cred.delegateHandle({
    service: "google",
    userId: "default",
    appClientId,
    scopes: ["drive.readonly"],
  });

  console.log(`✓ Got Google delegation handle (expires in ${credential.expiresIn}s)`);
  console.log(`  Scopes: ${credential.scopes.join(", ")}`);

  const result = await cred.use({
    delegationId: credential.delegationId,
    url: "https://www.googleapis.com/drive/v3/files?pageSize=10&fields=files(id,name,mimeType)",
    method: "GET",
  });

  if (!result.ok) {
    throw new Error(`Drive API error: ${result.status} ${JSON.stringify(result.body)}`);
  }

  const data = result.body as { files?: Array<{ id: string; name: string; mimeType: string }> };

  console.log(`\nDrive files (${data.files?.length ?? 0}):`);
  for (const file of data.files ?? []) {
    console.log(`  ${file.name} (${file.mimeType})`);
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});

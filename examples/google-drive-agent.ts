// Demonstrates: agent receives a scoped, key-bound Google Delegation Token via Cred.
// Raw OAuth credentials and provider access tokens never touch the agent host.
//
// Prerequisites:
//   1. A running Cred server (npx @credninja/server) with Google configured
//   2. Google connected via the server's /connect/google endpoint
//   3. CRED_BASE_URL, CRED_AGENT_TOKEN, and CRED_APP_CLIENT_ID environment variables set
//
// Run: npx tsx examples/google-drive-agent.ts

import { Cred, generateAgentIdentity } from "@credninja/sdk";

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

  // The Delegation Token is bound to this agent's key (DPoP): only this
  // identity can exercise it, and each call carries a fresh proof.
  const agentIdentity = await generateAgentIdentity();

  // Delegate to Google. The returned token is used through Cred's broker.
  const credential = await cred.delegateHandle({
    service: "google",
    userId: "default",
    appClientId,
    scopes: ["drive.readonly"],
    agentIdentity,
  });

  console.log(`✓ Got Google Delegation Token (expires in ${credential.expiresIn}s)`);
  console.log(`  Scopes: ${credential.scopes.join(", ")}`);

  const result = await cred.use({
    token: credential.token,
    agentIdentity,
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

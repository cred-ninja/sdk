// Demonstrates: agent receives a scoped Google access token via Cred.
// Raw OAuth credentials never touch the agent host.
//
// Prerequisites:
//   1. A running Cred server (npx @credninja/server) with Google configured
//   2. Google connected via the server's /connect/google endpoint
//   3. CRED_SERVER_URL and CRED_AGENT_TOKEN environment variables set
//
// Run: npx tsx examples/google-drive-agent.ts

import { Cred } from "@credninja/sdk";

async function main() {
  const serverUrl = process.env.CRED_SERVER_URL;
  if (!serverUrl) {
    throw new Error("Set CRED_SERVER_URL to your Cred server (e.g. http://localhost:3456)");
  }

  const agentToken = process.env.CRED_AGENT_TOKEN;
  if (!agentToken) {
    throw new Error("Set CRED_AGENT_TOKEN to your agent token (starts with cred_at_)");
  }

  const cred = new Cred({
    baseUrl: serverUrl,
    agentToken,
  });

  // Delegate to Google — Cred handles the token retrieval + refresh
  const credential = await cred.delegate({
    service: "google",
    userId: "default",
  });

  console.log(`✓ Got Google token (expires in ${credential.expiresIn}s)`);
  console.log(`  Scopes: ${credential.scopes.join(", ")}`);

  // Use the delegated token to list Drive files
  const res = await fetch(
    "https://www.googleapis.com/drive/v3/files?pageSize=10&fields=files(id,name,mimeType)",
    {
      headers: {
        Authorization: `Bearer ${credential.accessToken}`,
      },
    }
  );

  if (!res.ok) {
    throw new Error(`Drive API error: ${res.status} ${await res.text()}`);
  }

  const data = await res.json();

  console.log(`\n📁 Drive files (${data.files?.length ?? 0}):`);
  for (const file of data.files ?? []) {
    console.log(`  ${file.name} (${file.mimeType})`);
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});

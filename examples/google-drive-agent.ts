// Demonstrates: agent receives a scoped Google access token via Cred.
// Raw OAuth credentials never touch the agent host.
//
// The agent delegates authentication to Cred, which returns a short-lived
// access token. The agent uses it to call the Google Drive REST API directly.

import { CredClient } from "@credninja/sdk";

async function main() {
  const client = new CredClient({
    serverUrl: process.env.CRED_SERVER_URL ?? "http://localhost:3000",
    agentToken: process.env.CRED_AGENT_TOKEN!,
  });

  // Delegate to Google — Cred handles the OAuth flow and returns a scoped token
  const credential = await client.delegate("google");

  console.log(`✓ Got Google token (expires ${credential.expiresAt})`);
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

  // CLI equivalent:
  // GOOGLE_WORKSPACE_CLI_TOKEN=<token> gws drive files list
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});

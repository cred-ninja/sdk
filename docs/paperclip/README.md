# Paperclip + Cred

This document explains how Cred fits into the current open source `paperclipai/paperclip` model, what Cred adds on top of it, and how to wire the two systems together without pretending Paperclip already has native Cred support.

## What Paperclip Does Today

Current Paperclip OSS is a control plane with:

- bearer agent API keys
- approval and governance workflows enforced by Paperclip itself
- imported company templates such as GStack through the same runtime model

Paperclip core does not currently ship with:

- a native Cred integration
- a built-in MCP-to-Cred bridge
- a first-class plugin surface for credential delegation

That means the right integration shape is a bridge/adapter. GStack is only one company template that runs inside that broader model.

## What Cred Adds

Paperclip can already tell an agent "do not merge until approved." Cred makes that a cryptographic issuance constraint instead of an instruction.

With the Cred bridge in place:

- Paperclip authenticates the calling agent to Cred through `agentRequestVerifier`
- Cred Guard evaluates policy before issuing a delegation
- signed delegation receipts can carry approval claims across an agent handoff
- downstream agents can sub-delegate from a parent receipt instead of sharing raw tokens

The key practical outcome is:

- a Release Engineer can be unable to receive `github:write` authority unless the incoming receipt chain carries `staff-engineer:approved`

## Bridge Model

The clean split is:

- Cred core provides the generic primitives:
  - custom request verification via `agentRequestVerifier`
  - Guard enforcement with `receiptClaimsPolicy`
  - signed receipt chaining via `/api/v1/subdelegate`
  - MCP tools `cred_delegate`, `cred_subdelegate`, and `cred_use`
- the Paperclip adapter provides Paperclip-specific identity mapping:
  - verify a Paperclip agent request
  - map Paperclip agent/company context into a Cred principal
  - attach trusted receipt claims when Paperclip says an approval exists

## How Approval Travels

The important rule is that approval claims must come from trusted bridge state, not model-controlled request bodies.

In this implementation, receipt claims come from:

- trusted verifier metadata on the root delegation request
- an already signed parent receipt during sub-delegation

That means an agent cannot simply self-assert `staff-engineer:approved` in a normal HTTP body and get a write credential.

## Setup

### 1. Run Cred Server With a Paperclip Verifier

Use `@credninja/server` and implement `agentRequestVerifier` with your Paperclip bridge:

```ts
import { createServer } from '@credninja/server';
import { CredGuard, receiptClaimsPolicy } from '@credninja/guard';

const guard = new CredGuard({
  policies: [
    receiptClaimsPolicy({
      perProvider: {
        github: ['staff-engineer:approved'],
      },
    }),
  ],
});

const { app } = createServer({
  port: 3456,
  host: '127.0.0.1',
  vaultPassphrase: process.env.VAULT_PASSPHRASE!,
  vaultStorage: 'sqlite',
  vaultPath: './data/vault.sqlite',
  tofuStorage: 'sqlite',
  tofuPath: './data/tofu.sqlite',
  redirectBaseUri: 'https://cred.example.com',
  providers: [
    {
      slug: 'github',
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      defaultScopes: ['repo'],
    },
  ],
  guard,
  agentRequestVerifier: async (req) => {
    const paperclip = await verifyPaperclipRequest(req);
    if (!paperclip) {
      return { ok: false, status: 401, error: 'invalid paperclip agent' };
    }

    return {
      ok: true,
      principal: {
        type: 'paperclip-bridge',
        principalId: paperclip.agentId,
        metadata: {
          companyId: paperclip.companyId,
          role: paperclip.role,
          receiptClaims: paperclip.approvedByStaff
            ? ['staff-engineer:approved']
            : [],
        },
      },
    };
  },
});
```

`verifyPaperclipRequest(req)` is the adapter-specific part. In current Paperclip OSS, that function is not provided by Paperclip itself. You need to implement it in the bridge layer using the Paperclip identity you actually control.

### 2. Start MCP Inside the Paperclip Agent Runtime

Run Cred MCP in cloud mode from the agent environment:

```json
{
  "mcpServers": {
    "cred": {
      "command": "npx",
      "args": ["-y", "@credninja/mcp"],
      "env": {
        "CRED_BASE_URL": "https://cred.example.com",
        "CRED_AGENT_TOKEN": "paperclip-to-cred-agent-token",
        "CRED_APP_CLIENT_ID": "paperclip",
        "CRED_AGENT_DID": "paperclip:agent:release-engineer"
      }
    }
  }
}
```

`CRED_AGENT_DID` lets Cred return signed receipts for that agent identity. It does not need to be a literal DID from Paperclip core; it just needs to be a stable identifier within the delegation chain.

### 3. Use the Handoff Flow

The MCP flow is:

1. `cred_delegate` gets a delegated token and returns:
   - a local `delegationId` handle for `cred_use`
   - a signed `receipt` when `CRED_AGENT_DID` is configured
2. `cred_subdelegate` takes the parent receipt and child agent identity and returns:
   - a new local `delegationId`
   - a child receipt
   - chain metadata
3. `cred_use` performs the actual upstream API request without exposing the raw OAuth token to the model

## Example Paperclip Flow

For the GStack-style merge gate:

1. Staff Engineer runs review and Paperclip records approval.
2. The Paperclip bridge exposes that approval to Cred as a trusted receipt claim.
3. Staff Engineer receives a signed receipt carrying `staff-engineer:approved`.
4. Release Engineer calls `cred_subdelegate` with that parent receipt.
5. Guard checks the receipt chain before issuing a GitHub-capable delegation.
6. If the claim is missing, issuance fails.

That is the key difference from plain MCP OAuth brokering. The approval survives the handoff because it is part of the signed authority chain.

## Notes on Company Templates

This approach is not GStack-specific. It applies to any company imported through `companies.sh` because those templates run on the same Paperclip control-plane model.

Use GStack as the demo and acceptance fixture. Do not hard-code Cred core around GStack-specific roles or company structure.

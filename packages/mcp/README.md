# @credninja/mcp

MCP server for OAuth2 credential delegation. Secure token brokering for AI agents.

**Your MCP config should be shareable. Credentials shouldn't be in it.**

## Overview

This MCP server enables AI agents running in MCP-compatible runtimes to request delegated OAuth2 access through Cred. Works in two modes:

- **Remote server mode:** calls a Cred server over HTTP. `CRED_BASE_URL` can point to your own self-hosted deployment.
- **Local mode:** uses `@credninja/oauth` + `@credninja/vault` for fully offline, self-contained credential management

## Installation

Run directly with npx (recommended):

```bash
npx @credninja/mcp
```

Or install globally:

```bash
npm install -g @credninja/mcp
cred-mcp
```

## MCP Client Setup

Add to your MCP client configuration:

### Remote Server Mode

```json
{
  "mcpServers": {
    "cred": {
      "command": "npx",
      "args": ["-y", "@credninja/mcp"],
      "env": {
        "CRED_AGENT_TOKEN": "your_agent_token",
        "CRED_AGENT_DID": "did:key:z6Mk...",
        "CRED_AGENT_PRIVATE_KEY_HEX": "your_agent_private_key",
        "CRED_APP_CLIENT_ID": "your_app_client_id",
        "CRED_BASE_URL": "https://cred.example.com"
      }
    }
  }
}
```

The server binds every delegation to this agent's key, and issues nothing until an operator grants the DID a Permission (`POST /admin/permissions`).

### Local Mode

No Cred account needed. Tokens are stored in an encrypted local vault:

```json
{
  "mcpServers": {
    "cred": {
      "command": "npx",
      "args": ["-y", "@credninja/mcp"],
      "env": {
        "CRED_MODE": "local",
        "CRED_VAULT_PASSPHRASE": "your-passphrase",
        "CRED_VAULT_STORAGE": "sqlite",
        "CRED_VAULT_PATH": "./cred-vault.sqlite",
        "CRED_PROVIDERS": "google:your-google-client-id:your-google-client-secret"
      }
    }
  }
}
```

When your MCP client needs your calendar, you approve interactively. The token is brokered at runtime, never in your config file.

## Environment Variables

### Remote Server Mode

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CRED_AGENT_TOKEN` | Yes | | Agent token configured on your Cred server |
| `CRED_AGENT_DID` | Cloud mode | | did:key of the agent. Brokered mode needs it together with `CRED_AGENT_PRIVATE_KEY_HEX`: the Delegation Token is bound to that key |
| `CRED_AGENT_PRIVATE_KEY_HEX` | Cloud mode | | Cloud mode: 32-byte Ed25519 private key (hex) of the did:key in `CRED_AGENT_DID`. `cred_delegate` and `cred_use` sign a DPoP proof with it (servers always require one for agent delegations), and `cred_subdelegate` signs an `actor_token` with it (always required). The key stays in the MCP process |
| `CRED_APP_CLIENT_ID` | Yes | | App client ID expected by your Cred server |
| `CRED_BASE_URL` | Yes (remote mode) | — | Your Cred server URL |
| `CRED_WEB_BOT_AUTH_PRIVATE_KEY_HEX` | No | | Raw 32-byte Ed25519 private key in hex. Enables native Web Bot Auth signing |
| `CRED_WEB_BOT_AUTH_SIGNATURE_AGENT` | No | | HTTPS URL for the agent's `Signature-Agent` directory |
| `CRED_WEB_BOT_AUTH_TTL_SECONDS` | No | `30` | Signature lifetime in seconds. Must be between `1` and `300` |

### Local Mode

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CRED_MODE` | Yes | | Set to `local` |
| `CRED_VAULT_PASSPHRASE` | Yes | | Passphrase for encrypted local vault |
| `CRED_VAULT_PATH` | No | `./cred-vault.json` | Path to the local vault file |
| `CRED_VAULT_STORAGE` | No | `file` | `file` or `sqlite` |
| `CRED_PROVIDERS` | No | | Comma-separated provider credentials, for example `google:clientId:clientSecret,github:clientId:clientSecret` |

## What the Agent Can Do

Once connected, your MCP-compatible agent has access to four tools:

### `cred_delegate`

Get delegated OAuth access for a user's connected service.

**Input:**
- `user_id` (string, required): The user to delegate for
- `service` (string, required): Service name. One of `google`, `github`, `slack`, `notion`, `salesforce`.
- `scopes` (string[], optional): OAuth scopes to request

**Returns:** A local delegation handle and expiry, or a consent URL if the user hasn't authorized yet. In remote server mode the local handle maps to a server-held, key-bound Delegation Token, so provider tokens are not cached by MCP.

### `cred_subdelegate`

Create a child delegation from a signed parent receipt.

**Input:**
- `parent_receipt` (string, required): Signed parent delegation receipt
- `agent_did` (string, required): Stable identifier for the child agent
- `user_id` (string, required): The user to delegate for
- `service` (string, required): Service slug
- `scopes` (string[], optional): Optional subset of the parent scopes

**Returns:** A local delegation handle, a child receipt, and chain metadata.

### `cred_status`

List a user's connected services and granted scopes.

**Input:**
- `user_id` (string, required): User identifier to check connections for

**Returns:** List of connected services with their granted scopes.

### `cred_revoke`

Revoke a user's connection to a service.

**Input:**
- `user_id` (string, required): User identifier whose connection to revoke
- `service` (string, required): Service slug to revoke

**Returns:** Confirmation message.

### Policy weight-space tools (`cred_policy_inspect`, `cred_policy_propose`, `cred_policy_apply`)

Present only when the server is started with a `policyEditor` (a
`PolicyWeightSpaceEditor` from `@credninja/guard` bound to the same `guard`).
Without one, none of the three is listed.

- `cred_policy_inspect` returns the guard's policy chain as a hashed snapshot,
  a plain-language interpretation of what each provider may do, and findings
  where the chain disagrees with recent decisions, each with the smallest
  patch that addresses it. Read-only; like `cred_whoami` it is never
  guard-wrapped, so it works during a guard outage. `include` selects
  sections.
- `cred_policy_propose` takes `patch` (JSON Pointer ops such as
  `{ "op": "remove", "path": "/scope-filter/allowedScopes/github/2" }`) and
  `rationale`, and returns a proposal: its id and hash, the snapshot hash it
  applies to, its effect (widening, narrowing, neutral, unknown, mixed), its
  magnitude (parameters touched over total) and a replay of recorded
  decisions showing which would flip. It never changes the guard.
- `cred_policy_apply` takes `proposal_id` and `approvals`. By default every
  patch needs an Ed25519-signed approval from a configured approver, made
  outside the agent with `signProposal()`; the agent carries it and cannot
  forge it. A proposal written against a chain that has since changed is
  refused with `base_mismatch`.

```typescript
import { CredGuard, rateLimitPolicy, scopeFilterPolicy, PolicyWeightSpaceEditor } from '@credninja/guard';
import { createCredMcpServer } from '@credninja/mcp';

const guard = new CredGuard({
  policies: [rateLimitPolicy({ maxRequests: 60, windowMs: 60_000 }), scopeFilterPolicy({ allowedScopes: { github: ['repo'] } })],
  decisionHistorySize: 1000,
});
const policyEditor = new PolicyWeightSpaceEditor(guard, {
  approvers: [{ id: 'ops', publicKey: process.env.POLICY_APPROVER_PUBLIC_KEY_PEM! }],
  requireApprovalFor: 'widening', // the agent may tighten its own guard unsigned, never loosen it
});

const server = createCredMcpServer({ ...config, guard, policyEditor });
```

## Example Conversation

Here's what it looks like when an MCP client uses the Cred MCP server:

```
User: Check my Google Calendar for tomorrow's meetings

Assistant: I'll get access to your Google Calendar and check tomorrow's meetings.

        [Calling cred_delegate with service="google", user_id="user_123",
         scopes=["calendar.readonly"]]

        Got delegation handle (expires in 3600s)

        [Calling cred_use with the delegation handle...]

        Here are your meetings for tomorrow:
        • 9:00 AM - Team standup (30 min)
        • 2:00 PM - Product review (1 hour)
        • 4:30 PM - 1:1 with Sarah (30 min)
```

If the user hasn't connected their Google account yet:

```
User: Check my Google Calendar for tomorrow

Assistant: I'll need access to your Google Calendar.

        [Calling cred_delegate with service="google", user_id="user_123"]

        It looks like you haven't connected your Google account yet.
        Please visit this link to authorize:

        https://cred.example.com/connect/google?request=...

        Once you've authorized, let me know and I'll check your calendar.
```

## How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│  @credninja/mcp │────▶│   Cred API      │
│                 │     │  (local server) │     │ (your server)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌─────────────────┐
                        │  Google/GitHub/ │
                        │  Slack/etc API  │
                        └─────────────────┘
```

1. Your MCP client starts the MCP server locally via npx
2. When the agent needs a credential, it calls `cred_delegate`
3. If authority needs to move across agents, it calls `cred_subdelegate`
4. The MCP server calls the Cred API with your agent token
5. Cred returns a Delegation Token bound to the agent's key, within its Permission, and a signed receipt. The token stays in this process
6. The agent uses the local delegation handle with `cred_use`, and each call is checked against what was granted

## Programmatic Usage

```typescript
import { createCredMcpServer, loadConfig } from '@credninja/mcp';

const config = loadConfig();
const server = createCredMcpServer(config);
```

## Security

- Agent tokens are scoped to your app and can only access users who have consented
- Delegations are short-lived and scoped to the requested permissions
- In remote server mode, provider access tokens stay on the Cred server and `cred_use` brokers calls through it
- In local mode, the MCP server runs locally and keeps delegated access tokens only in its in-process cache
- `cred_use` checks each call against the delegation's scopes in both modes: at the server in remote mode, and in this process in local mode, with the same refusals (`operation_not_mapped`, `scope_insufficient`). It does not follow upstream redirects. `CRED_ALLOW_UNCLASSIFIED_BROKER_CALLS=true` turns this off in local mode: it is deprecated, warns at startup and marks audit events
- Refresh tokens are never exposed to agents
- Local mode: AES-256-GCM encryption with PBKDF2 key derivation for vault storage

## Native Web Bot Auth Signing

If `CRED_WEB_BOT_AUTH_PRIVATE_KEY_HEX` and `CRED_WEB_BOT_AUTH_SIGNATURE_AGENT` are set, MCP adds native Web Bot Auth headers:

- Remote server mode: on requests from MCP to the Cred server, including brokered `cred_use`
- Local mode: on outbound API requests made directly by local `cred_use`

- `Signature`
- `Signature-Input`
- `Signature-Agent`

This makes MCP mode the first Cred execution path that can speak Web Bot Auth directly. If those variables are not set, `cred_use` behaves exactly as before.

`cred_use` strips caller-supplied auth, signature, host, cookie, proxy, forwarding, and hop-by-hop headers before signing or forwarding so the LLM cannot spoof transport identity or framing, and refuses a method override in the query, the headers or the body.

## Deployment Modes

Use local mode for single-user tools and offline workflows. Use remote server mode when you want a separate self-hosted broker, shared policy enforcement, or central OAuth connection management for multiple agents.

## License

Apache License 2.0

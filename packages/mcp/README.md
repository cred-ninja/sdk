# @credninja/mcp

MCP server for OAuth2 credential delegation. Secure token brokering for AI agents.

**Your MCP config should be shareable. Credentials shouldn't be in it.**

## Overview

This MCP server enables AI agents running in MCP-compatible runtimes to request delegated OAuth2 access tokens through Cred. Works in two modes:

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
        "CRED_AGENT_DID": "agent:release-engineer",
        "CRED_APP_CLIENT_ID": "your_app_client_id",
        "CRED_BASE_URL": "https://cred.example.com"
      }
    }
  }
}
```

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
        "VAULT_PASSPHRASE": "your-passphrase",
        "GOOGLE_CLIENT_ID": "...",
        "GOOGLE_CLIENT_SECRET": "..."
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
| `CRED_AGENT_DID` | No | | Stable agent identifier used when Cred should return signed delegation receipts |
| `CRED_APP_CLIENT_ID` | Yes | | App client ID expected by your Cred server |
| `CRED_BASE_URL` | Yes (remote mode) | — | Your Cred server URL |
| `CRED_WEB_BOT_AUTH_PRIVATE_KEY_HEX` | No | | Raw 32-byte Ed25519 private key in hex. Enables native Web Bot Auth signing for `cred_use` |
| `CRED_WEB_BOT_AUTH_SIGNATURE_AGENT` | No | | HTTPS URL for the agent's `Signature-Agent` directory |
| `CRED_WEB_BOT_AUTH_TTL_SECONDS` | No | `30` | Signature lifetime in seconds. Must be between `1` and `300` |

### Local Mode

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CRED_MODE` | Yes | | Set to `local` |
| `VAULT_PASSPHRASE` | Yes | | Passphrase for encrypted local vault |
| `{PROVIDER}_CLIENT_ID` | Yes | | OAuth client ID per provider |
| `{PROVIDER}_CLIENT_SECRET` | Yes | | OAuth client secret per provider |

## What the Agent Can Do

Once connected, your MCP-compatible agent has access to four tools:

### `cred_delegate`

Get an OAuth access token for a user's connected service.

**Input:**
- `user_id` (string, required): The user to delegate for
- `service` (string, required): Service name. One of `google`, `github`, `slack`, `notion`, `salesforce`.
- `scopes` (string[], optional): OAuth scopes to request

**Returns:** Access token and expiry, or a consent URL if the user hasn't authorized yet.

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

## Example Conversation

Here's what it looks like when an MCP client uses the Cred MCP server:

```
User: Check my Google Calendar for tomorrow's meetings

Assistant: I'll get access to your Google Calendar and check tomorrow's meetings.

        [Calling cred_delegate with service="google", user_id="user_123",
         scopes=["calendar.readonly"]]

        ✓ Got access token (expires in 3600s)

        [Calling Google Calendar API with the delegated token...]

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

        https://cred.example.com/connect/google?app_client_id=...

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
5. Cred returns a delegated access token and, when configured with `CRED_AGENT_DID`, a signed receipt
6. The agent uses the local delegation handle with `cred_use` to call the service API

## Programmatic Usage

```typescript
import { createCredMcpServer, loadConfig } from '@credninja/mcp';

const config = loadConfig();
const server = createCredMcpServer(config);
```

## Security

- Agent tokens are scoped to your app and can only access users who have consented
- Access tokens are short-lived and scoped to the requested permissions
- The MCP server runs locally. Credentials never leave your machine except to call APIs.
- Refresh tokens are never exposed to agents
- Local mode: AES-256-GCM encryption with PBKDF2 key derivation for vault storage

## Native Web Bot Auth Signing

If `CRED_WEB_BOT_AUTH_PRIVATE_KEY_HEX` and `CRED_WEB_BOT_AUTH_SIGNATURE_AGENT` are set, `cred_use` adds native Web Bot Auth headers on outbound API requests:

- `Signature`
- `Signature-Input`
- `Signature-Agent`

This makes MCP mode the first Cred execution path that can speak Web Bot Auth directly. If those variables are not set, `cred_use` behaves exactly as before.

`cred_use` strips any caller-supplied `Authorization`, `Signature`, `Signature-Input`, and `Signature-Agent` headers before signing so the LLM cannot spoof or override the final transport identity.

## Deployment Modes

Use local mode for single-user tools and offline workflows. Use remote server mode when you want a separate self-hosted broker, shared policy enforcement, or central OAuth connection management for multiple agents.

## License

Apache License 2.0

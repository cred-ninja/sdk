# @credninja/mcp

MCP server for OAuth2 credential delegation. Secure token brokering for Claude Desktop and AI agents.

**Your MCP config should be shareable. Credentials shouldn't be in it.**

## Overview

This MCP server enables AI agents running in Claude Desktop (or any MCP-compatible runtime) to request delegated OAuth2 access tokens through Cred. Works in two modes:

- **Cloud mode:** calls the hosted Cred API for managed delegation, multi-tenant storage, and audit trails
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

## Claude Desktop Setup

Add to your Claude Desktop configuration:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

### Cloud Mode

```json
{
  "mcpServers": {
    "cred": {
      "command": "npx",
      "args": ["-y", "@credninja/mcp"],
      "env": {
        "CRED_AGENT_TOKEN": "your_agent_token",
        "CRED_APP_CLIENT_ID": "your_app_client_id"
      }
    }
  }
}
```

Get your `CRED_AGENT_TOKEN` and `CRED_APP_CLIENT_ID` from the [Cred Dashboard](https://cred.ninja/dashboard).

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

When Claude needs your calendar, you approve interactively. The token is brokered at runtime, never in your config file.

## Environment Variables

### Cloud Mode

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CRED_AGENT_TOKEN` | Yes | | Agent token from Cred dashboard |
| `CRED_APP_CLIENT_ID` | Yes | | App client ID from Cred dashboard |
| `CRED_BASE_URL` | No | `https://api.cred.ninja` | Cred API base URL |

### Local Mode

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CRED_MODE` | Yes | | Set to `local` |
| `VAULT_PASSPHRASE` | Yes | | Passphrase for encrypted local vault |
| `{PROVIDER}_CLIENT_ID` | Yes | | OAuth client ID per provider |
| `{PROVIDER}_CLIENT_SECRET` | Yes | | OAuth client secret per provider |

## What the Agent Can Do

Once connected, Claude (or any MCP-compatible agent) has access to three tools:

### `cred_delegate`

Get an OAuth access token for a user's connected service.

**Input:**
- `user_id` (string, required): The user to delegate for
- `service` (string, required): Service name. One of `google`, `github`, `slack`, `notion`, `salesforce`.
- `scopes` (string[], optional): OAuth scopes to request

**Returns:** Access token and expiry, or a consent URL if the user hasn't authorized yet.

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

Here's what it looks like when Claude Desktop uses the Cred MCP server:

```
User: Check my Google Calendar for tomorrow's meetings

Claude: I'll get access to your Google Calendar and check tomorrow's meetings.

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

Claude: I'll need access to your Google Calendar.

        [Calling cred_delegate with service="google", user_id="user_123"]

        It looks like you haven't connected your Google account yet.
        Please visit this link to authorize:

        https://cred.ninja/connect/google?app_client_id=...

        Once you've authorized, let me know and I'll check your calendar.
```

## How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude Desktop │────▶│  @credninja/mcp │────▶│   Cred API      │
│                 │     │  (local server) │     │ (api.cred.ninja)│
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌─────────────────┐
                        │  Google/GitHub/ │
                        │  Slack/etc API  │
                        └─────────────────┘
```

1. Claude Desktop starts the MCP server locally via npx
2. When the agent needs a credential, it calls `cred_delegate`
3. The MCP server calls the Cred API with your agent token
4. Cred returns a delegated access token (or consent URL)
5. The agent uses the token to call the service API

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

## Upgrade to Cred Cloud

Local mode is perfect for single-user setups and development. When you need multi-tenant storage, managed token refresh, audit logs, and enterprise-grade isolation, check out [cred.ninja](https://cred.ninja). Same MCP server, managed infrastructure.

## License

MIT

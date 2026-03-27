# Cred

[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](./LICENSE)
[![npm](https://img.shields.io/npm/v/@credninja/sdk)](https://www.npmjs.com/package/@credninja/sdk)
[![GitHub stars](https://img.shields.io/github/stars/cred-ninja/sdk)](https://github.com/cred-ninja/sdk)
[![Website](https://img.shields.io/badge/website-cred.ninja-00ff88)](https://cred.ninja)

**OAuth2 credential delegation for AI agents. Tokens are brokered, never exposed.**

*Delegation, not exposure.*

Cred is credential delegation middleware for AI agents. When your agent needs to access a user's Google Calendar, Slack workspace, or GitHub repos, Cred validates the agent's identity, checks that the user consented, and returns a short-lived access token. Refresh tokens never leave the vault. Three lines of code to integrate. Works with your existing auth provider.

## Why Cred?

AI agents need to access user accounts (Google Calendar, Slack, GitHub, Notion), but there's no standard way to do it securely:

- **2,000+ MCP servers** store OAuth tokens in plaintext config files
- **No standard exists** for agents to request scoped, short-lived user credentials
- **OWASP ranks Identity & Privilege Abuse** as the #3 agentic AI risk
- Users can't see what agents accessed, or revoke access without revoking everything

Existing solutions don't fit:

| Alternative | Problem |
|-------------|---------|
| **Tokens in config files** | Insecure by default. One leaked config = full account access. No scoping, no expiry. |
| **HashiCorp Vault** | Built for infrastructure secrets (DB passwords), not user-delegated OAuth tokens. |
| **Auth0 Token Vault** | Auth0-only, $1,500+/mo, enterprise sales cycle. |
| **Roll your own OAuth** | 2+ months of plumbing per app. Token rotation, PKCE, refresh handling, per-provider quirks. |

Cred is the missing layer: a credential delegation broker that handles OAuth token lifecycle so agents get short-lived access and users stay in control.

## Quickstart

### 1. Fastest: Create an App

```bash
npx create-cred-app my-cred-server
cd my-cred-server
npm start
```

Open [http://localhost:3456/connect](http://localhost:3456/connect) to connect OAuth providers. Give your agent the token from `.env`.

### 2. Self-Hosted Server

```bash
npm install @credninja/server
npx cred-server
```

Configure providers via environment variables. See the [server docs](./packages/server) for Docker, HTTPS, and two-machine production setups.

### 3. Local OAuth + Vault

No server needed. Run OAuth + encrypted vault in your own process:

```typescript
import { OAuthClient, GoogleAdapter } from '@credninja/oauth';
import { createVault } from '@credninja/vault';

// 1. OAuth flow
const google = new OAuthClient({
  adapter: new GoogleAdapter(),
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: 'http://localhost:3000/callback',
});
const { url, state, codeVerifier } = await google.getAuthorizationUrl({
  scopes: ['calendar.readonly'],
});
// redirect user to `url`, handle callback to get `code`
const tokens = await google.exchangeCode({ code, codeVerifier });

// 2. Encrypted vault
const vault = await createVault({
  passphrase: process.env.VAULT_PASSPHRASE!,
  storage: 'sqlite',
  path: './cred-vault.db',
});
await vault.store({
  provider: 'google', userId: 'user-123',
  accessToken: tokens.access_token,
  refreshToken: tokens.refresh_token,
  expiresAt: new Date(Date.now() + tokens.expires_in * 1000),
  scopes: ['calendar.readonly'],
});

// 3. Retrieve (auto-decrypts)
const creds = await vault.get({ provider: 'google', userId: 'user-123' });
```

### 4. MCP Server

Your MCP config should be shareable. Credentials shouldn't be in it.

```json
{
  "mcpServers": {
    "cred": {
      "command": "npx",
      "args": ["-y", "@credninja/mcp"],
      "env": {
        "VAULT_PASSPHRASE": "your-passphrase",
        "GOOGLE_CLIENT_ID": "your-google-client-id",
        "GOOGLE_CLIENT_SECRET": "your-google-client-secret"
      }
    }
  }
}
```

When your MCP client needs your calendar, you approve interactively. The token is brokered at runtime, never stored in your config file.

## How It Works

1. **User consents** once, via a standard OAuth flow
2. **Cred stores the refresh token** encrypted at rest (AES-256-GCM), never returned to agents
3. **Agent requests access.** Cred validates identity, checks consent, returns a fresh short-lived token
4. **Token is used and discarded.** Your agent never persists credentials

## Packages

### Core

| Package | Description | Install |
|---------|-------------|---------|
| [`@credninja/oauth`](./packages/oauth) | Zero-dep OAuth2 client. 7 provider adapters, PKCE, Express middleware | `npm i @credninja/oauth` |
| [`@credninja/vault`](./packages/vault) | Encrypted local token vault. AES-256-GCM, SQLite or file storage | `npm i @credninja/vault` |
| [`@credninja/sdk`](./packages/sdk) | Credential delegation SDK for self-hosted servers or standalone use | `npm i @credninja/sdk` |
| [`@credninja/server`](./packages/server) | Self-hosted credential server. Express, Docker, admin UI | `npm i @credninja/server` |
| [`@credninja/guard`](./packages/guard) | Policy engine for delegation guardrails. Rate limits, scope filtering, time windows, URL allowlists | `npm i @credninja/guard` |
| [`@credninja/mcp`](./packages/mcp) | MCP server for MCP-compatible runtimes | `npx @credninja/mcp` |
| [`create-cred-app`](./packages/create-cred-app) | Scaffold a self-hosted Cred server in seconds | `npx create-cred-app` |
| [`cred-auth`](./packages/sdk-python) | Python SDK | `pip install cred-auth` |

### Framework Integrations

| Package | Framework | Install |
|---------|-----------|---------|
| [`@credninja/ai`](./packages/integrations/vercel-ai) | Vercel AI SDK | `npm i @credninja/ai` |
| [`cred-langchain`](./packages/integrations/langchain) | LangChain | `pip install cred-langchain` |
| [`cred-crewai`](./packages/integrations/crewai) | CrewAI | `pip install cred-crewai` |
| [`cred-openai-agents`](./packages/integrations/openai-agents) | OpenAI Agents SDK | `pip install cred-openai-agents` |
| [`cred-autogen`](./packages/integrations/autogen) | Microsoft AutoGen | `pip install cred-autogen` |
| [`cred-semantic-kernel`](./packages/integrations/semantic-kernel) | Microsoft Semantic Kernel | `pip install cred-semantic-kernel` |

## Supported Services

| Service | Scopes | PKCE |
|---------|--------|------|
| Google | Gmail, Calendar, Drive, all Google OAuth scopes | S256 |
| GitHub | repo, read:user, all GitHub OAuth scopes | |
| Slack | channels:read, chat:write, all Slack OAuth scopes | |
| Notion | read_content, update_content, all Notion OAuth scopes | |
| Salesforce | api, refresh_token, all Salesforce OAuth scopes | S256 |
| Linear | read, write, issues:create, comments:create, admin | S256 |
| HubSpot | crm.objects.contacts.read/write, content, automation, all HubSpot OAuth scopes | |

Need a provider that's not listed? [Adding an adapter](./CONTRIBUTING.md#adding-an-oauth-provider-adapter) is the most common contribution.

## Security

- **AES-256-GCM encryption.** All refresh tokens encrypted at rest with per-account key isolation.
- **PKCE (RFC 7636).** S256 challenge for all providers that support it.
- **PBKDF2-SHA256.** 100,000 iteration key derivation for local vault.
- **Append-only audit trail.** Cryptographic delegation receipts (Ed25519 JWS).
- **Per-account isolation.** Cross-account access requires possession of the account DEK.
- **Zero runtime dependencies.** TypeScript SDK and OAuth package use only Node.js built-ins.
- **Pre-launch audits.** 6 security audits documented in [SECURITY-AUDITS.md](./SECURITY-AUDITS.md).

## Guard — Policy Engine

[`@credninja/guard`](./packages/guard) adds runtime guardrails to credential delegation. Composable policies that run before any token is issued.

```typescript
import { CredGuard, rateLimitPolicy, scopeFilterPolicy, timeWindowPolicy } from '@credninja/guard';

const guard = new CredGuard({
  policies: [
    rateLimitPolicy({ maxRequests: 10, windowMs: 60_000 }),
    scopeFilterPolicy({
      allowedScopes: {
        google: ['calendar.readonly', 'gmail.readonly'],
        github: ['repo', 'read:user'],
      },
    }),
    timeWindowPolicy({ allowedHours: { start: 9, end: 17 }, timezone: 'America/New_York' }),
  ],
});

// Wire into @credninja/server
const { app } = createServer({ ...config, guard });

// Or wrap MCP tool handlers
const guardedHandler = guard.wrapMcpTool(handleUse);
```

**Built-in policies:** rate limiting (per agent per provider), scope filtering (deny-by-default), time windows (IANA timezone), URL allowlists (prefix + regex), max TTL caps. Write custom policies with a single `evaluate()` method.

**Policy chain:** first DENY short-circuits, no policies = ALLOW (opt-in), errors = DENY (fail-closed). Every decision produces an Ed25519-compatible audit event.

## What Cred Is NOT

- **Not an auth provider.** Cred never handles login. It receives verified identity from your existing provider (WorkOS, Supabase, Clerk, NextAuth) and manages outbound credential lifecycle from there.
- **Not a vault/secret manager.** HashiCorp Vault manages infrastructure secrets (DB passwords, API keys you own). Cred manages user-delegated OAuth tokens: credentials users grant to your agent.
- **Not primarily an API proxy.** Core Cred delegation is not in the hot path of upstream API calls. The main exception is signed execution paths such as MCP `cred_use`, where Cred can add Web Bot Auth headers before the upstream request is sent.

## Web Bot Auth

Cred now supports Cloudflare-style Web Bot Auth as a transport identity layer on top of credential delegation:

- `@credninja/server` can host a signed `/.well-known/http-message-signatures-directory`
- `@credninja/server` can verify inbound signed-agent requests
- `@credninja/mcp` can emit signed outbound requests
- `@credninja/sdk` can manage Web Bot Auth keys and create signed requests

Use Web Bot Auth for "who sent this request?" and Cred for "what user-delegated credential is this agent allowed to use?"

Docs:

- [Docs index](./docs/README.md)
- [Web Bot Auth overview](./docs/web-bot-auth.md)
- [Cloudflare submission checklist](./docs/cloudflare-submission-checklist.md)
- [TOFU proof of possession](./docs/tofu-proof-of-possession.md)

## Standalone First

Use `@credninja/oauth` + `@credninja/vault` for full local control. No account needed, no cloud dependency. Apache 2.0 licensed. Your credentials stay on your machine.

## Self-Hosting

This repo (Apache 2.0) contains all SDKs, the OAuth toolkit, the local vault, and all framework integrations. The standalone packages (`@credninja/oauth` + `@credninja/vault`) give you everything you need to run credential delegation locally or on your own infrastructure.

For production deployments, [`@credninja/server`](./packages/server) includes Docker Compose, Caddy HTTPS, and two-machine isolation guides.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). SDK, integration, and documentation contributions welcome.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability disclosure. Pre-launch security audits documented in [SECURITY-AUDITS.md](./SECURITY-AUDITS.md).

## License

Apache License 2.0. See [LICENSE](./LICENSE). Trademarks are covered separately in [TRADEMARKS.md](./TRADEMARKS.md).

---

⭐ **Star this repo** if credential delegation for AI agents matters to you.

[Read the docs](https://cred.ninja/docs) · [Browse the repo](https://github.com/cred-ninja/sdk) · [View the roadmap](https://cred.ninja/roadmap)

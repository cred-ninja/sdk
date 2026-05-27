# My Cred Server

Self-hosted credential delegation for AI agents, powered by [@credninja/server](https://github.com/cred-ninja/sdk/tree/main/packages/server).

## Quick Start

```bash
npm start
```

Then open `http://localhost:3456/admin/login` and sign in with `ADMIN_TOKEN` from `.env` to manage OAuth providers.

## Configuration

Edit `.env` to configure:

- **VAULT_PASSPHRASE** — Encryption key for stored tokens (auto-generated, don't lose it)
- **ADMIN_TOKEN** — Token for provider-management browser routes
- **AGENT_TOKEN** — Token your AI agents use to request credentials
- **Provider credentials** — OAuth client ID/secret for each provider

## Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /admin/login` | None | Admin login form |
| `GET /connect` | Admin | Admin UI for managing providers |
| `GET /connect/:provider` | Admin | Start OAuth flow |
| `POST /api/v1/delegate` | Bearer | Get a brokered handle or short-lived access token |
| `POST /api/v1/use` | Bearer | Broker an upstream API call with a delegation handle |
| `GET /api/v1/connections` | Bearer | List stored provider connections |
| `DELETE /api/v1/connections/:provider` | Bearer | Revoke a stored provider connection |
| `GET /api/token/:provider` | Bearer | Compatibility token route |
| `DELETE /api/token/:provider` | Bearer | Revoke stored credentials |
| `GET /health` | None | Health check |
| `GET /providers` | Admin | List available providers |

## Docker Deployment

See [@credninja/server docs](https://github.com/cred-ninja/sdk/tree/main/packages/server#docker) for Docker + Caddy deployment.

## Docs

[cred.ninja/docs](https://cred.ninja/docs)

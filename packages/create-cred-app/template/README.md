# My Cred Server

Self-hosted credential delegation for AI agents, powered by [@credninja/server](https://github.com/cred-ninja/sdk/tree/main/packages/server).

## Quick Start

```bash
npm start
```

Then open [http://localhost:3456/connect](http://localhost:3456/connect) to manage OAuth providers.

## Configuration

Edit `.env` to configure:

- **VAULT_PASSPHRASE** — Encryption key for stored tokens (auto-generated, don't lose it)
- **AGENT_TOKEN** — Token your AI agents use to request credentials
- **Provider credentials** — OAuth client ID/secret for each provider

## Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /connect` | None | Admin UI for managing providers |
| `GET /connect/:provider` | None | Start OAuth flow |
| `GET /api/token/:provider` | Bearer | Get access token (agent-facing) |
| `DELETE /api/token/:provider` | Bearer | Revoke stored credentials |
| `GET /health` | None | Health check |
| `GET /providers` | None | List available providers |

## Docker Deployment

See [@credninja/server docs](https://github.com/cred-ninja/sdk/tree/main/packages/server#docker) for Docker + Caddy deployment.

## Docs

[cred.ninja/docs](https://cred.ninja/docs)

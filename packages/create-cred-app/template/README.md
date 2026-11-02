# My Cred Server

Self-hosted credential delegation for AI agents, powered by [@credninja/server](https://github.com/cred-ninja/sdk/tree/main/packages/server).

## Quick Start

```bash
npm start
```

Then:

1. Add a provider's OAuth credentials to `.env` and restart.
2. Open `http://localhost:3456/admin/login`, sign in with `ADMIN_TOKEN` from `.env`, and connect the provider for a user.
3. Grant your agent what it may do. An agent with no Permission is issued nothing:

   ```bash
   npm run grant -- github github.read
   ```

4. Give your agent `agent.env`: the server URL, the agent token and a new agent identity, generated for this app.

Agents get what they are granted, and each brokered call is checked against it: under `github.read` a read reaches GitHub and a write is refused. See [operation enforcement](https://github.com/cred-ninja/sdk/tree/main/packages/server#operation-enforcement).

## Configuration

Edit `.env` to configure:

- **VAULT_PASSPHRASE** — Encryption key for stored tokens (auto-generated, don't lose it)
- **ADMIN_TOKEN** — Token for provider-management browser routes
- **AGENT_TOKEN** — Token your AI agents use to request credentials
- **SINGLE_USER_MODE**: `false` (generated): every request names `user_id`. Set `true` only when the server holds one person's accounts; requests without `user_id` then act on the shared user `default`
- **Provider credentials** — OAuth client ID/secret for each provider

`agent.env` holds what your agent needs and the server does not, including the agent's private key. Keep it with the agent.

## Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /admin/login` | None | Admin login form |
| `GET /connect` | Admin | Admin UI for managing providers |
| `GET /connect/:provider` | Admin | Start OAuth flow (from a connect request link) |
| `POST /connect/:provider/start` | Admin | Mint a connect request for `{ user_id, scopes }` |
| `POST /admin/permissions` | Admin | Grant an agent scopes on a service (`npm run grant`) |
| `DELETE /admin/permissions/:id` | Admin | Revoke it: the agent's delegations end, and it gets nothing new until granted again |
| `POST /api/v1/delegate` | Bearer + DPoP | Get a Delegation Token bound to the agent's did:key (`agent_did` and a `DPoP` proof by that key) |
| `POST /api/v1/use` | `DPoP <token>` + DPoP | Broker an upstream API call with a Delegation Token and a fresh DPoP proof (`ath` = SHA-256 of the token) |
| `GET /api/v1/connections` | Bearer | List stored provider connections |
| `DELETE /api/v1/connections/:provider` | Bearer | Revoke a stored provider connection |
| `GET /api/token/:provider` | Bearer | Compatibility token route, off unless `CRED_ALLOW_RAW_TOKENS=true` (deprecated) |
| `DELETE /api/token/:provider` | Bearer | Revoke stored credentials |
| `GET /health` | None | Health check |
| `GET /providers` | Admin | List available providers |

## Docker Deployment

See [@credninja/server docs](https://github.com/cred-ninja/sdk/tree/main/packages/server#docker) for Docker + Caddy deployment.

## Docs

[cred.ninja/docs](https://cred.ninja/docs)

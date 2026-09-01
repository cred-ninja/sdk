# @credninja/server

Self-hosted credential delegation server for AI agents.

Stores OAuth tokens in an encrypted vault and can either serve delegated access tokens to authenticated agents or broker upstream API calls behind opaque delegation handles.

## Quick Start

```bash
# Install
npm install @credninja/server

# Set up configuration
cp node_modules/@credninja/server/.env.example .env
# Edit .env — set VAULT_PASSPHRASE, ADMIN_TOKEN, AGENT_TOKEN, and at least one provider

# Run
npx cred-server
```

Or from the repo:

```bash
cd packages/server
cp .env.example .env
# Edit .env
npm run dev
```

## How It Works

```
┌─────────────────┐         ┌──────────────────────┐         ┌─────────────┐
│   AI Agent      │  HTTP   │   Cred Server        │  OAuth  │  Google     │
│   (Machine B)   │────────▸│   (Machine A)        │────────▸│  GitHub     │
│                 │◂────────│                      │◂────────│  Slack ...  │
│  Bearer token   │  token  │  Encrypted vault     │  tokens │             │
└─────────────────┘         └──────────────────────┘         └─────────────┘
```

1. **Admin connects providers** — Sign in at `/admin/login`, then complete OAuth
2. **Tokens stored encrypted** — AES-256-GCM, PBKDF2-SHA256 key derivation
3. **Agent requests delegation** — `POST /api/v1/delegate` with Bearer auth
4. **Server returns a handle or access token** — Brokered handles keep provider tokens on the server; legacy token routes remain available.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Liveness check |
| GET | `/.well-known/http-message-signatures-directory` | None | Web Bot Auth key directory |
| GET | `/admin/login` | None | Admin login form |
| POST | `/admin/login` | None | Create admin session cookie |
| GET | `/providers` | Admin | List configured providers + connection status |
| GET | `/connect` | Admin | Browser UI for managing provider connections |
| GET | `/connect/:provider` | Admin | Start OAuth flow (browser) |
| GET | `/connect/:provider/callback` | None | OAuth callback |
| POST | `/api/v1/delegate` | Bearer | Primary v1 delegation endpoint |
| POST | `/api/v1/subdelegate` | Bearer | Sub-delegate from a verified parent receipt. Always returns a brokered handle (never the raw provider token), regardless of the requested `token_format` — see note below |
| POST | `/api/v1/use` | Bearer | Broker an upstream API call with a delegation handle |
| GET | `/api/v1/connections` | Bearer | List stored connections for SDK compatibility |
| DELETE | `/api/v1/connections/:provider` | Bearer | Revoke stored credentials for SDK compatibility |
| POST | `/api/v1/tofu/register` | Bearer | Register a TOFU identity |
| GET | `/api/v1/web-bot-auth/keys` | Bearer | List registered Web Bot Auth identities |
| POST | `/api/v1/web-bot-auth/keys` | Bearer | Register or import a Web Bot Auth public key |
| POST | `/api/v1/web-bot-auth/keys/:agentId/rotate` | Bearer + verified identity | Rotate a registered Web Bot Auth key — see [Security](#security) |
| POST | `/api/v1/agents/:agentId/revoke-all` | Bearer + verified identity | Revoke a stored agent record — see [Security](#security) |
| GET | `/api/token/:provider` | Bearer | Compatibility delegation route |
| DELETE | `/api/token/:provider` | Bearer | Revoke stored credentials |

> **Sub-delegation is broker-only.** Scope attenuation on a raw provider access token can't be
> enforced once it has left the server, so every response from `/api/v1/subdelegate`
> (chain depth ≥ 1) is a brokered handle, even if the request sends `"token_format": "raw"`.
> A downgraded request gets `token_format_enforced: "brokered"` (and `requested_token_format`)
> in the response instead of an error. If the target service has no brokered-use path
> (`POST /api/v1/use`) at all, the request is rejected with `400 brokered_format_unsupported`
> rather than minting a handle that could never be redeemed. `/api/v1/subdelegate` also checks
> the status of *every* ancestor agent in the delegation chain — not just the immediate parent —
> before minting a child receipt, so revoking a grandparent (or any earlier ancestor) still blocks
> new descendants even if the presenting parent agent is itself still active. This is enforced via
> a signed `lineage` claim each receipt carries (extended at every hop), since there's no
> persisted delegation-chain table to walk; receipts minted before this claim existed carry no
> lineage and degrade to a parent-only check for that hop until they age out under
> `RECEIPT_TTL_SECONDS`. Delegation receipts also now carry an `exp` claim (see
> `RECEIPT_TTL_SECONDS` below) — expired parent receipts are rejected.

## Configuration

All configuration via environment variables (or `.env` file):

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_PASSPHRASE` | Yes | Encryption passphrase for the token vault |
| `ADMIN_TOKEN` | Yes | Admin token for provider-management browser routes (must start with `cred_admin_`) |
| `AGENT_TOKEN` | Yes | Bearer token for agent API access (must start with `cred_at_`) |
| `PORT` | No | Server port (default: 3456) |
| `HOST` | No | Bind address (default: 127.0.0.1) |
| `VAULT_STORAGE` | No | `sqlite` (default, audit-capable) or `file` |
| `VAULT_PATH` | No | Path to vault file (default: `./data/vault.sqlite`) |
| `REDIRECT_BASE_URI` | No | OAuth redirect base (default: `http://localhost:3456`) |
| `RECEIPT_TTL_SECONDS` | No | TTL (seconds) for the `exp` claim on delegation receipts, and the max age for legacy receipts minted without one (default: `3600`) |
| `RECEIPT_AUDIENCE` | No | Audience (`aud` claim) for delegation receipts (default: `REDIRECT_BASE_URI`) |
| `WEB_BOT_AUTH_MODE` | No | `off` (default), `optional`, or `require` for ingress Web Bot Auth verification |
| `WEB_BOT_AUTH_NONCE_STORE` | No | `memory` (default) or `sqlite` for replay defense state |
| `WEB_BOT_AUTH_NONCE_PATH` | No | SQLite path for shared Web Bot Auth nonce storage |
| `WEB_BOT_AUTH_ALLOWED_ORIGINS` | No | Comma-separated trusted remote `Signature-Agent` origins for ingress verification |
| `GOOGLE_CLIENT_ID` | No | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | No | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | No | GitHub OAuth client secret |
| `SLACK_CLIENT_ID` | No | Slack OAuth client ID |
| `SLACK_CLIENT_SECRET` | No | Slack OAuth client secret |
| ... | No | Same pattern for NOTION, SALESFORCE, LINEAR, HUBSPOT |

`ADMIN_TOKEN` and `AGENT_TOKEN` are required when you use `loadConfig()` from environment variables. For embedded/programmatic agent auth, you can instead provide a custom `agentRequestVerifier` function in `createServer(config)` and omit the static agent token entirely. Admin routes still require `adminToken`.

## Docker Deployment (Production)

```bash
cd packages/server
cp .env.example .env
# Edit .env with your credentials

# Build and run
docker compose up -d

# Verify
curl http://localhost:3456/health
```

The vault is stored in a named Docker volume (`cred-data`) — survives container restarts and rebuilds.

### HTTPS with Caddy

For production with automatic TLS:

1. Point your domain's DNS to the server
2. Edit `Caddyfile` — replace `cred.yourdomain.com` with your domain
3. Uncomment the `caddy` service in `docker-compose.yml`
4. Run `docker compose up -d`

Caddy auto-provisions Let's Encrypt certificates. Agents connect via `https://cred.yourdomain.com`.

### Updating

```bash
cd packages/server
git pull
docker compose build
docker compose up -d
```

Vault data is in the named volume and survives rebuilds.

## Two-Machine Setup (Production)

For true credential isolation, run the server on a separate host from your agents:

### 1. Server (Machine A)

```bash
# On your server (VPS, on-prem, etc.)
git clone https://github.com/cred-ninja/sdk.git
cd sdk/packages/server
cp .env.example .env
# Edit .env with your credentials

# Install Caddy for automatic HTTPS
sudo apt install caddy

# Configure Caddy (create /etc/caddy/Caddyfile)
echo 'cred.yourdomain.com {
    reverse_proxy localhost:3456
}' | sudo tee /etc/caddy/Caddyfile
sudo systemctl restart caddy

# Start the server
npm install && npm start
```

### 2. Agent (Machine B)

```typescript
import { Cred } from '@credninja/sdk';

const cred = new Cred({
  agentToken: process.env.CRED_AGENT_TOKEN!,
  baseUrl: 'https://cred.yourdomain.com',
});

const google = await cred.delegateHandle({
  service: 'google',
  userId: 'default',
  appClientId: 'local',
});

const events = await cred.use({
  delegationId: google.delegationId,
  url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
  method: 'GET',
});
```

Or with curl:

```bash
curl https://cred.yourdomain.com/api/v1/delegate \
  -H "Authorization: Bearer $CRED_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"service":"google","user_id":"default","appClientId":"local","token_format":"handle"}'

curl https://cred.yourdomain.com/api/v1/use \
  -H "Authorization: Bearer $CRED_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"delegation_id":"del_...","url":"https://www.googleapis.com/calendar/v3/calendars/primary/events","method":"GET"}'
```

## Security

- **Refresh tokens never leave the server.** Brokered delegation handles also keep provider access tokens on the server.
- **Vault encrypted at rest** with AES-256-GCM (PBKDF2-SHA256, 100K iterations).
- **Agent tokens validated** using constant-time comparison (timing-attack resistant).
- **Provider-management routes require admin auth.** Browser login posts `ADMIN_TOKEN`, then sets an HttpOnly same-site session cookie.
- **Brokered upstream calls are bounded.** `/api/v1/use` enforces service URL allowlists, delegated Google scope checks, configured Guard policies, and strips caller-supplied auth, cookie, proxy, forwarding, signature, and hop-by-hop headers before forwarding.
- **Optional ingress Web Bot Auth verification** validates `Signature`, `Signature-Input`, and `Signature-Agent` on incoming agent requests and rejects replayed nonces within the signature validity window.
- **`POST /api/v1/web-bot-auth/keys/:agentId/rotate` and `POST /api/v1/agents/:agentId/revoke-all` always require a verified caller identity**, regardless of `WEB_BOT_AUTH_MODE`. A caller must present either a valid Web Bot Auth signature for the target agent, or (with a custom `agentRequestVerifier`) a `principalId` equal to the target agent's id — the shared static bearer token alone is not sufficient. Static-bearer-only deployments (`WEB_BOT_AUTH_MODE=off`, no custom `agentRequestVerifier`) will receive `403` on these two routes until one of those identity sources is configured. Requirements for each identity source:
  - **Custom `agentRequestVerifier`:** `principalId` must equal the internal id these routes compare against — the registered Web Bot Auth `agent_id` for `rotate`, or the vault `AgentRecord.id` for `revoke-all` — not merely a stable, unforgeable identifier in the verifier's own scheme.
  - **Vault `AgentRecord.fingerprint`** (used by `revoke-all`) must be provisioned as `sha256(hex(publicKey))`, matching the Web Bot Auth key's fingerprint exactly — a different encoding or digest denies every legitimate owner, not only after a key rotation.
  - There is currently no supported tool to update an `AgentRecord`'s `fingerprint` after a key rotation; an owner locked out of `revoke-all` after rotating their key needs the record refreshed via direct storage-layer access, the same way `AgentRecord`s are provisioned today.
- **Shared replay defense is available** with `WEB_BOT_AUTH_NONCE_STORE=sqlite`, allowing multiple Cred instances to reject the same nonce when they share the same nonce database.
- **Remote `Signature-Agent` fetches are origin-gated.** Cred only resolves remote directories from `WEB_BOT_AUTH_ALLOWED_ORIGINS`, requires the canonical well-known directory path, and rejects redirects during fetch.
- **HTTPS required for remote access.** The SDK refuses to send agent tokens over HTTP to non-localhost servers.
- **For production:** Always run behind a TLS reverse proxy (Caddy auto-provisions certificates).

## Web Bot Auth Validation

For local verification, run the server test suite:

```bash
npm test --workspace=packages/server
```

For a live deployed directory smoke check, run:

```bash
RUN_WEB_BOT_AUTH_LIVE_SMOKE=1 \
WEB_BOT_AUTH_LIVE_BASE_URL=https://cred.example.com \
npm test --workspace=packages/server
```

That smoke path fetches the live `/.well-known/http-message-signatures-directory` document and verifies that the response is signed and non-empty.

## Programmatic Usage

```typescript
import { createServer, loadConfig } from '@credninja/server';

const config = loadConfig(); // reads from process.env
const { app, vault } = createServer(config);
await vault.init();
app.listen(3456);
```

### Custom Agent Auth

For integrations that already have their own agent identity system, use a programmatic verifier instead of a shared static bearer token:

```typescript
import { createServer } from '@credninja/server';

const { app, vault } = createServer({
  port: 3456,
  host: '127.0.0.1',
  vaultPassphrase: process.env.VAULT_PASSPHRASE!,
  vaultStorage: 'file',
  vaultPath: './data/vault.json',
  tofuStorage: 'file',
  tofuPath: './data/tofu.json',
  adminToken: process.env.CRED_ADMIN_TOKEN!,
  redirectBaseUri: 'http://localhost:3456',
  providers: [],
  agentRequestVerifier: async (req) => {
    const assertion = req.get('X-Agent-Assertion');
    if (!assertion) {
      return { ok: false, status: 401, error: 'Missing agent assertion' };
    }

    // Verify the assertion using your own runtime's identity system.
    return {
      ok: true,
      principal: {
        type: 'external-runtime',
        principalId: 'agent_123',
        metadata: { runtime: 'external-runtime' },
      },
    };
  },
});

await vault.init();
app.listen(3456);
```

This keeps Cred core generic while letting adapters for external runtimes translate their native auth model into Cred's issuance path.

If your verifier returns a stable `principalId`, Cred can derive a stable per-agent hash for downstream Guard policies and rate limits even when no bearer token is present on the request.

## License

Apache License 2.0

# @credninja/server

Self-hosted credential delegation server for AI agents.

Stores OAuth tokens in an encrypted vault and serves delegated access tokens to authenticated agents. Run on a separate host from your AI agents for true credential isolation.

## Quick Start

```bash
# Install
npm install @credninja/server

# Set up configuration
cp node_modules/@credninja/server/.env.example .env
# Edit .env — set VAULT_PASSPHRASE, AGENT_TOKEN, and at least one provider

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

1. **Admin connects providers** — Visit `/connect/google` in a browser, complete OAuth
2. **Tokens stored encrypted** — AES-256-GCM, PBKDF2-SHA256 key derivation
3. **Agent requests delegation** — `POST /api/v1/delegate` with Bearer auth
4. **Server returns access token** — Auto-refreshes if expired. Refresh token never leaves the server.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Liveness check |
| GET | `/.well-known/http-message-signatures-directory` | None | Web Bot Auth key directory |
| GET | `/providers` | None | List configured providers + connection status |
| GET | `/connect/:provider` | None | Start OAuth flow (browser) |
| GET | `/connect/:provider/callback` | None | OAuth callback |
| POST | `/api/v1/delegate` | Bearer | Primary v1 delegation endpoint |
| GET | `/api/v1/web-bot-auth/keys` | Bearer | List registered Web Bot Auth identities |
| POST | `/api/v1/web-bot-auth/keys` | Bearer | Register or import a Web Bot Auth public key |
| POST | `/api/v1/web-bot-auth/keys/:agentId/rotate` | Bearer | Rotate a registered Web Bot Auth key |
| GET | `/api/token/:provider` | Bearer | Compatibility delegation route |
| DELETE | `/api/token/:provider` | Bearer | Revoke stored credentials |

## Configuration

All configuration via environment variables (or `.env` file):

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_PASSPHRASE` | Yes | Encryption passphrase for the token vault |
| `AGENT_TOKEN` | Yes | Bearer token for agent API access (must start with `cred_at_`) |
| `PORT` | No | Server port (default: 3456) |
| `HOST` | No | Bind address (default: 127.0.0.1) |
| `VAULT_STORAGE` | No | `file` (default) or `sqlite` |
| `VAULT_PATH` | No | Path to vault file (default: `./data/vault.json`) |
| `REDIRECT_BASE_URI` | No | OAuth redirect base (default: `http://localhost:3456`) |
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

`AGENT_TOKEN` is required when you use `loadConfig()` from environment variables. For embedded/programmatic usage, you can instead provide a custom `agentRequestVerifier` function in `createServer(config)` and omit the static token entirely.

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

const google = await cred.delegate({
  service: 'google',
  userId: 'default',
  appClientId: 'local',
});

// Use google.accessToken with any Google API
```

Or with curl:

```bash
curl https://cred.yourdomain.com/api/v1/delegate \
  -H "Authorization: Bearer $CRED_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"service":"google","user_id":"default","appClientId":"local"}'
```

## Security

- **Refresh tokens never leave the server.** Delegation endpoints return only the access token.
- **Vault encrypted at rest** with AES-256-GCM (PBKDF2-SHA256, 100K iterations).
- **Agent tokens validated** using constant-time comparison (timing-attack resistant).
- **Optional ingress Web Bot Auth verification** validates `Signature`, `Signature-Input`, and `Signature-Agent` on incoming agent requests and rejects replayed nonces within the signature validity window.
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

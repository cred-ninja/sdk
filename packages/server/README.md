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
3. **Agent requests token** — `GET /api/token/google` with Bearer auth
4. **Server returns access token** — Auto-refreshes if expired. Refresh token never leaves the server.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Liveness check |
| GET | `/providers` | None | List configured providers + connection status |
| GET | `/connect/:provider` | None | Start OAuth flow (browser) |
| GET | `/connect/:provider/callback` | None | OAuth callback |
| GET | `/api/token/:provider` | Bearer | Get delegated access token |
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
| `GOOGLE_CLIENT_ID` | No | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | No | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | No | GitHub OAuth client secret |
| `SLACK_CLIENT_ID` | No | Slack OAuth client ID |
| `SLACK_CLIENT_SECRET` | No | Slack OAuth client secret |
| ... | No | Same pattern for NOTION, SALESFORCE, LINEAR, HUBSPOT |

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
});

// Use google.accessToken with any Google API
```

Or with curl:

```bash
curl https://cred.yourdomain.com/api/token/google \
  -H "Authorization: Bearer $CRED_AGENT_TOKEN"
```

## Security

- **Refresh tokens never leave the server.** The `/api/token/:provider` endpoint returns only the access token.
- **Vault encrypted at rest** with AES-256-GCM (PBKDF2-SHA256, 100K iterations).
- **Agent tokens validated** using constant-time comparison (timing-attack resistant).
- **HTTPS required for remote access.** The SDK refuses to send agent tokens over HTTP to non-localhost servers.
- **For production:** Always run behind a TLS reverse proxy (Caddy auto-provisions certificates).

## Programmatic Usage

```typescript
import { createServer, loadConfig } from '@credninja/server';

const config = loadConfig(); // reads from process.env
const { app, vault } = createServer(config);
await vault.init();
app.listen(3456);
```

## License

MIT

# SKILL.md — Cred Dashboard Setup

A local credential control panel that dogfoods `@credninja/oauth` and `@credninja/vault`.
Connect OAuth accounts, inspect stored tokens, refresh, revoke, and test API calls — all
from a dark-theme UI running in your browser.

This document covers every installation path: local dev, Docker on one machine,
and Docker on a remote server (the only path that provides true credential isolation
from the agent calling Cred).

---

## Security Model — Read This First

Cred's job is to keep raw credentials away from AI agents. Whether it succeeds depends
entirely on the deployment topology:

| Path | Agent can read raw creds? | Good for |
|------|--------------------------|----------|
| A — Local (same machine) | ✅ Yes (filesystem access) | Development, personal use |
| B — Docker (same machine) | Harder but possible (docker exec) | Not recommended for production |
| C — Remote server | ❌ No | Production, demos, team use |

**For a demo that proves the isolation model, use Path C.**
An agent on your machine can call `http://your-server:3456/api/token` and receive a
scoped access token. It has no path to the raw credentials — they live on a different host.

---

## Prerequisites (all paths)

### 1. OAuth App — Google (example, others follow same pattern)

1. Go to [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials)
2. **+ Create Credentials → OAuth 2.0 Client ID**
3. Application type: **Web application**
4. Name: anything (e.g. `Cred Dashboard`)
5. Authorized redirect URI:
   - Local: `http://localhost:3456/callback`
   - Server: `http://YOUR_SERVER_IP:3456/callback` (or your domain)
6. Copy **Client ID** and **Client Secret**
7. Enable the APIs you want to delegate:
   - [Google Drive API](https://console.cloud.google.com/apis/library/drive.googleapis.com)
   - [Gmail API](https://console.cloud.google.com/apis/library/gmail.googleapis.com)
   - [Google Calendar API](https://console.cloud.google.com/apis/library/calendar-json.googleapis.com)

> **Unverified app warning:** Google will show a consent screen warning for unverified apps.
> Click "Advanced → Go to [app name] (unsafe)" during development. For production, verify
> the app in Google Cloud Console.

### 2. Clone the repo

```bash
git clone https://github.com/cred-ninja/sdk.git cred
cd cred/cred-dashboard   # or wherever cred-dashboard lives relative to your clone
```

---

## Path A — Local Dev (same machine, no isolation)

**Use when:** You're building against Cred, running tests, or just kicking the tires.
**Security:** Credentials are on the same machine as your agent. Not for production.

```bash
# 1. Install dependencies (from repo root — packages must be built first)
cd ../cred-oss/packages/oauth && npm install && npm run build
cd ../vault && npm install && npm run build
cd ../../cred-dashboard

# 2. Configure
cp .env.example .env
$EDITOR .env   # fill in VAULT_PASSPHRASE and at least one provider

# 3. Install and run
npm install
npm run dev    # hot-reload dev server at http://localhost:3456
# or: npm run build && npm start
```

Open [http://localhost:3456](http://localhost:3456) → click a provider → authorize → token stored.

---

## Path D — Local Hardened (macOS Keychain, same machine)

**Use when:** You want meaningful protection on a single Mac without running a server.
**Security:** Vault passphrase is in the OS Keychain, not the filesystem. An agent with
filesystem access cannot read the passphrase without triggering a Keychain prompt.
macOS only.

```bash
# Store the passphrase in Keychain (one-time)
security add-generic-password \
  -a "$USER" \
  -s "cred-dashboard" \
  -w "your-strong-passphrase-here"

# Read it back in your shell (add to shell profile or run before starting)
export VAULT_PASSPHRASE=$(security find-generic-password -a "$USER" -s "cred-dashboard" -w)

# Then follow Path A steps — just omit VAULT_PASSPHRASE from .env
# The env var set above takes precedence
npm run dev
```

To rotate the passphrase:
```bash
security delete-generic-password -a "$USER" -s "cred-dashboard"
security add-generic-password -a "$USER" -s "cred-dashboard" -w "new-passphrase"
# Note: existing vault entries encrypted with the old passphrase will be unreadable.
# Re-connect your OAuth accounts after rotating.
```

---

## Path C — Docker on Remote Server (true isolation)

**Use when:** You want to prove (or demo) that an AI agent cannot access raw credentials.
**Security:** Credentials live in a container on a different host. The calling agent has
HTTP access only — no shell, no filesystem, no docker CLI.

### C1 — Hetzner VPS (recommended for demos)

**Provision the server:**

```bash
# Install hcloud CLI (macOS)
brew install hcloud

# Create server — CX11 ($4/mo, 2GB RAM, enough for the dashboard)
hcloud server create \
  --name cred-demo \
  --type cx11 \
  --image ubuntu-24.04 \
  --ssh-key YOUR_KEY_NAME

# Note the IP address printed after creation
export SERVER_IP=<ip from output>
```

**On the server:**

```bash
ssh root@$SERVER_IP

# Install Docker
apt-get update && apt-get install -y docker.io
systemctl enable --now docker

# Pull or build the image
# Option 1: build from source (requires repo on server)
git clone https://github.com/cred-ninja/sdk.git cred
cd cred
docker build -f cred-dashboard/Dockerfile -t cred-dashboard .

# Create a named volume for the vault (survives container restarts)
docker volume create cred-vault
```

**Configure and run:**

```bash
# Create the env file on the server — edit directly, never paste secrets in chat
nano /root/cred-dashboard.env
```

Contents of `/root/cred-dashboard.env`:
```
VAULT_PASSPHRASE=<strong random string>
REDIRECT_URI=http://<SERVER_IP>:3456/callback
GOOGLE_CLIENT_ID=<from Google Cloud Console>
GOOGLE_CLIENT_SECRET=<from Google Cloud Console>
# Add other providers as needed
```

```bash
# Run the container
docker run -d \
  --name cred-dashboard \
  --restart unless-stopped \
  -p 3456:3456 \
  -v cred-vault:/app/data \
  --env-file /root/cred-dashboard.env \
  cred-dashboard

# Verify it's running
curl http://localhost:3456   # should return HTML
```

**Access the dashboard (two options):**

Option 1 — SSH tunnel (most secure, no port exposed publicly):
```bash
# Run on your local machine
ssh -L 3456:localhost:3456 root@$SERVER_IP -N
# Then open http://localhost:3456 in your browser
# The port is NOT open to the internet — only you can reach it
```

Option 2 — Open port 3456 in firewall (accessible from browser directly):
```bash
# On the server — only do this if you've set up auth on the dashboard
ufw allow 3456
```

> **For demos:** Use Option 1 (SSH tunnel). The dashboard is only reachable through
> your tunnel. The agent calls the server IP directly over port 3456 (which IS open
> to the agent's network). This keeps the management UI private.

**Update Google OAuth redirect URI:**
Go back to Google Cloud Console and add `http://<SERVER_IP>:3456/callback` as an
authorized redirect URI for your OAuth app.

### C2 — Render (one-click, managed)

Coming soon — one-click deploy button in README.

### C3 — On-prem Docker (enterprise, stays in your network)

Same as C1. Use your internal server IP or hostname.
Point `REDIRECT_URI` at your internal address.
No internet exposure required if your agents are on the same network.

---

## Verifying the setup

1. Open the dashboard (locally or via SSH tunnel)
2. Click **Connect** next to Google
3. Complete the OAuth flow — you'll be redirected back and see the token listed
4. Click **Test** — should return live data from the Google API
5. Click **Refresh** — manually trigger a token refresh
6. Click **Revoke** — deletes the token from the vault

If the flow completes and the test call succeeds, Cred is working.

---

## Calling Cred from an agent

Once the dashboard has a stored token, agents retrieve it via HTTP:

```bash
# Get a delegated access token for Google
curl http://localhost:3456/api/token/google \
  -H "Authorization: Bearer <your-agent-token>"
```

Response:
```json
{
  "provider": "google",
  "accessToken": "ya29.a0...",
  "expiresAt": "2026-03-05T20:00:00Z",
  "scopes": ["calendar.readonly", "gmail.readonly"]
}
```

Pass that `accessToken` to `gws` (Google Workspace CLI):
```bash
GOOGLE_WORKSPACE_CLI_TOKEN=<accessToken> gws drive files list
```

The agent received a scoped, time-limited token. The raw OAuth client secret and
refresh token never left the Cred server.

---

## Updating

```bash
# On the server
cd cred && git pull
docker build -f cred-dashboard/Dockerfile -t cred-dashboard .
docker stop cred-dashboard && docker rm cred-dashboard
docker run -d \
  --name cred-dashboard \
  --restart unless-stopped \
  -p 3456:3456 \
  -v cred-vault:/app/data \
  --env-file /root/cred-dashboard.env \
  cred-dashboard
```

Vault data is in the named volume (`cred-vault`) and survives container rebuilds.

---

## Troubleshooting

**"redirect_uri_mismatch" from Google**
The redirect URI in your `.env` must exactly match what's registered in Google Cloud Console.
Check: `REDIRECT_URI=http://YOUR_IP:3456/callback` and the console entry are identical.

**Container starts but dashboard is blank**
Check logs: `docker logs cred-dashboard`
Usually missing `VAULT_PASSPHRASE` or a provider with only one of client ID/secret set.

**Token test fails after refresh**
The OAuth app may be in "testing" mode with scope limits. Switch to production mode
in Google Cloud Console or reduce the scopes.

**Port 3456 not reachable from agent**
If using Hetzner, check the firewall: `ufw status`. The agent's IP needs access to port 3456.
Use the SSH tunnel for the dashboard UI and keep 3456 open for agent API calls only.

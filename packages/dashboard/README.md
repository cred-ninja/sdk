# Cred Dashboard

Local credential control panel. Dogfoods `@credninja/oauth` and `@credninja/vault` from the monorepo.

## What It Does

- Connect OAuth accounts (Google, GitHub, Slack, Notion, Salesforce) via real OAuth flows
- View stored credentials with provider, scopes, expiry, and last refresh time
- Manually refresh tokens
- Revoke and delete credentials
- Test credentials by making sample API calls

## Setup

1. Install dependencies:

```bash
npm install
```

2. Copy the env file and fill in your OAuth credentials:

```bash
cp .env.example .env
```

Only providers with both `CLIENT_ID` and `CLIENT_SECRET` configured will appear in the dashboard.

3. Build and run:

```bash
npm run build
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

4. Open http://localhost:3456

## Provider Setup

For each provider, create an OAuth app and set the redirect URI to:

```
http://localhost:3456/callback
```

### Google

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create an OAuth 2.0 Client ID (Web application)
3. Add `http://localhost:3456/callback` as an authorized redirect URI
4. Copy Client ID and Client Secret to `.env`

### GitHub

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Set callback URL to `http://localhost:3456/callback`
4. Copy Client ID and Client Secret to `.env`

### Slack

1. Go to [Slack API](https://api.slack.com/apps)
2. Create a new app, add OAuth redirect URL
3. Copy Client ID and Client Secret to `.env`

### Notion

1. Go to [Notion Integrations](https://www.notion.so/my-integrations)
2. Create a new integration (public, OAuth)
3. Set redirect URI to `http://localhost:3456/callback`
4. Copy OAuth Client ID and Secret to `.env`

### Salesforce

1. Go to Salesforce Setup, create a Connected App
2. Enable OAuth, add callback URL `http://localhost:3456/callback`
3. Copy Consumer Key and Consumer Secret to `.env`

## Architecture

```
cred-dashboard/
  src/
    index.ts      Express server on port 3456
    auth.ts       OAuth flow routes (/connect/:provider, /callback)
    dashboard.ts  Dashboard routes (/, /refresh, /revoke, /test)
    render.ts     HTML template renderer (dark theme, server-rendered)
    config.ts     Provider config from .env
  data/
    vault.json    Encrypted credential store (gitignored)
```

Vault uses AES-256-GCM encryption via `@credninja/vault` with file backend. Passphrase is read from `VAULT_PASSPHRASE` env var.

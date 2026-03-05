# @credninja/oauth

**Standalone OAuth2 middleware toolkit for Node.js.** Zero runtime dependencies. TypeScript-first. Works standalone or as part of [Cred Cloud](https://cred.ninja).

Five battle-tested provider adapters: Google, GitHub, Slack, Notion, Salesforce. Each with provider-specific quirks handled correctly out of the box.

---

## Installation

```bash
npm install @credninja/oauth
```

**Requirements:** Node.js ≥ 18 (uses built-in `fetch` and `crypto`).

---

## 5-Minute Quickstart

```typescript
import { OAuthClient, GoogleAdapter } from '@credninja/oauth';

const google = new OAuthClient({
  adapter: new GoogleAdapter(),
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: 'http://localhost:3000/callback',
});

// Step 1: Generate auth URL (PKCE + CSRF state auto-generated)
const { url, state, codeVerifier } = await google.getAuthorizationUrl({
  scopes: ['calendar.readonly', 'gmail.readonly'],
});

// Store `state` and `codeVerifier` in session, then redirect user to `url`

// Step 2: Handle callback
const tokens = await google.exchangeCode({
  code: req.query.code as string,
  codeVerifier,            // required for PKCE
});

// Step 3: Refresh when expired
const refreshed = await google.refreshToken(tokens.refresh_token!);

// Step 4: Revoke
await google.revokeToken(tokens.access_token);
```

---

## Provider Reference

### Google

```typescript
import { OAuthClient, GoogleAdapter } from '@credninja/oauth';

const client = new OAuthClient({
  adapter: new GoogleAdapter(),
  clientId: '...',
  clientSecret: '...',
  redirectUri: '...',
});

// Short scope names are auto-prefixed
const { url } = await client.getAuthorizationUrl({
  scopes: ['calendar.readonly', 'drive', 'gmail.readonly'],
  // Becomes: https://www.googleapis.com/auth/calendar.readonly, etc.
});
```

**Quirks handled:**
- `access_type=offline` and `prompt=consent` added automatically (required for refresh tokens)
- Short scope names prefixed with `https://www.googleapis.com/auth/`
- Full PKCE support (S256)

---

### GitHub

```typescript
import { OAuthClient, GitHubAdapter } from '@credninja/oauth';

const client = new OAuthClient({
  adapter: new GitHubAdapter(),
  clientId: '...',
  clientSecret: '...',
  redirectUri: '...',
});

const { url } = await client.getAuthorizationUrl({
  scopes: ['repo', 'read:user'],
});
```

**Quirks handled:**
- `Accept: application/json` header sent automatically (GitHub returns plain text by default)
- Scopes are comma-separated
- Token revocation via `DELETE /applications/{clientId}/token` with Basic auth
- 404 on revoke treated as success (already revoked)
- No PKCE (GitHub doesn't support it)

---

### Slack

```typescript
import { OAuthClient, SlackAdapter } from '@credninja/oauth';

const client = new OAuthClient({
  adapter: new SlackAdapter(),
  clientId: '...',
  clientSecret: '...',
  redirectUri: '...',
});

const { url } = await client.getAuthorizationUrl({
  scopes: ['channels:read', 'chat:write'],
});
```

**Quirks handled:**
- Scopes are comma-separated
- `authed_user.access_token` extracted from nested response (user tokens)
- Tokens don't expire → `refreshToken()` throws `Error('Slack tokens do not expire')`
- Revocation uses `Bearer {token}` auth (not client credentials)
- `token_revoked` error treated as success on revoke

---

### Notion

```typescript
import { OAuthClient, NotionAdapter } from '@credninja/oauth';

const client = new OAuthClient({
  adapter: new NotionAdapter(),
  clientId: '...',
  clientSecret: '...',
  redirectUri: '...',
});
```

**Quirks handled:**
- Token exchange uses `Authorization: Basic base64(clientId:clientSecret)`. client_secret is NOT in the body
- Notion-Version header sent automatically
- Tokens don't expire → `refreshToken()` throws
- No revocation endpoint → `revokeToken()` is a no-op
- No PKCE support

---

### Salesforce

```typescript
import { OAuthClient, SalesforceAdapter, SALESFORCE_SANDBOX } from '@credninja/oauth';

// Production (default)
const client = new OAuthClient({
  adapter: new SalesforceAdapter(),
  clientId: '...',
  clientSecret: '...',
  redirectUri: '...',
});

// Sandbox
const sandboxClient = new OAuthClient({
  adapter: new SalesforceAdapter(SALESFORCE_SANDBOX),
  clientId: '...',
  clientSecret: '...',
  redirectUri: '...',
});

const tokens = await client.exchangeCode({ code: '...' });
// tokens.instance_url → 'https://na1.salesforce.com' (use for API calls)
```

**Quirks handled:**
- `instance_url` returned in token response (required for Salesforce API calls)
- Full PKCE support (S256)
- Sandbox config available via `SALESFORCE_SANDBOX`

---

## PKCE

PKCE (Proof Key for Code Exchange, RFC 7636) is generated automatically for adapters that support it (Google, Salesforce). You can also use the helpers directly:

```typescript
import { generatePKCE, generateVerifier, computeChallenge } from '@credninja/oauth';

const { verifier, challenge } = generatePKCE();
// verifier: 64-char URL-safe random string
// challenge: base64url(sha256(verifier)), no padding

// Or separately:
const verifier2 = generateVerifier(96);           // 43–128 chars
const challenge2 = computeChallenge(verifier2);   // S256 method
```

The challenge method is always `S256`. Plain challenge (`code_challenge_method=plain`) is not supported.

---

## Express Middleware

Optional import. Keeps your bundle lean if you don't need it:

```typescript
import express from 'express';
import session from 'express-session';
import { credOAuth } from '@credninja/oauth/express';
import { GoogleAdapter, GitHubAdapter } from '@credninja/oauth';

const app = express();
app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));

app.use('/auth', credOAuth({
  google: {
    adapter: new GoogleAdapter(),
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    scopes: ['calendar.readonly'],
  },
  github: {
    adapter: new GitHubAdapter(),
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    scopes: ['repo'],
  },
}, {
  redirectUri: 'http://localhost:3000/auth/callback',
  onSuccess: (req, res, { provider, tokens }) => {
    req.session.tokens = tokens;
    res.redirect('/dashboard');
  },
  onError: (req, res, error) => {
    res.status(400).json({ error: error.message });
  },
}));

// Routes created automatically:
// GET /auth/google          → redirects to Google consent screen
// GET /auth/google/callback → exchanges code, calls onSuccess
// GET /auth/github          → redirects to GitHub auth
// GET /auth/github/callback → exchanges code, calls onSuccess
```

State parameter is validated on callback (CSRF protection). PKCE verifier is stored in session and sent automatically.

---

## Custom Adapters

Extend `BaseServiceAdapter` for any OAuth 2.0 provider:

```typescript
import { BaseServiceAdapter } from '@credninja/oauth';

export class MyProviderAdapter extends BaseServiceAdapter {
  readonly slug = 'my-provider';
  readonly authorizationUrl = 'https://provider.example.com/oauth/authorize';
  readonly tokenUrl = 'https://provider.example.com/oauth/token';
  readonly revocationUrl = 'https://provider.example.com/oauth/revoke';
  readonly supportsPkce = true;
  readonly supportsRefresh = true;
}
```

---

## Zero Dependencies

`@credninja/oauth` has **zero runtime dependencies**. It uses:
- `fetch`: built into Node 18+ (no axios, no node-fetch)
- `crypto`: built into Node.js (no jsonwebtoken, no bcrypt)
- `URLSearchParams`: built into Node.js

---

## Upgrade to Cred Cloud

Need managed token refresh, multi-tenant storage, audit logs, or AI agent delegation?

→ [cred.ninja](https://cred.ninja). OAuth tokens for AI agents, managed in the cloud.

`@credninja/oauth` is the open-source foundation. Cred Cloud adds the production-grade layer on top.

---

## License

MIT © CredNinja

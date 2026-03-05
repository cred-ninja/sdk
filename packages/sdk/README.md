# @credninja/sdk

OAuth2 credential delegation SDK for AI agents. Open-source OAuth2 credential delegation for AI agents.

## Install

```bash
npm install @credninja/sdk
```

## Quick Start: Cloud Mode

```typescript
import { Cred, ConsentRequiredError } from '@credninja/sdk';

const cred = new Cred({
  agentToken: process.env.CRED_AGENT_TOKEN!,
});

try {
  const { accessToken } = await cred.delegate({
    userId: 'user_123',
    appClientId: 'your_app_client_id',
    service: 'google',
    scopes: ['https://www.googleapis.com/auth/calendar.readonly'],
  });

  // Use the token. Don't store it, it expires.
  const response = await fetch('https://www.googleapis.com/calendar/v3/calendars/primary', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
} catch (err) {
  if (err instanceof ConsentRequiredError) {
    // User hasn't connected Google yet. Send them to the consent URL.
    console.log('User needs to authorize:', err.consentUrl);
  }
}
```

## Quick Start: Local / Standalone Mode

No Cred account needed. Use `@credninja/oauth` and `@credninja/vault` directly:

```typescript
import { OAuthClient, GoogleAdapter } from '@credninja/oauth';
import { createVault } from '@credninja/vault';

// OAuth flow
const google = new OAuthClient({
  adapter: new GoogleAdapter(),
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: 'http://localhost:3000/callback',
});

const { url, codeVerifier } = await google.getAuthorizationUrl({
  scopes: ['calendar.readonly'],
});
// redirect user to url, exchange code on callback
const tokens = await google.exchangeCode({ code, codeVerifier });

// Encrypted local vault
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
```

See [`@credninja/oauth`](../oauth) and [`@credninja/vault`](../vault) for full standalone docs.

## Configuration

### Cloud Mode

```typescript
const cred = new Cred({
  agentToken: 'your_agent_token',   // required, from Cred dashboard
  baseUrl: 'https://api.cred.ninja', // optional, this is the default
});
```

`agentToken` and `appClientId` are deployment-time config. Bake them into your agent's environment variables. Don't pass them at runtime from user input.

## API

### `cred.delegate(params)`

Get a delegated access token for a service on behalf of a user.

```typescript
const result = await cred.delegate({
  userId: 'user_123',           // required: the user you're acting on behalf of
  appClientId: 'app_xxx',       // required: your app's client ID
  service: 'google',            // required: service slug
  scopes: ['calendar.readonly'], // optional: defaults to app's configured scopes
  agentDid: 'did:key:z6Mk...',  // optional: agent's DID for receipt verification
});

// result.accessToken    - use this for API calls
// result.expiresIn      - seconds until expiry (usually 3600)
// result.receipt        - JWS-signed delegation receipt (if agentDid provided)
```

Throws `ConsentRequiredError` with `.consentUrl` if the user hasn't connected the service.

### `cred.getConsentUrl(params)`

Get the URL to send a user to for connecting a service.

```typescript
const { consentUrl } = await cred.getConsentUrl({
  userId: 'user_123',
  appClientId: 'app_xxx',
  service: 'google',
  scopes: ['calendar.readonly'],
  redirectUri: 'https://yourapp.com/callback', // optional
});
```

### `cred.getUserConnections(params)`

List a user's active service connections.

```typescript
const { connections } = await cred.getUserConnections({
  userId: 'user_123',
  appClientId: 'app_xxx',
});

// connections[].service       - service slug
// connections[].scopes        - granted scopes
// connections[].consentedAt   - when the user consented
```

### `cred.revoke(params)`

Revoke a user's connection to a service.

```typescript
await cred.revoke({
  userId: 'user_123',
  appClientId: 'app_xxx',
  service: 'google',
});
```

## DID agent identity

Agents can have a cryptographic identity (`did:key`) to produce verifiable delegation receipts.

```typescript
import { Cred, generateAgentIdentity, importAgentIdentity, verifyDelegationReceipt } from '@credninja/sdk';

// Generate once and persist the private key
const identity = await generateAgentIdentity();
console.log(identity.did); // 'did:key:z6Mk...'

const exported = identity.export();
// Save exported.privateKeyHex securely. This is your agent's private key.

// On subsequent runs, import from persisted key
const identity = await importAgentIdentity({
  did: exported.did,
  privateKeyHex: exported.privateKeyHex,
});

// Delegate with your DID. The receipt proves this delegation happened.
const { accessToken, receipt } = await cred.delegate({
  userId: 'user_123',
  appClientId: 'app_xxx',
  service: 'google',
  agentDid: identity.did,
});

// Verify the receipt
const valid = await verifyDelegationReceipt(receipt!, {
  expectedDid: identity.did,
});
```

## Supported services

| Service | Slug |
|---------|------|
| Google (Gmail, Calendar, Drive, etc.) | `google` |
| GitHub | `github` |
| Slack | `slack` |
| Notion | `notion` |
| Salesforce | `salesforce` |

## Error handling

```typescript
import { Cred, ConsentRequiredError, CredError } from '@credninja/sdk';

try {
  const { accessToken } = await cred.delegate({ ... });
} catch (err) {
  if (err instanceof ConsentRequiredError) {
    // User needs to authorize. Send them to err.consentUrl.
    return { redirect: err.consentUrl };
  }
  if (err instanceof CredError) {
    // API error: err.code, err.status, err.message
    console.error('Cred API error:', err.code, err.message);
  }
}
```

## Requirements

- Node.js 18+ (uses built-in `fetch`)
- Zero runtime dependencies

## Standalone First

For fully local operation, use [`@credninja/oauth`](../oauth) + [`@credninja/vault`](../vault). No account needed, no cloud dependency.

Managed cloud delegation is coming. [Join the waitlist](https://cred.ninja/waitlist).

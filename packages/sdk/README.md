# @credninja/sdk

OAuth2 credential delegation SDK for AI agents. Open-source OAuth2 credential delegation for AI agents.

## Install

```bash
npm install @credninja/sdk
```

## Quick Start: Remote Server Mode

```typescript
import { Cred, ConsentRequiredError, importAgentIdentity } from '@credninja/sdk';

const cred = new Cred({
  agentToken: process.env.CRED_AGENT_TOKEN!,
  baseUrl: process.env.CRED_BASE_URL!,
});
// The agent's key, which only this process holds. An operator grants this DID a
// Permission on the server; without one it is issued nothing.
const agentIdentity = await importAgentIdentity({
  did: process.env.CRED_AGENT_DID!,
  privateKeyHex: process.env.CRED_AGENT_PRIVATE_KEY_HEX!,
});

try {
  const { token } = await cred.delegateHandle({
    userId: 'user_123',
    appClientId: 'your_app_client_id',
    service: 'google',
    scopes: ['calendar.readonly'],
    agentIdentity,
  });

  // The call goes through Cred, which checks it against the grant. The provider
  // token never reaches this process.
  const result = await cred.use({
    token,
    agentIdentity,
    url: 'https://www.googleapis.com/calendar/v3/calendars/primary',
    method: 'GET',
  });
  console.log(result.status, result.body);
} catch (err) {
  if (err instanceof ConsentRequiredError) {
    // User hasn't connected Google yet. Send them to the consent URL.
    console.log('User needs to authorize:', err.consentUrl);
  }
}
```

`agentToken`, `baseUrl`, and `appClientId` are deployment-time config. Bake them into your agent's environment variables. Don't pass them at runtime from user input.

## API

### `cred.delegate(params)`

Local mode, or a server run with the deprecated `CRED_ALLOW_RAW_TOKENS=true`: get the provider
access token itself. Servers refuse this by default (`raw_token_disabled`), and a token handed out
this way carries the connection's whole scope. Against a server, use `delegateHandle()` and `use()`
below.

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

### `cred.delegateHandle(params)` and `cred.use(params)`

Brokered delegation: the provider token stays on the Cred server, and the agent gets a Delegation
Token, a JWT it can use only with its own key. The server binds the token to the agent's did:key
and requires a DPoP proof (RFC 9449) by that key to issue it and on every call. `delegateHandle()`
requires `agentIdentity`; the SDK signs the proofs and the private key never leaves your process.

The agent needs a Permission on the server (`403 permission_required` otherwise), and access stays
revoked until an operator grants it again (`403 agent_access_revoked`). Each `use()` is checked
against the grant: `403 scope_insufficient` when it does not cover the call, and
`403 operation_not_mapped` when the server has not mapped it. See the
[server docs](https://github.com/cred-ninja/sdk/tree/main/packages/server#operation-enforcement).

```typescript
import { importAgentIdentity } from '@credninja/sdk';

const agent = importAgentIdentity({ did: savedDid, privateKeyHex: savedKeyHex });

const credential = await cred.delegateHandle({
  userId: 'user_123',
  appClientId: 'app_xxx',
  service: 'google',
  scopes: ['calendar.readonly'],
  agentIdentity: agent,          // the token is bound to this key
});

const res = await cred.use({
  token: credential.token,       // sent as Authorization: DPoP <token>
  url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
  method: 'GET',
  agentIdentity: agent,          // signs a fresh DPoP proof for this call
});
```

`delegateHandle()` returns `{ token, jkt, delegationId, receipt, expiresIn, ... }`. The token alone,
even together with the deployment's agent token, cannot make a call: each `use()` carries a fresh
DPoP proof whose `ath` is the SHA-256 of the token and whose `cred_req` covers the exact request
body. A token sub-delegated to another agent is bound to that agent's key, not yours.

For agent-to-agent handoff, the delegating agent calls `cred.subDelegateGrant({ ..., delegatorIdentity })`
for a single-use grant, and the receiving agent calls
`cred.redeemDelegationGrant({ delegationGrant, agentIdentity })` for its own Delegation Token.

Every hop is judged against both agents' Permissions: the receiving agent's row must allow the
requested scopes and depth, and the *delegating* agent's own row (when the deployment or, in local
mode, the vault holds one) must be `delegatable`, must allow the child's depth, must not have
`expiresAt` in the past, and must still cover every scope the hop would grant. Otherwise the
handoff is refused with `delegation_not_allowed`, `depth_exceeded`, `permission_expired` or
`invalid_scope` before any credential is released. The child holds only what both rows still
cover: a scope an admin removed from the grantor's row after the receipt was minted is never
passed on. Where an agent has both a record-id row and a DID row, the tighter of the two applies.

Derived read scopes (`github.read`, `salesforce.read`, `notion.read`) are judged against what the
stored connection covers, not against what a receipt names: `public_repo` cannot hand on
`github.read` over a token holding `repo` (likewise `api` over `full`, and `read_content` over a
Notion connection with `content` stored or with none at all, which is the whole connection),
because the read would reach past the row, while a token holding only `public_repo` under a
`public_repo` row still derives `github.read`. The same rule bounds a receiving agent's
Permission and scope ceiling, so a recipient row naming only the narrower source is not issued
the read. Deciding it reads the stored row's scope list through `getStored` on the built-in file
and SQLite backends: it decrypts the row's stored credential fields, without refreshing them or
calling the provider, and no token value is logged or returned. That holds for those backends
and for accessors whose read and error behaviour is known, not for an arbitrary custom
`StorageBackend`, whose `get()` fallback may refresh or hide an expired row. A refusal on that
basis releases no credential. A scope a wildcard parent receipt covers (`crm.*` covering
`crm.read`) is carried into the child's delegation by name, and the receiving agent's ceiling
bounds the child's returned scopes, its receipt and the hop's audit record.

### `cred.getConsentUrl(params)`

Get the URL to send a user to for connecting a service.

```typescript
const consentUrl = cred.getConsentUrl({
  userId: 'user_123',
  appClientId: 'app_xxx',
  service: 'google',
  scopes: ['calendar.readonly'],
  redirectUri: 'https://yourapp.com/callback',
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

### `cred.listWebBotAuthKeys()`

List registered Web Bot Auth identities from a Cred server.

```typescript
const keys = await cred.listWebBotAuthKeys();
```

### `cred.getWebBotAuthDirectoryUrl()`

Return the expected `Signature-Agent` directory URL for the configured Cred server.

```typescript
const signatureAgent = cred.getWebBotAuthDirectoryUrl();
```

### `cred.getWebBotAuthDirectory()`

Fetch the current Web Bot Auth directory document from the Cred server.

```typescript
const directory = await cred.getWebBotAuthDirectory();

for (const key of directory.keys) {
  console.log(key.kid);
}
```

### `cred.registerWebBotAuthKey(params)`

Register or import a Web Bot Auth public key.

```typescript
const registered = await cred.registerWebBotAuthKey({
  publicKey: myEd25519PublicKeyBytes,
  initialScopes: ['calendar.readonly'],
  metadata: { environment: 'prod' },
});
```

### `cred.rotateWebBotAuthKey(params)`

Rotate the public key for a registered Web Bot Auth identity.

```typescript
const rotated = await cred.rotateWebBotAuthKey({
  agentId: registered.agentId,
  publicKey: nextEd25519PublicKeyBytes,
  gracePeriodHours: 24,
});
```

### `createWebBotAuthSigner(config)`

Create a reusable Web Bot Auth signer for outbound HTTP requests.

```typescript
import { createWebBotAuthSigner } from '@credninja/sdk';

const signer = createWebBotAuthSigner({
  privateKeyHex: process.env.CRED_WEB_BOT_AUTH_PRIVATE_KEY_HEX!,
  signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
  ttlSeconds: 60,
});

const signedHeaders = signer.signRequest({
  url: 'https://api.example.com/v1/resource',
  method: 'GET',
});
```

This signer is transport-agnostic. It only returns headers; it does not send the request.

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
const { receipt } = await cred.delegateHandle({
  userId: 'user_123',
  appClientId: 'app_xxx',
  service: 'google',
  agentIdentity: identity,
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
| Linear | `linear` |
| HubSpot | `hubspot` |

## Error handling

```typescript
import { Cred, ConsentRequiredError, CredError } from '@credninja/sdk';

try {
  const { token } = await cred.delegateHandle({ ... });
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

- Node.js 22+ (uses built-in `fetch`)
- Runtime dependencies: the dependency-free `@credninja/protocol` and
  `@credninja/attenuation` packages. Cloud-only installs do not need the optional
  `@credninja/vault` or `@credninja/oauth` peers.
- All cloud delegation methods validate and detach constraints before transport
  or signing. Values JSON would silently drop or coerce (such as nested
  `undefined`) are rejected with `invalid_constraints`, not signed after alteration.

## Standalone First

For fully local operation, use [`@credninja/oauth`](../oauth) + [`@credninja/vault`](../vault). No account needed.

For a separate broker process, point `baseUrl` at your own self-hosted [`@credninja/server`](../server) deployment.

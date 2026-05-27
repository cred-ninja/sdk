# @credninja/tofu

Trust-on-first-use agent identity primitives for Cred.

`@credninja/tofu` stores Ed25519 agent identities, verifies agent signatures,
publishes Web Bot Auth-compatible JWKs, and supports key rotation with a grace
window. It is used by `@credninja/server` to bind agent keys before accepting
signed delegation requests.

## Install

```bash
npm install @credninja/tofu
```

## Quick Start

```typescript
import { createAgentVault, generateKeypair } from '@credninja/tofu';

const vault = await createAgentVault({
  storage: 'sqlite',
  path: './agents.sqlite',
});

const keypair = await generateKeypair();

const registered = await vault.registerAgent({
  publicKey: keypair.publicKey,
  initialScopes: ['calendar.readonly'],
  metadata: { name: 'calendar-agent' },
});

await vault.claimAgent({
  fingerprint: registered.fingerprint,
  ownerUserId: 'user_123',
});

const agents = await vault.listAgents();
console.log(agents[0]?.keyId);
```

## Web Bot Auth Directory Keys

```typescript
import { agentIdentityToDirectoryJwks } from '@credninja/tofu';

const [agent] = await vault.listAgents();
const jwks = agentIdentityToDirectoryJwks(agent);
```

The generated JWKs use `kty: "OKP"`, `crv: "Ed25519"`, `alg: "EdDSA"`, and
stable RFC 7638 thumbprint key IDs.

## Key Rotation

```typescript
const rotated = await generateKeypair();

await vault.rotateKey({
  fingerprint: registered.fingerprint,
  newPublicKey: rotated.publicKey,
  gracePeriodHours: 24,
});
```

During the grace window, both the current key and previous key can verify
signatures. After the window expires, only the current key is accepted.

## Storage

Two storage backends are included:

- `sqlite`: durable local SQLite storage via `better-sqlite3`.
- `file`: encrypted-free JSON storage for simple local development and tests.

Use SQLite for production server deployments.

## Security Notes

- Raw private keys are never stored by this package.
- Public keys must be raw 32-byte Ed25519 public keys.
- Revoked agents cannot verify signatures or rotate keys.
- Rotation requires the current fingerprint, which prevents rotating from an
  already-expired previous key.

## License

Apache License 2.0

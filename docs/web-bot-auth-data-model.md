# Web Bot Auth Data Model

This document captures the data model Cred uses for native Web Bot Auth support and how it extends the existing TOFU agent store.

## Canonical Identity Fields

Each registered signed-agent identity is modeled with these canonical fields:

- `agentId`: Cred's stable logical principal ID for the agent.
- `fingerprint`: Cred's legacy TOFU fingerprint for the current raw Ed25519 public key.
- `keyId`: RFC 7638 JWK thumbprint for the current public key. This is the canonical Web Bot Auth key identifier.
- `status`: `unclaimed`, `active`, or `revoked`.
- `signatureAgent`: the absolute `/.well-known/http-message-signatures-directory` URL published by the Cred server.
- `initialScopes`: scope ceiling captured at registration time.
- `metadata`: operator-supplied structured metadata for environment, app ownership, or deployment tags.
- `createdAt`, `updatedAt`, `claimedAt`, `revokedAt`: lifecycle timestamps.

## Rotation Fields

Cred currently models a pragmatic two-key rotation window:

- `previousFingerprint`: the immediately previous TOFU fingerprint.
- `previousKeyId`: the immediately previous RFC 7638 thumbprint.
- `rotationGraceExpiresAt`: the time until which the previous key remains published in the directory.

During the grace window, the directory publishes both the current and previous JWK entries. Once the grace window expires, only the current key remains published.

## Storage Mapping

The Web Bot Auth model is stored on top of the existing TOFU agent vault.

- The TOFU store remains the durable source of agent principal records.
- Web Bot Auth adds JWK-compatible metadata rather than replacing the TOFU store.
- `keyId` is derived from the stored public key and persisted with the identity record so audit trails and policy decisions can reference stable Web Bot Auth identifiers.

This means Cred has one agent registry, not separate TOFU and Web Bot Auth registries.

## Directory Representation

Cred publishes a Web Bot Auth directory document with:

- the server directory signing key
- all non-revoked current agent JWKs
- previous agent JWKs that are still inside their configured grace window

Each key is published as an OKP Ed25519 JWK with:

- `kty: "OKP"`
- `crv: "Ed25519"`
- `x`
- `kid`
- `alg: "EdDSA"`
- `use: "sig"`

## Migration Rules

Existing TOFU records migrate into the Web Bot Auth model as follows:

1. Preserve the existing `agentId`.
2. Preserve the existing TOFU `fingerprint` for compatibility.
3. Derive and store `keyId` from the same public key as the canonical Web Bot Auth identifier.
4. Treat historical rows without explicit rotation metadata as single-key active identities.

No refresh-token or OAuth-vault data is affected by this migration.

## Non-Goals of the Current Model

The current implementation intentionally does not attempt:

- an arbitrary active keyset per agent
- remote KMS-backed private-key management for agent keys
- cross-server key federation between independent Cred deployments

Those are future extensions. The current model is sufficient for direct Web Bot Auth publishing, verification, rotation grace, auditability, and Guard enforcement.

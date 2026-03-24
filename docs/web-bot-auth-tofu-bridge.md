# TOFU and Web Bot Auth Bridge

Cred currently supports both its original TOFU proof-of-possession flow and native Web Bot Auth. This document defines how those identity systems relate.

## Core Rule

There is one logical agent principal in Cred.

- TOFU is the bootstrap and compatibility identity mechanism.
- Web Bot Auth is the standards-facing transport identity mechanism.

They are not separate agent registries.

## Principal Resolution

Cred resolves a principal in this order:

1. Web Bot Auth verified ingress identity, when present and successfully verified.
2. TOFU-authenticated principal from explicit proof-of-possession material.
3. Bearer-token-only caller identity, with no signed-agent guarantee.

When Web Bot Auth verification succeeds, its `keyId`, `signatureAgent`, and resolved agent metadata are treated as the authoritative ingress identity for Guard and audit.

## Shared Record Model

Both identity paths map to the same stored agent record:

- TOFU references the raw public key fingerprint.
- Web Bot Auth references the RFC 7638 JWK thumbprint for the same public key.
- Rotation metadata is shared so the same principal can continue to verify during grace windows.

This is why registration and rotation APIs write into the TOFU-backed store instead of creating a second identity database.

## Migration Story

The migration path from TOFU-only agents to Web Bot Auth-capable agents is:

1. Keep the existing agent record and `agentId`.
2. Derive a canonical Web Bot Auth `keyId` from the stored public key.
3. Publish the public key in the Cred-hosted `Signature-Agent` directory.
4. Optionally begin sending signed HTTP requests using the same key material or a rotated successor key.

This keeps older TOFU flows working while allowing newer signed-agent flows to layer on top.

## Audit Semantics

Audit entries must avoid identity ambiguity.

- `fingerprint` remains available for TOFU compatibility.
- `keyId` is the canonical Web Bot Auth key identifier.
- `signatureAgent` is captured when a request is Web Bot Auth-verified.
- Guard and server audit flows should prefer verified Web Bot Auth metadata over caller-supplied headers.

## Policy Semantics

`webBotAuthPolicy` operates on verified ingress state, not on raw caller claims. That allows Guard to enforce:

- signed-agent required
- expected `signatureAgent`
- expected `keyId`
- known registration state

TOFU-specific policies can still run independently where proof-of-possession flows are used.

## Residual Limitations

The current bridge still has a few pragmatic limits:

- rotation is modeled as current plus previous key, not an arbitrary keyset
- TOFU remains available as a bootstrap path even when Web Bot Auth is enforced elsewhere
- multi-deployment trust federation is out of scope

Those do not create ambiguity about how a principal is resolved inside one Cred deployment.

# ADR: Web Bot Auth Identity Model

## Status

Accepted

## Date

2026-03-23

## Context

Cred already uses Ed25519 in two places:

- delegation receipts in the SDK and server
- TOFU agent identity in `@credninja/tofu`

Cloudflare Web Bot Auth uses HTTP Message Signatures with Ed25519 keys published through a signed directory at `/.well-known/http-message-signatures-directory`.

That means Cred already has compatible cryptographic primitives, but not a canonical identity model for Web Bot Auth.

## Decision

Cred will speak Web Bot Auth directly.

The canonical public representation for Web Bot Auth keys is:

- JWK for individual keys
- JWKS for directory responses
- RFC 7638 JWK thumbprints for `kid` / `keyid`

Cred's existing identity formats remain valid, but with narrower roles:

- raw Ed25519 public keys remain the internal storage primitive
- `did:key` remains valid for Cred delegation receipts
- TOFU fingerprint remains an internal Cred identity handle and migration aid
- JWK thumbprint becomes the canonical Web Bot Auth key identifier

## Consequences

### Direct Cred support

Cred can host a native Web Bot Auth directory and later sign outbound requests directly without depending on another product.

### TOFU remains useful

TOFU is not removed immediately. It remains:

- a local identity bootstrap mechanism
- a server-side proof-of-possession flow for delegation requests
- an internal bridge to Web Bot Auth-managed keys

### VestAuth remains compatible

VestAuth is treated as a compatible partner path on top of Cred:

- Cred can manage and expose native Web Bot Auth keys directly
- users who prefer VestAuth-managed signing may still pair it with Cred delegation
- future integration work may let Cred import or reference VestAuth-managed identity material

## Non-Goals for the First Slice

- full HTTP Message Signature signing for all outbound request paths
- signed directory responses
- a complete TOFU-to-Web-Bot-Auth migration story
- SDK-level signing helpers across all runtimes

## First Supported Execution Path

The first signed outbound request path should be MCP/proxy mode, because that is where Cred already sits in the upstream HTTP execution path.

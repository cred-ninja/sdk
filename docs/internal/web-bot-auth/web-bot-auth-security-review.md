# Web Bot Auth Security Review

This document records the practical hardening review for Cred's native Web Bot Auth implementation.

## Review Scope

Reviewed surfaces:

- directory publishing
- directory signature generation
- inbound signature verification
- nonce replay defense
- rotation grace behavior
- Guard and audit metadata handling
- MCP outbound signing path

## Issues Reviewed and Current State

### Replay within validity window

Status: mitigated

- Request verification requires a nonce.
- Nonces are rejected if reused before signature expiry.
- Cred supports a shared SQLite nonce store so multiple instances can reject the same replay when they share the same nonce database.

Residual risk:

- large distributed deployments may prefer Redis or Postgres-backed nonce storage for stronger operational semantics.

### Unsafely trusted caller headers

Status: mitigated

- MCP strips caller-supplied `Authorization`, `Signature`, `Signature-Input`, and `Signature-Agent` before signing.
- Guard/audit prefer verified ingress identity over forwarded metadata.

Residual risk:

- operators still need to avoid trusting unsigned upstream forwarding layers that rewrite identity-related headers.

### Rotation confusion

Status: mitigated

- directory publication includes both current and previous keys during the grace window.
- key APIs return previous-key and grace metadata so operators can inspect live rotation state.

Residual risk:

- the model is still current-plus-previous rather than a full multi-key lifecycle.

### Stale or mirrored directories

Status: mitigated

- directories are signed with the directory signing key.
- inbound verification validates directory signature headers before trusting remote directory contents.

Residual risk:

- deployments should still use HTTPS and sensible cache controls.

### Incomplete transport coverage

Status: partially mitigated

- MCP outbound traffic can be signed natively.
- Cred server ingress can require signed-agent requests.
- SDK exposes a public signer for non-MCP transports.

Residual risk:

- not every integration path in the broader ecosystem will automatically sign unless the caller adopts the signer.

## Test Evidence

Coverage exists for:

- JWK/thumbprint generation
- directory publishing
- directory signature verification
- ingress success and failure cases
- nonce replay rejection, including shared SQLite state across instances
- MCP signed and unsigned request execution
- SDK signer output and verification

There is also a gated live smoke harness for external directory validation.

## Operational Signoff Criteria

Before production signoff, verify:

1. HTTPS is enforced end-to-end.
2. `WEB_BOT_AUTH_MODE=require` is enabled where signed-agent enforcement is desired.
3. shared nonce storage is configured for multi-instance deployments.
4. rotation grace windows are documented operationally.
5. the Cloudflare submission checklist has been completed.

## Review Outcome

Outcome: acceptable for production use with the documented residual risks.

The remaining work is operational enhancement, not a blocker to native Web Bot Auth support in Cred.

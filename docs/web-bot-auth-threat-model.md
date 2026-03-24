# Web Bot Auth Threat Model

This note captures the main security assumptions and residual risks in Cred's current Web Bot Auth implementation.

## Scope

- Signed directory hosting in `@credninja/server`
- Inbound Web Bot Auth verification on authenticated server routes
- Outbound Web Bot Auth signing via MCP and SDK helpers
- Key lifecycle APIs for register, list, and rotate

## Trust Boundaries

- Bearer agent auth remains a separate control from Web Bot Auth transport identity.
- `Signature-Agent` directories are trusted only after signature verification.
- A shared nonce store is required to reject cross-instance replay in multi-node deployments.
- TOFU and Web Bot Auth identities may coexist; audit records must make the active identity source explicit.

## Primary Risks

### Replay

- Risk: an attacker replays a valid signed request inside the signature validity window.
- Current control:
  - `created` and `expires` are enforced.
  - `nonce` is required.
  - Nonces are rejected on reuse.
  - Cross-instance replay is covered when all instances share the same SQLite nonce store.
- Residual gap:
  - SQLite on local disk is not sufficient for regionally distributed or ephemeral multi-host deployments without shared storage.

### Stale or Mirrored Directories

- Risk: a stale directory is replayed or a mirrored directory is served under an attacker-controlled URL.
- Current control:
  - Directories must be signed with `tag="http-message-signatures-directory"`.
  - Directory signing key must be present in the directory.
  - Signature expiry is enforced.
  - Remote `Signature-Agent` URLs must use HTTPS unless localhost.
- Residual gap:
  - There is no pinning or allowlist of remote directory hosts beyond HTTPS and signature validation.

### Rotation Confusion

- Risk: old and new keys are interpreted inconsistently during grace windows.
- Current control:
  - TOFU rotation preserves the previous key for a bounded grace period.
  - Directory publication now includes both current and previous keys during that window.
  - API responses expose previous key metadata.
- Residual gap:
  - The lifecycle still models one current key plus one previous key, not an arbitrary keyset with richer state transitions.

### Downgrade / Partial Adoption

- Risk: deployments believe they are protected while running with only Bearer auth.
- Current control:
  - `WEB_BOT_AUTH_MODE=require` forces signed ingress.
  - `optional` exists for migration and mixed-client periods.
- Residual gap:
  - `off` remains the default for compatibility, so production operators must opt into enforcement deliberately.

### Metadata Trust Confusion

- Risk: policy evaluates user-supplied Web Bot Auth metadata rather than verified ingress state.
- Current control:
  - Server ingress verification injects verified `web_bot_auth_key_id` and `signature_agent` into the request path.
  - Guard and audit carry identity-source fields.
- Residual gap:
  - Not every caller path distinguishes verified metadata from merely forwarded metadata with first-class type separation.

## Operational Guidance

- Use `WEB_BOT_AUTH_MODE=require` for production signed-agent ingress.
- Use `WEB_BOT_AUTH_NONCE_STORE=sqlite` with a storage path shared by all Cred instances that must reject the same nonce.
- Keep the directory served over stable HTTPS.
- Rotate keys with a non-zero grace window and verify the directory shows both keys before cutting traffic.

## Follow-On Hardening

- Add a Redis or Postgres nonce backend for stronger distributed replay defense.
- Add host allowlists or pinning controls for remote `Signature-Agent` verification.
- Model multi-key active sets explicitly instead of only current-plus-previous.
- Separate verified identity metadata from caller-supplied metadata more strongly in Guard APIs.

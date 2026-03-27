# Web Bot Auth Build Tickets

This document turns the Web Bot Auth integration plan into a sequential GitHub-ready backlog for `cred-oss`.

Execution rules:

- Run tickets in order.
- Do not start a ticket until all listed dependencies are complete.
- Keep Web Bot Auth identity concerns separate from credential delegation concerns.
- Default to shipping the first signed-request path through MCP/proxy mode before broad SDK transport work.

Suggested shared labels:

- `area/identity`
- `area/server`
- `area/sdk`
- `area/mcp`
- `area/guard`
- `area/docs`
- `area/security`
- `type/design`
- `type/feature`
- `type/testing`

## Ticket 1: ADR - Agent Identity Strategy

- Type: `type/design`
- Labels: `area/identity`, `area/docs`
- Estimate: `M`
- Depends on: none

### Summary
Write an architecture decision record defining how Cred will integrate with Cloudflare Web Bot Auth and how that relates to existing TOFU identity flows.

### Problem
The repo currently has Ed25519-based agent identity and receipt signing, but no canonical Web Bot Auth identity model. Without a written decision, later storage, API, and SDK work will drift.

### Scope
- Define canonical agent identity representation for Web Bot Auth.
- Decide whether `did:key`, raw Ed25519, and JWK are internal-only or public interfaces.
- Decide whether Cred manages signing keys, imports them, or supports both.
- Define the role of `@credninja/tofu` after Web Bot Auth support lands.
- Define non-goals for v1.

### Acceptance Criteria
- ADR merged under `docs/` or equivalent design location.
- Canonical public key format is explicitly named.
- TOFU relationship is explicit: retained, bridged, or deprecated.
- The first supported signed-request execution path is explicitly chosen.

## Ticket 2: Data Model Design for Web Bot Auth Keys

- Type: `type/design`
- Labels: `area/identity`, `area/server`
- Estimate: `M`
- Depends on: Ticket 1

### Summary
Design the persistence model required to host Cloudflare-compatible key directories and rotate signing keys safely.

### Problem
The current TOFU model stores public keys and fingerprints, but Web Bot Auth needs JWK-compatible material, thumbprints, directory URLs, and rotation state.

### Scope
- Define fields for JWK export, JWK thumbprint, active status, previous keys, rotation grace windows, and signature-agent URL.
- Map current TOFU rows to the new model.
- Decide whether one agent can have multiple active Web Bot Auth keys.
- Define audit fields required for key lifecycle events.

### Acceptance Criteria
- Schema design is documented.
- Migration approach from current TOFU records is documented.
- Distinction between TOFU fingerprint and Web Bot Auth `keyid` is explicit.

## Ticket 3: Implement JWK Export and Thumbprint Utilities

- Type: `type/feature`
- Labels: `area/identity`, `area/sdk`
- Estimate: `M`
- Depends on: Ticket 2

### Summary
Add utilities to convert Cred-managed Ed25519 public keys into Web Bot Auth compatible JWK and JWKS material.

### Problem
Cloudflare requires Ed25519 public keys to be exposed as JWK/JWKS and referenced by base64url JWK thumbprints. The repo currently only exposes raw public-key bytes and custom fingerprints.

### Scope
- Convert raw Ed25519 public keys to OKP JWK.
- Compute RFC 7638 thumbprints.
- Serialize valid JWKS payloads.
- Add fixture-based tests.

### Acceptance Criteria
- Utility API returns stable JWK output.
- RFC 7638 thumbprint output is deterministic.
- Tests cover malformed keys and round-trip serialization.

## Ticket 4: Extend `@credninja/tofu` Storage for Web Bot Auth Metadata

- Type: `type/feature`
- Labels: `area/identity`, `area/server`
- Estimate: `L`
- Depends on: Ticket 3

### Summary
Extend agent storage so Web Bot Auth metadata can live alongside existing TOFU identity records.

### Problem
The current storage layer cannot represent the extra metadata needed to host a signature directory and manage rotation windows cleanly.

### Scope
- Add storage fields from Ticket 2.
- Preserve current TOFU register, claim, revoke, and verification behavior.
- Support current and previous signing key metadata.
- Expose query methods needed by server routes.

### Acceptance Criteria
- Storage backends migrate cleanly.
- Existing TOFU tests keep passing or are updated intentionally.
- Web Bot Auth key metadata can be read without custom SQL in server code.

## Ticket 5: Host `/.well-known/http-message-signatures-directory`

- Type: `type/feature`
- Labels: `area/server`, `area/identity`
- Estimate: `M`
- Depends on: Ticket 4

### Summary
Add the required Cloudflare key directory route to `@credninja/server`.

### Problem
The server currently exposes no `/.well-known/http-message-signatures-directory` endpoint, which blocks Cloudflare registration entirely.

### Scope
- Add `GET /.well-known/http-message-signatures-directory`.
- Serve a JWKS payload with active Ed25519 public keys only.
- Use the Cloudflare-required content type.
- Support multi-key output during rotation windows.

### Acceptance Criteria
- Route exists and returns `200`.
- Content type is `application/http-message-signatures-directory+json`.
- Response never leaks private key material.
- Integration test covers single-key and rotating-key cases.

## Ticket 6: Sign the Directory Response

- Type: `type/feature`
- Labels: `area/server`, `area/security`
- Estimate: `L`
- Depends on: Ticket 5

### Summary
Sign the key directory response using HTTP Message Signatures in the format Cloudflare expects.

### Problem
Hosting a JWKS is not enough. Cloudflare requires the directory response itself to be signed with `Signature` and `Signature-Input`.

### Scope
- Sign the directory response headers.
- Include required `tag="http-message-signatures-directory"`.
- Compute `keyid` using JWK thumbprints.
- Use a short expiry window.
- Add validation fixtures and negative tests.

### Acceptance Criteria
- Directory response includes valid `Signature` and `Signature-Input` headers.
- Tests verify the signed response canonicalization.
- Failure mode is explicit when no signing key is configured.

## Ticket 7: Add Reusable Web Bot Auth Request Signer

- Type: `type/feature`
- Labels: `area/sdk`, `area/mcp`, `area/identity`
- Estimate: `L`
- Depends on: Ticket 6

### Summary
Add a reusable internal signer for outbound HTTP requests that emits Cloudflare-compatible Web Bot Auth headers.

### Problem
There is no reusable signing primitive for outbound requests, so every future integration path would otherwise reimplement header construction and canonicalization.

### Scope
- Create a signer module for `Signature`, `Signature-Input`, and `Signature-Agent`.
- Start with minimal recommended components: `@authority` and `signature-agent`.
- Support nonce and short-lived expiry.
- Keep the signer transport-agnostic.

### Acceptance Criteria
- Signer can decorate an outbound request object without sending it.
- Output matches expected fixture format.
- Unit tests cover GET and POST requests and expiry logic.

## Ticket 8: Integrate Web Bot Auth Signing into `cred_use`

- Type: `type/feature`
- Labels: `area/mcp`, `area/sdk`, `area/security`
- Estimate: `M`
- Depends on: Ticket 7

### Summary
Make MCP proxy mode the first shipping path for Cred-originated signed requests.

### Problem
The main SDK architecture is not in the hot path of upstream API requests, but `cred_use` already is. This is the fastest path to real compatibility.

### Scope
- Add optional signing support in `packages/mcp/src/tools/use.ts`.
- Preserve existing SSRF protections and bearer-token handling.
- Gate signing by config or service allowlist.
- Include `Signature-Agent` in signed components.

### Acceptance Criteria
- Signed requests are emitted when enabled.
- Existing unsigned behavior is unchanged by default.
- Tests cover signed and unsigned request execution.

## Ticket 9: Add Agent Registration and Key Management API

- Type: `type/feature`
- Labels: `area/server`, `area/identity`
- Estimate: `L`
- Depends on: Ticket 8

### Summary
Expose a stable server API for registering, importing, rotating, and listing Web Bot Auth keys.

### Problem
Without API support, key lifecycle remains implementation-only and difficult to operate or automate.

### Scope
- Add routes to register/import keys.
- Add routes to list active keys and metadata.
- Add rotation support with grace periods.
- Return canonical `keyid` and signature-agent URL values.

### Acceptance Criteria
- API is documented and covered by tests.
- Rotation preserves old-key validation for the configured grace period.
- Returned metadata matches directory output.

## Ticket 10: Bridge TOFU Identity to Web Bot Auth Identity

- Type: `type/feature`
- Labels: `area/identity`, `area/server`
- Estimate: `L`
- Depends on: Ticket 9

### Summary
Define and implement the compatibility layer between current TOFU-authenticated principals and new Web Bot Auth identities.

### Problem
Cred already has TOFU-based request authentication and authorization hooks. Without a bridge, the repo will carry two overlapping identity systems with unclear semantics.

### Scope
- Map existing TOFU principals to Web Bot Auth identity records.
- Decide when TOFU remains valid for delegation requests.
- Prevent identity confusion in audit logs and permissions.
- Add migration and interoperability tests.

### Acceptance Criteria
- A principal can be resolved consistently across TOFU and Web Bot Auth.
- Audit events identify the same principal deterministically.
- Legacy TOFU flows remain functional or are intentionally deprecated with docs.

## Ticket 11: Add `webBotAuthPolicy` to `@credninja/guard`

- Type: `type/feature`
- Labels: `area/guard`, `area/identity`, `area/security`
- Estimate: `M`
- Depends on: Ticket 10

### Summary
Add a Guard policy that can enforce Web Bot Auth identity requirements before Cred delegates credentials.

### Problem
Cred's durable value is policy and governance. Without Guard support, Web Bot Auth stays an attachment instead of becoming part of authorization decisions.

### Scope
- Add a built-in Guard policy for Web Bot Auth identity checks.
- Support configuration to require registered signing identity.
- Support configuration to require specific key states or signing modes.
- Emit structured audit metadata for policy decisions.

### Acceptance Criteria
- Policy denies when identity requirements are not met.
- Policy composes with existing Guard chain behavior.
- Tests cover allow, deny, and skip cases.

## Ticket 12: Extend Audit Model for Signed-Agent Metadata

- Type: `type/feature`
- Labels: `area/security`, `area/server`, `area/identity`
- Estimate: `M`
- Depends on: Ticket 11

### Summary
Add audit metadata that captures which signed-agent identity was used for key events and outbound signed requests.

### Problem
Current audit events capture delegation and scope information, but not the Web Bot Auth identity material needed for debugging and compliance.

### Scope
- Add optional audit fields for thumbprint, signature-agent URL, key version, and signing mode.
- Preserve backward compatibility for existing audit queries.
- Update audit documentation and tests.

### Acceptance Criteria
- New metadata appears in audit records when available.
- Existing readers do not break.
- No private key material or unsafe secrets are logged.

## Ticket 13: Add SDK Surface for Signed-Agent Workflows

- Type: `type/feature`
- Labels: `area/sdk`, `area/identity`
- Estimate: `M`
- Depends on: Ticket 12

### Summary
Expose a minimal SDK interface for accessing signed-agent metadata and optional request signing helpers.

### Problem
Once the server and MCP path support Web Bot Auth, application developers still need a clean public interface instead of internal modules.

### Scope
- Add SDK helpers to fetch directory URL and key metadata.
- Optionally expose outbound request signing helpers for Node environments.
- Keep signing APIs separate from delegation APIs.

### Acceptance Criteria
- Public API is documented and tested.
- API naming clearly separates identity and authorization concerns.
- No breaking change to existing `Cred` delegation flow.

## Ticket 14: Add End-to-End Examples for Cred + Web Bot Auth

- Type: `type/feature`
- Labels: `area/docs`, `area/sdk`, `area/mcp`
- Estimate: `M`
- Depends on: Ticket 13

### Summary
Add runnable examples showing how Cred works with Cloudflare Web Bot Auth and with an external signer such as VestAuth.

### Problem
Without examples, users will continue to assume Cred competes with Web Bot Auth rather than complementing it.

### Scope
- Example: Cred delegation plus MCP signed outbound request.
- Example: Cred delegation plus external signer flow.
- Example: Cred plus VestAuth interoperability notes or sample.
- Add short architecture explanation for each example.

### Acceptance Criteria
- Examples are committed under `examples/` or package docs.
- Examples compile or run under documented prerequisites.
- Docs clearly describe when to use Cred, Web Bot Auth, or both.

## Ticket 15: Add Cloudflare Compatibility Test Harness

- Type: `type/testing`
- Labels: `area/security`, `area/server`, `area/mcp`
- Estimate: `L`
- Depends on: Ticket 14

### Summary
Create a compatibility harness that validates signed requests and signature directory responses against Cloudflare expectations.

### Problem
Web Bot Auth failures are easy to introduce through subtle header or canonicalization mistakes. Manual testing is not enough.

### Scope
- Add fixture tests for signed requests.
- Add fixture tests for directory responses.
- Add negative tests for common Cloudflare rejection cases.
- Optionally add a gated live smoke test against `crawltest.com`.

### Acceptance Criteria
- Test suite catches malformed `Signature-Agent`.
- Test suite catches missing signed `signature-agent` component.
- Test suite catches expired signatures and bad thumbprints.

## Ticket 16: Security Review and Hardening Pass

- Type: `type/feature`
- Labels: `area/security`
- Estimate: `L`
- Depends on: Ticket 15

### Summary
Run a focused security review on the new identity, signing, and directory-hosting surfaces and implement hardening fixes.

### Problem
This feature introduces replay windows, key lifecycle complexity, and header-canonicalization risk. Shipping without a dedicated hardening pass is not acceptable.

### Scope
- Threat model replay, stale directories, mirrored directories, mixed identity confusion, and rotation edge cases.
- Review log safety and audit fields.
- Review downgrade and misconfiguration behavior.
- Land fixes and add missing tests.

### Acceptance Criteria
- Threat model notes are documented.
- All high-severity issues are fixed before release.
- Security-sensitive defaults are explicit in docs and config.

## Ticket 17: Refresh Product and Technical Documentation

- Type: `type/feature`
- Labels: `area/docs`, `area/sdk`, `area/server`
- Estimate: `M`
- Depends on: Ticket 16

### Summary
Update repo documentation to position Cred correctly relative to Web Bot Auth and describe the new capabilities accurately.

### Problem
Current docs say Cred is not in the hot path of API calls, while the MCP path can become the first signed outbound path. Messaging and architecture docs need to match reality.

### Scope
- Update top-level README and relevant package READMEs.
- Document identity versus authorization responsibilities.
- Document TOFU relationship after the bridge work.
- Add deployment notes for directory hosting and rotation.

### Acceptance Criteria
- Docs do not claim compatibility before the feature actually exists.
- README clearly explains Cred versus Web Bot Auth.
- Deployment steps for directory hosting and request signing are documented.

## Ticket 18: Cloudflare Submission Readiness

- Type: `type/feature`
- Labels: `area/identity`, `area/server`, `area/docs`
- Estimate: `S`
- Depends on: Ticket 17

### Summary
Prepare the project and operations checklist required to submit Cred-backed signed agents or key directories to Cloudflare.

### Problem
Technical support alone is not enough. The project needs a clear readiness checklist for production hosting, stable keys, and registration workflow.

### Scope
- Verify production HTTPS requirements for the directory.
- Verify operational key rotation process.
- Verify real signed requests from the intended execution path.
- Prepare submission checklist and example registration values.

### Acceptance Criteria
- Submission checklist is documented.
- Required runtime configuration values are known.
- Project is ready for real Cloudflare registration without additional design work.

## Recommended Milestone Cuts

If a smaller first release is needed, use these milestone boundaries:

- Milestone A: Tickets 1-6
  - Web Bot Auth-ready key model and signed directory
- Milestone B: Tickets 7-8
  - First signed outbound request path via MCP
- Milestone C: Tickets 9-12
  - Managed identity lifecycle and Guard integration
- Milestone D: Tickets 13-18
  - Public SDK, examples, hardening, docs, and submission readiness

## Notes for GitHub Issue Creation

When creating issues from this file:

- Use the section title as the issue title.
- Copy `Summary`, `Problem`, `Scope`, and `Acceptance Criteria` into the issue body.
- Preserve the `Depends on` field in the issue description or linked-project metadata.
- Keep execution sequential unless dependencies are intentionally reworked.

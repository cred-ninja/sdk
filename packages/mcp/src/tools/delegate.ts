# Security Audits

This document is a running log of security reviews conducted on the packages in this repository. We publish our security posture before launch — not after. If you find something we missed, see [SECURITY.md](./SECURITY.md).

---

## Audit 1 — SDK Static Analysis
**Date:** 2026-03-03
**Scope:** `packages/sdk`, `packages/sdk-python`, `packages/integrations/*`
**Method:** Static analysis

### Summary
No vulnerabilities found.

### What was verified

**Credential handling**
- Agent tokens are never logged, included in error messages, or exposed in stack traces
- `ConsentRequiredError` surfaces only `consentUrl` and `code` — no internal state
- SDK is stateless between calls
- All HTTP calls require HTTPS — no plaintext fallback

**Dependency surface**
- TypeScript SDK: zero runtime dependencies (Node.js built-in `fetch` only)
- Python SDK: single dependency (`httpx`) — no transitive credential handling
- Integration packages: depend only on their respective frameworks plus the Python SDK

**Import isolation**
- No SDK package imports from proprietary infrastructure
- All packages are fully self-contained

---

## Audit 2 — Transport Security
**Date:** 2026-03-03
**Scope:** `packages/sdk/src/cred.ts`, `packages/sdk-python/cred/client.py`, `packages/mcp/src/config.ts`

### Summary
One finding identified and resolved.

### Findings

#### ✅ Resolved — Base URL validation
All three packages now validate the configured base URL at construction time. Non-HTTPS URLs are rejected with an explicit error before any network request is made.

Affected files: `sdk/src/cred.ts`, `sdk-python/cred/client.py`, `mcp/src/config.ts`

---

## Audit 3 — MCP Server Security
**Date:** 2026-03-03
**Scope:** `packages/mcp/src/`
**Method:** Threat modeling and code review

### Summary
Four findings identified, all resolved.

### Findings

#### ✅ Resolved — Token handling in tool results
MCP tool responses are now constructed to avoid including sensitive credential material. The `cred_delegate` tool returns a short-lived delegation handle; the `cred_use` tool exchanges the handle server-side and returns only the upstream API response.

#### ✅ Resolved — Outbound request validation
`cred_use` validates the target URL against a per-service allowlist before making any outbound request. Requests to URLs outside the known API surface for a given service are rejected.

| Service | Allowed origins |
|---------|----------------|
| Google | 8 specific `*.googleapis.com` API bases |
| GitHub | `https://api.github.com/` |
| Slack | `https://slack.com/api/` |
| Notion | `https://api.notion.com/` |
| Salesforce | `*.salesforce.com`, `*.force.com` |

#### ✅ Resolved — Header sanitization
The `Authorization` header cannot be overridden via caller-supplied extra headers. The server-side credential is always used.

#### ✅ Resolved — Response size control
Upstream API responses are truncated at 32KB. Oversized responses include a `truncated: true` field.

---

## Audit 4 — DID Agent Identity
**Date:** 2026-03-03
**Scope:** `packages/sdk/src/identity.ts`, `packages/sdk-python/cred/identity.py`
**Method:** Cryptographic correctness review

### Summary
No vulnerabilities found.

### What was verified

- `did:key` encoding follows spec — multicodec prefix `0xed01` correct for Ed25519, Base58btc alphabet verified identical in both implementations
- Both implementations produce identical DIDs for the same key material
- Key material is copied on read — callers cannot mutate stored keys
- `verifyDelegationReceipt()` throws if called with the pre-launch placeholder key — no silent acceptance or rejection

---

## Known Limitations

| Item | Status | Notes |
|------|--------|-------|
| `CRED_PUBLIC_KEY_HEX` | Pre-launch placeholder | Will be replaced with real key before npm/PyPI publish. Throws on use until replaced. |
| Delegation receipt signing | Pending (API-side) | `receipt` in `DelegationResult` is `undefined` until the Cred API implements server-side signing. |
| Automated dependency scanning | Pending | `npm audit` / `pip audit` not yet in OSS CI. |
| Independent third-party audit | Pending | Pre-launch audits are self-conducted. Independent audit planned before v1.0 GA. |

---

## Responsible Disclosure

Found something? Email **security@cred.ninja** — do not open a public issue.

We follow coordinated disclosure with a 90-day window. Details in [SECURITY.md](./SECURITY.md).

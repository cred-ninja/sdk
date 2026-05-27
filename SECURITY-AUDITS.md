# Security Audits

Cred was built security-first. This document summarizes audits conducted on the SDK, MCP, integration, and self-hosted server packages. Published before launch, not after.

Found something we missed? See [SECURITY.md](./SECURITY.md).

---

## Design Principles

These invariants are enforced across the SDK-facing packages in this repo:

- **Bounded credential persistence.** SDKs are stateless. In local mode the MCP server stores delegated access tokens only in-process behind opaque handles until expiration; in remote server mode it stores brokered handles and leaves provider tokens on the Cred server. Refresh tokens stay in the encrypted vault.
- **HTTPS for remote transport.** SDK-facing packages reject non-HTTPS remote base URLs at construction time. Plain HTTP is allowed only for explicit localhost development URLs where supported.
- **Zero runtime dependencies (TypeScript).** The TypeScript SDK uses only Node.js built-in `fetch`. No transitive dependency handles credentials.
- **Minimal dependencies (Python).** The Python SDK depends on `httpx` and `cryptography`. No transitive credential handling.
- **Small cryptography surface.** DID identity uses Node.js built-in `crypto` in TypeScript and the Python `cryptography` package in Python.
- **Token isolation**. Agent tokens never appear in error messages, stack traces, or logs. `ConsentRequiredError` surfaces only the consent URL and status code.

---

## Audit 1. SDK Static Analysis

**Date:** 2026-03-03
**Scope:** `packages/sdk`, `packages/sdk-python`, `packages/integrations/*`

### Result: No vulnerabilities found.

**Verified:**
- Agent tokens excluded from all error surfaces and stack traces
- `ConsentRequiredError` exposes only `consentUrl` and `code`. No internal state
- SDK stateless between calls. No credential carryover
- All remote HTTP calls enforce HTTPS. Plain HTTP is allowed only for explicit localhost development URLs where supported.
- Import isolation confirmed: no package imports from server-side infrastructure
- All packages fully self-contained

---

## Audit 2. Transport Security

**Date:** 2026-03-03
**Scope:** `packages/sdk`, `packages/sdk-python`, `packages/mcp`

### Result: One finding identified and resolved.

**Finding:** Base URL validation added to all three packages. Non-HTTPS remote URLs are now rejected at construction time with a clear error message. This prevents misconfiguration from silently downgrading transport security.

**Verified:**
- TypeScript SDK: `new Cred({ baseUrl: 'http://remote.example.com' })` throws
- Python SDK: `Cred(base_url='http://remote.example.com')` raises `CredError`
- MCP server: config validation rejects non-HTTPS API URLs

---

## Audit 3. MCP Token Relay Security

**Date:** 2026-03-03
**Scope:** `packages/mcp`. Token relay, SSRF protection, response handling

### Result: Follow-up hardening completed. SSRF bypass tests and scope-aware endpoint checks are in place.

**Verified:**
- `cred_use` tool relays authenticated requests without exposing tokens to the LLM context window
- SSRF allowlist (`isAllowedUrl()`) validated against 45 bypass techniques including URL parser confusion, IP encoding variants, and redirect chain patterns
- Responses truncated at 32KB with `truncated: true` indicator
- All errors returned as MCP tool content. Never thrown into the LLM runtime
- Token cache returns copies, not references. Callers cannot mutate cached state
- Google broker/MCP relay URLs are constrained by delegated scopes and fail closed when scope metadata is missing
- Brokered server use runs configured Guard policies, including `urlAllowlistPolicy`, before forwarding upstream requests

---

## Audit 7. Self-Hosted Server Cleanup

**Date:** 2026-05-26
**Scope:** `packages/server`, `packages/mcp`, `packages/create-cred-app`

### Result: Findings remediated in-tree.

**Resolved:**
- Provider-management routes now require admin auth. Browser bootstrap uses `/admin/login` and stores an HttpOnly same-site session cookie.
- Admin UI revocation uses the admin session instead of prompting for an agent token.
- TOFU registration now requires agent Bearer auth.
- The self-hosted server now exposes SDK-compatible `/api/v1/connections` list/revoke routes.
- Brokered handle paths are available in the server, TypeScript SDK, Python SDK, MCP, Vercel AI integration, and Python framework integrations.
- MCP cached delegations retain granted scopes and apply Google endpoint restrictions from those scopes.
- `create-cred-app` writes `REDIRECT_BASE_URI`, generates private `.env` files, and documents admin bootstrap.

---

## Audit 4. DID Agent Identity

**Date:** 2026-03-03
**Scope:** `packages/sdk/src/identity.ts`, `packages/sdk-python/cred/identity.py`

### Result: No vulnerabilities found.

**Verified:**
- `did:key` encoding follows spec. Multicodec prefix `0xed01` for Ed25519, Base58btc alphabet identical across both implementations
- Cross-SDK parity: TypeScript and Python produce identical DIDs for the same key material
- Key material copied on read. Callers cannot mutate stored keys
- `verifyDelegationReceipt()` throws on pre-launch placeholder key. No silent acceptance

---

## Audit 5. Spec-vs-Implementation Gap Analysis

**Date:** 2026-03-04
**Scope:** DID identity (3 tasks) and MCP server (3 tasks). 50 spec items verified

### Result: 47/50 implemented as specified. 1 benign gap, 2 intentional security improvements.

**Gap (benign):** One external dependency replaced with inline implementation. Eliminates a supply chain dependency.

**Improvements beyond spec:**
- Placeholder key detection throws instead of returning false. Prevents silent misconfiguration in production
- Delegation endpoints support opaque handles instead of raw tokens. This prevents credentials from entering LLM context windows on brokered paths
- Token cache includes SSRF allowlist validation (not in original spec)
- HTTPS remote-transport enforcement added at SDK, MCP, and Python client levels (not in original spec)

---

## Audit 6. Adversarial Input Testing

**Date:** 2026-03-04
**Scope:** DID identity edge cases and MCP tool handler boundaries

### Result: All adversarial inputs handled correctly.

**DID identity tests:**
- Malformed receipts (null, undefined, invalid JSON, truncated JWS). All rejected with clear errors
- DID mismatch detection. Receipts signed for wrong agent correctly rejected
- Base58 alphabet verification. Cross-SDK consistency confirmed
- Export/import round-trip integrity. Key material survives serialization

**MCP tool handler tests:**
- 6 end-to-end flows with real token cache and mocked dependencies
- Consent-required two-step flow verified
- Expired delegation handles correctly rejected
- Concurrent delegation requests isolated (no cache contamination)
- Provider failure errors contained and returned as tool content

---

## Test Coverage

| Package | Tests | Coverage |
|---------|-------|----------|
| TypeScript SDK | Unit + integration | `npm test` in `packages/sdk` |
| Python SDK | Unit + integration | `pytest` in `packages/sdk-python` |
| MCP Server | Unit + SSRF dynamic analysis | `npm test` in `packages/mcp` |
| Integrations | Per-framework unit tests | `pytest` in each integration package |

Key test suites:
- **45 SSRF bypass tests**. `packages/mcp/src/__tests__/ssrf-dynamic.test.ts`
- **Token cache isolation tests**. `packages/mcp/src/__tests__/token-cache.test.ts`
- **DID identity parity tests**. `packages/sdk/src/__tests__/identity.test.ts` + `packages/sdk-python/tests/test_identity.py`

---

## Dependency Audit

| Package | Runtime Dependencies | Status |
|---------|---------------------|--------|
| `@credninja/sdk` | 0 | Stateless TypeScript client; verify with `npm audit` |
| `cred-auth` (Python) | 2 (`httpx`, `cryptography`) | Minimal Python client; verify with Python audit tooling |
| `@credninja/mcp` | 2 (`@modelcontextprotocol/sdk`, `@credninja/sdk`) | Scope-aware relay; verify with `npm audit` |
| `cred-langchain` | 2 (`langchain-core`, `cred-auth`) | Integration package; verify with Python audit tooling |
| `cred-crewai` | 3 (`crewai`, `langchain-core`, `cred-auth`) | Integration package; verify with Python audit tooling |
| `cred-openai-agents` | 2 (`agents`, `cred-auth`) | Integration package; verify with Python audit tooling |

---

## Roadmap

| Item | Status |
|------|--------|
| Receipt signing | Ships with API v1.0. SDK verification code is ready |
| CI dependency scanning | `npm audit` in CI; Python audit tooling pending constraints/lockfile setup |
| Independent third-party audit | Planned before v1.0 GA |

---

## Responsible Disclosure

Found something? Email **security@cred.ninja**. Do not open a public issue.

We follow coordinated disclosure with a 90-day window. Details in [SECURITY.md](./SECURITY.md).

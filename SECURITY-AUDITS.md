# Security Audits

Cred was built security-first. This document summarizes the audits conducted on the client-side packages in this repository. Published before launch, not after.

Found something we missed? See [SECURITY.md](./SECURITY.md).

---

## Design Principles

These invariants are enforced across every package in this repo:

- **Zero credential persistence.** SDKs are stateless. No token is ever written to disk, cached between calls, or stored in memory beyond a single request lifecycle.
- **HTTPS-only.** All packages reject non-HTTPS base URLs at construction time. No plaintext fallback exists.
- **Zero runtime dependencies (TypeScript).** The TypeScript SDK uses only Node.js built-in `fetch`. No transitive dependency handles credentials.
- **Minimal dependencies (Python).** The Python SDK depends on `httpx` only. No transitive credential handling.
- **No third-party cryptography.** DID identity uses Node.js built-in `crypto` and Python stdlib `cryptography`. No external crypto packages.
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
- All HTTP calls enforce HTTPS. No plaintext fallback
- Import isolation confirmed: no package imports from server-side infrastructure
- All packages fully self-contained

---

## Audit 2. Transport Security

**Date:** 2026-03-03
**Scope:** `packages/sdk`, `packages/sdk-python`, `packages/mcp`

### Result: One finding identified and resolved.

**Finding:** Base URL validation added to all three packages. Non-HTTPS URLs are now rejected at construction time with a clear error message. This prevents misconfiguration from silently downgrading transport security.

**Verified:**
- TypeScript SDK: `new Cred({ baseUrl: 'http://...' })` throws
- Python SDK: `Cred(base_url='http://...')` raises `ValueError`
- MCP server: config validation rejects non-HTTPS API URLs

---

## Audit 3. MCP Token Relay Security

**Date:** 2026-03-03
**Scope:** `packages/mcp`. Token relay, SSRF protection, response handling

### Result: No vulnerabilities found. 45 SSRF bypass tests added.

**Verified:**
- `cred_use` tool relays authenticated requests without exposing tokens to the LLM context window
- SSRF allowlist (`isAllowedUrl()`) validated against 45 bypass techniques including URL parser confusion, IP encoding variants, and redirect chain patterns
- Responses truncated at 32KB with `truncated: true` indicator
- All errors returned as MCP tool content. Never thrown into the LLM runtime
- Token cache returns copies, not references. Callers cannot mutate cached state

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
- Delegation endpoint returns opaque handle instead of raw token. Prevents credentials from entering LLM context windows
- Token cache includes SSRF allowlist validation (not in original spec)
- HTTPS-only enforcement added at SDK, MCP, and Python client levels (not in original spec)

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
| `@credninja/sdk` | 0 | ✅ Clean |
| `cred-auth` (Python) | 1 (`httpx`) | ✅ Clean |
| `@credninja/mcp` | 2 (`@modelcontextprotocol/sdk`, `@credninja/sdk`) | ✅ Clean |
| `cred-langchain` | 2 (`langchain-core`, `cred-auth`) | ✅ Clean |
| `cred-crewai` | 2 (`crewai`, `cred-auth`) | ✅ Clean |
| `cred-openai-agents` | 2 (`agents`, `cred-auth`) | ✅ Clean |

---

## Roadmap

| Item | Status |
|------|--------|
| Receipt signing | Ships with API v1.0. SDK verification code is ready |
| CI dependency scanning | `npm audit` / `pip audit` in CI pipeline |
| Independent third-party audit | Planned before v1.0 GA |

---

## Responsible Disclosure

Found something? Email **security@cred.ninja**. Do not open a public issue.

We follow coordinated disclosure with a 90-day window. Details in [SECURITY.md](./SECURITY.md).

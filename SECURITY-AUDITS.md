# Security Review Notes

Last updated 2026-11-10. The Design Principles, Test Coverage and Dependencies sections describe `main` at commit `8aa78d3`.

These are notes from security reviews Cred's maintainers ran on the SDK, MCP, integration, and self-hosted server packages. They are not independent audits: no third party has audited Cred. Each review describes the code on its date and covers only the scope it names, and later changes can make it out of date. The current code is authoritative.

For vulnerabilities reported or fixed since these reviews, see this repository's [GitHub Security Advisories](https://github.com/cred-ninja/sdk/security/advisories). Found something we missed? See [SECURITY.md](./SECURITY.md).

---

## Design Principles

These are the design goals for the SDK-facing packages in this repo. Where a test checks a principle, it is linked.

- **Bounded credential persistence.** SDKs keep no credential state between calls. In local mode the MCP server stores delegated access tokens only in-process behind opaque handles until expiration; in remote server mode it stores brokered handles and leaves provider tokens on the Cred server. Refresh tokens stay in the encrypted vault, which derives its AES key from a passphrase with PBKDF2-SHA256 at 100,000 iterations (`packages/vault/src/crypto.ts`).
- **HTTPS for remote transport.** The TypeScript and Python SDKs reject non-HTTPS base URLs at construction time, except `localhost`, `127.0.0.1` and `::1` for local development (tested in `packages/sdk/src/__tests__/cred.test.ts` and `packages/sdk-python/tests/test_security.py`). In remote mode, the MCP server accepts only HTTPS for `CRED_BASE_URL`, with no localhost exception (`packages/mcp/src/config.ts`). No test covers that MCP check.
- **No third-party runtime dependencies in cloud mode (TypeScript SDK).** `@credninja/sdk` depends only on two first-party packages, `@credninja/attenuation` and `@credninja/protocol`, which have no runtime dependencies of their own. It uses Node.js built-in `fetch` and `crypto`. Local mode loads the optional peers `@credninja/oauth` and `@credninja/vault`, and the vault depends on `better-sqlite3`.
- **Minimal dependencies (Python SDK).** `cred-auth` depends on `httpx` and `cryptography`.
- **Small cryptography surface.** DID identity uses Node.js built-in `crypto` in TypeScript and the Python `cryptography` package in Python.
- **Token isolation.** The SDKs are designed so that agent tokens do not appear in error messages. Tests check this for HTTPS-rejection, invalid-URL, API-error and network-failure errors in TypeScript (`packages/sdk/src/__tests__/cred.test.ts`), and for base-URL errors in Python (`packages/sdk-python/tests/test_security.py`). No test checks log output. `ConsentRequiredError` carries only a message, the code `consent_required`, status 403 and the consent URL.

---

## Review 1. SDK Static Analysis

**Date:** 2026-03-03
**Scope:** `packages/sdk`, `packages/sdk-python`, `packages/integrations/*`
**Method:** Static analysis

### Result: No issues found within this scope on this date.

**Checked:**
- Agent tokens excluded from error surfaces and stack traces
- `ConsentRequiredError` exposes only `consentUrl` and `code`. No internal state
- SDK keeps no state between calls. No credential carryover
- Remote HTTP calls enforce HTTPS. Plain HTTP is allowed only for explicit localhost development URLs
- Import isolation: no package imports from server-side infrastructure

---

## Review 2. Transport Security

**Date:** 2026-03-03
**Scope:** `packages/sdk`, `packages/sdk-python`, `packages/mcp`

### Result: One finding identified and resolved.

**Finding:** Base URL validation added to all three packages. Non-HTTPS remote URLs are now rejected at construction time with a clear error message. This prevents misconfiguration from silently downgrading transport security.

**Checked:**
- TypeScript SDK: `new Cred({ baseUrl: 'http://remote.example.com' })` throws
- Python SDK: `Cred(base_url='http://remote.example.com')` raises `CredError`
- MCP server: config validation rejects non-HTTPS API URLs

---

## Review 3. MCP Token Relay Security

**Date:** 2026-03-03
**Scope:** `packages/mcp`. Token relay, SSRF protection, response handling

### Result: Follow-up hardening completed. SSRF bypass tests and scope-aware endpoint checks are in place.

**Checked:**
- `cred_use` tool relays authenticated requests without exposing tokens to the LLM context window
- SSRF allowlist (`isAllowedUrl()`) tested against URL parser confusion and encoding variants. See Test Coverage below for the current suite
- `cred_use` does not follow upstream redirects, so a token is not forwarded to a redirect target (`packages/mcp/src/tools/use.ts`, tested in `packages/mcp/src/__tests__/use-classification.test.ts`). The deprecated opt-out that follows redirects re-checks each hop against the allowlist; no test covers that path
- Responses truncated at 32KB with `truncated: true` indicator
- Errors returned as MCP tool content, not thrown into the LLM runtime
- Token cache returns copies, not references. Callers cannot mutate cached state
- Google relay URLs are constrained by delegated scopes and fail closed when scope metadata is missing. Other providers use service-level URL allowlists
- Brokered server use runs configured Guard policies, including `urlAllowlistPolicy`, before forwarding upstream requests

---

## Review 4. DID Agent Identity

**Date:** 2026-03-03
**Scope:** `packages/sdk/src/identity.ts`, `packages/sdk-python/cred/identity.py`

### Result: No issues found within this scope on this date.

**Checked:**
- `did:key` encoding follows spec. Multicodec prefix `0xed01` for Ed25519, Base58btc alphabet identical across both implementations
- Cross-SDK parity: TypeScript and Python produce identical DIDs for the same key material
- Key material copied on read. Callers cannot mutate stored keys
- `verifyDelegationReceipt()` throws on pre-launch placeholder key. No silent acceptance

---

## Review 5. Spec-vs-Implementation Gap Analysis

**Date:** 2026-03-04
**Scope:** DID identity and MCP server, checked against an internal task specification that is not published.

### Result: One benign gap, and the deviations from the specification listed below.

**Gap (benign):** One external dependency replaced with inline implementation. Eliminates a supply chain dependency.

**Behavior beyond the specification:**
- Placeholder key detection throws instead of returning false. Prevents silent misconfiguration in production
- Delegation endpoints support opaque handles instead of raw tokens. This prevents credentials from entering LLM context windows on brokered paths
- Token cache includes SSRF allowlist validation
- HTTPS remote-transport enforcement added at SDK, MCP, and Python client levels

---

## Review 6. Adversarial Input Testing

**Date:** 2026-03-04
**Scope:** DID identity edge cases and MCP tool handler boundaries

### Result: The adversarial inputs listed below were handled correctly.

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

## Review 7. Self-Hosted Server Cleanup

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

## Test Coverage

As of commit `8aa78d3`.

| Package | Tests | How to run |
|---------|-------|------------|
| TypeScript SDK | Unit + integration | `npm test` in `packages/sdk` |
| Python SDK | Unit + integration (needs the `dev` extra, which includes `respx`) | `pytest` in `packages/sdk-python` |
| MCP Server | Unit + SSRF dynamic analysis | `npm test` in `packages/mcp` |
| Integrations | Per-framework unit tests | `pytest` in each Python integration package |

Key test suites:
- **SSRF allowlist suite**, `packages/mcp/src/__tests__/ssrf-dynamic.test.ts`: 47 cases in 10 categories (userinfo injection, subdomain confusion, URL encoding and control characters, protocol variations, private and internal IPs, Unicode homoglyphs, cross-service misdirection, Salesforce hostnames, non-standard ports, malformed input). 40 cases expect rejection, 6 are controls that expect a valid URL to be allowed, and 1 checks that a URL longer than 100,000 characters does not throw.
- **Token cache isolation tests**, `packages/mcp/src/__tests__/token-cache.test.ts`
- **DID identity parity tests**, `packages/sdk/src/__tests__/identity.test.ts` and `packages/sdk-python/tests/test_identity.py`
- **Token-in-error tests**, `packages/sdk/src/__tests__/cred.test.ts` and `packages/sdk-python/tests/test_security.py`

---

## Dependencies

Direct runtime dependencies as of commit `8aa78d3`, from each package's `package.json` or `pyproject.toml`. Peer dependencies are listed separately.

| Package | Runtime dependencies | Notes |
|---------|---------------------|-------|
| `@credninja/sdk` | 2 first-party (`@credninja/attenuation`, `@credninja/protocol`) | Optional peers for local mode: `@credninja/oauth`, `@credninja/vault` (which depends on `better-sqlite3`) |
| `@credninja/attenuation` | 0 | |
| `@credninja/protocol` | 0 | |
| `cred-auth` (Python) | 2 (`httpx`, `cryptography`) | |
| `@credninja/mcp` | 3 (`@modelcontextprotocol/sdk`, `@credninja/sdk`, `@credninja/guard`) | Scope-aware relay. Peers for local mode: `@credninja/oauth`, `@credninja/vault` |
| `@credninja/guard` | 3 (`@credninja/protocol`, `@types/express`, `graphql`) | Policy engine and operation classifier |
| `@credninja/ai` (Vercel AI SDK) | 1 (`@types/json-schema`) | Peers: `@credninja/sdk`, `ai`, `zod` |
| `cred-langchain` | 2 (`langchain-core`, `cred-auth`) | |
| `cred-crewai` | 3 (`crewai`, `langchain-core`, `cred-auth`) | |
| `cred-openai-agents` | 2 (`openai-agents`, `cred-auth`) | |
| `cred-autogen` | 2 (`autogen-core`, `cred-auth`) | |
| `cred-semantic-kernel` | 2 (`semantic-kernel`, `cred-auth`) | |

CI runs `npm audit --omit=dev --audit-level=high` as a blocking job, and a full `npm audit` as a non-blocking report (`.github/workflows/ci.yml`). Every pull request to `main` also runs GitHub's dependency review, which fails on high-severity advisories in changed dependencies (`.github/workflows/dependency-review.yml`). No CI job audits the full set of Python dependencies.

---

## Roadmap

| Item | Status |
|------|--------|
| Receipt signing | Shipped |
| CI dependency scanning | `npm audit` in CI; Python audit tooling pending constraints/lockfile setup |
| Independent third-party audit | Not done |

---

## Responsible Disclosure

Found something? Email **security@cred.ninja**. Do not open a public issue.

We follow coordinated disclosure. Details, including response times, are in [SECURITY.md](./SECURITY.md).

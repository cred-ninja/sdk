---
title: "feat: WIMSE request signing in the Python SDK, MCP server and framework integrations"
type: feat
date: 2026-11-13
origin: none
---

# WIMSE request signing in the Python SDK, MCP server and framework integrations

## Problem frame

Branch `hackathon/ietf127` lets a workload reach Cred with a WIT plus an HTTP Message Signature (draft-ietf-wimse-http-signature-08), optionally with a bound Txn-Token. Only the TypeScript SDK can act as such a workload today (`signRequest` + `createWimseHttpSigner`). The Python SDK, the MCP server's cloud mode and the framework integrations all require an agent token and have no way to sign requests. `docs/residual-review-findings/hackathon-ietf127.md` lists this as residual work.

## Requirements

- R1. The Python SDK can sign every request it sends with a WIMSE HTTP signature, matching the TypeScript signer's covered components and parameters, for both `Cred` and `AsyncCred`.
- R2. A Python client configured with a signer does not need an agent token. A signer combined with an agent token is refused, as in the TypeScript SDK.
- R3. The MCP server's cloud mode can be configured to sign with a WIT from env-named files, read per request so rotated files take effect. `CRED_AGENT_TOKEN` stays required unless WIMSE is configured. WIMSE combined with an agent token or Web Bot Auth is refused.
- R4. Each framework integration that builds a Cred client accepts a client the caller built, so a signing client can be passed in. Existing `agent_token` construction is unchanged.
- R5. Existing paths are unchanged: agent-token, DPoP, did:key, Web Bot Auth and local mode behave as before, and existing tests pass unmodified.
- R6. `@credninja/sdk` and `@credninja/oauth` keep zero runtime dependencies. The Python SDK adds none (it already depends on `cryptography` and `httpx`).
- R7. Records of non-code items: the Cofide PoC difference list stays in `conformance/interop/cofide.md` (Cred is not loosened); npm publication of `signRequest` is not done here.

## Scope boundaries

- No server changes. The verifier, routes and Txn-Token checks are unchanged.
- No npm or PyPI publish, no tag, no merge to main.
- Not in scope: response-signature verification in the clients, and Txn-Token minting in any client.
- An independent Python implementation of the draft is not this work. If none is published, the interop record stays NOT DONE.

## Key technical decisions

- **Python signing via an httpx request event hook.** httpx calls request hooks with the final `Request` after it encodes the JSON body, so the hook signs the exact bytes and headers that go on the wire. That includes the `Authorization: DPoP <DT>` header that `use()` sets. This mirrors the TypeScript rule that `signRequest` runs last.
- **Signer signature (Python):** `create_wimse_http_signer(wit, private_key, alg, audience=None, txn_token=None, lifetime_sec=60)` returns a callable that takes `(method, url, headers, body: bytes | None)` and returns a dict of headers to add. `wit` and `txn_token` may be callables, for rotation. ES256 signatures are raw r||s (decoded from DER with `cryptography`'s `decode_dss_signature`); Ed25519 uses the key's `sign`.
- **MCP config from files, not env values.** `CRED_WIMSE_WIT_FILE`, `CRED_WIMSE_KEY_FILE` (PKCS#8 PEM), `CRED_WIMSE_ALG` (`ES256` or `EdDSA`) and optional `CRED_TXN_TOKEN_FILE`. The key is loaded once at startup. The WIT and Txn-Token files are read on each request. Keeping the key out of env values follows the existing rule that keys never appear in process listings or logs.
- **MCP rate-limit identity in WIMSE mode.** The guard keys rate limits on a hash of the agent token. With no agent token, the hash is taken over the WIT's `sub` claim (the workload identity), read without verification only for keying. The server still verifies the WIT on every request.
- **Integrations take a prebuilt client** (`cred=` keyword for Python, `cred` option for Vercel AI). This is less code than adding WIMSE options to six packages, and it keeps one place, the SDK, that knows how to sign.

## Implementation units

### U1. Python SDK signer and hook

- **Goal:** R1, R2, R6.
- **Files:** create `packages/sdk-python/cred/wimse.py`; modify `packages/sdk-python/cred/client.py` and `packages/sdk-python/cred/__init__.py`; test in `packages/sdk-python/tests/test_wimse.py`.
- **Approach:** add a `sign_request` keyword to `_CredBase.__init__`, with `agent_token` now optional. The client must have exactly one of them. When `sign_request` is set, omit the Bearer header and register a sync or async request hook that calls the signer with the final request and updates its headers.
- **Patterns:** `packages/sdk/src/wimse-signer.ts` (components, parameters, `sfString` rules, audience default); `packages/sdk-python/cred/identity.py` for key handling.
- **Test scenarios:**
  - A signed GET carries a WIT, `Signature-Input` with tag `wimse-workload-to-workload`, `created`, `expires`, `nonce`, `wimse-aud`, and no `keyid` or `alg`.
  - Signed POST: `Content-Digest` matches the sent body and is covered, and so is `content-type`.
  - Independent check: rebuild the signature base from the sent request and verify with `cryptography` for ES256 and Ed25519.
  - A `txn_token` callable adds a covered `Txn-Token`, and `wit` callables are called per request.
  - `use()` signs with `authorization` covered.
  - Errors: no agent token and no signer raises; both raises; an unsupported alg raises; a non-VCHAR header value raises.
  - `AsyncCred` signs the same way.
  - Cross-language integration: start the real server from the TypeScript fixture and run a Python delegate and use against it. Do this in a script only if the Python environment permits; otherwise cover it with the independent check.
- **Verification:** `pytest packages/sdk-python/tests` passes, and existing tests are unchanged.

### U2. MCP cloud-mode WIMSE

- **Goal:** R3, R5, R6.
- **Files:** modify `packages/mcp/src/config.ts` and `packages/mcp/src/server.ts`; test in `packages/mcp/src/__tests__/` (new `config-wimse.test.ts`).
- **Approach:** parse the WIMSE env vars into `config.wimse = {witFile, privateKey, alg, txnTokenFile?}`. `agentToken` becomes optional only when `wimse` is set. `createCredClient` passes `signRequest: createWimseHttpSigner({wit: () => readFileSync(witFile).trim(), ...})`. The rate-limit hash comes from the WIT `sub` in WIMSE mode.
- **Test scenarios:**
  - No agent token and no WIMSE config is still an error with the same message.
  - WIMSE without an agent token parses.
  - WIMSE plus an agent token is refused.
  - WIMSE plus Web Bot Auth is refused.
  - A partial WIMSE config (a WIT file with no key, or no alg) is refused, as is an unknown alg.
  - An unreadable key file is refused at startup.
  - The client signs requests: start a stub HTTP server and assert that `Signature-Input` and `Workload-Identity-Token` arrive, and that rewriting the WIT file changes the next request's WIT.
- **Verification:** the MCP test suite passes.

### U3. Integrations accept a prebuilt client

- **Goal:** R4, R5.
- **Files:** in `packages/integrations/{autogen,crewai,langchain,openai-agents,semantic-kernel}`, the module that calls `Cred(agent_token=...)`; `packages/integrations/vercel-ai/src/tool.ts`; one test per package next to its existing tests.
- **Approach:** add an optional `cred` parameter. When given, use it and require neither `agent_token` nor `base_url`. When absent, the code behaves exactly as before.
- **Test scenarios:** for each package, a passed client is the one used, the default construction is unchanged, and a call with neither a client nor a token still raises as before.
- **Verification:** each package's tests pass where its environment installs. If a package's framework dependency cannot install on the local Python, record that rather than claiming a pass.

### U4. Docs and records

- **Goal:** R7, plus documentation of U1 to U3.
- **Files:** `docs/HACKATHON.md` (Python and MCP sections), `packages/sdk-python/README.md`, `packages/mcp/README.md`, `CHANGELOG.md` [Unreleased], `docs/residual-review-findings/hackathon-ietf127.md` (resolved items moved), `conformance/interop/cofide.md` (confirm the difference list is complete).
- **Verification:** `npm run release:hygiene` passes.

## Risks

- httpx versions before 0.24 do not have request hooks of this shape. The package already requires `httpx>=0.24`, which has them.
- If MCP rate-limit keying uses an unverified `sub`, a caller could pick its own bucket. But the caller is the MCP host's own configured workload, and the server rejects a WIT it cannot verify, so the bucket only separates local counters.
- Integration framework packages may not install on the local Python. Record what ran.

## Verification

The full gate passes (`npm ci`, build, typecheck, lint, test, release:hygiene), with `pytest` for the Python SDK and the integrations that install.

## Review decisions (plan review, 2026-11-13)

- U1: `@path` and `@query` come from the encoded URL as sent, never httpx's decoded `URL.path`. Test with a percent-encoded path segment. `_CredBase` gains a read-only `base_url` property.
- U2: WIMSE mode also requires `CRED_AGENT_DID` and `CRED_AGENT_PRIVATE_KEY_HEX`, because `/delegate` and `/use` still need the DPoP proof of the agent key. The WIT file is read as UTF-8 per request. A missing or empty file raises `wimse WIT unavailable` without the path. The file is checked at startup. The rate-limit key is `sha256('wit-sub:' + sub)`, with `sub` read once at startup. A WIT whose `sub` changes needs a restart, and the README says so.
- U3: a passed client must be a sync `Cred` (otherwise a `TypeError`). `base_url` is taken from it, and a different explicit `base_url` is refused, so the token caches still key on the server. In Vercel AI, `baseUrl` stays required alongside `cred`.
- Risks correction: httpx had request hooks before 0.24. The existing floor is kept, but not for that reason.

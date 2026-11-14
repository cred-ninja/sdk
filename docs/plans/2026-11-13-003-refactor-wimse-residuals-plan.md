---
title: "refactor: close the remaining WIMSE residual findings"
type: refactor
date: 2026-11-13
origin: none
---

# Close the remaining WIMSE residual findings

## Problem frame

`docs/residual-review-findings/hackathon-ietf127.md` still lists five minor items on branch `hackathon/ietf127`. None of them is a known exploitable defect, but each leaves an operator or a reader without something they need:

1. The replay cache for WPT `jti`s and signature nonces exists in one process only, so a value replayed to another replica is accepted there.
2. `webBotAuthMode: 'require'` together with external identity makes every WIMSE request also need a Web Bot Auth signature, and nothing warns about it.
3. Cred Link delegations used with a Txn-Token fail closed, but no test pins that down.
4. `cred_capabilities` and `cred_whoami` do not say how this MCP instance authenticates (agent token or WIMSE workload, and whether it carries a Txn-Token).
5. Three P2 refactors in `packages/server/src/server.ts`.

## Requirements

- R1. An operator can plug in a replay store that several server instances share. With one configured, a WPT `jti` or request-signature nonce accepted by one instance is refused by another. A store failure refuses the request. Without one, behaviour is unchanged.
- R2. `createServer` warns once at startup when external identity sources are configured and `webBotAuthMode` is `'require'`, naming the consequence.
- R3. A test shows that a Cred Link delegation exercised inside a verified transaction is refused and the provider is never called.
- R4. `cred_capabilities` and `cred_whoami` report this MCP instance's authentication: `agent-token` or `wimse-workload`, plus whether a Txn-Token file and Web Bot Auth signing are configured. They never report paths, keys or tokens.
- R5. Txn-Token policy decisions live in a module under `packages/server/src/identity/` with unit tests. `server.ts` keeps only the Express wiring.
- R6. One helper writes the external-identity deny audit event, replacing the two copies.
- R7. `/use` workload authentication verifies without assigning the request principal, so nothing is saved and restored through `any`.
- R8. Existing behaviour is unchanged: all current server, MCP and SDK tests pass unmodified, and the #419 vectors still pass 28/28.

## Scope boundaries

- No shared-store implementation (Redis or similar) ships, because the server takes no new runtime dependency. The interface, a reference in-memory implementation for tests, and documentation do.
- No server endpoint reports server-side WIMSE or Txn-Token configuration. MCP reports only what it knows about itself.
- The response-nonce replay check, which runs on the client side, keeps using the local cache.

## Key technical decisions

- **A shared replay store is a second, async layer.** The exported verifiers (`verifyWimseRequestSignature`, `verifyWpt`) stay synchronous and keep the local cache. The WIMSE source's `authenticate`, which is already async, calls an optional `sharedReplay.checkAndRecord(key, expiresAt)`, which returns a Promise of a boolean, after local verification passes. This keeps every exported signature unchanged. The key is namespaced the same way as the local one (`wpt:` or `httpsig:`).
- **Fail closed on store errors.** A rejected promise or a thrown error refuses the request with refusal code `replay_store_unavailable`. On the http-sig path that surfaces as the usual single `400` problem.
- **Capabilities report this instance's configuration, not the server's.** MCP cannot see the server's configuration, and claiming it would be a guess.
- **Policy extraction is a pure decision function.** The new `identity/txn-policy.ts` takes the trust map, the mappings, the verified identity, the header value and the route path. It returns either a verified token or a refusal code with its detail. `checkTxnToken` in `server.ts` translates that into audit, response and audit-context updates. Everything already exercised through HTTP keeps its tests. The new module gets direct unit tests.
- **Principal assignment becomes an option** on `authenticateExternalIdentity`: `assignPrincipal: false` for `/use`.

## Implementation units

### U1. Shared replay store

- **Goal:** R1, R8.
- **Files:** `packages/server/src/identity/types.ts` (interface `SharedReplayStore`, `createInMemorySharedReplayStore` for tests and single-host use); `packages/server/src/identity/wimse.ts` (`sharedReplay?` on the source config, checked after local verification); `packages/server/src/index.ts` (export); test `packages/server/src/__tests__/wimse-shared-replay.test.ts`.
- **Test scenarios:**
  - Two server instances share one store, so a WPT replayed to the second is refused.
  - With the shared store, a signed request replayed to the second instance is refused (`400 wimse-signature-invalid`).
  - The same replay without a shared store is accepted by the second instance, which documents the per-process default.
  - A store that rejects refuses the request and the provider is not called.
  - The first use is accepted.
- **Verification:** the new tests pass; the existing identity tests are unchanged.

### U2. Startup warning

- **Goal:** R2.
- **Files:** `packages/server/src/server.ts` (in `createServer`); test in `packages/server/src/__tests__/external-identity-httpsig.test.ts`.
- **Test scenarios:**
  - External identity with `webBotAuthMode: 'require'` warns exactly once.
  - `'optional'` or `'off'` does not warn.
  - `'require'` without external identity does not warn.
- **Verification:** tests pass.

### U3. Link delegation with a Txn-Token

- **Goal:** R3.
- **Files:** a test in `packages/server/src/__tests__/txn-token-enforcement.test.ts`, using `link-harness.ts` patterns.
- **Approach:** at execution time, find how a Link delegation can reach `/api/v1/use` inside a verified transaction, then assert the refusal (expected `txn_user_mismatch`, or the earlier agent-mapping refusal) and zero provider calls. If no route lets a Link delegation carry a verified Txn-Token at all, the test asserts that instead, and the residual entry records why.
- **Verification:** the test passes, and a mutation that removes the refusal makes it fail.

### U4. MCP authentication reporting

- **Goal:** R4.
- **Files:** `packages/mcp/src/tools/capabilities.ts`, `packages/mcp/src/tools/whoami.ts`, `packages/mcp/src/server.ts` (an `authentication` summary on the tool context); tests in `capabilities-tool.test.ts` and `whoami-tool.test.ts`.
- **Test scenarios:**
  - Agent-token mode reports `agent-token`.
  - WIMSE mode reports `wimse-workload`, with the Txn-Token flag true when its file is configured.
  - Local mode reports `local`.
  - The output never contains the WIT file path, the key or the token.
  - Existing output fields are unchanged.
- **Verification:** MCP tests pass.

### U5. server.ts refactors

- **Goal:** R5, R6, R7, R8.
- **Files:**
  - create `packages/server/src/identity/txn-policy.ts`;
  - modify `packages/server/src/server.ts`;
  - test `packages/server/src/__tests__/txn-policy.test.ts`.
- **Execution note:** behaviour-preserving. Run the full server suite before and after each of the three steps.
- **Approach:** three steps.
  - Extract `credentialRoute`, `txnTrustRequiredFor` and the decision part of `checkTxnToken`.
  - Add a `writeExternalDenyAudit` helper used by `refuseExternalIdentity` and the unbound-token refusal.
  - Add `assignPrincipal` to `authenticateExternalIdentity` and drop the save and restore in `authenticateUseWorkload`.
- **Test scenarios (unit, new module):**
  - No trust configured: ok.
  - A header without a WIMSE identity: `txn_token_unbound`.
  - An untrusted domain with a header: `txn_token_untrusted`.
  - Required and missing on a credential route: `txn_token_required`. On a revocation route: ok.
  - Required in another mapped domain: required.
  - An HTTP signature not covering `txn-token`: `txn_token_unbound`.
  - Two headers: `txn_token_invalid`.
  - A valid token: the verified token is returned.
- **Verification:** the server suite and the #419 run are unchanged in count and outcome (1288 passed, 1 skipped; 28/28).

### U6. Docs

- **Goal:** record the outcomes.
- **Files:** `docs/residual-review-findings/hackathon-ietf127.md` (items resolved), `packages/server/README.md` (shared replay store, the warning), `packages/mcp/README.md` (reported fields), `CHANGELOG.md`.
- **Verification:** `npm run release:hygiene` passes.

## Risks

- The U5 refactor touches the authentication path. Mitigation: no behaviour change, the full suite before and after each step, and a review pass.
- A slow shared store adds latency to every WIMSE request. Document that it is called once per request, after local checks.

# Residual review findings: hackathon/ietf127

From the multi-reviewer code review of `hackathon/ietf127` against `45fb411` (correctness, security, adversarial, testing, maintainability, project standards, API contract, agent-native, learnings). Fixes for the confirmed defects are in `0bc3f9d`. These items were not applied, and are recorded here instead of a tracker.

## Residual Review Findings

- P2 `packages/server/src/server.ts` (WIMSE and Txn-Token helpers): the workload-identity and Txn-Token policy lives inside `createServer`. Extract it into a module under `identity/` (for example a factory returning the route-facing checks). Manual refactor; needs a design decision.
- P2 `packages/server/src/server.ts` `refuseExternalIdentity` / `checkTxnToken` refusal: the deny audit event is built in two places. Extract one helper.
- P2 `packages/server/src/server.ts` `authenticateUseWorkload`: saves and restores `agentPrincipal` and `agentTokenHash` through `any`. Split verification from principal assignment.
- Resolved: P2 `packages/sdk/src/types.ts` `authenticateRequest(method, url)` received no body. `signRequest` (called last, with the final headers and body) and `createWimseHttpSigner` were added; see `sdk-wimse-signer.test.ts`.
- P2 `packages/mcp`, `packages/integrations/*`, `packages/sdk-python`: no path to the WIT + HTTP-signature or Txn-Token authentication. Parity work.
- P3 `cred_capabilities` / `cred_whoami`: do not report whether external identity or Txn-Tokens are enabled.
- P3 HTTP-signature refusal body: `application/problem+json` without an `error` member. Envelope-based clients get no code. Consider adding one.
- Resolved: P3 Fresh pre-fetch check. An agent record present at authorization and gone at the provider call is now refused (test "an agent record that disappears …").
- P3 Cred Link delegations with a Txn-Token: Link user ids are reserved vault ids, so `txn_user_mismatch` will refuse such exercises. Fails closed; untested.
- P3 Txn-Token `req_wl` is not compared with the presenting workload. Any workload in the trust domain that holds a bound Txn-Token can present it for its own mapped agent within the token's lifetime.
- P3 Replay cache: WPT `jti` and signature nonces share one bounded per-process cache that fails closed when full. High-rate valid traffic can exhaust it; replicas do not share it.
- P3 `webBotAuthMode: 'require'` with WIMSE: every WIMSE request also needs a Web Bot Auth signature. No startup warning.
- Testing gap: chunked (`Transfer-Encoding`) bodies through the raw-capture path, and concurrent interleaved requests on one connection for the audit context.

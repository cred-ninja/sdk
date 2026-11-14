---
title: "feat: WIMSE HTTP-signature PoP, Transaction Tokens and hackathon interop on the final hop"
type: feat
status: active
date: 2026-11-13
---

# feat: WIMSE HTTP-signature PoP, Transaction Tokens and hackathon interop on the final hop

**Target repo:** sdk (branch `hackathon/ietf127`, based on `feat/wimse-workload-identity` @ `45fb411`)

---

## Summary

Cred already verifies a WIMSE Workload Identity Token (WIT) with a Workload Proof Token (WPT) and maps the workload to an existing agent. This plan adds the second proof-of-possession profile, HTTP Message Signatures per draft-ietf-wimse-http-signature-08, on agent routes and on the brokered `/api/v1/use` call. It also adds Transaction Token (draft-ietf-oauth-transaction-tokens-11) verification, binding and authority narrowing, proves both against the public #419 test vectors, and ships a one-command local demo plus recorded interop runs against other WIMSE implementations. Everything is opt-in and leaves the did:key, agent-token, Web Bot Auth and Tailscale paths unchanged.

---

## Problem Frame

At the IETF 127 WIMSE hackathon table, a user request enters trust domain A and gets a Txn-Token. Agent hops authenticate with a WIT plus an HTTP signature or WPT, cross into domain B, and finally reach a resource server that does not speak WIMSE. Cred is that final hop. An agent in domain B presents its workload identity and a domain-B Txn-Token, and Cred calls the third-party provider with a delegated user credential (draft-sweeney-wimse-credential-delegation). Cred must verify the workload and the Txn-Token, enforce the delegation with authority that only narrows, never forward WIMSE tokens to the provider, and record the transaction id in its audit trail.

---

## Requirements

- R1. A new RFC 9421 verifier profiled to http-signature-08: key from the WIT `cnf.jwk` (ES256 P-256, Ed25519); `keyid` and `alg` parameters refused; required components `@method`, `@path`, `@query` (or `@method`, `@authority` for CONNECT); `content-type`, `content-digest`, `authorization`, `txn-token`, `workload-identity-token` covered when present; Content-Digest recomputed over the received body; `created`/`expires`/`nonce`/`tag` required; `wimse-aud` compared by simple string comparison against configured audiences, never Host; validity window enforced; nonce recorded only after the signature verifies; WIT validated before the signature; one undifferentiated error.
- R2. A real RFC 8941 structured-field parser for `Signature-Input` and `Signature` (dictionaries, inner lists, parameters, strings, byte sequences, booleans, integers, tokens), not a regex.
- R3. Response signature verification (client side) per §3.4–3.5: `wimse-req-nonce` equals the request nonce, response coverage list, unsigned response rejected when `wimse-sign-response` was requested.
- R4. All 28 #419 vectors (6 positive, 22 negative), with the issue's corrections applied, run as a data-driven conformance suite; per-vector results recorded with a README. A vector that cannot pass because the vectors and the draft disagree is recorded as a draft/vector note, never silently skipped.
- R5. WIT + HTTP-sig accepted wherever WIT + WPT is accepted, through the existing identity source and mapping.
- R6. On `/api/v1/use`, an optional WIT + HTTP-sig whose signature covers `Authorization: DPoP <Delegation Token>`; the WIT's mapped agent must be the agent the Delegation Token was issued to.
- R7. Transaction Token verification, configured per trust domain (`aud`, JWKS, user-subject rule): `typ` `txntoken+jwt`; key selected by configured `aud` and `kid`, never `iss`; signature; `aud` equals the configured trust domain; `exp`, `iat`, `txn`, `sub`, `scope`, `req_wl` present.
- R8. Binding: WPT `tth` must match; on the HTTP-sig path the `txn-token` header must be covered. When external identity and a Txn-Token configuration are present, an unbound Txn-Token is refused, including one sent with Tailscale, DPoP-only or agent-token auth. With external identity off, the header is ignored and never forwarded.
- R9. Authority only narrows (and cannot be dodged: an agent mapped to a WIMSE subject whose trust domain requires Txn-Tokens must present WIT + HTTP-sig + Txn-Token on `/use`): effective scopes = Permission ∩ delegation scopes ∩ `txnScopeMap[service]` applied to `txn.scope`. An unmapped scope yields refusal. The user subject must equal the delegation's user. A Txn-Token with no user subject is autonomous and cannot use a user-delegated credential.
- R10. `txn` recorded in audit metadata; in receipts only if receipt verifiers ignore unknown claims.
- R11. `Txn-Token`, `Workload-Identity-Token`, `Signature`, `Signature-Input`, `Content-Digest` and WPT-bearing headers never reach the provider.
- R12. A fresh authorization check (mapping, agent status, revocation, delegation, Permission including `requiresApproval`) immediately before every provider fetch, compared against what this request authorized: it refuses on a change, never because approval is on (an approved CIBA delegation still works).
- R13. A one-command demo with no Docker that prints PASS/FAIL for a delegated read and ten refusals (WIT without proof of possession, replayed request, wrong audience, Txn-Token swapped after signing, Txn-Token from another trust domain, workload from an untrusted trust domain, autonomous identity on a delegated action, agent with no delegation, write under a read-only grant, revocation between authorization and use), a merged audit trail carrying one transaction id, and proof that the provider received no WIMSE header. Plus a short participant guide.
- R14. Recorded interop runs against other implementations (Cofide PoC, go-spiffe v2.7.0, SPIRE main if buildable without Docker, wimsey, the independent Python implementation if published), each with commands, commits and output, or marked not done with the reason.
- R15. Additive and off by default; no exported API removed or changed in signature; `@credninja/sdk` and `@credninja/oauth` keep zero runtime dependencies; no server dependency added.

---

## Scope Boundaries

- Cred does not sign responses. A request with `wimse-sign-response` set gets `501 wimse-signed-response-unsupported` (§3.6), which is the conformant outcome for a server without response signing.
- Cred's routes never accept CONNECT. The verifier module supports CONNECT coverage so vector P-04 can run, but no route exposes it.
- No change to the hard-coded broker host allowlist: the demo's mock provider stands in for a real provider host in-process.
- The replay cache stays per process, as in the base branch.

### Deferred to Follow-Up Work

- Response signing by Cred (needs Cred's own WIT and key).
- macOS Tailscale LocalAPI and the shared-account revocation guard (carried from the base branch's own deferrals).
- Identity chaining across trust domains at Cred: Cred trusts domain B's Txn-Token issuer only; cross-domain exchange happens before the final hop.

---

## Context & Research

### Relevant Code and Patterns

- `packages/server/src/identity/types.ts`: `ExternalIdentitySource`, `VerifiedExternalIdentity` (already has `proof: 'http-sig'`), `IdentityRefusal`, `createReplayCache`.
- `packages/server/src/identity/wimse.ts`: `verifyWit`, `verifyWpt`, `createWimseIdentitySource`; the `tth` check already exists for WPT. The new HTTP-sig path reuses `verifyWit` and the alg/key helpers.
- `packages/server/src/identity/trust-bundle.ts`: JWKS loading by `kid` and `use`; Txn-Token JWKS loading can reuse it.
- `packages/server/src/server.ts`: `authenticateExternalIdentity` and `refuseExternalIdentity` (single refusal surface, audit `deny`), `requireAgentAuth`, `requireExerciseAuth`, `verifyWebBotAuth` / `attemptWebBotAuthIdentity` (these read `Signature*` headers too), the `/api/v1/use` handler and its final `fetch`, `BLOCKED_BROKER_EXTRA_HEADERS`, `scopesAllowedNow`, `evaluateBrokerUseGuard`, `delegationRevokedBy`.
- Tests to mirror: `__tests__/identity-wimse.test.ts` (pure verifier style), `__tests__/external-identity.test.ts` and `__tests__/external-identity-e2e.test.ts` (server wiring), `__tests__/fixtures/wimse/` (draft vectors).

### External References

- draft-ietf-wimse-http-signature-08 §3–3.6; RFC 9421 §2.2.x, §2.3, §2.5, §3.2; RFC 8941 §3–4; RFC 9530 (Content-Digest).
- draft-ietf-wimse-workload-creds-03 §5.1.3; draft-ietf-wimse-wpt-02 §2; draft-ietf-wimse-identifier-04 §4; draft-ietf-oauth-transaction-tokens-11 §9, §12.2, §14.
- ietf-wg-wimse/draft-ietf-wimse-s2s-protocol issue #419: test vectors and corrections (`@query` leading `?` for P-01/P-02/P-06/N-15; P-04 `@authority` without `:443`).
- Implementations listed in http-signature-08 §4: cofide/wimse-s2s-httpsig-poc (Go), kanywst/wimsey (Rust). go-spiffe v2.7.0 has an experimental `exp/` WIT package.

---

## Key Technical Decisions

- **New module `identity/http-signature.ts`, not the Web Bot Auth closures.** Those closures live inside `createServer`, aren't exported, and enforce a different profile (`keyid` required, `tag` `web-bot-auth`).
- **Structured-field parser in its own module (`identity/structured-fields.ts`)**, a straight RFC 8941 §4.2 recursive-descent parser with length bounds, so attacker input is parsed without backtracking regexes.
- **Signature selection by tag only.** No `wimse-workload-to-workload` tag means no WIMSE signature (null). More than one means rejection. Labels are never used.
- **Verification order:** parse → select by tag → coverage and parameter checks → WIT verify → time window → Content-Digest → signature → audience → nonce record. This puts the WIT before the signature (§3), and records the nonce only after every check passes.
- **Error surface.** `refuseExternalIdentity` takes the proof type: every refusal of an HTTP-sig request, whether thrown in the source or decided after it (unmapped, agent status, expired, multiple identities, agent mismatch), returns `400` `application/problem+json` with type `https://iana.org/assignments/http-problem-types#wimse-signature-invalid`, identical across checks. The WPT path keeps its existing 401 (wpt-02 uses the Authorization scheme).
- **Raw body for Content-Digest.** Capture the exact received bytes for every content type on requests carrying a WIT (a buffering step before `express.json`, plus the existing `/use` verify branch). Body presence is decided from `Content-Length`/`Transfer-Encoding`, not from captured bytes. A request with a body and no Content-Digest is refused; a body whose bytes were not captured, or one with a `Content-Encoding`, is refused.
- **Audience.** By default it is the configured public base URI plus the request path, the same string the WPT path uses. An optional explicit `audiences` list adds exact strings. Host is never consulted.
- **`/use` binding.** When a WIMSE credential is present on `/use`, Cred verifies it with the same source. The mapped agent DID must equal the Delegation Token's `client_id`, and the signature must cover `authorization`. The existing Delegation Token and DPoP checks still run; WIMSE adds a check and replaces nothing.
- **Web Bot Auth coexistence.** A request whose `Signature-Input` carries the WIMSE tag, with external identity configured, is not handed to Web Bot Auth verification (implemented once in `attemptWebBotAuthIdentity`, which both `verifyWebBotAuth` and `requireVerifiedIdentityRegardlessOfMode` call). A WIMSE identity never satisfies `requireVerifiedIdentityRegardlessOfMode` (rotate, revoke-all), and a request carrying both a Web Bot Auth member and a WIMSE member is refused there. With external identity off, nothing changes.
- **Txn-Token module `identity/txn-token.ts`** with a pure `verifyTxnToken`. The configuration is selected by the WIT's (already verified) trust domain, which is Cred's own domain; its expected `aud` and JWKS come from that configuration, `kid` picks the key. The user subject comes from a configured claim and a full-string anchored pattern with one capture group, run on a length-capped value; with no rule or no match the token is autonomous.
- **Narrowing at exercise.** `/use` computes `scopesNow ∩ mapped(txn.scope)` before Guard and classification, so the existing operation classifier enforces read-versus-write with the narrowed set.
- **`txn` in audit via request context.** Once a Txn-Token verifies, the request continues inside an `AsyncLocalStorage` holding `txn`; `writeAuditEventIfSupported` merges it into `metadata`, so all existing call sites carry it without threading.
- **Strip, don't trust.** Incoming request headers are already never forwarded (the provider request is built from body fields); stripping concerns `extra_headers`. WIMSE and Txn-Token header names are added to the blocked broker extra-header set, and a demo assertion proves the provider sees none of them.

---

## Assumptions

Conservative readings chosen without a reviewer (headless planning):

- When a trust domain has `txnToken` configured, WIMSE-authenticated requests from it must carry a Txn-Token (`requireTxnToken` defaults to true for that domain). A missing one is refused rather than allowed.
- A Txn-Token on a request authenticated by anything other than WIT + WPT/HTTP-sig is refused as unbound.
- At `/api/v1/delegate`, a Txn-Token's user subject must equal `user_id`. Autonomous tokens are refused, and any requested scope outside the mapped set is refused rather than silently dropped.
- A sender nonce has 128 bits from `crypto.randomBytes`. The verifier's nonce floor is a configurable option (default 16 characters, checked against every #419 positive vector before it is set); entropy can't be measured from one value (N-16 is a sender-side case). A peer under the floor is recorded in the interop notes, not accommodated silently.
- `txn` goes into receipts only if the receipt verifiers are shown to ignore unknown claims; otherwise audit only.

---

## High-Level Technical Design

Request flow on the final hop (prose is authoritative where they differ):

```mermaid
sequenceDiagram
  participant A as Agent (domain B)
  participant C as Cred
  participant P as Provider (no WIMSE)
  A->>C: POST /api/v1/use<br/>Authorization: DPoP <DT>, DPoP proof<br/>Workload-Identity-Token, Txn-Token<br/>Signature-Input/Signature (covers authorization, txn-token, wit, digest)
  C->>C: DT + DPoP (existing)
  C->>C: HTTP-sig: tag select, coverage, WIT, window, digest, sig, wimse-aud, nonce
  C->>C: WIT subject -> agentDid == DT client_id
  C->>C: Txn-Token: kid/aud from config, claims, user == delegation.userId
  C->>C: scopes = Permission ∩ delegation ∩ txnScopeMap(scope); Guard; classifier
  C->>C: fresh check: agent status, revocation, Permission (requiresApproval)
  C->>P: Bearer <provider token> only (WIMSE headers stripped)
  P-->>C: response
  C-->>A: result; audit line carries txn
```

HTTP-sig verifier stages (directional):

```
parse(Signature-Input, Signature)            RFC 8941 dictionaries
  -> select members with tag="wimse-workload-to-workload"   0 -> null, >1 -> refuse
  -> params: created, expires, nonce, tag, wimse-aud(req)   keyid/alg present -> refuse
  -> components: required set + present-header set         CONNECT branch
  -> verifyWit(WIT header)                                  before signature
  -> window: created <= now+skew, now <= expires, expires-created <= max
  -> Content-Digest recompute when body present
  -> base = RFC 9421 §2.5; verify with cnf key/alg
  -> wimse-aud in trusted set (exact)
  -> replay.checkAndRecord(nonce)                           last
```

---

## Output Structure

```
conformance/wimse-419/
  vectors.json            transcribed vectors with corrections applied
  results-2026-11-13.json per-vector outcome
  README.md
packages/server/src/identity/
  structured-fields.ts
  http-signature.ts
  txn-token.ts
scripts/hackathon/
  demo.mjs                one-command demo
  lib/                    issuers, mock provider, client
  interop/                go-spiffe program, Cofide and wimsey runners, recorded runs
docs/HACKATHON.md
```

---

## Implementation Units

### U1. RFC 8941 structured-field parser

**Goal:** Parse `Signature-Input` and `Signature` dictionaries and serialize inner lists for `@signature-params`.
**Requirements:** R2
**Dependencies:** none
**Files:** `packages/server/src/identity/structured-fields.ts`, `packages/server/src/__tests__/structured-fields.test.ts`
**Approach:** Recursive descent per RFC 8941 §4.2: dictionary, list, inner list, item, parameters, bare items (integer, decimal, string, token, byte sequence, boolean). Length caps on input and member counts. The parser also returns each dictionary member's original serialized text: the verifier uses that text as the `@signature-params` value (RFC 9421 §2.3). The serializer is for the signer side only.
**Test scenarios:**
- A dictionary with two members, inner lists with parameters, parses to the expected structure.
- Strings with escaped `\"` and `\\` round-trip. A bad escape, a non-ASCII byte or an unterminated string refuses.
- A byte sequence decodes. Invalid base64 refuses.
- Booleans `?1`/`?0`, and a parameter with no value is true.
- Integer range limits (15 digits) and leading-whitespace rules; a trailing comma or a duplicate key behaves per the RFC (last wins for dictionaries).
- Oversized input refuses without exponential work.
**Verification:** Parser tests pass, and the #419 `Signature-Input` lines parse.

### U2. http-signature-08 verifier and signer

**Goal:** Verify signed requests and responses per the profile, and sign requests and responses for the demo, the conformance suite and interop.
**Requirements:** R1, R3
**Dependencies:** U1
**Files:** `packages/server/src/identity/http-signature.ts`, `packages/server/src/__tests__/http-signature.test.ts`
**Approach:** `verifyWimseRequestSignature(msg, cfg)` and `verifyWimseResponseSignature(msg, requestNonce, cfg)` over a plain message description (method, path, query, authority, headers, raw body), so the module has no Express coupling. Component derivation per RFC 9421 §2.2: `@query` keeps `?`, an empty query is `?`, `@authority` is lower-cased without the default port, and `;req` components come from the request. ES256 signatures are raw r||s. Ed25519 accepts the `EdDSA` and `Ed25519` names. The signer generates 128-bit nonces and a short `expires`. The verifier returns the WIT, the nonce and the covered component set so callers can check coverage of `authorization` and `txn-token`.
**Test scenarios:**
- Happy path for ES256 and Ed25519 requests, with and without a body.
- The signature does not cover `txn-token` while the header is present: refused.
- `authorization` present but not covered: refused.
- A forged signature does not consume the nonce (a replay cache entry appears only after success).
- An expired WIT with a valid signature is refused, and the signature check is not reached (order instrumented).
- `expires - created` above the configured max: refused. `created` in the future beyond skew: refused.
- Response: `wimse-req-nonce` missing or different: refused. A response that covers `@path;req` for CONNECT: refused.
**Verification:** Unit tests pass, and the #419 suite (U3) passes.

### U3. #419 conformance suite

**Goal:** Run the 28 vectors data-driven and record results.
**Requirements:** R4
**Dependencies:** U2
**Files:** `conformance/wimse-419/vectors.json`, `conformance/wimse-419/README.md`, `conformance/wimse-419/results-2026-11-13.json`, `packages/server/src/__tests__/conformance-wimse-419.test.ts`, `scripts/conformance/run-wimse-419.mjs`
**Approach:** Transcribe the vectors with the issue's corrections. Message variations (N-01 to N-15, N-21) are built from a baseline plus a declared mutation, re-signed with the published test keys where the case says the signature is recomputed. Behaviour cases map to the Cred role that applies: N-16 checks the signer's nonce generator, N-17 compares server error responses, N-18 checks for 501 on `wimse-sign-response`, N-19 checks the server ignores weaker `Accept-Signature`, N-20 is a server probe with no side effect, and N-22 is selection by tag with swapped labels. The suite is excluded from the test-case budget.
**Test expectation:** every vector's outcome equals its expected outcome. A positive vector may be classed as a vector/draft disagreement only if (1) Cred's derived signature base equals the published base byte for byte and (2) the published signature verifies over the published base with `node:crypto` directly, outside the verifier; both results go in the note. Anything else is an implementation failure, and the CHANGELOG makes no "implements" claim for that area. The suite injects a fixed clock (T0+60) and the #419 audience set. Negative variations that need re-signing use the published test keys and a minimal independent signer in the suite, not Cred's signer.
**Verification:** `results-<date>.json` shows 28/28, or shows each exception with its note.

### U4. HTTP-sig on agent routes

**Goal:** WIT + HTTP-sig authenticates wherever WIT + WPT does.
**Requirements:** R5, R1 (error surface), R15
**Dependencies:** U2
**Files:** `packages/server/src/identity/wimse.ts`, `packages/server/src/server.ts`, `packages/server/src/__tests__/external-identity-httpsig.test.ts`
**Approach:** The WIMSE source chooses its proof by headers: `Authorization: WPT` → WPT; a WIMSE-tagged `Signature-Input` → HTTP-sig; both, or a WIT with neither, are refused. The source receives the raw body and the request's path and query. HTTP-sig refusals carry a marker so `refuseExternalIdentity` answers 400 problem+json. `wimse-sign-response` returns 501 after authentication passes. Web Bot Auth skips WIMSE-tagged signatures when external identity is configured.
**Test scenarios:**
- A mapped workload reaches `/api/v1/connections` with WIT + HTTP-sig and no agent token.
- A WIT without a proof gets 400. A WIT with both WPT and HTTP-sig: refused.
- A replayed signed request: refused. Wrong `wimse-aud`: refused. An untrusted trust domain: refused. An unmapped subject: refused.
- A WIT failure, a signature failure and an unmapped subject give byte-identical response bodies (N-17).
- `wimse-sign-response` gives 501 `wimse-signed-response-unsupported`.
- With Web Bot Auth mode `require`, a WIMSE-signed request is not rejected as bad Web Bot Auth. With external identity off, Web Bot Auth behaviour is unchanged.
- A body with a mismatched Content-Digest: refused, for both a JSON and a `text/plain` body.
- A WIMSE-tagged signature on rotate or revoke-all does not satisfy verified identity.
**Verification:** Tests pass, and the existing external-identity suites still pass.

### U5. HTTP-sig on `/api/v1/use`

**Goal:** Bind workload identity to brokered calls.
**Requirements:** R6
**Dependencies:** U4
**Files:** `packages/server/src/server.ts`, `packages/server/src/__tests__/external-identity-httpsig.test.ts`
**Approach:** In the `/use` handler, after Delegation Token verification, when WIMSE headers are present and external identity is configured, run the WIMSE source. When the token's agent is mapped to a WIMSE subject whose trust domain requires Txn-Tokens, WIMSE headers are mandatory on `/use`. It must yield `proof: 'http-sig'`, `authorization` must be among the covered components, and the mapped DID must equal the token's `client_id`. If WIMSE headers are present but external identity is not configured, the existing behaviour continues; those headers are ignored and never forwarded.
**Test scenarios:**
- A delegated read with DT + DPoP + WIT + HTTP-sig succeeds.
- A signature that does not cover `authorization`: refused.
- A WIT mapped to a different agent than the DT: refused.
- A swapped DT after signing: refused (the signature covers `authorization`).
- A mapped, Txn-Token-required agent calling `/use` with DT + DPoP only: refused.
**Verification:** Tests pass. A `/use` call without WIMSE headers behaves exactly as before.

### U6. Txn-Token verifier

**Goal:** Verify Txn-Tokens against per-trust-domain configuration.
**Requirements:** R7
**Dependencies:** none
**Files:** `packages/server/src/identity/txn-token.ts`, `packages/server/src/__tests__/txn-token.test.ts`
**Approach:** The configuration is keyed by the WIMSE trust domain: `{ aud, keys (JWKS), userSubject?: { claim, pattern }, scopeMap: { [service]: { [txnScope]: scopes[] } }, required? }`. The caller selects the configuration by the verified WIT's trust domain (never by anything in the Txn-Token). The check runs in this order: compact JWS, `typ` (case-insensitive, with an optional `application/` prefix), asymmetric alg, `kid` lookup in that configuration's keys, signature, then `aud` equality with the configured value (string, or a one-element array), then the `exp`/`iat` window and the presence and types of `txn`, `sub`, `scope` and `req_wl`. Header `jwk`/`jku`/`x5u`/`x5c` and `crit` are refused. The user-subject pattern is validated at load (anchored, one capture group).
**Test scenarios:**
- A valid ES256 token verifies; an Ed25519 token verifies.
- Each missing claim is refused (one case per claim).
- `aud` belongs to another trust domain: refused. `iss` names a configured key but `kid` doesn't match: refused.
- Expired: refused. `iat` in the future: refused. `typ` `jwt`: refused. `alg` `none` or HS256: refused.
- User subject extracted by pattern; no rule or no match means autonomous; a pattern that would match only a substring is refused at load (`^`…`$` required).
**Verification:** Tests pass.

### U7. Txn-Token binding, narrowing, audit, stripping and fresh check

**Goal:** Enforce Txn-Tokens on agent routes and `/use`.
**Requirements:** R8, R9, R10, R11, R12
**Dependencies:** U4, U5, U6
**Files:** `packages/server/src/server.ts`, `packages/server/src/config.ts` (if config types live there), `packages/server/src/__tests__/txn-token-enforcement.test.ts`
**Approach:** After external identity succeeds, check the binding: on the WPT path `tth` is already enforced, and on the HTTP-sig path the covered set must include `txn-token`. With external identity and a Txn-Token configuration present, a Txn-Token header on a request not authenticated by WIMSE is refused, and so is a missing one when it is required. With external identity off the header is ignored. The verified `txn` enters a request-scoped `AsyncLocalStorage` that `writeAuditEventIfSupported` reads. `/use` narrows `scopesNow`. `/delegate` checks the user and the scopes. Blocked extra headers gain `txn-token`, `workload-identity-token`, `signature`, `signature-input`, `content-digest` and `dpop`. The fresh check extends the existing `revokedInFlight`/`getStored` block before `fetch` (approval-enable already revokes live delegations). Right before the provider fetch, Cred re-resolves the mapping, agent status, revocation, delegation and Permission (including `requiresApproval`), and compares them with a snapshot taken when this request was authorized: it refuses on any change, never because approval is on.
**Test scenarios:**
- A bound Txn-Token on WPT and on HTTP-sig: accepted. Swapped after signing: refused on both paths.
- A Txn-Token with agent-token auth: refused. A required Txn-Token missing: refused.
- A Txn-Token from another trust domain: refused.
- Autonomous token on `/use`: refused. User subject ≠ delegation user: refused.
- Txn scope maps to read only, and a write call follows: refused by the classifier. An unmapped txn scope: refused.
- The audit `access` event carries `txn`, and refusal events carry it too once the token is verified.
- `extra_headers` containing `Txn-Token` or `Workload-Identity-Token`: the provider receives neither.
- `requiresApproval` turned on, or the agent suspended, between authorization and use: refused at the fresh check.
- An approval-gated Permission with an approved CIBA consent still succeeds on `/use`.
**Verification:** Tests pass, and the earlier suites still pass.

### U8. One-command hackathon demo and participant guide

**Goal:** Participants run one command and see every case pass.
**Requirements:** R13
**Dependencies:** U7
**Files:** `scripts/hackathon/demo.mjs`, `scripts/hackathon/lib/*.mjs`, `docs/HACKATHON.md`, root `package.json` (script), `packages/server/src/__tests__/hackathon-demo.test.ts`
**Approach:** One Node process starts Cred on the built server package, configured for trust domain B with a trust bundle file written at start and loaded from disk. It also starts a local WIT issuer, a Txn-Token issuer, and a mock Google Calendar provider on a local port. The demo wraps `globalThis.fetch` only for `https://www.googleapis.com` and passes everything else through; it records the headers at that interception point, i.e. the request exactly as Cred constructed it. No production code changes. The process seeds an agent, a Permission and a stored connection, then runs the WPT and HTTP-sig clients. It prints PASS/FAIL per case, a merged audit trail filtered by the run's `txn`, and the provider's received header names.
**Test scenarios:**
- The demo exits 0 with every case PASS (run in the test suite or the gate).
**Verification:** `npm run hackathon:demo` prints all PASS and the provider-header check.

### U9. Interop harnesses and recorded runs

**Goal:** Recorded runs against other implementations.
**Requirements:** R14
**Dependencies:** U4, U8
**Files:** `scripts/hackathon/interop/go-spiffe/` (Go module pinned to v2.7.0), `scripts/hackathon/interop/cofide/run.sh`, `scripts/hackathon/interop/wimsey/run.sh`, `conformance/interop/{cofide,go-spiffe,wimsey,spire,python}.md`
**Approach:** Required: Cofide PoC and go-spiffe v2.7.0; best effort, time-boxed (about 2h each): wimsey, SPIRE main (only without Docker), the Python implementation (only if published). Each one not run gets a run file with the reason. Interop runs against a trust domain with no Txn-Token configuration, so only WIT + HTTP-sig/WPT are tested; the run file records the configuration. Go code keeps its own `go.mod` under `scripts/hackathon/interop/`. Each harness clones or pins at a recorded commit, builds locally, points the implementation's trust material at Cred and its client at a Cred route, and records the request, Cred's decision and the audit line. Where an implementation follows an older draft, the run records the differences instead of loosening Cred.
**Test expectation:** none (recorded runs, not unit tests).
**Verification:** Each run file holds the command, the commits and versions, and the output.

### U10. Gate, docs and changelog

**Goal:** Ship-ready branch.
**Requirements:** R15
**Dependencies:** all
**Files:** `CHANGELOG.md`, `packages/server/README.md`, `packages/server/src/index.ts` (exports)
**Approach:** A clean `npm ci`, then build, typecheck, lint, the full test suite and release hygiene. The CHANGELOG under [Unreleased] says "implements draft-X-NN" only where the tests and vectors cover it.
**Verification:** All gate commands exit 0.

---

## System-Wide Impact

- **Interaction graph:** `requireAgentAuth`, `requireExerciseAuth`, `verifyWebBotAuth` and `/use` all gain a branch that runs only when `externalIdentity` is configured.
- **Error propagation:** the HTTP-sig path answers 400 problem+json, while the WPT path keeps 401 `WWW-Authenticate: WPT`.
- **API surface parity:** new optional config fields; new exports from `@credninja/server` only; no SDK change required.
- **Unchanged invariants:** with no external identity configured, every route behaves as before; existing test suites are the regression proof.

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Express folds the raw body away before Content-Digest can be checked | A buffering step for every content type on WIT-bearing requests; body presence from Content-Length/Transfer-Encoding |
| Web Bot Auth rejects WIMSE-signed requests when its mode is on | Tag-based bypass only when external identity is configured; covered by a test |
| An interop target implements an older draft revision | Record the differences and run with a compatibility shim on the client side only, never by loosening Cred |
| Vectors disagree with the draft | Record in draft notes with the quote; never skip |

---

## Sources & References

- Drafts: https://www.ietf.org/archive/id/draft-ietf-wimse-http-signature-08.txt, draft-ietf-wimse-workload-creds-03, draft-ietf-wimse-wpt-02, draft-ietf-wimse-identifier-04, draft-ietf-oauth-transaction-tokens-11.
- Vectors: https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol/issues/419
- RFC 9421, RFC 8941, RFC 9530.
- draft-sweeney-wimse-credential-delegation (the delegation model Cred implements on the final hop).

# Cred Protocol Conformance (Reference Implementation)

> Status: **first-pass map**, maintained alongside [`cred-ninja/protocol`](https://github.com/cred-ninja/protocol).
> This SDK is named as the protocol's reference implementation. This document maps
> what the SDK actually implements to the protocol's capabilities and the six RFCs
> it profiles, and tracks the gaps. It should be reconciled with the protocol
> repo's formal conformance section as that stabilizes. The spec is at
> [`draft-sweeney-wimse-credential-delegation-01`](https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/)
> (posted 2026-10-13; individual I-D, not yet adopted). Its offline companion is
> `draft-asor-wimse-agent-delegation-chain`, and the WIMSE WG has since adopted
> `draft-ietf-wimse-aims` (AI Identity Management System, formerly
> draft-klrc-aiagent-auth), whose Section 10.3 claim conventions this document
> now tracks.

## How to read this

- **Implemented** — the capability exists in this repo, grounded in the cited code.
- **Adjacent** — the capability exists, but via a mechanism *other than* the RFC the
  spec profiles (e.g. PoP via HTTP Message Signatures instead of DPoP). Functionally
  equivalent, not wire-compatible with the profiled RFC.
- **Gap** — not implemented yet.
- **Divergent** — the daemon (`cred-ninja/daemon`) and this SDK make different
  choices here; needs an explicit decision to converge.

## Capability conformance

The protocol README advertises these capabilities. Against the SDK:

| Protocol capability | Status | Where in this repo |
|---|---|---|
| Ephemeral agent identity via `did:key` | **Implemented** | `packages/sdk/src/identity.ts` (`generateAgentIdentity`, Ed25519 → `did:key:z…` multicodec) |
| Multi-hop delegation with attenuation | **Implemented** | `packages/attenuation/src/delegation-chain.ts` (`validateSubDelegation`, re-exported by `@credninja/vault`), server `/api/v1/subdelegate`. Attenuation is enforced end-to-end at chain depth ≥ 1: `/api/v1/subdelegate` always returns a brokered handle (never the raw provider token), regardless of the requested `token_format`, so scope attenuation can't be bypassed by exfiltrating a raw token. |
| Credential wrapping (agents never handle raw secrets) | **Implemented** | Brokered `cred_use` keeps the token server-side: `packages/mcp/src/tools/use.ts`, server `/api/v1/use` |
| Proof of possession | **Adjacent** | TOFU payload signing (`packages/tofu`, `cred.tofuDelegate`) + Web Bot Auth / HTTP Message Signatures (`packages/sdk/src/web-bot-auth.ts`). See RFC 9449 row. |
| Fine-grained capability tokens (not broad grants) | **Partial** | Scope-filter + max-ttl + url-allowlist policies (`packages/guard/src/policies`). Receipts now also carry per-delegation `constraints` ceilings covering all six asor-01 §4.2 types (`max`, `min`, `one_of`, `not_one_of`, `prefix`, `rank` with numeric or label values; fail-closed, monotonic down the chain per §4.3: `packages/attenuation/src/constraints.ts`), plus the -02 cumulative types `max_lifetime` and `max_subtree`. A label `rank` carrying an on-wire `order` (asor-02 §4.2) compares through that order; a legacy label without `order` compares through a per-key ordering (`DEFAULT_RANK_ORDERINGS` seeds the draft's `egress` none < internal < any; callers add their own via `rankOrderings`). Still scope strings + constraints, not RFC 9396 `authorization_details`. |
| Fast revocation (<5s propagation) | **Implemented** (within one server) | Cascading revocation: every issued delegation is recorded with its parent (`vault_delegations`), and `DELETE /api/v1/delegations/:delegationId` or an agent revocation revokes the whole subtree in one SQLite transaction (iterative, cycle-safe, bounded walk in `packages/vault/src/delegation-revocation.ts`). `/api/v1/use` answers `401 delegation_revoked` for a revoked handle, including one already in flight, and one `revoke` audit event per delegation names the revoked ancestor. Tests assert 1,111 descendants revoke in under 5 s (measured around 12 ms). Raw tokens already handed out and delegations issued before this release are not reached. Before that: revoke endpoints exist (`/api/v1/agents/:agentId/revoke-all`, `DELETE /api/token/:provider`, `DELETE /api/v1/connections/:provider`). `/api/v1/subdelegate` checks the status of *every* ancestor agent in the delegation chain — not just the immediate parent — before minting a child receipt. There is no persisted table of delegations to walk for this, so the check instead walks a `lineage` claim (ancestor DIDs, root first) that each receipt carries and that is extended and re-signed by the trusted issuer at every hop; a requesting agent cannot forge or truncate it. This closes the "revoke a grandparent, an still-active parent keeps minting new descendants" gap, *as long as every receipt in that chain was minted after this claim was introduced* — receipts minted before it carry no lineage and degrade to a parent-only check for that hop, until they age out under `RECEIPT_TTL_SECONDS`. Propagation latency (how fast a revocation is checked, not full historical-chain migration) is not measured or asserted by tests. |
| Cumulative constraints with a single writer (`max_lifetime`, `max_subtree`) | **Implemented** | `packages/vault/src/cumulative-ledger.ts` (`SqliteCumulativeLedger`). `/api/v1/use` debits the delegation's own `max_lifetime` and every `max_subtree` held by it or an ancestor in one transaction before the upstream call; `max_calls` is metered per call, other keys need a declared `quantities` entry; a delegation whose ancestors the ledger does not hold is refused. |
| Signed receipts behind a signer interface | **Implemented** | `packages/attenuation/src/jws.ts` (`JwsSigner`, EdDSA default, ES256 by key, `kid` in the header), `packages/server/src/receipt-signing.ts`. Verifiers hold an accepted-algorithm list; the header `alg` must equal the resolved key's algorithm. |
| Principal in `sub`, agent in `client_id` and `act.sub` | **Implemented** | Receipt claim layout `draft-02` (default): `sub` = principal, `client_id` = `act.sub` = agent, ancestors as nested `act`, `jti`, `cnf.jkt` from the agent's did:key (`packages/attenuation/src/receipt-claims.ts`, `did-key.ts`). Old-layout receipts are still read. |
| Sub-Delegation Exchange (single-use grant) | **Implemented** | `exchange: "grant"` on `/api/v1/subdelegate`, then `POST /api/v1/token` (RFC 8693) with the grant as `subject_token` and an RFC 7523 `actor_token` signed by the receiving agent's did:key (`packages/server/src/delegation-grants.ts`). Second redemption and wrong actor are rejected. Proof of possession is the actor token, not DPoP. |
| Chain-Verifiable Profile | **Implemented** | `token_profile: "agent_delegation"` on `/api/v1/delegate` and `/api/v1/subdelegate` mints an asor -02 token unchanged (`mintAgentDelegationToken`); `verifyAgentDelegationChain` checks one offline. The receipt records the token's `jti` and the scope mapping. Not yet accepted at `/api/v1/use`. |
| Cross-provider interoperability | **Implemented** | OAuth provider adapters in `packages/oauth/src/adapters` (Google, GitHub, Slack, Notion, Salesforce, Linear, HubSpot, …) |
| Protocol-version handshake | **Implemented** | `packages/sdk/src/protocol.ts` (`CRED_PROTOCOL_VERSION`, `CRED_PROTOCOL_VERSION_HEADER`, supported-version set); SDK advertises via `Cred.headers()`, server selects/rejects via early middleware. See section below. |

## RFC profile conformance

The spec profiles six standards. The SDK currently realizes the *intent* of several
through adjacent mechanisms rather than the profiled RFC itself:

| Profiled standard | Status | Notes |
|---|---|---|
| **RFC 8693** — Token Exchange | **Partial** | The Sub-Delegation Exchange issuance step is an RFC 8693 token exchange at `POST /api/v1/token`. Root delegation still uses the custom `POST /api/v1/delegate` flow, and the issued token is a brokered handle, not a DPoP-bound JWT. |
| **RFC 9449** — DPoP | **Adjacent** | No DPoP headers. PoP is achieved via TOFU payload signatures and Web Bot Auth (RFC 9421 HTTP Message Signatures). |
| **RFC 9396** — Rich Authorization Requests | **Partial** | Chain-Verifiable Profile tokens carry one `agent_delegation` detail. Receipts still carry scope strings plus `constraints`, not a `cred_delegation` detail. |
| **RFC 7523** — JWT Bearer | **Partial** | The receiving agent's `actor_token` at `POST /api/v1/token` is an RFC 7523 assertion signed with its did:key (`iss` = `sub` = DID, `aud`, `exp` at most 300 seconds after `iat`, `jti` replay-checked). Other agent auth is still opaque `cred_at_` bearer tokens plus TOFU-signed payloads. |
| **OIDC-CIBA** — Backchannel consent | **Gap** | Async consent is a redirect/poll flow surfaced via `ConsentRequiredError` + `consent_url`, not CIBA `auth_req_id` backchannel. |
| **W3C did:key** — Decentralized identifiers | **Implemented** | `did:key` generation + resolution (`packages/sdk/src/identity.ts`). |

## Divergence from the daemon

`cred-ninja/daemon` (Rust, M0) and this SDK overlap heavily (its `vault` / `Guard` /
`OAuth manager` mirror `@credninja/vault` / `guard` / `oauth`), but diverge on the
delegation token format:

| Concern | SDK (this repo) | Daemon | Action |
|---|---|---|---|
| Delegation token / attenuation proof | Ed25519 audit receipts + signed TOFU payloads | **biscuit** tokens | **Divergent** — decide whether the reference impl adopts biscuit, or the protocol admits both token profiles. |
| Identity document | `did:key` + agent records | SVID minting | Map `did:key` ↔ SVID claims. |
| Authorization enforcement | `@credninja/guard` (fail-closed, scope attenuation) | Guard component (fail-closed, monotonic attenuation) | Aligned in spirit; converge the attenuation algebra. |

## Protocol-version handshake — Implemented

A protocol-version identifier is now exchanged between the SDK client and server
via the `Cred-Protocol-Version` HTTP header. The protocol repo now fixes
`0.1.0` as the canonical initial wire version and defines a
`protocol_version_unsupported` error for explicit unsupported versions.

- **Version constant:** `CRED_PROTOCOL_VERSION = '0.1.0'`, exported from
  `@credninja/sdk` (`packages/sdk/src/protocol.ts`).
- **Supported set / floor:** `CRED_PROTOCOL_SUPPORTED_VERSIONS = ['0.1.0']` and
  `CRED_PROTOCOL_VERSION_MINIMUM = '0.1.0'`.
- **Advertise (SDK client):** `@credninja/sdk` sends `Cred-Protocol-Version: 0.1.0`
  on every outbound request via `Cred.headers()`.
- **Select (server):** `@credninja/server` sets `Cred-Protocol-Version: 0.1.0` on
  every response through an early middleware registered after JSON parsing.
- **Reject explicit unsupported versions:** the server returns HTTP 426 with
  `error: protocol_version_unsupported`, `requested_version`,
  `supported_versions`, `minimum_version`, and `current_version` when a request
  explicitly advertises a version outside the supported set. Missing request
  headers are still accepted during the `0.1.0` compatibility window because
  there is no earlier wire version to downgrade to.
- **Client selected-version check:** the SDK rejects a response that selects a
  version outside the SDK-supported set, surfacing the same
  `protocol_version_unsupported` code.
- **Future daemon path:** the daemon's ACRP server can advertise the same header,
  giving one negotiation path across all three implementations.

## Open questions / next steps

- [ ] Reconcile this table against the protocol repo's formal conformance section (needs that repo in scope, or its `CONFORMANCE` doc).
- [ ] Decide biscuit vs Ed25519-receipt token profile (SDK ↔ daemon convergence).
- [x] Fix the canonical `CRED_PROTOCOL_VERSION` string and wire the handshake. *(Done — `0.1.0` with explicit unsupported-version rejection.)*
- [ ] Decide whether RAR (`authorization_details`) replaces or augments scope strings.
- [x] Add a revocation-propagation latency test to back the "<5s" claim. *(Done: cascading revocation tests in `packages/vault` and `packages/server`.)*
- [x] Align the acting-agent identifier with adopted WG framing (done in
  the draft-02 receipt layout: principal in `sub`, agent in `client_id` and
  `act.sub`; history below):
  `draft-ietf-wimse-aims-00` Section 10.3 puts the acting agent in `client_id` and
  the delegating principal in `sub` (per RFC 9068). Receipts now mint a `client_id`
  claim naming the agent DID alongside `sub`. Remaining (breaking, next wire
  version): move the delegating principal into `sub` and stop duplicating the agent
  there; mirror the split in audit records.
- [x] Strict JSON for receipt payloads (Oct 7, 2026): `parseStrictJson` in
  `packages/attenuation/src/strict-json.ts` (formerly in vault) rejects duplicate member names and
  integers outside the binary64 exact range (RFC 7493 2.2/2.3, RFC 8785);
  `/api/v1/subdelegate` receipt decoding and `receipt-chain.ts` use it. The
  asor runner decodes the same way, closing `reject_duplicate_member` and
  `reject_unsafe_integer`: 20 of 20.
- [x] *(vocabulary done)* Converge the constraint vocabulary with
  `draft-asor-wimse-agent-delegation-chain-01` §4.2 / §10: all six registered
  constraint types parse and subsume (Oct 6, 2026). The asor interop runner
  now passes `constraints` through; `reject_exceeded_ceiling` moves from GAP
  to PASS (18 of 20, then 20 of 20 with strict JSON below). See `docs/design/delegation-constraints.md`.
- [ ] Remaining convergence: wrap scopes + constraints in an RFC 9396
  `authorization_details` entry of type `agent_delegation` so offline-minted
  chains and server-issued receipts read the same (next wire version).
- [x] Raised with Asor for -02: `rank` labels had no on-wire ordering.
  Resolved in `draft-asor-wimse-agent-delegation-chain-02` §4.2 (2026-10-15):
  a label-valued `rank` carries an `order` array, least to most permissive,
  and a child's `order` must equal its parent's. Cred still resolves labels
  through `DEFAULT_RANK_ORDERINGS`; reading `order` from the token is a
  follow-up below.
- [x] asor-02 vector set (35 files, attenu-guard v0.20.0, byte-identical
  in attenu-guard-ts v0.14.0): 35 of 35, scored natively rather than
  through the hop-model mapping. `verifyAgentDelegationChain()` in
  `packages/attenuation/src/agent-delegation.ts` implements Section 6
  steps 1 to 5 and the audience half of step 8 over the -02 token format
  unchanged, with the parse-time rules of Sections 3, 4, 4.2 and 4.4:
  required `client_id`, `cnf` (`jkt`, `jwk` or `x5t#S256`), `aud` as a
  string or non-empty array, a non-empty Principal in `sub` identical at
  every hop, exactly one closed `agent_delegation` detail, every scope
  literal, wildcard or opaque (an invalid scope is `malformed`), `rank`
  with an `order`, unknown constraint types kept and subsumed only by an
  identical constraint, per-hop `del_max_depth` (rule 5), and RFC 8785 JCS
  bytes. Step 1 takes the algorithm from the verifier's own accepted list
  and key, never from the header. The vectors are vendored under
  `packages/attenuation/src/__tests__/fixtures/asor-02/` and run in CI
  (`asor-02-vectors.test.ts`), with the hop and rule each reject vector
  isolates pinned so a rejection for an unrelated reason fails. The -01
  twenty stay byte-stable and Cred's 20 of 20 on them stands (they are not
  -02 tokens: no `client_id`, no `cnf`).

## WIMSE composition tracking

- [ ] Track the AIMS example composing Sections 10.4.3, 10.5, 10.8, and
  10.6: require re-verification at every hop, monotonic narrowing, preserved
  delegated subject and accurate actor attribution, and reconstructable
  evidence for Section 11. RFC 8693 Section 4.1's `act` is an attribution
  carrier; it does not establish delegated authority.
- [ ] Reconcile the Oct 1 `instance_bound` test-vector note. The original
  Oct 1 sweep text was not recovered; this item is reconstructed from the
  Oct 6 report's one-line summary and records only that a note about an
  `instance_bound` vector was requested. No SDK code, vendored vector, or
  design doc currently defines such a constraint.

## asor -02 constraint alignment (non-breaking) - Implemented Oct 18, 2026

Against `draft-asor-wimse-agent-delegation-chain-02` sections 4.2, 4.3 and
6 step 8. Details and rationale: `docs/design/delegation-constraints.md`.

- [x] Uniqueness per (key, type), not per key; a range (`min` plus `max` on one
  key) parses and is evaluated independently.
- [x] Closed constraint objects: `key`, one type member, and the members that
  type defines (`order` for a label `rank`). Anything else fails closed.
- [x] `rank` with on-wire `order`: label must be in `order`; a child's `order`
  must equal its parent's. Label ranks without `order` keep resolving through
  `DEFAULT_RANK_ORDERINGS` for legacy receipts (a divergence from -02, which
  calls them malformed).
- [x] `max_lifetime` and `max_subtree` parse and subsume; no inference across
  types.
- [x] Cumulative constraints at exercise: `POST /api/v1/use` debits them
  through `SqliteCumulativeLedger` and refuses with `403
  cumulative_constraint_unenforceable` when the ledger does not hold the
  delegation's ancestors. `token_format: "raw"` is refused under one.
- [x] Producer rule: `max` is per action only; issuance refuses a new `max` on
  a running-count key (`max_calls`).
- [x] DS-side atomic check-and-debit for cumulative constraints.
- [ ] Per-action constraint evaluation at `/api/v1/use`.
- [ ] Breaking, next wire version: mandatory `cnf` and
  `client_id`; one closed `agent_delegation` detail; reject legacy malformed
  scopes and label `rank` without `order`.

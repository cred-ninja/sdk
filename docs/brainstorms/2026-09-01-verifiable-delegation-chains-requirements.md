---
date: 2026-09-01
topic: verifiable-delegation-chains
---

# Verifiable Delegation Chains

## Summary

Add an opt-in "verifiable chain" track to delegation receipts: a caller marks a delegation as verifiable at the root of a lineage, and every descendant sub-delegation then gets full ancestor-chain provenance checking, a shorter receipt TTL, and constraint-ceiling enforcement — without changing default sub-delegation behavior at all. Alongside the build, produce a recommendation covering the full offline-verification landscape (provenance, revocation, key distribution, constraints, legacy migration) as input to the Option A/B alignment call already flagged in `docs/design/delegation-constraints.md`.

## Problem Frame

`verifyDelegationChain` (`packages/vault/src/chain-verify.ts`) already implements rigorous offline chain verification — signature validity, parent-hash linkage, depth, scope narrowing, expiry ordering. But the sub-delegation mint route only invokes it when the caller optionally supplies the full ancestor chain. The route's own comment admits the gap: `parentReceiptHash` is "written on every hop but never read before this." When a caller omits the optional ancestor chain — the common case — the server writes a hash of whatever `parent_receipt` it was handed without ever confirming that receipt is itself the genuine leaf of a validated lineage.

This SDK is the named reference implementation of a pre-submission IETF draft (`cred-ninja/protocol`). The draft's `reject_exceeded_ceiling` conformance vector stays a permanently declared gap under current behavior, since numeric ceilings are enforced entirely server-side and invisible to any offline verifier. A separate, already-open design question (`docs/design/delegation-constraints.md`) frames the two extremes — carry constraints in every receipt (Option A) vs. stay server-in-the-loop and document the gap (Option B) — as undecided, pending an alignment call. A sibling Rust daemon (`cred-ninja/daemon`) uses biscuit tokens for the same job, an unresolved divergence that adds durability risk to any heavy investment in the current Ed25519-receipt format specifically.

## Key Decisions

- **Build the opt-in track now; keep the full model question a recommendation, not a decision.** Shipping code doesn't require resolving Option A vs. B for all of Cred — the opt-in track is additive and doesn't force that call.
- **Root-level opt-in, not per-hop.** A caller decides once, at the root, whether a lineage is verifiable; that status inherits automatically down every descendant. Cuts the "forgot to opt in" risk from one chance per hop to one chance per lineage.
- **Reuse existing mechanisms over building new ones.** Provenance checking reuses `verifyDelegationChain` as-is — no new algorithm, only new call sites. Key distribution reuses the existing Web Bot Auth key-directory pattern.
- **Short receipt TTL over a distributable revocation list.** The verifiable track's revocation-freshness need is met by bounding trust duration, not by building CRL-equivalent infrastructure.
- **Constraint registry starts minimal.** Scoped to only the constraint keys needed for the `reject_exceeded_ceiling` conformance vector, not a general-purpose vocabulary from day one.
- **No legacy migration.** A lineage opts in from its root or not at all. Already-minted default-track receipts are untouched and never retrofitted.
- **Biscuit vs. Ed25519 token format stays out of scope.** The build and the recommendation both evaluate Ed25519 receipts on their own merits, regardless of which format eventually wins for the reference implementation.

## Actors

- A1. Delegating caller (SDK consumer or agent) — decides at root-delegation time whether a lineage is verifiable.
- A2. Cred server — enforces provenance and constraint checks at every mint for verifiable lineages, mints short-TTL receipts for that track, and publishes the signing key.
- A3. Independent verifier — a relying party checking a chain without live contact to the Cred server, beyond fetching the published signing key.

## Key Flows

- F1. Opt-in verifiable lineage
  - **Trigger:** A caller requests a root delegation and marks it verifiable.
  - **Actors:** A1, A2
  - **Steps:** The server marks the root receipt verifiable and short-TTL. Every subsequent sub-delegation off that lineage inherits verifiable status automatically. Each such mint runs full ancestor-chain verification (signature, parent-hash linkage, depth, scope narrowing, expiry) before minting, and embedded constraint ceilings are checked for subsumption at each hop.
  - **Outcome:** A chain independently verifiable by A3 using only the published signing key and the receipts themselves, within the receipts' TTL window.
  - **Covered by:** R1-R8

## Requirements

**Opt-in and inheritance**
- R1. A caller marks a delegation as verifiable only when creating the root of a lineage; the property cannot be added to an already-existing chain retroactively.
- R2. Verifiable status propagates automatically to every descendant sub-delegation of a verifiable root, without the caller re-requesting it at each hop.

**Mint-time provenance**
- R3. For a verifiable lineage, every sub-delegation mint validates the full ancestor chain (signature, parent-hash linkage, depth, scope narrowing, expiry ordering) before minting the child, reusing the existing chain-verification engine rather than a new algorithm.
- R4. If ancestor-chain validation fails for a verifiable lineage, the mint is rejected rather than silently downgraded to non-verifiable.

**Revocation and freshness**
- R5. Receipts minted on the verifiable track carry a shorter TTL than default-track receipts, bounding how long an independent verifier can trust a receipt without rechecking.

**Key distribution**
- R6. The receipt-signing public key is published at a stable, fetchable location, so an independent verifier can check receipt signatures without any other call to the Cred API.

**Constraints and ceilings**
- R7. Verifiable-track receipts can carry a small set of numeric-ceiling constraint claims, scoped initially to only the keys needed to satisfy the `reject_exceeded_ceiling` conformance vector.
- R8. A constraint ceiling present on a parent receipt must be at least as tight on the corresponding child at every hop of a verifiable lineage; an unrecognized constraint key fails closed.

**Isolation from default behavior**
- R9. Default (non-opt-in) sub-delegation behavior is unchanged: immediate-parent-only checks, optional `ancestor_receipts`, default TTL, no constraint claims.
- R10. The verifiable track ships on a separate branch/package boundary, not merged into main-line default code paths, until a decision is made to graduate it.

**Recommendation deliverable**
- R11. Independent of the opt-in track's implementation, produce a recommendation covering the full offline-verification landscape — provenance, revocation, key distribution, constraints/ceilings, and legacy migration — sized with concrete costs and risks, as input to the Option A vs. B alignment call. This does not decide Option A vs. B.
- R12. The recommendation evaluates Ed25519 receipts on their own merits and does not attempt to resolve the biscuit-token divergence with the daemon.

## Scope Boundaries

**Outside this build:**
- Full Option A (constraints embedded in every default receipt, mandatory legacy migration, general-purpose constraint registry) — stays a recommendation for the alignment call, not something this work implements.
- Resolving the biscuit vs. Ed25519 token-format divergence with `cred-ninja/daemon`.
- Retrofitting verifiability onto already-minted default-track receipts.

**Deferred for later:**
- Graduating the opt-in track to default behavior, if real usage later supports it.

## Dependencies / Assumptions

- Assumes `docs/design/delegation-constraints.md`'s Option A/B framing stays current; if that doc's framing changes materially, reconcile the recommendation against it before the alignment call.
- Assumes `verifyDelegationChain`'s existing semantics (strict signature, hash, depth, scope, and expiry checks) are sufficient for provenance checking as-is — no algorithm changes, only new call sites for the verifiable track.
- Assumes the existing Web Bot Auth key-directory pattern (`WebBotAuthDirectory`/`WebBotAuthDirectoryKey`) is reusable for publishing the receipt-signing key without protocol changes.

## Outstanding Questions

**Deferred to Planning:**
- Exact mechanism for the "separate branch/package boundary" (new package, feature flag, or literal deployment boundary).
- Exact short-TTL duration for verifiable-track receipts.
- Exact constraint-key names and value shape for the `reject_exceeded_ceiling` vector.

## Sources / Research

- `packages/vault/src/chain-verify.ts` — the existing offline verification engine (`verifyDelegationChain`) that R3/R4 reuse.
- `packages/server/src/server.ts` — the sub-delegation route; its `ancestor_receipts`-optional behavior and the "written on every hop but never read before this" comment is the concrete gap this doc scopes against.
- `docs/design/delegation-constraints.md` — the Option A/B framing and the alignment-call requirement behind R11.
- `docs/protocol-conformance.md` — the reference-implementation positioning, the `reject_exceeded_ceiling` gap, and the biscuit/daemon divergence behind R12's scope exclusion.
- `packages/sdk/src/types.ts` (`WebBotAuthDirectory`, `WebBotAuthDirectoryKey`) — the existing key-distribution pattern reused for R6.

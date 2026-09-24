# Delegation constraints: where numeric ceilings live

Status: **decided Sep 2, 2026 — Option A** (constraints travel in receipts), implemented Sep 24, 2026: `packages/vault/src/constraints.ts` (parse + subsumption), `validateSubDelegation` (inherit-or-tighten with `constraint_escalation_denied`), `verifyDelegationChain` (per-hop fail-closed parse, pairwise subsumption), and the `/api/v1/delegate` / `/api/v1/subdelegate` routes (accept a `constraints` body field, mint the claim). Migration stance: a fully legacy chain (no ceilings anywhere) verifies; a legacy child under a constrained parent fails `not_narrower`, per the draft's absent-means-unbounded rule. Lifetime aggregates (`max_calls` measured across a delegation's lifetime) remain server-enforced; the in-receipt claim carries the ceiling, the Delegation Server does the debit. The options below are kept for the record.

## Current position

A Cred delegation receipt carries `scopes` and nothing else that bounds what the holder may do. Every other limit is enforced by the Delegation Server at request time:

- TTL, rate limits, time windows, and URL allowlists are Guard policies (`@credninja/guard`), configured per server and evaluated on every exercise.
- Per-agent `scopeCeiling` caps the scopes any delegation to that agent can carry, on direct and sub-delegation alike.
- Chain depth is a per-permission `maxDelegationDepth`, checked when a child is minted.

There is no per-delegation numeric ceiling. A parent cannot say "you may read CRM rows, but at most 5000 of them" and have that bound travel with the receipt. `draft-asor-wimse-agent-delegation-chain-01` defines exactly that: a `constraints` array on each Delegation Token (section 4.2, e.g. `{"key": "max_rows", "max": 5000}`), and a subsumption relation (section 4.3) where every ceiling in the parent must appear in the child at least as tight, and a ceiling absent from the child means the child is unbounded on that dimension and therefore not narrower. Unknown constraint types fail closed (section 4.2), and -01 adds a proposed "Agent Delegation Constraint Types" IANA registry (section 10). The `reject_exceeded_ceiling` vector loosens `max_rows` from 5000 to 10000000 at hop 2; Cred cannot see the change.

Since -01, the September 2026 wimse-list thread on the draft settled the division of labor: offline chains carry attenuation and are spent at enforcement points, while aggregate budgets (counters like `max_calls` that debit across a delegation's lifetime) are an online problem belonging to a single-writer allocator, the role `draft-sweeney-wimse-credential-delegation` gives the Delegation Server. That maps onto the options below: Option A covers per-hop ceilings; lifetime aggregates stay server-side under either option.

## Option A: carry `constraints` in receipts

Add a `constraints` claim to receipts with the same shape as the draft: entries of `{key, max}` for numeric ceilings and `{key, rank}` for ordered enums, unknown entry types fail closed. `validateSubDelegation` gains a constraint subsumption check alongside scopes. `verifyDelegationChain` checks it at every hop.

Costs:

- Wire change to the receipt. Every consumer that parses receipts sees a new claim; legacy receipts have none and must be treated as unbounded, which is the permissive direction, so a migration window is needed during which mixed chains are either rejected or the missing constraint is filled in from policy.
- A second enforcement point. Today a ceiling is enforced once, at the server, from policy. With constraints in the token there is a token-carried bound and a server-carried bound, and the two must be reconciled (meet, not either-or) on every exercise. Divergence between them is a new class of bug.
- Vocabulary governance. Constraint keys are only meaningful if the resource server knows them. Cred would need a registry, or defer entirely to the draft's, and decide what an unregistered key means on exercise.
- Offline verifiers gain real power. A relying party holding only the chain can enforce ceilings without calling the server. This is the property the draft is built around and the one Cred does not currently offer.

## Option B: keep ceilings server-side and say so

Leave receipts as they are. State in CONFORMANCE.md and in the I-D that Cred enforces numeric ceilings from server policy at exercise time, and that a Cred receipt chain verified offline proves scope narrowing, depth, linkage, and expiry ordering but not ceiling narrowing.

Costs:

- Cred does not satisfy the draft's ceiling subsumption rule. `reject_exceeded_ceiling` stays a declared gap in the conformance matrix, permanently.
- Any convergence with the draft's token profile has to carve ceilings out as an extension Cred does not implement, which weakens the "one profile, two implementations" story.
- Offline verifiers cannot bound resource use; they must trust that the server did. That is consistent with Cred's server-in-the-loop model, and it is also the exact property the draft argues against in its section 1.1.
- Nothing to build, nothing to migrate.

## What each option is really choosing

Option A moves Cred toward the draft's model, where the token is the enforcement unit. Option B keeps Cred in its own model, where the server is. The receipt format question is downstream of that. Decide the model on the call; the format follows.

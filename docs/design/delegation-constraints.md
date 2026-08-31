# Delegation constraints: where numeric ceilings live

Status: open question for the draft-asor alignment call. No decision recorded here.

## Current position

A Cred delegation receipt carries `scopes` and nothing else that bounds what the holder may do. Every other limit is enforced by the Delegation Server at request time:

- TTL, rate limits, time windows, and URL allowlists are Guard policies (`@credninja/guard`), configured per server and evaluated on every exercise.
- Per-agent `scopeCeiling` caps the scopes any delegation to that agent can carry, on direct and sub-delegation alike.
- Chain depth is a per-permission `maxDelegationDepth`, checked when a child is minted.

There is no per-delegation numeric ceiling. A parent cannot say "you may read CRM rows, but at most 5000 of them" and have that bound travel with the receipt. `draft-asor-wimse-agent-delegation-chain-00` section 4.2 rules 2 and 3 define exactly that: a `constraints` list on each Delegation Token, and a subsumption relation where every ceiling in the parent must appear in the child at least as tight, and a ceiling absent from the child means the child is unbounded on that dimension and therefore not narrower. Appendix B vector `reject_exceeded_ceiling` loosens `max_rows` from 5000 to 10000000 at hop 2; Cred cannot see the change.

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

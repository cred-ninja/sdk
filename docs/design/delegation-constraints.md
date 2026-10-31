# Delegation constraints: where numeric ceilings live

Status: **decided Sep 2, 2026: Option A** (constraints travel in receipts), implemented Sep 24, 2026 (numeric `max` / `rank`), extended Oct 6, 2026 to all six asor-01 §4.2 types (`max`, `min`, `one_of`, `not_one_of`, `prefix`, `rank` as number or label; label ranks resolve through a per-key ordering, `DEFAULT_RANK_ORDERINGS` plus caller `rankOrderings`, fail-closed when unregistered): `packages/vault/src/constraints.ts` (parse + subsumption), `validateSubDelegation` (inherit-or-tighten with `constraint_escalation_denied`), `verifyDelegationChain` (per-hop fail-closed parse, pairwise subsumption), and the `/api/v1/delegate` / `/api/v1/subdelegate` routes (accept a `constraints` body field, mint the claim). Migration stance: a fully legacy chain (no ceilings anywhere) verifies; a legacy child under a constrained parent fails `not_narrower`, per the draft's absent-means-unbounded rule. Lifetime aggregates (`max_calls` measured across a delegation's lifetime) belong to the Delegation Server: the in-receipt claim carries the ceiling and the server does the debit, at `/api/v1/use`, in its cumulative ledger (section below). Extended Oct 18, 2026 to the non-breaking part of draft-asor-wimse-agent-delegation-chain-02 (section below). The options below are kept for the record.

## asor -02 alignment (Oct 18, 2026)

What is implemented, all without changing how a receipt minted before -02 parses or verifies:

- **Uniqueness per (key, type).** Two constraints with the same key and different types (a `min` plus a `max` forming a range) parse and are evaluated independently. A repeated (key, type) pair is malformed. A repeated key with the same type was already malformed, so no legacy receipt changes meaning.
- **Closed constraint objects.** An entry carries `key`, exactly one type member, and only the members that type defines (`order` for a label `rank`). Anything else is malformed and fails closed.
- **`rank` with `order`.** A label `rank` may carry `order`, least to most permissive, two or more distinct strings, and the label must be in it. The ordering is read from the token; no registry entry is needed. A child's `order` must equal its parent's for the same key, element for element, or the result is not narrower. A label with `order` never compares with one without.
- **Legacy labels.** -02 treats a label `rank` without `order` as malformed. Cred does not: receipts minted under -01 carry bare labels, so they still parse and resolve through `DEFAULT_RANK_ORDERINGS` plus the caller's `rankOrderings`, failing closed when no ordering is registered. This is a documented divergence from -02, kept for legacy receipts.
- **`max_lifetime` and `max_subtree`.** Both parse as finite non-negative numbers and subsume with child no wider than parent. No inference across types: a `max_lifetime` under a parent `max` on the same key, or the reverse, is not narrower.
- **Exercise-time debit.** -02 section 6 step 8: an action under a cumulative constraint is permitted only where the running total is held. The Delegation Server holds it in a cumulative ledger (`packages/vault/src/cumulative-ledger.ts`; in process memory by default, a shared SQLite file with `CUMULATIVE_LEDGER_PATH`), keyed by delegation id for `max_lifetime` and walking up to the subtree root for `max_subtree`. `POST /api/v1/use` checks and debits it atomically before the upstream call and refunds the debit when the call never reaches the provider. A delegation restored in a process whose ledger does not hold its running total (another replica, or a restart without a shared ledger) is refused with `403 cumulative_constraint_unenforceable`, never restarted from zero. `POST /api/v1/delegate` refuses `token_format: "raw"` under a cumulative constraint with `400 cumulative_constraint_unenforceable`, because a raw provider token cannot be held to a running total once it leaves the server. Sub-delegation is broker-only.
- **Server-side metering.** Every constraint is decided from what the server measures (draft-sweeney-wimse-credential-delegation-02 Sections 5.3 and 6.1; `packages/server/src/metering.ts`); an agent never reports its own quantities. Request-side keys (`calls`/`max_calls`, `method`, `destination`, `request_bytes`) are decided before the upstream call; response-side keys (`response_bytes`, `items`/`rows`/`max_rows`/`max_results`) from the response, which is withheld from the agent when over a bound. A key with no meter cannot be decided, so an exercise under it is denied (`unmetered_constraint`).
- **Producer rule.** `max` is per action only. Issuance (`/api/v1/delegate`, `/api/v1/subdelegate`) refuses to mint a `max` on a key that names a running count (`DEFAULT_RUNNING_COUNT_KEYS`: `max_calls` and `calls`) with `400 invalid_constraints`. A child that carries such a ceiling unchanged from its parent is inherited, not produced, and is not re-judged, so chains under receipts minted before this rule keep working. Verification does not apply the rule.

What remains:

- A shared running total across replicas without a shared ledger file: each process holds its own unless `CUMULATIVE_LEDGER_PATH` names one SQLite file they all use.
- Ceilings on Cred Link delegations: a Link delegate call that carries `constraints` is refused.
- An unknown constraint type is malformed at parse. -02 lets a verifier carry an unknown type through subsumption when parent and child carry it byte-identical, and deny at step 8. Cred is stricter.
- Breaking, next wire version: the principal in `sub`, mandatory `cnf` and `client_id`, scopes and constraints inside one closed `agent_delegation` detail, rejecting legacy malformed scopes, and rejecting a label `rank` without `order`.

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

# Durable cumulative-budget admission

Status: **proposal; design only; implementation approval required**.

This note specifies a hardening target for the existing cumulative ledger. It
adds no runtime behavior and does not claim that current releases implement the
reservation, retry, recovery or unified-revocation semantics below.

## Current implementation, not the historical design summary

Reviewed base: SDK commit `a7eb38fda59a4ef82fa5e7e1d6e7460d9764242c`.

The SDK already implements `SqliteCumulativeLedger` in
`packages/vault/src/cumulative-ledger.ts`. Its `debit()` method uses a
`BEGIN IMMEDIATE` transaction to check and increment the exercised token's
`max_lifetime` bounds and all applicable ancestor `max_subtree` bounds together.
Existing tests cover sibling sharing, all-or-nothing debits, exclusion of parent
lifetime totals, missing ancestors and reopening a file-backed ledger. The hosted
server calls the ledger before upstream `fetch`.

The following boundaries remain, based on the code rather than claims of full
protocol conformance:

| Boundary | Current behavior | Proposed requirement |
| --- | --- | --- |
| Storage lifetime | Default `:memory:`; `CUMULATIVE_LEDGER_PATH` selects a file. Handles are also process-local. | Explicit durable supported topology, coordinated recovery and no silent empty-ledger fallback. Losing a handle is not evidence that old handles remain usable after restart. |
| Revocation ordering | Server checks revocation before the ledger call; the ledger transaction does not itself read revocation state. | One authoritative ordering of revocation, admission and dispatch claims. |
| Quantity measurement | Server meters `max_calls` itself but accepts other non-negative `quantities` from the caller. | Only server-owned meters can authorize consumption. Caller declarations are not evidence of actual spend, rows or bytes. |
| Complete budget set | `debit()` iterates quantities supplied to it. Its interface does not require every applicable quantity. | The store derives all applicable accounts and rejects missing measurements. |
| Retries and outcomes | No request-bound idempotency or reservation/outcome lifecycle in the ledger interface. | Durable request identity, reservations and explicit indeterminate outcomes. |
| Duplicate registration | First registration of an identifier wins, without comparing the replacement metadata. | Exact retries are idempotent; conflicting parent, principal, policy or bound metadata is rejected. |
| Numeric accounting | Bounds and totals use SQLite `REAL`. | A supported meter defines units and an exact, overflow-checked accounting domain. |

Relevant current paths are `packages/server/src/server.ts` (`/api/v1/use`,
`buildDelegationResponse`), `packages/server/src/config.ts`,
`packages/vault/src/cumulative-ledger.ts`, and the delegation records/revocation
implementations. Historical text in `docs/design/delegation-constraints.md`
predates the ledger and must not be used as a description of current behavior.

## Invariants and non-goals

1. A valid chain is not proof of remaining budget. Admission is online.
2. Each accepted exercise reserves every applicable cumulative account in one
   transaction, or reserves none. A child-only account cannot replace an
   ancestor's account.
3. Counters, request records, grant identity, lineage and revocation state belong
   to one authoritative admission store and recovery boundary.
4. No provider credential is returned to an agent to bypass these controls.
5. Unavailable, incomplete, stale, malformed or unsupported accounting state
   denies exercise. A store error never selects an in-memory fallback.
6. Budget arithmetic is exact for the supported units. Untrusted quantities do
   not authorize their own accuracy.
7. A retry cannot create a second allowance or another unprotected provider
   side effect under the same request identity.
8. The provider is not a participant in the database transaction. This design
   does not promise generic exactly-once provider execution, rollback of accepted
   effects, or instant cancellation of in-flight requests.

Non-goals for the first implementation: distributed multi-region consensus,
Byzantine custody, disconnected spending allocations, generic financial
settlement, every provider's idempotency scheme, and implementing unknown
constraint types. Unknown constraints still deny exercise.

## Semantic identities

The normative baseline is
[draft-asor-wimse-agent-delegation-chain-02](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-02),
Sections 4.2, 4.3, 6 and 9.4. In particular:

- `max_lifetime` belongs to one token identified by `jti`. Exercising a child
  does not debit its parent's lifetime account.
- `max_subtree` belongs to its owning token and includes that token and every
  descendant. Each ancestor can impose a separate, tighter applicable account.
- Reissuance with a new `jti` starts a new token-lifetime total. An allowance
  intended to span reissuance must not be replenished accidentally: reduce the
  replacement's available bound under a coordinated retirement procedure, or
  impose an explicitly separate grant-wide account. Do not redefine the wire
  meaning of `max_lifetime`.
- Repeating `register()` with the same token cannot change its parent, epoch,
  bounds or accumulated consumption.

Use composite database keys, not string concatenation with an ambiguous
separator. At minimum, scope identities by stable DS issuer, tenant and grant
namespace, then token `jti`, constraint `key` and type. Bind the subject,
provider/connection identity, policy version, parent and expiry to immutable
registration metadata. A caller cannot select another tenant's account.

For continuation of a previously approved grant across replacement tokens, the
recommended deployment policy is an explicit, stable **grant allowance account**
consulted alongside token accounts. It is server-side policy, not a new claim or
an alternative interpretation of an Asor constraint. Existing children and both
old and new token identifiers must consult it while they remain usable. A new
allowance requires an explicit new authorization decision; generating a new
`jti` is not that decision. Migration must not double-count the same consumption
by both carrying a spent total and reducing the same account's original bound.

## Bounded first implementation

Support one hosted DS authority on one host, with durable SQLite storage on a
supported local filesystem. Multiple local workers may serialize on the same
store. Configure and test SQLite durability, busy handling and recovery. Do not
support independent SQLite files, network filesystems, remote replicas or the
file-vault backend for this profile.

Revocation, active grant/connection epochs, immutable lineage, accounts and
requests must be accessible through the same transaction boundary. Opening a
second SQLite connection to an unrelated revocation database does not provide
that atomicity. A Link deployment whose current authority remains in a separate
store needs a deliberate integration design before it can advertise this
profile. Guard checks outside the store are additional denials, not a substitute
for the store's authoritative epoch checks.

Initially meter only `max_calls`, with one unit per authorized dispatch attempt.
Use checked non-negative integer arithmetic and reject bounds or totals outside
the exact supported range. Other keys remain unenforceable until a server-owned
adapter defines units, a conservative pre-dispatch bound and any reconciliation
rules. Never accept a client's `max_spend: 0` as proof that a request costs zero.
Known per-action constraints also require their own enforcement; a successful
budget reservation must not be presented as proof of all other constraints.

## Proposed persistent records

These are conceptual records, not an approved SQL migration or public API:

- **Grants:** stable subject/provider binding, current authorization epoch,
  revocation status and optional grant-wide allowance.
- **Tokens:** scoped `jti`, parent reference, immutable registration commitment,
  constraints, validity, grant reference and status.
- **Accounts:** owning token or explicit grant account, dimension, type, units,
  bound, reserved amount and charged amount.
- **Requests:** scoped idempotency key, authenticated holder, request digest,
  grant/connection epochs, state, reservation references and outcome reference.
- **Transitions:** committed sequence, operation identifier and enough metadata
  to reconstruct admission, cancellation and finalization. No provider secrets.

The request digest binds the selected grant and holder, provider/connection,
method, validated target URI including relevant query, the exact serialized body
bytes that will be sent, and semantically relevant forwarded headers. Perform
normalization once, then use those same bytes for digesting and dispatch. Do not
include bearer credentials in an audit record or a digest input exposed to
clients. Same idempotency key plus different request content is a conflict.

## Admission and dispatch

1. Authenticate the caller, validate the chain and reject unknown or unsupported
   constraints. Resolve the provider operation and server-owned meter. These
   checks cannot authorize a call without the authoritative store below.
2. Start a write transaction. Verify tenant, subject, holder, expiry, active
   grant/connection epochs and every relevant ancestor's current status.
3. Resolve the scoped idempotency record. An exact retry returns its stored
   state; it neither reserves again nor dispatches again. Reject digest or
   identity mismatches.
4. Derive the complete set of applicable accounts: the exercised token's
   lifetime account, all subtree accounts on its lineage, and any explicit
   grant-wide account. Reject missing lineage, missing meter output, cycles,
   mismatched registration, exhausted bounds or arithmetic overflow.
5. Atomically reserve the measured amount in all accounts and insert the
   request in `reserved` state. Persist the admission event in the same
   transaction and commit. Only a successful commit creates a reservation.
6. Claim dispatch in a second transaction. Recheck current authority and
   epochs, atomically transition this request once to `dispatch_claimed`, and
   assign its executor identity/fence. For the initial `max_calls` meter, move
   the unit from reserved to charged in every applicable account in this same
   transaction. The invariant is `reserved + charged <= bound`; this transfer
   is not a second debit. If revocation or expiry won the race, cancel the
   unclaimed request and release its reservation atomically.
7. After the dispatch claim commits, perform the provider call outside the
   transaction. The `max_calls` charge is permanent, including failed or
   indeterminate calls. It is never refunded merely because an HTTP response
   is an error.
8. Finalize the definitive response or an indeterminate outcome in a separate
   idempotent transaction. Write audit transitions before emitting an associated
   signed execution receipt. A chain receipt is not itself an execution receipt.

The final dispatch claim is the linearization point for authorizing a new
provider attempt. A revocation committed before that claim prevents it. A claim
committed earlier is in-flight authority and may result in an effect later.
There is an unavoidable gap between this database commit and provider acceptance;
this design does not describe that gap as atomic. Where stronger cancellation is
required, an enforcement point on the actual egress path must enforce current
fences, or the provider must participate.

A fence prevents a superseded worker from claiming new requests or changing a
new worker's state. It does not revoke a legacy provider bearer credential or
magically recall a previously claimed HTTP request. Never reassign a potentially
dispatched request to an unprotected second sender after a worker timeout.

## Retry and crash matrix

| Last durable state | Retry/recovery behavior |
| --- | --- |
| No reservation committed | Retry may perform a fresh admission. |
| `reserved`, never claimed | Recheck authority; claim once or cancel atomically. Recovery can safely release only after preventing any later claim. |
| `dispatch_claimed`, no definitive outcome | Treat as indeterminate and keep the charge. Do not resend automatically. A crash before actual send still belongs here unless non-dispatch is established. |
| Provider responded but finalization failed | Same conservative treatment until reconciled. A successful provider response cannot justify another dispatch. |
| Finalized | Return the stored safe result or outcome reference without another debit or dispatch. |
| Same key, different request | Conflict; no dispatch and no new reservation. |
| Store unavailable or corruption detected | Deny new work; do not manufacture a missing state or refund. |

Provider-side idempotency may permit carefully bounded resubmission only for an
adapter that documents provider retention, request binding and lookup behavior.
Do not infer idempotency from HTTP method alone. Idempotency records and tombstones
must survive every period in which the corresponding grant, token or retry can
be accepted. Retention and safe response storage need explicit privacy limits.

## Recovery, migration and deployment

- Initialize durable identity, lineage and accounting together. A ledger-only
  backup is not sufficient to restore authorization state safely.
- Detect stale restores with a deployment epoch anchored outside the restorable
  snapshot, or revoke affected grants and require fresh approval. Restoring an
  old database must not silently recreate spendable authority.
- Do not reconstruct spent totals as zero from a signed receipt. Existing live
  grants can migrate only with an authoritative state transfer; otherwise keep
  them denied or retire them explicitly. Lost process-local handles do not
  provide evidence for recovering an old allowance.
- Specify a versioned migration, rollback restrictions and failure-safe startup
  behavior. A schema downgrade cannot bypass request tombstones or accounting.
- Register replacements and retire or bind prior authority transactionally.
  Include reserved, charged and indeterminate work in any remaining-allowance
  calculation. Concurrent reissuance cannot allocate the same remainder twice.
- Observability reports supported meters/topology and denied/indeterminate work.
  It must not claim generic budget enforcement from chain verification alone.

## Required acceptance tests before enabling the new profile

1. Parallel siblings cannot jointly overspend any shared ancestor; a descendant's
   own tighter bound also holds. All applicable accounts move together or none do.
2. Child use does not debit parent `max_lifetime`; reissued `jti` semantics and
   separate grant-continuity policy are tested independently.
3. Identical retries reserve and claim once. Changed body, target, holder, tenant
   or grant under the same key is rejected. Definitive retries do not call upstream.
4. Revocation and dispatch-claim races have one recorded ordering. Revocation
   before the claim prevents upstream dispatch; a prior claim is labeled in-flight.
5. Fault injection at each commit and network boundary preserves charges and
   outcomes. Lost responses never cause an automatic second provider effect.
6. Restart, simultaneous local processes, lock contention and stale worker fences
   preserve the same authority and account identities.
7. Unknown keys/types, absent or caller-forged quantities, fractional/unsafe
   arithmetic and unavailable meters fail before upstream access. Counter units
   are metered by the server, not the client.
8. Missing/cyclic lineage, conflicting registration, cross-tenant references,
   database unavailability and stale restores fail closed.
9. Reissuance, concurrent replacement and old/new descendants cannot replenish a
   grant-wide allowance or incorrectly charge it twice.
10. Raw-token export, Link and alternate/local exercise paths cannot bypass the
    profile. Unsupported backends/topologies refuse it explicitly.
11. A real handler integration exercises reserve, claim, dispatch and finalize,
    with upstream-call counts. Ledger-only mocks do not establish this property.
12. Existing valid non-cumulative behavior and both pinned Asor vector sets do
    not regress. Offline vector passes do not count as online accounting tests.

## Approval gates

Before implementation, approve: the first supported topology and SQLite
integration, the `max_calls` charging boundary, grant-continuity policy,
idempotency lifetime, indeterminate-outcome API, migration/recovery procedure,
and behavior for existing deployments that accept caller-declared quantities.

This PR deliberately does not disable or replace existing ledger behavior. It
records the limits and the proposed next implementation. A future implementation
must remain opt-in until the acceptance tests above pass and its unsupported
paths deny exercise explicitly.

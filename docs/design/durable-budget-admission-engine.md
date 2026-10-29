# Durable budget admission engine — first code slice

Status: **opt-in library; not integrated with any existing exercise route**.

This implements the bounded admission/dispatch core from
[the merged design proposal](https://github.com/cred-ninja/sdk/blob/8475f87fc35ed42a3009109781f96057a6a6943a/docs/design/durable-cumulative-budgets.md). It does **not**
replace `SqliteCumulativeLedger`, change HTTP routes, or enable a new SDK/MCP/Link
profile. A passing library test is not evidence that a production handler or an
alternate credential path cannot bypass admission.

## Supported authority and storage boundary

`DurableBudgetStore`, `prepareBudgetOperation`, and `executeBudgetedOperation`
are exported from `@credninja/vault`. The implementation uses the existing
`better-sqlite3` dependency; no dependency/version changes are required.

The supported topology is one hosted authority on **one host, one durable SQLite
file, on a supported local filesystem**. Multiple processes on that host may use
the same file. Network filesystems, independent files, remote replicas,
`:memory:`, the file-vault backend, and a separate revocation database do not
implement this profile. The library does not automatically detect the filesystem
or prove that all workers use the same path: deployment must establish that.

Opening requires an absolute file path, issuer, and deployment epoch. Creation
requires `initialize: 'new'`, which exclusively creates a new file with mode
`0600`; an existing file is never initialized, migrated, repaired, or reset.
Ordinary opening requires the file to exist. Schema definitions, schema version,
issuer, deployment epoch, SQLite integrity and foreign keys are checked. Missing,
incompatible or unavailable state throws rather than selecting a memory store.
A removed/replaced file is rejected by subsequent operations using its recorded
file identity. The containing directory must be access-controlled by the host;
this is not a defense against a malicious local database owner.

The store sets and verifies WAL mode and `synchronous=FULL`, enables foreign keys,
and sets an explicit busy timeout (default 5000 ms, accepted range 0–60000 ms).
All admission, cancellation, claims, finalization and administrative authority
changes use `BEGIN IMMEDIATE`. A lock timeout or SQLite failure is a denial, not
an implicit retry or a reason to dispatch. These durability settings depend on
the filesystem/hardware honoring SQLite's durability assumptions; process-kill
tests are not power-loss certification.

**An epoch comparison does not detect a same-epoch stale snapshot.** There is no
external anti-rollback anchor or coordinated restore protocol in this slice.
Operators must not restore an older database and resume authority based only on
matching epochs. Externally anchored recovery, or retirement of affected grants
and fresh approval, remains a deployment gate. Path/inode checks are likewise
not anti-rollback protection. A trusted clock is required for expiry; this library
does not make a rolled-back system clock monotonic.

## Trusted host responsibilities

These APIs are not client-facing authorization endpoints. Before calling them,
the host must:

- Authenticate the caller and resolve the issuer/tenant/subject/holder from
  authoritative state, not copy them from a request body.
- Verify the signed chain, token/holder proofs, scope, audience and the selected
  provider operation. Registration is not signature or scope verification.
- Authorize every connection, stable grant allowance and token registration.
  `registerGrant()` is an explicit authorization decision. Exposing it to an
  arbitrary client would let the client mint fresh allowances.
- Resolve and validate the final target against provider/scope/SSRF policy. Basic
  HTTPS/URI validation in preparation is not an egress allowlist.
- Use this database as the authority for relevant revocation and grant/connection
  epoch changes. An unrelated legacy or Link store is not transactionally joined
  just because the host checks it before admission.
- Keep credentials exclusively in the trusted transport callback. Transport must
  dispatch the supplied operation once, without automatic retry, redirects,
  additional provider calls or changed method/target/body/semantic headers.
  Provider authentication headers may be attached there, not during preparation.
- Allocate safe opaque outcome references and enforce access control when looking
  them up. A reference is not a stored provider response.

The library enforces registered identity bindings and budget/expiry/revocation
state; it does not replace these host obligations.

## API and immutable records

| API | Purpose |
| --- | --- |
| `new DurableBudgetStore(options)` | Open a compatible existing store, or exclusively initialize with `initialize: 'new'`. |
| `registerConnection(input)` | Register issuer/tenant/subject/provider/connection and initial `epoch`. |
| `registerGrant(input)` | Explicitly authorize a stable grant, policy version, connection epoch, initial grant `epoch`, and required `maxCalls` allowance. |
| `registerToken(input)` | Register immutable context, scoped token ID, parent ID (explicit `null` for roots), expiry in Unix **milliseconds**, and explicit constraints array. |
| `reserve(context, requestKey, prepared)` | Derive all applicable accounts, reserve one unit atomically, or return an existing matching request. |
| `claim(context, requestKey, prepared, executor)` | Recheck live authority, transfer reserved to charged once, and return a dispatch fence only to the winning claimant. |
| `finalize(fence, outcome)` | Idempotently save a definitive safe outcome; a different executor/fence or conflicting outcome is rejected. |
| `markIndeterminate(fence)` | Record uncertainty without refunding; never overwrite an already finalized result. |
| `cancel(context, requestKey, prepared)` | Release only an unclaimed reservation, retaining its permanent cancellation tombstone. |
| `revokeToken(key)` / `revokeGrant(key)` | Trusted authoritative revocation, ordered with claims in the same database. |
| `advanceConnectionEpoch(key, expected, next)` / `advanceGrantEpoch(key, expected, next)` | Trusted compare-and-set, strictly increasing epochs; never reset totals or reactivate revoked grants. |
| `accounts(context)` | Inspect the derived account set for a currently authorized context. |
| `close()` | Close this connection; safe to call repeatedly. |

`BudgetAuthenticatedContext` contains `issuer`, `tenant`, `grantId`, `tokenId`,
`subject`, `holder`, `provider`, `connectionId`, `policyVersion`, `grantEpoch`, and
`connectionEpoch`. A token's parent is a token ID within the same
issuer/tenant/grant namespace. Parent and child holders may differ, but each
exercise must match the selected token's registered holder.

Connection keys are `(issuer, tenant, provider, connectionId)`. Grant keys are
`(issuer, tenant, grantId)`. Token keys are `(issuer, tenant, grantId, tokenId)`.
Accounts use separate columns for namespace, owner and constraint type; there is
no ambiguous delimiter-based key construction. The sole account dimension is
`max_calls`. The grant account has distinct type `grant`, so a token ID equal to
a grant ID cannot collide with it.

Registrations compare the complete normalized supported metadata. Exact repeats
are idempotent without changing balances or status; conflicts fail. Constraint
ordering is canonicalized. Token registration uses the existing strict
`parseConstraints` and `constraintsSubsume` helpers. A child cannot omit, change
the type of, or loosen a parent's constraint or extend its expiry. Lineages are
bounded to 64 tokens. Missing/malformed/cyclic lineage, absent required accounts,
invalid reservation references and detected malformed records deny admission.

Epoch advancement invalidates earlier token authority without replenishing the
grant account. Explicitly authorized new token IDs in the new grant epoch may
reuse that same allowance. A grant's connection-epoch binding is immutable:
advancing the connection epoch disables that grant's old connection binding;
this slice has no automatic reauthorization or migration to a new connection
epoch. Repeated registration cannot undo this invalidation or revocation.

## Metering and constraint support

Only `max_lifetime` and `max_subtree` constraints on `max_calls` are supported.
There is always a required, separate, server-authorized grant-wide allowance.
Known per-action constraints (including `max`), other quantity keys and unknown
constraint types are rejected with an unsupported-constraint reason, rather than
silently discarded. No caller quantity object is accepted. Extra authorization
or operation fields are rejected at runtime, not just by TypeScript.

Every dispatch claim charges exactly one unit against:

1. The exercised token's own `max_lifetime`, if present;
2. Every `max_subtree` from that token through all its ancestors;
3. Its required stable grant allowance.

A child's exercise does **not** charge a parent's lifetime account. A reissued
`jti` has its own lifetime total, while old/new roots and their descendants share
the grant allowance as long as they remain authorized. Minting another token
cannot replenish this account.

Bounds/counters are nonnegative safe integers, at most
`Number.MAX_SAFE_INTEGER`. Fractions, nonfinite/unsafe values and overflow deny.
SQLite INTEGER checks and checked reads protect `reserved + charged <= bound`.
Reservation checks use subtraction to avoid overflowing an intermediate sum.
All applicable accounts, request references and the transition are committed
atomically. Finalization never adjusts consumption.

## Prepared operations, retry identity and privacy

`prepareBudgetOperation({ method, target, headers?, body? })` produces an opaque
in-process handle. `body` is a `Uint8Array`/`Buffer` of the **already serialized**
bytes. Preparation detaches the bytes into a frozen array and freezes the
normalized target, uppercase method and headers. The adapter supplies these same
snapshots to transport as a `FrozenBudgetOperation`; transport can create its
outbound byte buffer using `Buffer.from(operation.body)`. Later mutation of the
input buffer or header object cannot alter the digest or dispatch.

Operation fields are captured once before validation and normalization. Byte
capture uses the intrinsic typed-array iterator, not a caller-defined iterator,
length getter or byte-view hook; the frozen array contains only primitive numeric
bytes and respects the supplied view's offset and length. GET/HEAD validation
uses that detached snapshot, so an overridden iterator cannot introduce a body
after validation. This does not claim isolation from malicious global runtime
modifications.

Supported methods are GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS. GET/HEAD
cannot carry nonempty bodies. The target uses URL normalization once, retains
query ordering/content, requires HTTPS, and rejects fragments, userinfo and common
credential-bearing query parameter names. Only `accept`, `content-type`,
`if-match`, `if-none-match`, and `idempotency-key` headers can be forwarded in this
slice. Names are lowercased, values trimmed, and duplicate case-insensitive names
rejected. Credential headers and all other header names are refused. This narrow
allowlist is intentional; it is not permission to omit provider-required semantic
headers. An operation needing other headers needs a reviewed extension.

The internal SHA-256 fingerprint binds the complete selected authenticated
context (including both epochs), normalized method/target/query, forwarded
headers and exact body bytes. It is not exposed in returned request views.
Credential-free operation data is a host responsibility: arbitrary secrets in an
otherwise allowed body, URL path/query or header value cannot be recognized
reliably by this library. Neither provider bearer credentials nor credential
header digests belong in admission records or client outputs.

**Request keys are issuer-wide, not holder-, tenant-, token- or grant-scoped.**
The host should allocate unpredictable opaque keys and preserve them across a
retry. Reusing a key with a different tenant, holder, token, grant, epoch or
operation is a conflict. A legitimate different tenant must use a different key.
Do not expose a raw arbitrary-key namespace that allows one tenant to preempt
another tenant's keys.

Exact retries return only `{ requestKey, state, outcome?, reason? }`. They do not
reserve again or dispatch a claimed request again. A terminal replay may return
its stored result even after expiry/revocation: this is retrieval of a previous
outcome, not a new exercise. The host must still authenticate and authorize the
caller to see that reference. An existing `reserved` request must pass fresh
authority checks at claim.

`BudgetOutcome` contains a host-generated opaque `reference` (1–128 ASCII letters,
digits, underscores or hyphens) and optionally an integer HTTP status (100–599).
No credential, request/response body, response header collection or exception
message is stored. Syntax alone cannot prove a reference is non-sensitive; the
host must not encode sensitive data into it. Full provider responses must be
managed separately with appropriate access control and retention.

There is **no automatic deletion** of requests, cancellation tombstones,
transitions, registrations or counters. They must outlive accepted grants/tokens
and retries. Database contents still reveal identity, usage, ordering through
transitions and internal request digests; fingerprints can permit guesses about
low-entropy request content. Protect the file and backups accordingly. Bounded
retention, deletion/privacy policy, encrypted backup handling and storage-growth
monitoring remain deployment work. Do not delete tombstones to recover capacity.

## Dispatch lifecycle and failure contract

The final claim commit is the linearization point. Revocation, expiry or epoch
invalidation before it cancels and releases an unclaimed reservation atomically.
A claim committed first is in-flight authority, even if revocation commits before
the provider accepts the request. Finalization of that in-flight request does not
recheck authority and never refunds its charge.

| Durable state | Adapter behavior on an exact retry |
| --- | --- |
| No request | May reserve, then claim a new attempt. |
| `reserved` | May claim once after current authority checks, or atomically cancel. |
| `dispatch_claimed` | Return that state; treat as in-flight/possibly dispatched. Never reclaim or resend. |
| `indeterminate` | Return uncertainty; retain permanent charge. |
| `finalized` | Return the safe stored outcome reference/status, not a reconstructed provider response. |
| `cancelled` | Return its tombstone; do not revive it. |

`executeBudgetedOperation(store, authenticatedContext, requestKey, prepared,
executor, trustedTransport)` runs reserve → claim → transport → finalize.
Transport receives the frozen operation and the winning request-specific fence.
Only that claim yields a fence. A repeat claim (even by the same executor) cannot
obtain permission to send again, and a different/stale fence cannot finalize.
The fence is not a credential and does not revoke an already in-flight provider
request.

Both finalization methods require a closed data-only fence with `requestKey`,
`executor` and `fence` string fields. Store-created frozen fences and serialized
plain-data copies are accepted; accessors, extra fields and missing or malformed
values are rejected. Each scalar is captured and validated once, and that same
snapshot selects, checks, updates, audits and returns the request. Caller field
changes cannot switch the target after another request's fence was checked.

If transport throws, a response is lost, or finalization fails, the adapter tries
to mark the request indeterminate. If a finalization commit succeeded but its
acknowledgement was lost, it preserves the already finalized outcome. If the
store is unavailable even for the indeterminate write, it throws an explicit
store error; the existing claim stays charged. A process killed after claim,
even before any actual send, leaves `dispatch_claimed` and is never automatically
resent. There is no worker lease/reassignment or indeterminate reconciliation
API in this version. Direct low-level users must obey the same fence/no-resend
contract as the adapter.

This is **not generic exactly-once provider execution**. SQLite and the provider
are not in one transaction. The API supplies conservative at-most-one automatic
transport invocation for a successfully recorded request, not provider rollback,
instant cancellation, or safe retry after arbitrary host/transport behavior.
Any provider-specific resubmission protocol requires a separate reviewed adapter.

## Minimal host usage

The following is an illustrative host-side skeleton, not a new HTTP handler.
`context` must already be authenticated and resolved from registered authority;
`trustedTransport` must satisfy the contract above and return a real safe outcome
reference.

```ts
import {
  DurableBudgetStore,
  prepareBudgetOperation,
  executeBudgetedOperation,
  type BudgetAuthenticatedContext,
  type BudgetDispatchFence,
  type BudgetOutcome,
  type FrozenBudgetOperation,
} from '@credninja/vault';

async function exercise(
  store: DurableBudgetStore,
  context: BudgetAuthenticatedContext,
  requestKey: string,
  trustedTransport: (operation: FrozenBudgetOperation, fence: BudgetDispatchFence) => Promise<BudgetOutcome>,
) {
  const prepared = prepareBudgetOperation({
    method: 'POST',
    target: 'https://provider.example/items?view=summary',
    headers: { 'Content-Type': 'application/json' },
    body: Buffer.from(JSON.stringify({ item: 'synthetic-example' })),
  });
  return executeBudgetedOperation(store, context, requestKey, prepared, 'worker-1', trustedTransport);
}
```

Initialize a **new** store with `{ path, issuer, deploymentEpoch, initialize:
'new' }` only in an explicit provisioning step. Register the connection, grant
and complete token lineage under trusted authorization before calling
`exercise`. Reopen without `initialize`; never retry a failed open with a new
empty store. `BudgetAdmissionError.code` reports store/authority/account failures;
malformed closed-object/prepared-operation input also throws `TypeError` with a
fixed validation reason. Do not return raw provider exceptions as admission
errors.

## Verification and remaining acceptance gates

The focused tests use actual SQLite files under an explicitly configured `TMPDIR`
or Node's `os.tmpdir()` fallback, synthetic identities, and instrumented trusted
transports. `TMPDIR` is optional; setting it keeps test files under a chosen root.
They cover:

- Shared sibling/ancestor limits, tighter descendant limits, all-or-none changes,
  lifetime exclusion, grant continuity across reissuance and numeric boundaries;
- Exact/changed retries, identity isolation, immutable registration conflicts,
  detached byte/header snapshots and credential/quantity/constraint denial;
- Revocation/expiry ordering before and after claim, authoritative epochs,
  cancellation, stale executor fences and terminal replay;
- Missing/malformed/cyclic lineage, absent accounts/reservation references,
  corrupted metadata/outcomes, incompatible/missing stores and restart behavior;
- Transaction/audit-write failures, response loss, finalization failure and lost
  acknowledgement, and a store becoming unavailable after transport;
- Four genuine child processes contending over siblings, concurrently reissued
  roots/children, and a shared request key; cross-process SQLite lock contention;
- Actual SIGKILL after reserve and after claim followed by reopened recovery.

The child-process fixture transpiles current owned TypeScript source with the
existing TypeScript dependency, rather than relying on potentially stale `dist`
output. Database-trigger failures exercise transactional rollback; they are not
claims of disk-full, torn-write or power-failure testing. Clock tests use a
controlled `Date.now`; they do not certify host clock reliability.

Run focused tests/build/typecheck from the repository root with the pinned
native-binding runtime used for this slice:

```sh
npm exec --yes --package=node@22.23.4 --package=npm@10.9.9 -- npm run test --workspace=packages/vault -- src/__tests__/durable-budget-admission.test.ts
npm exec --yes --package=node@22.23.4 --package=npm@10.9.9 -- npm run test --workspace=packages/vault
npm exec --yes --package=node@22.23.4 --package=npm@10.9.9 -- npm run build --workspace=packages/vault
npm exec --yes --package=node@22.23.4 --package=npm@10.9.9 -- npm run typecheck --workspace=packages/vault
```

The full profile remains **disabled** pending authoritative legacy/Link store
integration; handler-level reserve/claim/dispatch/finalize tests; closure of
raw-token/local/alternate-path bypasses; authoritative migration of existing
grants and consumption; externally anchored stale-restore recovery; deployment
retention/privacy/observability decisions; filesystem/power-loss qualification;
and the independent complete candidate suite, package smoke tests and pinned
Asor conformance gates. Nothing in this library-only slice certifies those gates.

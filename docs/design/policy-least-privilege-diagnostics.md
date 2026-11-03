# Least-privilege policy diagnostics

Status: shipped in `@credninja/guard` and `@credninja/server`, default off.
Read-only. Nothing in this feature changes a running guard.

## Problem

A `CredGuard` is configured once, at setup, by an operator guessing which
scopes, URL patterns and rate limits an agent will need. The guess is almost
always generous, and nothing revisits it: the guard records every decision it
makes, but no tool compares those decisions with the configuration that
produced them. The scope nobody requests, the URL pattern nobody hits, the
provider the chain never looks at, and the limit set ten times higher than
peak traffic all stay in place.

Cloud IAM solved the same problem for roles with IAM Access Analyzer:
generate findings from access logs, propose the least-privilege policy the
observed traffic supports, let a human apply it. This feature is that loop
for the guard.

## What was built

### Read the chain as data

`CredPolicy` gains two optional methods. `describe()` returns the policy's
configuration as JSON (`{ kind, parameters, opaquePaths?, stateful? }`).
`withParameters(parameters)` builds a new instance from an edited tree for a
dry run, validating it. Every built-in policy implements both. A custom
policy that implements neither is recorded as `kind: "opaque"`: it is carried
over by reference in a dry run and no patch may touch it.

`snapshotGuard(guard)` collects the descriptors in evaluation order, adds the
guard's error disposition, counts the leaves and hashes the canonical JSON.
The hash identifies a configuration, so a finding or a patch can name the
exact state it was computed against.

Non-serializable values are kept honest rather than dropped. A RegExp
pattern becomes `{ "$regex": source, "flags": flags }` and round-trips. A
`scopeGate` predicate becomes `{ "$opaque": true }`, is listed in
`opaquePaths`, and is kept by reference when the policy is rebuilt for a
dry run; a patch that names it is refused.

### Interpret

From the snapshot alone, `interpretSnapshot` reports per provider the scopes
an agent may request, the URL patterns it may reach, its rate limit and TTL
ceiling; globally the time window, identity requirements, error disposition,
and the treatment of providers no policy names. That last point is the one
most easily missed when reading code: `scope-filter` and `url-allowlist`
SKIP a provider they do not list, so removing a provider key widens access
rather than cleaning it up. The interpretation says so in plain sentences.

### Diagnose against recorded decisions

`CredGuard` gains an opt-in ring buffer (`decisionHistorySize`) of its recent
decisions as `GuardAuditEvent`s. `diagnosePolicies` reads that buffer, or any
other source of guard events, and reports where the configuration and the
traffic disagree. Each finding names the policy and parameter path, states
its evidence as counts, and carries the smallest patch that addresses it,
already classified as widening or narrowing:

| Code | What it reads | Suggested patch | Effect |
|---|---|---|---|
| `unused-allowed-scope` | an allowed scope no request asked for | remove that one scope | narrowing |
| `unused-url-pattern` | a pattern no brokered call matched | remove that one pattern | narrowing |
| `unconstrained-provider-scopes` | traffic to a provider scope-filter does not list | add the observed scope set | narrowing |
| `unconstrained-provider-urls` | brokered calls to a provider url-allowlist does not list | add the observed origins | narrowing |
| `rate-limit-slack` | observed peak far under the limit | per-provider limit at twice the peak | narrowing |
| `repeated-denial` | the same denial over and over | the scope the denials asked for | widening, human decision |
| `error-fails-open` | `onError: "allow"` | set `deny` | narrowing |
| `scope-narrowing-silent` | `narrowInsteadOfDeny` | set `false` | narrowing |
| `dead-policy` | a policy that skipped every request | none, informational | |

These are deterministic heuristics with observation thresholds, not
judgements. `repeated-denial` is the one finding whose patch widens; it is
offered so a reviewer can decide whether the denials describe a real
workflow or an agent probing its limits.

### Dry-run a patch

A patch is a list of JSON Pointer ops (`add`, `remove`, `replace`) against
the snapshot: `/onError`, `/<policy>` for a whole policy, or
`/<policy>/<pointer into its parameters>`. Dropping one scope is one op
touching one leaf. `applyPatch` is pure and all-or-nothing and names the
failing op. `diffSnapshots` recovers the minimal patch between two states,
comparing scalar arrays as sets so a reordering is not an edit.

`classifyPatch` places every op by the semantics of the policy kind it
touches: raising `maxRequests` widens, shortening `windowMs` widens,
removing a scope narrows, removing a provider key widens, dropping a policy
widens, adding a restrictive policy narrows, `onError: "allow"` widens, a
per-provider rate limit is compared with the limit it replaces. Anything it
cannot place is `unknown`, which callers treat as widening. The magnitude is
leaves touched over leaves in the base snapshot, so a reviewer can refuse a
patch that rewrites a table when one leaf would do.

`replayDecisions` rebuilds the base chain and the patched chain in
isolation and evaluates every recorded decision against both, reporting the
requests whose outcome flips in either direction. Stateful policies
(rate-limit) are left out of both chains, since their answer depends on
history the replay does not have, and the report names them.

### Surface

`GET /admin/policy` on `@credninja/server`, admin-authenticated and
rate-limited, present only when the server is given `guard` and
`policyDiagnostics: true`. It returns the snapshot, the interpretation and
the diagnosis, with `?include=` to select sections. It changes nothing: an
operator reviews a finding, applies the patch to configuration, and
redeploys. A CI job can call the same functions against a guard built from
the configuration under review.

There is no MCP tool and no agent-facing surface. An agent editing its own
guard is the wrong shape for a credential boundary, whatever approval
machinery sits in front of it.

## Security considerations

- Read-only by construction: every exported function is pure over a
  snapshot, and the route only reads. The one mutation an operator can make
  is to their own configuration, out of band.
- The report exposes policy parameters, not secrets. Scope lists and URL
  patterns are the same data `cred_whoami` already reveals in part; refresh
  tokens and agent tokens are never in a snapshot.
- Replay evidence is a sample, not a proof. A patch that flips nothing in
  the recorded window can still change an outcome the window did not
  contain. The classification is the stronger guarantee: a narrowing patch
  cannot admit a request the base denied.
- Default off. A deployment that does not set `policyDiagnostics` and
  `decisionHistorySize` records nothing extra and exposes no route.

## What is deliberately not built

- No live application of patches, no proposal store, no signing. A finding
  is applied by editing configuration.
- No LLM call. The output is structured so a model or a person can review
  it; which, and whether, is the operator's choice.
- No editing of Permission records, Link grants or the broker's operation
  tables. The policy chain is the first configuration this loop reads; see
  the follow-up note in the PR for the operation tables.

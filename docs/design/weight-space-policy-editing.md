# Weight-space policy editing

Status: shipped in `@credninja/guard`, `@credninja/mcp` and `@credninja/server`
behind explicit opt-in. The editor, patch format, classification, replay and
signed approvals are production-ready. The `weightArtifactPolicy` and the
diagnostic heuristics are experimental and marked as such below.

## The idea, borrowed

Weight-Space Programming (Takehi et al., MIT CSAIL, November 2026) shows a
frontier model reading a network's raw weights, naming what the network was
trained to do, diagnosing a failure such as a reasoning loop, and patching it
by editing a tiny fraction of parameters directly, with no gradient step. The
loop is: read the weights as data, interpret them, diagnose against observed
behaviour, propose a minimal edit, check it, apply it surgically.

Cred's guard has a weight space of its own. A `CredGuard` is an ordered chain
of policies, and each policy's configuration is a small tree of scalars: scope
lists, URL patterns, rate limits, TTL ceilings, time windows. Operators edit
those trees by hand, by redeploying, with no diff, no dry run and no record of
why. An agent that could reason about them had no way to read them, and no
safe way to touch them.

This design treats the policy chain as the weights and gives Cred the same
loop, with one difference the paper does not need: a policy edit can widen
what an agent may do with a user's credentials, so the loop ends in signed
human approval, not in the agent's own judgement.

## What was built

### Read the chain as data: `snapshotGuard`

`CredPolicy` gains two optional methods. `describe()` returns the policy's
configuration as JSON (`{ kind, parameters, opaquePaths?, stateful? }`).
`withParameters(parameters)` builds a new instance from an edited tree,
validating it. Every built-in policy implements both. A custom policy that
implements neither is recorded as `kind: "opaque"`: it is carried over by
reference on every edit and no patch may touch it.

`snapshotGuard(guard)` collects the descriptors in evaluation order, adds the
guard's error disposition, counts the leaves and hashes the canonical JSON.
The hash is the identity of a policy state. A patch is written against a hash
and applies only to that hash.

Non-serializable values are handled honestly rather than dropped. A RegExp
pattern becomes `{ "$regex": source, "flags": flags }` and round-trips. A
`scopeGate` predicate becomes `{ "$opaque": true }`, is listed in
`opaquePaths`, and is kept by reference when the policy is rebuilt; a patch
that names it is refused.

### Interpret: `interpretSnapshot`

From the snapshot alone, per provider: the scopes an agent may request, the
URL patterns it may reach, its rate limit and TTL ceiling; globally: the time
window, identity requirements, error disposition, and the treatment of
providers no policy names. The last point matters most and is easy to miss
when reading code: `scope-filter` and `url-allowlist` SKIP a provider they do
not list, so removing a provider key is a widening edit, not a cleanup. The
interpretation says so in plain sentences a reviewer or an LLM can act on.

### Diagnose against observed decisions: `diagnosePolicies`

`CredGuard` gains an opt-in ring buffer (`decisionHistorySize`) of its recent
decisions as `GuardAuditEvent`s. The diagnostics read that buffer, or any
other source of guard events, and report where the configuration and the
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
| `repeated-denial` | the same denial over and over | the scope the denials asked for | widening, needs approval |
| `error-fails-open` | `onError: "allow"` | set `deny` | narrowing |
| `scope-narrowing-silent` | `narrowInsteadOfDeny` | set `false` | narrowing |
| `dead-policy` | a policy that skipped every request | none, informational | |

These are deterministic heuristics with observation thresholds, not learned
judgements. They are the evidence an LLM reviews, in the same spirit as the
paper's models reading activations next to weights; the model's contribution
is to decide which findings describe a real workflow and which describe an
agent probing its limits.

### Patch surgically: `applyPatch`, `diffSnapshots`, `classifyPatch`

A patch is a list of JSON Pointer ops (`add`, `remove`, `replace`) against the
snapshot: `/onError`, `/<policy>` for a whole policy, or
`/<policy>/<pointer into its parameters>`. Adding one scope is one op touching
one leaf. `applyPatch` is pure and all-or-nothing and names the failing op.
`diffSnapshots` recovers the minimal patch between two states, comparing
scalar arrays as sets so a reordering is not an edit.

`classifyPatch` places every op by the semantics of the policy kind it
touches: raising `maxRequests` widens, shortening `windowMs` widens, removing
a scope narrows, removing a provider key widens, dropping a policy widens,
adding a restrictive policy narrows, `onError: "allow"` widens. Anything it
cannot place is `unknown`, and every approval rule treats `unknown` as
widening. The magnitude is leaves touched over leaves in the base snapshot;
the paper's 0.016% is the number to aim for, and the editor reports it so a
reviewer can refuse a patch that rewrites a table when one leaf would do.

### Check before applying: `replayDecisions`

The dry run rebuilds the base chain and the patched chain and evaluates every
recorded decision against both, reporting the requests whose outcome flips in
either direction. Stateful policies (rate-limit) are left out of both chains,
since their answer depends on history the replay does not have, and the
report says which were excluded.

### Apply under approval: `PolicyWeightSpaceEditor`

The editor binds the loop to a live guard. `inspect()` returns snapshot,
interpretation and diagnosis. `propose()` validates the patch, proves the
result can be built, classifies, measures and dry-runs it, and returns a
hashed proposal that records the base hash, the result hash and the dry run.
`apply()` checks the proposal is intact and unexpired, that the live chain
still matches its base hash, that enough valid approvals are present, and then
swaps the chain in one assignment, rebuilding only the policies the patch
changed. Untouched policies keep their instance and their runtime state: a
rate limit's counters survive an edit to the TTL ceiling.

Approvals are Ed25519 signatures over the proposal hash, made with keys the
editor is configured to trust. The agent that proposes carries the signature;
it cannot make one, because approval private keys never live where the agent
runs. The defaults are closed:

- every patch needs approval (`requireApprovalFor: 'all'`);
- a proposer cannot approve its own proposal;
- an editor with no approvers can propose and never apply;
- a proposal applies only to the exact hash it was written against;
- rollback is a new proposal under the same rules, since undoing a narrowing
  edit widens.

`requireApprovalFor: 'widening'` lets narrowing and neutral patches apply
without a signature. That is the configuration for an agent allowed to
tighten its own guard and never loosen it.

### Surfaces

- MCP: `cred_policy_inspect` (read-only, exempt from guard wrapping like
  `cred_whoami`, so it works during a guard outage), `cred_policy_propose`
  and `cred_policy_apply` (guard-wrapped and rate-limited). All three exist
  only when the operator passes a `policyEditor` to the MCP server.
- REST: `GET /admin/policy`, `POST /admin/policy/proposals`,
  `GET /admin/policy/proposals/:id`, `POST /admin/policy/proposals/:id/apply`,
  admin-authenticated, present only when the server is given a
  `policyEditor`. Every proposal, application and rejection is written to the
  vault audit log as a `policy` resource with the proposal id, effect,
  magnitude, hashes and approvers, inside the tamper-evident chain.

## Agents that program other models: `weightArtifactPolicy` (experimental)

An agent doing weight-space programming on another model moves checkpoints
and tensors between a store and its workspace. The credential for that store
(a hub token, object-store keys) is exactly what Cred vaults: the agent
delegates, and reads or writes through `cred_use`, never holding the token.
`weightArtifactPolicy` decides which such calls a delegation may make: the
hosts of the store, whether writes are allowed and under which path prefixes,
the SHA-256 digests the agent may load or push, and the largest artifact it
may move. Digest and size are declared by the caller in the call's metadata
and the policy fails closed when a pin or cap is configured and the
declaration is missing.

It is experimental because the policy cannot verify bytes it never sees: it
checks the agent's declaration, which the audit event records. Verifying the
response digest belongs in the broker and is not built.

## Security considerations

- Default deny holds everywhere: no approvers means nothing applies, unknown
  classification counts as widening, a patch on an opaque value is refused, a
  rebuilt policy that rejects its parameters fails the proposal before anyone
  signs.
- The agent's view is of policy parameters, not of secrets. Scope lists and
  URL patterns are the same data `cred_whoami` and the operator's config
  already expose in part; refresh tokens, agent tokens and approval keys are
  never in a snapshot.
- Every edit is attributable: proposer, approvers, base hash, result hash,
  patch, effect and magnitude go to the audit log, so a chain state can be
  reconstructed from the sequence of applied patches.
- Replay evidence is a sample, not a proof. A patch that flips nothing in the
  recorded window can still change an outcome the window did not contain. The
  classification is the stronger guarantee: a narrowing patch cannot admit a
  request the base denied.
- The MCP propose and apply tools are guard-wrapped under their own
  rate-limit buckets, so a looping agent cannot spam proposals faster than
  any other tool.

## What is deliberately not built

- No LLM call inside the SDK. The tooling produces the data an LLM reasons
  over and consumes the patch it proposes; which model, and whether one is
  involved at all, is the operator's choice.
- No automatic application of findings. Diagnostics suggest; approvals apply.
- No persistence of proposals across restarts. A pending proposal is bound to
  a live chain's hash and expires in an hour by default; a restart that
  rebuilds the chain from configuration invalidates it, which is the
  intended behaviour.
- No editing of Permission records or Link grants. Those have their own admin
  routes with their own semantics; the policy chain is the first weight
  space, not the last.

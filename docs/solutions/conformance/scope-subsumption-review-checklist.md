# Review checklist: scope comparison and subsumption changes

Distilled from the review of the wildcard scope subsumption work (PR 28). Start here for any change that alters how scopes are compared, in the vault delegation chain, the server ceiling checks, or stored consent.

## Semantics to pin down before reading the diff

- Directionality: a granted wildcard may cover a concrete request; a requested wildcard must never be covered by a concrete grant.
- Depth: decide whether `crm.*` covers `crm.contacts.read` (multi-level) or only `crm.read` (single-level), and cite the wire spec that decides it.
- Malformed input: a scope that fails validation must match only itself (exact literal) and never cover or be covered by anything else. Never-covered-at-all silently breaks renewal of legacy chains through the default-request path (the child requests nothing, the request defaults to the parent's own grant, and the parent's own scope fails self-coverage).
- Boundary: verify the dot boundary explicitly. `crm.*` must not cover `crm`, `crm.`, or `crmx.read`.

## Paths that must stay consistent

- `validateSubDelegation` in `packages/vault/src/delegation-chain.ts` (chain narrowing).
- All per-agent `scopeCeiling` checks in `packages/server/src/server.ts` (request check, stored-consent filter, sub-delegation cap). Grep for ceiling comparisons that bypass the shared helpers.
- `resolveGrantedScopes` (stored provider consent) is exact-match on purpose: provider scopes are provider-defined identifiers, not Cred delegation scopes. If a change makes wildcard grants storable, re-examine this asymmetry.

## Tests the change must carry

- Unit: each malformed shape, self-match for literals, one-directional coverage, dot-boundary negatives, multi-level positives.
- A renewal regression through the default-request path with a legacy literal scope in the parent grant.
- Server-level tests through every ceiling call site over HTTP, not just vault units.
- Error ordering: if the change touches which of `no_scopes_granted` or `scope_escalation_denied` fires first, pin the decision with a test.

## Conformance tie-in

The draft-asor vectors in cred-ninja/protocol `conformance/asor-delegation-chain/` exercise the wire subsumption relation. Run them locally against your branch before opening the PR: a scope-comparison change that flips a vector is a wire-visible behavior change.

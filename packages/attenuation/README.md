# @credninja/attenuation

Delegation attenuation for AI agents, with no runtime dependencies (Node.js
built-ins only, no native modules). This is the pure part of Cred's delegation
logic, split out of `@credninja/vault` so it can be used by any verifier that
holds only a chain of tokens. `@credninja/vault` re-exports the attenuation
API unchanged.

## What is in it

- **Scope grammar** (`classifyScope`, `scopeCovers`): literal, wildcard and
  opaque scopes as in draft-asor-wimse-agent-delegation-chain-02 Section 4.1.
  A wildcard `p.*` covers literals and longer wildcards under `p.`; an opaque
  scope covers only itself; nothing is case folded.
- **Constraint ceilings** (`parseConstraints`, `constraintsSubsume`): `max`,
  `min`, `one_of`, `not_one_of`, `prefix`, `rank` (with `order`),
  `max_lifetime` and `max_subtree`, closed objects, unique per (key, type),
  fail-closed parsing and per-type subsumption with no inference across types.
- **Per-hop issuance check** (`validateSubDelegation`).
- **Chain verification over plain hop records** (`verifyDelegationChain`).
- **Strict JSON** (`parseStrictJson`): rejects duplicate members and integers
  outside the binary64 exact range. **JCS** (`canonicalJson`, RFC 8785).
- **Compact JWS behind a signer interface** (`JwsSigner`, `createKeySigner`,
  `signCompactJws`): EdDSA (Ed25519) and ES256 (P-256), `kid` in the header,
  defaulting to the key's RFC 7638 thumbprint. Verification
  (`checkJwsSignature`) takes the verifier's own accepted-algorithm list and a
  key resolver; the header `alg` must be on the list and equal the resolved
  key's algorithm.
- **The -02 Delegation Chain format** (`verifyAgentDelegationChain`,
  `mintAgentDelegationToken`): tokens with exactly one `agent_delegation`
  detail, the Principal in `sub`, the Acting Agent in `client_id`, `cnf`,
  `aud`, `par_hash`, `del_depth` and `del_max_depth`, verified with Section 6
  steps 1 to 5 and the audience half of step 8.

## Verifying a chain

```ts
import { verifyAgentDelegationChain, createVerificationKey, staticKeyResolver } from '@credninja/attenuation';

const result = verifyAgentDelegationChain(tokens, {
  acceptedAlgs: ['EdDSA', 'ES256'],
  resolveKey: staticKeyResolver([createVerificationKey(issuerPublicKey)]),
  audience: 'https://rs.example.com',
});
if (!result.ok) throw new Error(`${result.reason} at hop ${result.hop}: ${result.message}`);
```

Holder binding (step 6) and status checks (step 7) need the request and a
status source and stay with the caller. Cumulative constraints are checked for
narrowing only; their running totals belong to the single writer that holds
them.

## Conformance

The 35 interop vectors published with draft-asor-wimse-agent-delegation-chain-02
(attenu-guard v0.20.0) are vendored under `src/__tests__/fixtures/asor-02/` and
scored natively by `src/__tests__/asor-02-vectors.test.ts`: 35 of 35.

## License

Apache-2.0

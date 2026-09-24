# Provider-native scopes vs asor-01 §4.1 scope ABNF

Status: blocking interop issue with `draft-asor-wimse-agent-delegation-chain-01`,
to be resolved with the author before his Nov 2 revision cutoff. Proposal below.

## The problem

asor-01 §4.1 requires every member of `scopes` to match:

```
lower          = %x61-7A
digit          = %x30-39
segment        = lower *(lower / digit / "_" / "-")
literal-scope  = segment "." segment *("." segment)
wildcard-scope = segment *("." segment) ".*"
scope          = literal-scope / wildcard-scope
```

Lowercase, dot-separated, minimum two segments — and a verifier that meets an
invalid scope MUST reject the whole Delegation Token as malformed. Every scope
Cred actually brokers fails that grammar: Google
(`https://www.googleapis.com/auth/drive.readonly` — colons, slashes), GitHub
(`repo:status`), Slack (`channels:read`), Microsoft Graph (`User.Read` —
uppercase, one dot but capitalized segments). A chain carrying any real
provider scope is unverifiable under §4.1 as written, which forecloses the
draft's own §8 bridge to an online Delegation Server brokering those
providers.

## Proposed fix (to send to Asor)

Split the grammar: keep the strict dot-segment grammar as the precondition for
*wildcard* scopes only, and admit provider-native literals as opaque tokens
compared by exact octet equality.

```
scope          = wildcard-scope / opaque-scope
wildcard-scope = segment *("." segment) ".*"        ; unchanged
opaque-scope   = 1*( %x21 / %x23-29 / %x2B-5B / %x5D-7E )
                 ; RFC 6749 scope-token minus "*" (%x2A)
```

Semantics: a wildcard scope covers per the existing segment-bounded rule,
unchanged. An opaque scope covers only a byte-identical child scope; it never
covers, and is never covered by, a wildcard (no segment structure is imputed
to it). `*` is excluded from opaque scopes entirely, so nothing can smuggle
wildcard semantics. This is fail-closed in the same spirit as the constraint
rules: unknown structure narrows nothing and widens nothing.

This matches what Cred's `isValidScope`/`scopeCovers`
(`packages/vault/src/delegation-chain.ts`) already implement: a malformed or
foreign scope matches only itself. One profile, two implementations, and
provider-native scopes ride through untouched.

## Fallback if the ABNF stays strict

Register a mapping segment: the broker canonicalizes provider scopes into the
dot grammar under a provider prefix (`google.drive.readonly`) and carries the
provider-native string in a non-normative claim. Rejected as primary because
it forces every verifier to trust the broker's mapping table, which reopens
the closed-vocabulary problem §4.1 was avoiding.

# Provider-native scopes vs asor-01 §4.1 scope ABNF

Status: sent to the wimse list 2026-10-06 as -02 input. Iman Schrock (emilia)
replied the same day with a defect in the two-way split below: `payment.release`
matches `opaque-scope`, so `payment.*` would stop covering it and the -01's own
positive vectors would fail. Corrected to the three-way split in "Resolution"
at the end of this document; the SDK implements the corrected form
(`classifyScope`, 2026-10-07). The two-way text is kept for the record.

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

## Resolution (2026-10-07): three classes, -01 grammar kept intact

```
scope          = literal-scope / wildcard-scope / opaque-scope
literal-scope  = segment "." segment *("." segment)        ; -01 4.1, unchanged
wildcard-scope = segment *("." segment) ".*"               ; -01 4.1, unchanged
opaque-scope   = 1*( %x21 / %x23-29 / %x2B-5B / %x5D-7E )  ; RFC 6749 scope-token minus "*"
```

The alternatives overlap, so a verifier classifies by precedence: literal,
then wildcard, then opaque; anything else is malformed and the token is
rejected. Coverage: a wildcard covers a literal per the -01 segment-bounded
rule and never covers an opaque scope; a literal covers only an identical
literal; an opaque scope covers only a byte-identical opaque scope.

Classification is a function of the string alone. A lowercase dotted string
with two or more segments is structured whoever minted it, so a wildcard
covers it, which is what the issuer of that wildcard asked for. Provider
strings fall to opaque because of what they contain (uppercase in `User.Read`,
a colon in `repo:status`, a slash in the Google URIs, one segment in
`openid`), not because of who issued them.

Correction to the earlier claim that Cred already behaved this way: before
2026-10-07 `scopeCovers` matched a wildcard by raw prefix with no grammar
check, so `drive.*` covered `drive.Read`. `classifyScope` in
`packages/vault/src/delegation-chain.ts` now implements the precedence rule
and `scopeCovers` only lets a wildcard cover a literal or a longer wildcard.
One Cred-local allowance remains: a malformed scope (a `*` anywhere but as
the trailing `.*` segment) still matches itself by exact equality, so legacy
receipts carrying such strings keep verifying; asor-01 rejects the token
instead. The three list vectors (wildcard over opaque: deny; opaque over
wildcard: deny; wildcard over literal: accept) pass under both readings.

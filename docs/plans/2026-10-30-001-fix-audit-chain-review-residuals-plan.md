---
title: "fix: Close the PR #86 review residuals (passphrase check, hashed field list, local-mode issuer)"
type: fix
status: active
date: 2026-10-30
---

# fix: Close the PR #86 review residuals

## Summary

The review of PR #86 (tamper-evident audit chain, receipt `iss`) left three
residuals that the follow-up commit on `fix/audit-chain-review` did not fix.
This plan closes them on the same branch: the vault refuses a passphrase that
does not match the one it was created with, the audit chain hashes every
audit column by construction, and SDK local mode names its own issuer in
receipts. The three larger items from the -03 triage (JWT Delegation Token,
per-exercise ceilings, consent records and CIBA) stay deferred: each needs
policy decisions, recorded below.

---

## Problem Frame

- **Wrong passphrase.** `CredVault.init()` derives a key from whatever
  passphrase it is given and never checks it. Credentials then fail to
  decrypt, but audit writes succeed and extend the chain under the wrong key,
  so a later verification reports a configuration mistake as tampering.
- **Hashed field list.** `auditChainHash` lists the audit columns by hand,
  separately from `AuditRow` and the `INSERT`. A column added later can be
  stored without being hashed, and edits to it would go undetected.
- **Local-mode issuer.** SDK local mode still signs receipts with
  `iss: did:key:local-cred`, which names no issuer and is not a valid
  did:key. Local verification checks no `iss` at all.

---

## Requirements

- R1. `CredVault.init()` fails, before any read or write, when the
  passphrase does not match the vault's stored check value.
- R2. A vault without a check value (new, or created before this change)
  gets one on its first successful init; later inits enforce it.
- R3. The audit chain hash covers every `AuditRow` field. Adding a field to
  `AuditRow` without adding it to the chain fails type-checking, and a test
  fails if the table has a column that neither `AuditRow` nor the chain
  covers.
- R4. The existing hash input order is unchanged, so chains written by the
  current code still verify.
- R5. Local-mode receipts carry `iss` equal to the did:key of the local
  receipt signing key.
- R6. Local verification refuses a parent receipt naming another issuer.
  The legacy `did:key:local-cred` is accepted only on a receipt issued before
  this `Cred` instance was constructed, which mirrors the server rule.

---

## Scope Boundaries

- No change to the wire format beyond the local-mode `iss` value.
- No change to the hosted server's issuer (`REDIRECT_BASE_URI`).
- The file storage backend keeps no audit log. It gets the passphrase check,
  because R1 is about the vault, not the audit log.

### Deferred to Follow-Up Work

These are -03 design items. Each needs a decision from Kieran before code:

- **JWT Delegation Token** (`authorization_details` with `cred_delegation`,
  `prf`, `consent_id`, `credential_handle`). Decision: the token's exact
  claim set and whether it replaces or sits beside the receipt plus handle.
  It changes the wire format for every client (TypeScript, Python, MCP,
  integrations).
- **Per-exercise ceilings.** Decision: which quantities to meter for each
  provider (rows, spend, messages) and where the metering runs (broker
  response parsing or provider-reported usage).
- **Consent records, 90-day retention, re-consent and CIBA.** Decision: the
  approval product flow and its boundary with Cred Enterprise approvals.
- **Admin-approved signatures for scheduled workloads** (raised earlier as a
  possible -03 approver type).

---

## Key Technical Decisions

- **Check value next to the salt, not in the database.** The salt already
  lives in `<path>.salt` for both backends. A sibling `<path>.check` holds
  `HMAC-SHA256(derivedKey, "cred:passphrase-check:v1")` in hex, mode 0600.
  It works for file and SQLite storage alike, and it is not secret.
- **Trust on first use for existing vaults.** A vault created before this
  change has no check value. The first init writes one, so a wrong
  passphrase on that first init is pinned. This is acceptable because the
  credentials would already fail to decrypt, which operators notice. Probing
  a stored credential to validate the first init would couple init to
  backend contents and is out of scope.
- **One field list for the hash.** `AUDIT_CHAIN_FIELDS` in `audit.ts`, in
  today's order, drives `auditChainHash`. A type-level exhaustiveness check
  ties it to `AuditRow`.
- **Local issuer as a real did:key.** The did:key of the local receipt
  signing public key names the signer, and that key verifies the signature.
  It needs no configuration and stays stable for a given local secret.

---

## Implementation Units

### U1. Passphrase check value

**Goal:** `CredVault.init()` refuses a passphrase that does not match the vault.
**Requirements:** R1, R2
**Dependencies:** none
**Files:** `packages/vault/src/vault.ts`, `packages/vault/src/__tests__/passphrase-check.test.ts`, `CHANGELOG.md`
**Approach:** After deriving the key and before setting the audit chain key,
compute the check value. If `<path>.check` exists, compare it in constant
time and throw a clear error on a mismatch. Otherwise write it with mode
0600. Init must not have touched the audit chain before the check runs.
**Patterns to follow:** `loadOrCreateSalt` in `vault.ts`.
**Execution note:** Test-first.
**Test scenarios:**
- New vault: init writes `.check`, and a second init with the same passphrase succeeds.
- A second init with another passphrase throws, and no audit row is written.
- A vault with salt but no `.check` (pre-upgrade) inits, writes `.check`, then enforces it.
- Both backends: the file backend is enforced as well.
- An unreadable or corrupt `.check` (not hex) gives a clear error, not a silent rewrite.

**Verification:** a wrong passphrase can no longer extend the chain. The
existing vault suite passes.

### U2. Single source of truth for hashed audit fields

**Goal:** the chain hashes every audit column by construction.
**Requirements:** R3, R4
**Dependencies:** none
**Files:** `packages/vault/src/audit.ts`, `packages/vault/src/index.ts`, `packages/vault/src/__tests__/audit-chain.test.ts`
**Approach:** Export `AUDIT_CHAIN_FIELDS` (the current order) and build the
hash input as seq followed by the listed fields. Add a type-level assertion
that `keyof AuditRow` minus the list is `never`. Add a test comparing the
list with `PRAGMA table_info(vault_audit_events)`, excluding `chain_seq` and
`chain_hash`.
**Test scenarios:**
- A hash computed with a fixed key and row equals a value pinned from the current implementation (R4).
- The table columns, less the two chain columns, equal `AUDIT_CHAIN_FIELDS` as a set.
- The existing chain tests still pass.

**Verification:** type-check passes and the pinned-hash test passes.

### U3. Local-mode receipt issuer

**Goal:** local receipts name their issuer, and local verification enforces it.
**Requirements:** R5, R6
**Dependencies:** none
**Files:** `packages/sdk/src/cred.ts`, `packages/sdk/src/identity.ts` (export the did:key encoder if it is not already reachable), `packages/sdk/src/__tests__/subdelegate-local.test.ts`, `CHANGELOG.md`
**Approach:** Derive the issuer from the local receipt public key with the
existing did:key encoder. Mint with it. In local parent-receipt
verification, after the signature check, accept `iss` equal to it. Accept
the legacy value only when `iat` is a number no later than the instance's
construction time. Otherwise refuse with `invalid_parent`.
**Execution note:** Test-first.
**Test scenarios:**
- A minted local receipt has `iss` equal to a `did:key:z6Mk…` that `publicKeyFromDidKey` resolves to the signing key.
- A local sub-delegation from a freshly minted parent succeeds.
- A correctly signed parent with a foreign `iss` is refused.
- A legacy-`iss` parent with an `iat` before construction is accepted; with a later `iat`, or no `iat`, it is refused.

**Verification:** the SDK suite passes and the existing legacy-iss fixtures
are updated or deliberately kept as legacy cases.

---

## Risks & Dependencies

- **Deleted check file.** Someone who can delete `.check` can re-pin a
  passphrase on the next init. Anyone with that access can also read the
  salt and database. The check guards against mistakes, not attackers.
- **Local signing secret changes.** If the local secret changes, the local
  issuer changes with it. Receipts signed under the old key already fail
  the signature check, so nothing new breaks.
- **Branch.** This work lands on `fix/audit-chain-review` together with the
  earlier review fixes (`e2febb1`).

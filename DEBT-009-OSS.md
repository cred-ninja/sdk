# DEBT-009 OSS-Native Delegation Chain

## Status

Proposed design and PR plan for implementing delegation-chain semantics in `cred-oss`
without importing the `cred` app's Postgres delegation graph.

## Why This Exists

`cred` implemented DEBT-009 around app-server SQL state:

- `delegations` table
- `parent_delegation_id`
- server-side parent lookup in Postgres
- explicit `chain_depth` columns

That does not map cleanly to `cred-oss`, which is built around:

- `@credninja/vault` storage and permission ceilings
- signed delegation receipts
- append-only audit events
- `@credninja/server` token issuance

The OSS-native version should preserve the security properties of DEBT-009
without introducing the wrong storage model.

## Existing Primitives

Current OSS code already has the building blocks:

1. Permission ceilings and max delegation depth in
   [packages/vault/src/permissions.ts](/Users/kieran/.openclaw/workspace/cred-oss/packages/vault/src/permissions.ts)
2. Append-only audit with `delegationChain` support in
   [packages/vault/src/audit.ts](/Users/kieran/.openclaw/workspace/cred-oss/packages/vault/src/audit.ts)
3. Signed delegation receipts in
   [packages/sdk/src/identity.ts](/Users/kieran/.openclaw/workspace/cred-oss/packages/sdk/src/identity.ts)
4. Local-mode permission enforcement in
   [packages/sdk/src/cred.ts](/Users/kieran/.openclaw/workspace/cred-oss/packages/sdk/src/cred.ts)
5. Short-lived MCP delegation handles in
   [packages/mcp/src/token-cache.ts](/Users/kieran/.openclaw/workspace/cred-oss/packages/mcp/src/token-cache.ts)
6. Agent-authenticated token access in
   [packages/server/src/server.ts](/Users/kieran/.openclaw/workspace/cred-oss/packages/server/src/server.ts)

## Design Goals

1. Child delegations must be attenuated from a verified parent delegation.
2. Chain depth must be enforced server-side or vault-side, never trusted from caller input.
3. Every hop must be auditable.
4. The lineage artifact must be signed and portable.
5. Local and cloud modes should converge on the same receipt semantics.

## Non-Goals

1. No SQL `delegations` table in OSS.
2. No `parent_delegation_id` foreign-key graph.
3. No trust in caller-supplied parent scopes.
4. No arbitrary caller-supplied `chainDepth`.
5. No feature slice that bypasses existing permission ceilings.

## Core Model

Use a signed receipt chain, not a database graph.

### Delegation Receipt v2

Extend the existing receipt payload with lineage fields:

- `delegationId`
- `chainDepth`
- `parentDelegationId?`
- `parentReceiptHash?`

The parent receipt itself is provided as proof input during sub-delegation,
but only the hash is persisted in the child receipt.

### Delegation Chain Link

Represent lineage as an ordered list of links:

- `delegatorDid`
- `delegateeDid`
- `service`
- `scopesGranted`
- `delegationId`
- `issuedAt`

This shape should be usable in both receipts and audit events.

### Sub-Delegation Request

Sub-delegation requires:

- `parentReceipt`
- `agentDid`
- `service`
- `userId`
- `appClientId`
- optional child `scopes`

The server or local SDK verifies the parent receipt, attenuates scopes,
increments depth, and issues a new signed child receipt.

## Enforcement Rules

For any child delegation:

1. Parent receipt signature must verify.
2. Parent receipt subject must match the delegator identity being used.
3. Service must match the parent receipt service.
4. App and logical user context must match the parent receipt.
5. Child scopes must be a subset of parent granted scopes.
6. Child scopes must still respect the vault permission `allowedScopes`.
7. Parent chain depth plus one must not exceed `maxDelegationDepth`.
8. Revoked or suspended agents fail closed.

## Audit Requirements

Every successful or denied sub-delegation must emit an audit event with:

- `action: 'delegate'` for success, `action: 'deny'` for rejected attempts
- `correlationId`
- `scopesRequested`
- `scopesGranted` when successful
- `delegationChain` with at least parent and child link

Audit remains fail-closed where the configured backend requires it.

## API Shape

Preferred cloud API:

- `POST /api/v1/subdelegate`

Reason:

- keeps root delegation and child delegation semantics separate
- avoids ambiguous optional behavior on `/api/v1/delegate`
- makes review and testing clearer

Request body:

- `parent_receipt`
- `agent_did`
- `service`
- `user_id`
- `appClientId`
- optional `scopes`

Response body:

- normal delegation payload
- `receipt`
- `chain_depth`
- `parent_delegation_id`

## Local Mode Shape

Add `cred.subDelegate()` in the SDK.

Local mode should:

1. Verify the supplied parent receipt locally.
2. Re-check permission ceilings from vault state.
3. Issue a child receipt using the same receipt format as cloud mode.
4. Write an audit event containing the lineage chain.

## Proposed PR Plan

### PR 1: Shared Types

Scope:

- SDK lineage types
- receipt payload v2 type updates
- sub-delegation request/result types

No runtime behavior change.

### PR 2: Shared Validation Helper

Scope:

- vault-native helper to validate parent receipt lineage
- subset attenuation check
- max-depth enforcement

Tests:

- allow valid child delegation
- deny scope widening
- deny depth overflow
- deny service mismatch

### PR 3: SDK Local Mode

Scope:

- implement `cred.subDelegate()` for local mode
- issue child receipts
- write chained audit events

### PR 4: Server Cloud Mode

Scope:

- add `POST /api/v1/subdelegate`
- verify parent receipt server-side
- issue child receipt and return lineage metadata

### PR 5: MCP Integration

Scope:

- optionally preserve receipt lineage in delegation handles
- only add a dedicated MCP tool if there is a concrete agent workflow for it

## Acceptance Criteria

1. A child cannot widen scopes beyond the parent receipt.
2. A child cannot exceed `maxDelegationDepth`.
3. Tampered parent receipts fail verification.
4. Revoked agents cannot receive child delegations.
5. Audit events capture success and deny lineage.
6. Receipt verification logic is shared across local and cloud semantics.

## Test Matrix

1. Root receipt has `chainDepth: 0`
2. Valid child delegation with subset scopes succeeds
3. Scope widening is denied
4. Service mismatch is denied
5. App mismatch is denied
6. User mismatch is denied
7. Depth overflow is denied
8. Revoked agent is denied
9. Tampered parent receipt is denied
10. Audit event stores a two-hop and three-hop chain correctly

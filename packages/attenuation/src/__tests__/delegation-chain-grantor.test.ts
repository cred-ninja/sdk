import { describe, expect, it } from 'vitest';
import { DelegationChainError, validateSubDelegation } from '../delegation-chain.js';
import type { ValidateSubDelegationInput } from '../types.js';

/**
 * Grantor-vs-recipient semantics for `delegatable` / `maxDelegationDepth`.
 *
 * A Permission belongs to one agent. Its `delegatable` and
 * `maxDelegationDepth` describe what THAT agent may do with a delegation it
 * holds: pass it on, and how deep the chain may go when it does. When agent
 * A sub-delegates to agent B, the gate is therefore A's (the grantor's)
 * permission — passed as `grantorPermission`. B's (the recipient's)
 * permission, passed as `permission`, decides only which scopes B may hold
 * (`allowedScopes`); B's own delegatable/depth govern the NEXT hop, when B
 * is the grantor.
 */
function makeInput(overrides: Partial<ValidateSubDelegationInput> = {}): ValidateSubDelegationInput {
  return {
    parent: {
      delegationId: 'del_parent',
      agentDid: 'did:key:z6MkParent',
      service: 'github',
      userId: 'user_123',
      appClientId: 'app_123',
      scopesGranted: ['repo', 'read:user'],
      chainDepth: 0,
    },
    childAgentDid: 'did:key:z6MkChild',
    service: 'github',
    userId: 'user_123',
    appClientId: 'app_123',
    requestedScopes: ['repo'],
    // Recipient (child) permission: scope eligibility only.
    permission: {
      allowedScopes: ['repo', 'read:user'],
      delegatable: true,
      maxDelegationDepth: 2,
    },
    // Grantor (parent) permission: owns the delegatable/depth gate.
    grantorPermission: {
      delegatable: true,
      maxDelegationDepth: 2,
    },
    ...overrides,
  };
}

describe('validateSubDelegation grantor gate', () => {
  it('denies when the GRANTOR permission is not delegatable, even if the recipient is', () => {
    try {
      validateSubDelegation(makeInput({
        grantorPermission: { delegatable: false, maxDelegationDepth: 2 },
      }));
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(DelegationChainError);
      expect((error as DelegationChainError).code).toBe('delegation_not_allowed');
    }
  });

  it('denies when the GRANTOR maxDelegationDepth is 0', () => {
    try {
      validateSubDelegation(makeInput({
        grantorPermission: { delegatable: true, maxDelegationDepth: 0 },
      }));
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(DelegationChainError);
      expect((error as DelegationChainError).code).toBe('depth_exceeded');
    }
  });

  it('allows depth exactly equal to the grantor max (boundary)', () => {
    const result = validateSubDelegation(makeInput({
      grantorPermission: { delegatable: true, maxDelegationDepth: 1 },
    }));
    expect(result.chainDepth).toBe(1);
  });

  it('denies depth one past the grantor max (boundary)', () => {
    const input = makeInput({
      grantorPermission: { delegatable: true, maxDelegationDepth: 1 },
    });
    input.parent.chainDepth = 1; // nextDepth would be 2 > 1
    try {
      validateSubDelegation(input);
      expect.unreachable();
    } catch (error) {
      expect((error as DelegationChainError).code).toBe('depth_exceeded');
    }
  });

  it('does NOT gate on the recipient delegatable/depth when a grantor permission is supplied', () => {
    // The recipient's delegatable=false / depth 0 mean the recipient may not
    // itself sub-delegate further (enforced at the next hop, when it is the
    // grantor). They do not stop it RECEIVING this delegation.
    const result = validateSubDelegation(makeInput({
      permission: { allowedScopes: ['repo', 'read:user'], delegatable: false, maxDelegationDepth: 0 },
      grantorPermission: { delegatable: true, maxDelegationDepth: 2 },
    }));
    expect(result.grantedScopes).toEqual(['repo']);
    expect(result.chainDepth).toBe(1);
  });

  it('still attenuates scopes to the recipient allowedScopes', () => {
    const result = validateSubDelegation(makeInput({
      requestedScopes: ['repo', 'read:user'],
      permission: { allowedScopes: ['repo'], delegatable: true, maxDelegationDepth: 2 },
    }));
    expect(result.grantedScopes).toEqual(['repo']);
  });

  it('still denies scope widening beyond the parent delegation', () => {
    try {
      validateSubDelegation(makeInput({ requestedScopes: ['repo', 'delete_repo'] }));
      expect.unreachable();
    } catch (error) {
      expect((error as DelegationChainError).code).toBe('scope_escalation_denied');
    }
  });

  it('legacy single-permission callers keep the old gate (no grantorPermission supplied)', () => {
    const { grantorPermission: _omit, ...legacy } = makeInput();
    expect(validateSubDelegation(legacy).chainDepth).toBe(1);
    try {
      validateSubDelegation({
        ...legacy,
        permission: { allowedScopes: ['repo'], delegatable: false, maxDelegationDepth: 2 },
      });
      expect.unreachable();
    } catch (error) {
      expect((error as DelegationChainError).code).toBe('delegation_not_allowed');
    }
  });
});

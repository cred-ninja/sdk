import { describe, expect, it } from 'vitest';
import { DelegationChainError, validateSubDelegation } from '../delegation-chain.js';
import type { ValidateSubDelegationInput } from '../types.js';

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
    permission: {
      allowedScopes: ['repo', 'read:user'],
      delegatable: true,
      maxDelegationDepth: 2,
    },
    ...overrides,
  };
}

describe('validateSubDelegation', () => {
  it('allows a child delegation with subset scopes and increments depth', () => {
    const result = validateSubDelegation(makeInput());

    expect(result).toEqual({
      parentDelegationId: 'del_parent',
      chainDepth: 1,
      grantedScopes: ['repo'],
    });
  });

  it('denies scope widening beyond the parent receipt', () => {
    expect(() => validateSubDelegation(makeInput({
      requestedScopes: ['repo', 'delete_repo'],
    }))).toThrowError(DelegationChainError);

    try {
      validateSubDelegation(makeInput({ requestedScopes: ['repo', 'delete_repo'] }));
    } catch (error) {
      expect(error).toBeInstanceOf(DelegationChainError);
      expect((error as DelegationChainError).code).toBe('scope_escalation_denied');
    }
  });

  it('denies service mismatch', () => {
    expect(() => validateSubDelegation(makeInput({
      service: 'google',
    }))).toThrowError(DelegationChainError);
  });

  it('denies app mismatch', () => {
    expect(() => validateSubDelegation(makeInput({
      appClientId: 'app_other',
    }))).toThrowError(DelegationChainError);
  });

  it('denies depth overflow', () => {
    expect(() => validateSubDelegation(makeInput({
      parent: {
        delegationId: 'del_parent',
        agentDid: 'did:key:z6MkParent',
        service: 'github',
        userId: 'user_123',
        appClientId: 'app_123',
        scopesGranted: ['repo'],
        chainDepth: 2,
      },
      permission: {
        allowedScopes: ['repo'],
        delegatable: true,
        maxDelegationDepth: 2,
      },
    }))).toThrowError(DelegationChainError);

    try {
      validateSubDelegation(makeInput({
        parent: {
          delegationId: 'del_parent',
          agentDid: 'did:key:z6MkParent',
          service: 'github',
          userId: 'user_123',
          appClientId: 'app_123',
          scopesGranted: ['repo'],
          chainDepth: 2,
        },
        permission: {
          allowedScopes: ['repo'],
          delegatable: true,
          maxDelegationDepth: 2,
        },
      }));
    } catch (error) {
      expect((error as DelegationChainError).code).toBe('depth_exceeded');
    }
  });

  it('denies non-delegatable permissions', () => {
    expect(() => validateSubDelegation(makeInput({
      permission: {
        allowedScopes: ['repo'],
        delegatable: false,
        maxDelegationDepth: 2,
      },
    }))).toThrowError(DelegationChainError);
  });

  it('denies when attenuation leaves no scopes', () => {
    expect(() => validateSubDelegation(makeInput({
      requestedScopes: ['read:user'],
      permission: {
        allowedScopes: ['repo'],
        delegatable: true,
        maxDelegationDepth: 2,
      },
    }))).toThrowError(DelegationChainError);

    try {
      validateSubDelegation(makeInput({
        requestedScopes: ['read:user'],
        permission: {
          allowedScopes: ['repo'],
          delegatable: true,
          maxDelegationDepth: 2,
        },
      }));
    } catch (error) {
      expect((error as DelegationChainError).code).toBe('no_scopes_granted');
    }
  });
});

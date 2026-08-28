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

// Wildcard scope subsumption. Semantics follow the wire subsumption relation
// in draft-asor-wimse-agent-delegation-chain section 4.2 rule 1. Malformed
// scopes match only themselves and fail closed on any expansion.
import { isValidScope, scopeCovers, scopeCoveredBy } from '../delegation-chain.js';

describe('scopeCovers', () => {
  const cases: Array<[granted: string, requested: string, covered: boolean]> = [
    ['crm.read', 'crm.read', true],
    ['crm.read', 'crm.write', false],
    ['crm.*', 'crm.read', true],
    ['crm.*', 'crm.contacts.read', true],
    ['crm.*', 'crm.contacts.*', true],
    ['crm.*', 'crm.*', true],
    ['crm.*', 'crm', false],
    ['crm.*', 'crm.', false],
    ['crm.*', 'crmx.read', false],
    ['crm.read', 'crm.*', false],
    ['crm.contacts.*', 'crm.*', false],
    ['crm.contacts.*', 'crm.read', false],
    ['mail.send', 'crm.read', false],
    ['*', '*', true],
    ['*', 'crm.read', false],
    ['crm*', 'crm.read', false],
    ['cr*m.read', 'cr*m.read', true],
    ['crm.*', '*', false],
    ['', '', false],
    ['   ', 'crm.read', false],
    ['read:user', 'read:user', true],
    ['read:*', 'read:*', true],
    ['read:*', 'read:other', false],
    ['read:other', 'read:*', false],
    ['https://www.googleapis.com/auth/calendar.readonly', 'https://www.googleapis.com/auth/calendar.readonly', true],
  ];

  for (const [granted, requested, covered] of cases) {
    it(`${JSON.stringify(granted)} ${covered ? 'covers' : 'does not cover'} ${JSON.stringify(requested)}`, () => {
      expect(scopeCovers(granted, requested)).toBe(covered);
    });
  }

  it('isValidScope accepts exact scopes and trailing ".*" only', () => {
    expect(isValidScope('crm.read')).toBe(true);
    expect(isValidScope('crm.*')).toBe(true);
    expect(isValidScope('*')).toBe(false);
    expect(isValidScope('.*')).toBe(false);
    expect(isValidScope('crm*')).toBe(false);
    expect(isValidScope('crm.*.write')).toBe(false);
    expect(isValidScope('')).toBe(false);
    expect(isValidScope(undefined)).toBe(false);
  });

  it('scopeCoveredBy is any-of over the granted list', () => {
    expect(scopeCoveredBy(['mail.send', 'crm.*'], 'crm.read')).toBe(true);
    expect(scopeCoveredBy(['mail.send', 'crm.*'], 'pay.transfer')).toBe(false);
    expect(scopeCoveredBy([], 'crm.read')).toBe(false);
  });
});

describe('validateSubDelegation with wildcard scopes', () => {
  // Mirrors attenu-guard tests/vectors/valid_chain.json hop 1:
  // root {crm.*, mail.send} to child {crm.read}.
  it('accepts narrowing a wildcard grant to a concrete scope', () => {
    const result = validateSubDelegation(makeInput({
      parent: {
        delegationId: 'chain:n0',
        agentDid: 'orchestrator',
        service: 'attenu',
        userId: 'default',
        appClientId: 'local',
        scopesGranted: ['crm.*', 'mail.send'],
        chainDepth: 0,
      },
      childAgentDid: 'summarizer',
      service: 'attenu',
      userId: 'default',
      appClientId: 'local',
      requestedScopes: ['crm.read'],
      permission: { allowedScopes: ['crm.*', 'mail.send'], delegatable: true, maxDelegationDepth: 6 },
    }));
    expect(result.grantedScopes).toEqual(['crm.read']);
    expect(result.chainDepth).toBe(1);
  });

  // Mirrors attenu-guard tests/vectors/reject_widened_scope.json: a child asks
  // for a scope no ancestor wildcard covers.
  it('rejects a scope outside every parent wildcard', () => {
    expect(() => validateSubDelegation(makeInput({
      parent: {
        delegationId: 'chain:n1',
        agentDid: 'summarizer',
        service: 'attenu',
        userId: 'default',
        appClientId: 'local',
        scopesGranted: ['crm.*'],
        chainDepth: 1,
      },
      childAgentDid: 'formatter',
      service: 'attenu',
      userId: 'default',
      appClientId: 'local',
      requestedScopes: ['crm.read', 'pay.transfer'],
      permission: { allowedScopes: ['crm.*', 'pay.transfer'], delegatable: true, maxDelegationDepth: 6 },
    }))).toThrowError(/pay\.transfer/);
  });

  it('never lets a requested wildcard widen a concrete parent grant', () => {
    expect(() => validateSubDelegation(makeInput({
      requestedScopes: ['repo', 'read:*'],
    }))).toThrowError(DelegationChainError);
    try {
      validateSubDelegation(makeInput({ requestedScopes: ['repo', 'read:*'] }));
    } catch (error) {
      expect((error as DelegationChainError).code).toBe('scope_escalation_denied');
    }
  });

  it('treats a malformed requested scope as not covered', () => {
    try {
      validateSubDelegation(makeInput({ requestedScopes: ['repo', '*'] }));
      throw new Error('expected rejection');
    } catch (error) {
      expect((error as DelegationChainError).code).toBe('scope_escalation_denied');
    }
  });

  // Regression: a parent chain holding a legacy literal scope that fails
  // isValidScope must still be renewable. With no requestedScopes the request
  // defaults to the parent's own grant, and a literal matches itself.
  it('carries a legacy literal starred scope through the default-request path', () => {
    const result = validateSubDelegation(makeInput({
      parent: {
        delegationId: 'del_parent',
        agentDid: 'did:key:z6MkParent',
        service: 'github',
        userId: 'user_123',
        appClientId: 'app_123',
        scopesGranted: ['repo', 'read:*'],
        chainDepth: 0,
      },
      requestedScopes: undefined,
      permission: {
        allowedScopes: ['repo', 'read:*'],
        delegatable: true,
        maxDelegationDepth: 2,
      },
    }));
    expect(result.grantedScopes).toEqual(['repo', 'read:*']);
  });
});

import { describe, it, expect } from 'vitest';
import { parseConstraints, constraintsSubsume, constraintTypeOf, DEFAULT_RANK_ORDERINGS, DELEGATION_CONSTRAINT_TYPES } from '../constraints.js';
import { validateSubDelegation, DelegationChainError } from '../delegation-chain.js';
import { verifyDelegationChain, type DelegationChainHop } from '../chain-verify.js';

describe('parseConstraints', () => {
  it('parses undefined as an empty list (legacy receipts)', () => {
    expect(parseConstraints(undefined)).toEqual({ ok: true, constraints: [] });
  });

  it('parses max and rank entries', () => {
    const r = parseConstraints([{ key: 'max_rows', max: 5000 }, { key: 'tier', rank: 2 }]);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.constraints).toHaveLength(2);
  });

  it('fails closed on unknown entry shapes', () => {
    expect(parseConstraints([{ key: 'x', regex: '^a' }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', max: 3, min: 1 }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', max: 3, rank: 1 }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', max: 3, extra: true }]).ok).toBe(false);
    expect(parseConstraints([{ max: 3 }]).ok).toBe(false);
    expect(parseConstraints(['max_rows=3']).ok).toBe(false);
    expect(parseConstraints({ key: 'x', max: 3 }).ok).toBe(false);
  });

  it('rejects non-finite, negative, and non-numeric bounds', () => {
    expect(parseConstraints([{ key: 'x', max: Number.POSITIVE_INFINITY }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', max: Number.NaN }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', max: -1 }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', max: '5' }]).ok).toBe(false);
  });

  it('rejects duplicate keys', () => {
    expect(parseConstraints([{ key: 'x', max: 3 }, { key: 'x', max: 2 }]).ok).toBe(false);
  });
});

describe('constraintsSubsume', () => {
  it('accepts equal and tighter ceilings, and child-only additions', () => {
    const parent = [{ key: 'max_rows', max: 5000 }];
    expect(constraintsSubsume(parent, [{ key: 'max_rows', max: 5000 }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'max_rows', max: 10 }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'max_rows', max: 10 }, { key: 'max_calls', max: 3 }]).ok).toBe(true);
    expect(constraintsSubsume([], [{ key: 'max_calls', max: 3 }]).ok).toBe(true);
  });

  it('rejects loosening (the reject_exceeded_ceiling case)', () => {
    const r = constraintsSubsume([{ key: 'max_rows', max: 5000 }], [{ key: 'max_rows', max: 10000000 }]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.key).toBe('max_rows');
  });

  it('rejects a child that omits a parent ceiling (absent = unbounded)', () => {
    expect(constraintsSubsume([{ key: 'max_rows', max: 5000 }], []).ok).toBe(false);
  });

  it('rejects restating a ceiling under a different comparator', () => {
    expect(constraintsSubsume([{ key: 'tier', rank: 2 }], [{ key: 'tier', max: 1 }]).ok).toBe(false);
  });
});

describe('validateSubDelegation constraints', () => {
  const base = {
    parent: {
      delegationId: 'del_parent',
      agentDid: 'did:key:parent',
      service: 'google',
      userId: 'u1',
      appClientId: 'local',
      scopesGranted: ['crm.read'],
      chainDepth: 0,
      constraints: [{ key: 'max_rows', max: 5000 }],
    },
    childAgentDid: 'did:key:child',
    service: 'google',
    userId: 'u1',
    appClientId: 'local',
    permission: { allowedScopes: ['crm.read'], delegatable: true, maxDelegationDepth: 5 },
  };

  it('inherits parent constraints when none are requested', () => {
    const r = validateSubDelegation({ ...base });
    expect(r.grantedConstraints).toEqual([{ key: 'max_rows', max: 5000 }]);
  });

  it('accepts tighter requested constraints', () => {
    const r = validateSubDelegation({ ...base, requestedConstraints: [{ key: 'max_rows', max: 100 }] });
    expect(r.grantedConstraints).toEqual([{ key: 'max_rows', max: 100 }]);
  });

  it('throws constraint_escalation_denied on loosening', () => {
    try {
      validateSubDelegation({ ...base, requestedConstraints: [{ key: 'max_rows', max: 10000000 }] });
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(DelegationChainError);
      expect((err as DelegationChainError).code).toBe('constraint_escalation_denied');
    }
  });

  it('throws constraint_escalation_denied when a requested list drops a parent ceiling', () => {
    expect(() => validateSubDelegation({ ...base, requestedConstraints: [] }))
      .toThrowError(DelegationChainError);
  });
});

describe('verifyDelegationChain constraints', () => {
  function hop(i: number, extra: Partial<DelegationChainHop> = {}): DelegationChainHop {
    return {
      agentDid: `did:key:a${i}`,
      delegationId: `del_${i}`,
      chainDepth: i,
      scopes: ['crm.read'],
      signatureValid: true,
      ...extra,
    };
  }

  it('accepts a chain whose ceilings only tighten', () => {
    const r = verifyDelegationChain([
      hop(0, { constraints: [{ key: 'max_rows', max: 5000 }] }),
      hop(1, { constraints: [{ key: 'max_rows', max: 100 }] }),
    ], { requireParentHash: false });
    expect(r.ok).toBe(true);
  });

  it('rejects a hop that loosens a ceiling', () => {
    const r = verifyDelegationChain([
      hop(0, { constraints: [{ key: 'max_rows', max: 5000 }] }),
      hop(1, { constraints: [{ key: 'max_rows', max: 10000000 }] }),
    ], { requireParentHash: false });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe('not_narrower');
      expect(r.hop).toBe(1);
    }
  });

  it('rejects a legacy child under a constrained parent (absent = unbounded)', () => {
    const r = verifyDelegationChain([
      hop(0, { constraints: [{ key: 'max_rows', max: 5000 }] }),
      hop(1),
    ], { requireParentHash: false });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('not_narrower');
  });

  it('accepts a fully legacy chain with no ceilings anywhere', () => {
    const r = verifyDelegationChain([hop(0), hop(1)], { requireParentHash: false });
    expect(r.ok).toBe(true);
  });

  it('rejects malformed constraints before evaluating subsumption', () => {
    const r = verifyDelegationChain([
      hop(0, { constraints: [{ key: 'x', regex: '^a' }] }),
      hop(1),
    ], { requireParentHash: false });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe('malformed');
      expect(r.hop).toBe(0);
    }
  });
});

describe('asor-01 section 4.2 constraint types', () => {
  it('registers exactly the six section 10 types', () => {
    expect([...DELEGATION_CONSTRAINT_TYPES]).toEqual(['max', 'min', 'one_of', 'not_one_of', 'prefix', 'rank']);
  });

  it('parses every type and reports it back', () => {
    const r = parseConstraints([
      { key: 'max_rows', max: 5000 },
      { key: 'tenure_years', min: 2 },
      { key: 'region', one_of: ['us', 'eu'] },
      { key: 'table', not_one_of: ['secrets'] },
      { key: 'path', prefix: '/crm/' },
      { key: 'egress', rank: 'any' },
      { key: 'tier', rank: 1 },
    ]);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.constraints.map(constraintTypeOf)).toEqual(['max', 'min', 'one_of', 'not_one_of', 'prefix', 'rank', 'rank']);
    }
  });

  it('rejects malformed values per type', () => {
    expect(parseConstraints([{ key: 'x', min: '2' }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', min: Number.NaN }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', one_of: 'us' }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', one_of: [{ a: 1 }] }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', one_of: ['us', 'us'] }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', one_of: [Number.POSITIVE_INFINITY] }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', not_one_of: null }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', prefix: 7 }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', rank: '' }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', rank: -1 }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', rank: true }]).ok).toBe(false);
  });

  it('allows empty sets (one_of admits nothing, not_one_of excludes nothing)', () => {
    expect(parseConstraints([{ key: 'x', one_of: [] }]).ok).toBe(true);
    expect(parseConstraints([{ key: 'x', not_one_of: [] }]).ok).toBe(true);
  });

  it('keeps 1 and "1" distinct as set members', () => {
    expect(parseConstraints([{ key: 'x', one_of: [1, '1'] }]).ok).toBe(true);
    expect(constraintsSubsume([{ key: 'x', one_of: [1] }], [{ key: 'x', one_of: ['1'] }]).ok).toBe(false);
  });
});

describe('asor-01 section 4.3 subsumption per type', () => {
  it('min: child floor must be at least the parent floor', () => {
    expect(constraintsSubsume([{ key: 't', min: 2 }], [{ key: 't', min: 2 }]).ok).toBe(true);
    expect(constraintsSubsume([{ key: 't', min: 2 }], [{ key: 't', min: 5 }]).ok).toBe(true);
    expect(constraintsSubsume([{ key: 't', min: 2 }], [{ key: 't', min: 1 }]).ok).toBe(false);
  });

  it('one_of: child set must be a subset of the parent set', () => {
    const parent = [{ key: 'region', one_of: ['us', 'eu', 'apac'] }];
    expect(constraintsSubsume(parent, [{ key: 'region', one_of: ['eu'] }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'region', one_of: [] }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'region', one_of: ['us', 'eu', 'apac'] }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'region', one_of: ['eu', 'latam'] }]).ok).toBe(false);
  });

  it('not_one_of: child must exclude everything the parent excludes', () => {
    const parent = [{ key: 'table', not_one_of: ['secrets'] }];
    expect(constraintsSubsume(parent, [{ key: 'table', not_one_of: ['secrets'] }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'table', not_one_of: ['secrets', 'salaries'] }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'table', not_one_of: ['salaries'] }]).ok).toBe(false);
    expect(constraintsSubsume(parent, [{ key: 'table', not_one_of: [] }]).ok).toBe(false);
  });

  it('prefix: child prefix must extend the parent prefix', () => {
    const parent = [{ key: 'path', prefix: '/crm/' }];
    expect(constraintsSubsume(parent, [{ key: 'path', prefix: '/crm/' }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'path', prefix: '/crm/accounts/' }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'path', prefix: '/' }]).ok).toBe(false);
    expect(constraintsSubsume(parent, [{ key: 'path', prefix: '/crmx/' }]).ok).toBe(false);
    expect(constraintsSubsume([{ key: 'path', prefix: '' }], [{ key: 'path', prefix: 'anything' }]).ok).toBe(true);
  });

  it('rank labels: compared through the registered ordering (egress none < internal < any)', () => {
    expect(DEFAULT_RANK_ORDERINGS.egress).toEqual(['none', 'internal', 'any']);
    const parent = [{ key: 'egress', rank: 'any' }];
    expect(constraintsSubsume(parent, [{ key: 'egress', rank: 'none' }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'egress', rank: 'internal' }]).ok).toBe(true);
    expect(constraintsSubsume(parent, [{ key: 'egress', rank: 'any' }]).ok).toBe(true);
    expect(constraintsSubsume([{ key: 'egress', rank: 'none' }], [{ key: 'egress', rank: 'any' }]).ok).toBe(false);
    expect(constraintsSubsume([{ key: 'egress', rank: 'internal' }], [{ key: 'egress', rank: 'any' }]).ok).toBe(false);
  });

  it('rank labels: fail closed without a registered ordering or with an unknown label', () => {
    expect(constraintsSubsume([{ key: 'tier', rank: 'gold' }], [{ key: 'tier', rank: 'silver' }]).ok).toBe(false);
    expect(constraintsSubsume([{ key: 'egress', rank: 'any' }], [{ key: 'egress', rank: 'vpn' }]).ok).toBe(false);
    expect(constraintsSubsume([{ key: 'egress', rank: 'everywhere' }], [{ key: 'egress', rank: 'none' }]).ok).toBe(false);
  });

  it('rank labels: caller-supplied orderings are honored and override defaults per key', () => {
    const rankOrderings = { tier: ['bronze', 'silver', 'gold'], egress: ['none', 'any'] };
    expect(constraintsSubsume([{ key: 'tier', rank: 'gold' }], [{ key: 'tier', rank: 'silver' }], { rankOrderings }).ok).toBe(true);
    expect(constraintsSubsume([{ key: 'tier', rank: 'silver' }], [{ key: 'tier', rank: 'gold' }], { rankOrderings }).ok).toBe(false);
    expect(constraintsSubsume([{ key: 'egress', rank: 'any' }], [{ key: 'egress', rank: 'internal' }], { rankOrderings }).ok).toBe(false);
  });

  it('rank: numeric and label ranks under one key never compare', () => {
    expect(constraintsSubsume([{ key: 'egress', rank: 2 }], [{ key: 'egress', rank: 'none' }]).ok).toBe(false);
    expect(constraintsSubsume([{ key: 'egress', rank: 'any' }], [{ key: 'egress', rank: 0 }]).ok).toBe(false);
  });

  it('verifyDelegationChain accepts the asor interop ceiling pattern and rejects the loosened leaf', () => {
    const hop = (i: number, constraints: unknown): DelegationChainHop => ({
      agentDid: `did:key:a${i}`, delegationId: `del_${i}`, chainDepth: i, scopes: ['crm.read'], signatureValid: true, constraints,
    });
    const valid = verifyDelegationChain([
      hop(0, [{ key: 'egress', rank: 'any' }, { key: 'max_rows', max: 100000 }]),
      hop(1, [{ key: 'egress', rank: 'none' }, { key: 'max_rows', max: 5000 }]),
      hop(2, [{ key: 'egress', rank: 'none' }, { key: 'max_rows', max: 100 }]),
    ], { requireParentHash: false });
    expect(valid.ok).toBe(true);
    const loosened = verifyDelegationChain([
      hop(0, [{ key: 'egress', rank: 'any' }, { key: 'max_rows', max: 100000 }]),
      hop(1, [{ key: 'egress', rank: 'none' }, { key: 'max_rows', max: 5000 }]),
      hop(2, [{ key: 'egress', rank: 'none' }, { key: 'max_rows', max: 10000000 }]),
    ], { requireParentHash: false });
    expect(loosened.ok).toBe(false);
    if (!loosened.ok) {
      expect(loosened.reason).toBe('not_narrower');
      expect(loosened.hop).toBe(2);
    }
  });

  it('verifyDelegationChain passes rankOrderings through', () => {
    const hop = (i: number, constraints: unknown): DelegationChainHop => ({
      agentDid: `did:key:a${i}`, delegationId: `del_${i}`, chainDepth: i, scopes: ['crm.read'], signatureValid: true, constraints,
    });
    const chain = [hop(0, [{ key: 'tier', rank: 'gold' }]), hop(1, [{ key: 'tier', rank: 'silver' }])];
    expect(verifyDelegationChain(chain, { requireParentHash: false }).ok).toBe(false);
    expect(verifyDelegationChain(chain, { requireParentHash: false, rankOrderings: { tier: ['bronze', 'silver', 'gold'] } }).ok).toBe(true);
  });

  it('validateSubDelegation passes rankOrderings through', () => {
    const input = {
      parent: {
        delegationId: 'del_parent', agentDid: 'did:key:parent', service: 'google', userId: 'u1', appClientId: 'local',
        scopesGranted: ['crm.read'], chainDepth: 0, constraints: [{ key: 'tier', rank: 'gold' }],
      },
      childAgentDid: 'did:key:child', service: 'google', userId: 'u1', appClientId: 'local',
      permission: { allowedScopes: ['crm.read'], delegatable: true, maxDelegationDepth: 5 },
      requestedConstraints: [{ key: 'tier', rank: 'silver' }],
    };
    expect(() => validateSubDelegation(input)).toThrowError(DelegationChainError);
    const r = validateSubDelegation({ ...input, rankOrderings: { tier: ['bronze', 'silver', 'gold'] } });
    expect(r.grantedConstraints).toEqual([{ key: 'tier', rank: 'silver' }]);
  });
});

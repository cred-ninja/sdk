import { describe, it, expect } from 'vitest';
import { parseConstraints, constraintsSubsume } from '../constraints.js';
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
    expect(parseConstraints([{ key: 'x', min: 3 }]).ok).toBe(false);
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
      hop(0, { constraints: [{ key: 'x', min: 1 }] }),
      hop(1),
    ], { requireParentHash: false });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe('malformed');
      expect(r.hop).toBe(0);
    }
  });
});

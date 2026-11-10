/**
 * draft-asor-wimse-agent-delegation-chain-02 sections 4.2 and 4.3, the parts
 * that change nothing on the wire for receipts minted before -02:
 * (key, type) uniqueness, closed constraint objects, `rank` with `order`,
 * `max_lifetime` / `max_subtree`, no inference across types, the producer
 * rule for `max`, and the cumulative-constraint helpers the exercise path
 * uses to fail closed.
 */
import { describe, it, expect } from 'vitest';
import {
  parseConstraints,
  constraintsSubsume,
  constraintTypeOf,
  cumulativeConstraints,
  producerConstraintViolations,
  unresolvableRankLabels,
  CUMULATIVE_CONSTRAINT_TYPES,
  CUMULATIVE_CONSTRAINT_UNENFORCEABLE,
  DEFAULT_RUNNING_COUNT_KEYS,
  type DelegationConstraint,
} from '../constraints.js';
import { validateSubDelegation, DelegationChainError } from '../delegation-chain.js';
import { verifyDelegationChain, type DelegationChainHop } from '../chain-verify.js';

function parsed(value: unknown): DelegationConstraint[] {
  const r = parseConstraints(value);
  if (!r.ok) throw new Error(`expected to parse: ${r.message}`);
  return r.constraints;
}

const ORDER = ['none', 'internal', 'any'];

/** The constraint set the -02 interop vectors carry at each hop of valid_chain. */
const CANONICAL = [
  [
    { key: 'egress', order: ORDER, rank: 'any' },
    { key: 'max_calls', max_lifetime: 50 },
    { key: 'max_rows', max: 100000 },
    { key: 'max_spend', max: 500 },
    { key: 'max_spend', max_subtree: 1000 },
  ],
  [
    { key: 'egress', order: ORDER, rank: 'none' },
    { key: 'max_calls', max_lifetime: 10 },
    { key: 'max_rows', max: 5000 },
    { key: 'max_spend', max: 60 },
    { key: 'max_spend', max_subtree: 400 },
  ],
  [
    { key: 'egress', order: ORDER, rank: 'none' },
    { key: 'max_calls', max_lifetime: 2 },
    { key: 'max_rows', max: 100 },
    { key: 'max_spend', max: 10 },
    { key: 'max_spend', max_subtree: 100 },
  ],
];

describe('-02 (key, type) uniqueness', () => {
  it('allows a min and a max on one key and evaluates them independently', () => {
    const p = parsed([{ key: 'tenure_years', max: 30 }, { key: 'tenure_years', min: 1 }]);
    expect(p.map(constraintTypeOf)).toEqual(['max', 'min']);
    const c = parsed([{ key: 'tenure_years', max: 10 }, { key: 'tenure_years', min: 2 }]);
    expect(constraintsSubsume(p, c).ok).toBe(true);
    // Each half is judged on its own: loosening either one fails.
    const looserMax = parsed([{ key: 'tenure_years', max: 31 }, { key: 'tenure_years', min: 2 }]);
    const looserMin = parsed([{ key: 'tenure_years', max: 10 }, { key: 'tenure_years', min: 0 }]);
    expect(constraintsSubsume(p, looserMax).ok).toBe(false);
    expect(constraintsSubsume(p, looserMin).ok).toBe(false);
  });

  it('rejects a repeated (key, type) pair as malformed, rather than choosing one', () => {
    const r = parseConstraints([{ key: 'max_rows', max: 100 }, { key: 'max_rows', max: 50 }]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message).toMatch(/duplicate \(key, type\)/);
    expect(parseConstraints([{ key: 'q', max_lifetime: 1 }, { key: 'q', max_lifetime: 1 }]).ok).toBe(false);
  });

  it('a child that drops one half of a range is not narrower', () => {
    const p = parsed([{ key: 'k', max: 30 }, { key: 'k', min: 1 }]);
    const c = parsed([{ key: 'k', max: 10 }]);
    const r = constraintsSubsume(p, c);
    expect(r.ok).toBe(false);
  });
});

describe('-02 closed constraint objects', () => {
  it('rejects a member the type does not define', () => {
    const r = parseConstraints([{ key: 'max_rows', max: 100, note: 'soft' }]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message).toMatch(/undefined member 'note'/);
  });

  it('rejects order on any type but a label rank', () => {
    expect(parseConstraints([{ key: 'm', max: 1, order: ORDER }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'm', max_lifetime: 1, order: ORDER }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'tier', rank: 2, order: ORDER }]).ok).toBe(false);
  });

  it('still rejects no type and two types', () => {
    expect(parseConstraints([{ key: 'x' }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'x', max: 1, max_lifetime: 1 }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'quota', units: 5, other_units: 2 }]).ok).toBe(false);
  });
});

describe('-02 rank with order', () => {
  it('parses a label with its order and keeps the order', () => {
    const [c] = parsed([{ key: 'egress', rank: 'internal', order: ORDER }]);
    expect(c).toEqual({ key: 'egress', rank: 'internal', order: ORDER });
  });

  it('rejects a label that is not in its order', () => {
    const r = parseConstraints([{ key: 'egress', rank: 'everywhere', order: ORDER }]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message).toMatch(/not in its order/);
  });

  it('rejects a malformed order', () => {
    expect(parseConstraints([{ key: 'e', rank: 'a', order: ['a'] }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'e', rank: 'a', order: ['a', 'a'] }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'e', rank: 'a', order: ['a', ''] }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'e', rank: 'a', order: ['a', 1] }]).ok).toBe(false);
    expect(parseConstraints([{ key: 'e', rank: 'a', order: 'a,b' }]).ok).toBe(false);
  });

  it('reads the ordering from the token, so a key with no registered ordering compares', () => {
    const order = ['low', 'mid', 'high'];
    const p = parsed([{ key: 'sensitivity', rank: 'mid', order }]);
    expect(constraintsSubsume(p, parsed([{ key: 'sensitivity', rank: 'low', order }])).ok).toBe(true);
    expect(constraintsSubsume(p, parsed([{ key: 'sensitivity', rank: 'mid', order }])).ok).toBe(true);
    expect(constraintsSubsume(p, parsed([{ key: 'sensitivity', rank: 'high', order }])).ok).toBe(false);
    expect(unresolvableRankLabels(p)).toEqual([]);
  });

  it('uses the token order even where it disagrees with the registered default', () => {
    // Reversed relative to DEFAULT_RANK_ORDERINGS.egress.
    const reversed = ['any', 'internal', 'none'];
    const p = parsed([{ key: 'egress', rank: 'internal', order: reversed }]);
    expect(constraintsSubsume(p, parsed([{ key: 'egress', rank: 'any', order: reversed }])).ok).toBe(true);
    expect(constraintsSubsume(p, parsed([{ key: 'egress', rank: 'none', order: reversed }])).ok).toBe(false);
  });

  it("a child whose order differs from its parent's is not narrower", () => {
    const p = parsed([{ key: 'egress', rank: 'internal', order: ORDER }]);
    const shorter = parsed([{ key: 'egress', rank: 'none', order: ['none', 'any'] }]);
    const permuted = parsed([{ key: 'egress', rank: 'none', order: ['internal', 'none', 'any'] }]);
    for (const c of [shorter, permuted]) {
      const r = constraintsSubsume(p, c);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.message).toMatch(/order .* differs/);
    }
  });

  it('a label with order never compares with a legacy label without one', () => {
    const withOrder = parsed([{ key: 'egress', rank: 'internal', order: ORDER }]);
    const legacy = parsed([{ key: 'egress', rank: 'none' }]);
    expect(constraintsSubsume(withOrder, legacy).ok).toBe(false);
    expect(constraintsSubsume(legacy, withOrder).ok).toBe(false);
  });

  it('legacy labels without order still resolve through DEFAULT_RANK_ORDERINGS', () => {
    const p = parsed([{ key: 'egress', rank: 'any' }]);
    expect(constraintsSubsume(p, parsed([{ key: 'egress', rank: 'none' }])).ok).toBe(true);
    expect(constraintsSubsume(parsed([{ key: 'egress', rank: 'none' }]), p).ok).toBe(false);
  });
});

describe('-02 max_lifetime and max_subtree', () => {
  it('parse as non-negative finite numbers', () => {
    expect(parsed([{ key: 'max_calls', max_lifetime: 50 }])).toEqual([{ key: 'max_calls', max_lifetime: 50 }]);
    expect(parsed([{ key: 'max_spend', max_subtree: 0 }])).toEqual([{ key: 'max_spend', max_subtree: 0 }]);
    for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY, '5', null]) {
      expect(parseConstraints([{ key: 'k', max_lifetime: bad }]).ok).toBe(false);
      expect(parseConstraints([{ key: 'k', max_subtree: bad }]).ok).toBe(false);
    }
  });

  it('subsume with child no wider than parent', () => {
    for (const type of ['max_lifetime', 'max_subtree'] as const) {
      const p = parsed([{ key: 'k', [type]: 10 }]);
      expect(constraintsSubsume(p, parsed([{ key: 'k', [type]: 10 }])).ok).toBe(true);
      expect(constraintsSubsume(p, parsed([{ key: 'k', [type]: 3 }])).ok).toBe(true);
      const r = constraintsSubsume(p, parsed([{ key: 'k', [type]: 11 }]));
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.message).toMatch(new RegExp(`${type} 10 to 11`));
      expect(constraintsSubsume(p, []).ok).toBe(false);
    }
  });

  it('make no inference across types', () => {
    // A max_lifetime under a parent max on the same key is not narrower,
    // whatever the values, and the reverse holds too.
    const r1 = constraintsSubsume(parsed([{ key: 'max_rows', max: 100 }]), parsed([{ key: 'max_rows', max_lifetime: 1 }]));
    expect(r1.ok).toBe(false);
    if (!r1.ok) expect(r1.message).toMatch(/no inference is made across types/);
    expect(constraintsSubsume(parsed([{ key: 'k', max_lifetime: 100 }]), parsed([{ key: 'k', max: 1 }])).ok).toBe(false);
    expect(constraintsSubsume(parsed([{ key: 'k', max_subtree: 100 }]), parsed([{ key: 'k', max_lifetime: 1 }])).ok).toBe(false);
    expect(constraintsSubsume(parsed([{ key: 'k', max_lifetime: 100 }]), parsed([{ key: 'k', max_subtree: 1 }])).ok).toBe(false);
  });

  it('cumulativeConstraints returns exactly the cumulative entries', () => {
    expect([...CUMULATIVE_CONSTRAINT_TYPES]).toEqual(['max_lifetime', 'max_subtree']);
    const all = parsed(CANONICAL[2]);
    expect(cumulativeConstraints(all)).toEqual([
      { key: 'max_calls', max_lifetime: 2 },
      { key: 'max_spend', max_subtree: 100 },
    ]);
    expect(cumulativeConstraints(parsed([{ key: 'max_rows', max: 1 }, { key: 'egress', rank: 'none' }]))).toEqual([]);
    expect(CUMULATIVE_CONSTRAINT_UNENFORCEABLE).toBe('cumulative_constraint_unenforceable');
  });
});

describe('-02 producer rule: max is per action only', () => {
  it('flags a max on a running-count key', () => {
    expect(DEFAULT_RUNNING_COUNT_KEYS).toContain('max_calls');
    const v = producerConstraintViolations(parsed([{ key: 'max_calls', max: 50 }]));
    expect(v).toHaveLength(1);
    expect(v[0]).toMatch(/max_lifetime or max_subtree/);
  });

  it('accepts the cumulative forms and a per-action max on other keys', () => {
    expect(producerConstraintViolations(parsed([
      { key: 'max_calls', max_lifetime: 50 },
      { key: 'max_calls', max_subtree: 100 },
      { key: 'max_rows', max: 5000 },
    ]))).toEqual([]);
  });

  it('honors caller-supplied running-count keys', () => {
    const c = parsed([{ key: 'requests', max: 10 }]);
    expect(producerConstraintViolations(c)).toEqual([]);
    expect(producerConstraintViolations(c, { runningCountKeys: ['requests'] })).toHaveLength(1);
  });

  it('does not re-judge a ceiling inherited unchanged from the parent', () => {
    const parent = parsed([{ key: 'max_calls', max: 50 }]);
    expect(producerConstraintViolations(parent, { inherited: parent })).toEqual([]);
    // A tightened restatement is minted here, so it is judged.
    expect(producerConstraintViolations(parsed([{ key: 'max_calls', max: 10 }]), { inherited: parent })).toHaveLength(1);
  });
});

describe('-02 chains through the vault verifiers', () => {
  const hops = (constraints: unknown[][]): DelegationChainHop[] => constraints.map((c, i) => ({
    agentDid: `did:key:agent${i}`,
    delegationId: `del_${i}`,
    chainDepth: i,
    scopes: ['crm.read'],
    constraints: c,
    signatureValid: true,
    selfHash: `h${i}`,
    ...(i > 0 ? { parentHash: `h${i - 1}` } : {}),
  }));

  it('verifyDelegationChain accepts the -02 canonical constraint set', () => {
    expect(verifyDelegationChain(hops(CANONICAL)).ok).toBe(true);
  });

  const mutateLeaf = (fn: (leaf: any[]) => any[]) => hops([CANONICAL[0], CANONICAL[1], fn(structuredClone(CANONICAL[2]))]);

  it.each([
    ['widened max_lifetime', (l: any[]) => l.map((c) => (c.key === 'max_calls' ? { ...c, max_lifetime: 1000 } : c)), 'not_narrower'],
    ['widened max_subtree', (l: any[]) => l.map((c) => ('max_subtree' in c ? { ...c, max_subtree: 5000 } : c)), 'not_narrower'],
    ['cross-type for max', (l: any[]) => l.map((c) => (c.key === 'max_rows' ? { key: 'max_rows', max_lifetime: 1 } : c)), 'not_narrower'],
    ['changed rank order', (l: any[]) => l.map((c) => (c.key === 'egress' ? { key: 'egress', rank: 'none', order: ['none', 'any'] } : c)), 'not_narrower'],
    ['rank outside order', (l: any[]) => l.map((c) => (c.key === 'egress' ? { ...c, rank: 'everywhere' } : c)), 'malformed'],
    ['extra member', (l: any[]) => l.map((c) => (c.key === 'max_rows' ? { ...c, note: 'soft' } : c)), 'malformed'],
    ['duplicate (key, type)', (l: any[]) => [...l, { key: 'max_rows', max: 50 }], 'malformed'],
  ])('verifyDelegationChain rejects the leaf with %s', (_name, fn, reason) => {
    const r = verifyDelegationChain(mutateLeaf(fn as (l: any[]) => any[]));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe(reason);
      expect(r.hop).toBe(2);
    }
  });

  it('validateSubDelegation inherits and checks -02 constraints', () => {
    const base = {
      parent: {
        delegationId: 'del_p', agentDid: 'did:key:p', service: 'crm', userId: 'u', appClientId: 'a',
        scopesGranted: ['crm.read'], chainDepth: 0, constraints: parsed(CANONICAL[0]),
      },
      childAgentDid: 'did:key:c', service: 'crm', userId: 'u', appClientId: 'a', requestedScopes: ['crm.read'],
      permission: { allowedScopes: ['crm.read'], delegatable: true, maxDelegationDepth: 3 },
    };
    expect(validateSubDelegation(base).grantedConstraints).toEqual(parsed(CANONICAL[0]));
    expect(validateSubDelegation({ ...base, requestedConstraints: parsed(CANONICAL[1]) }).grantedConstraints)
      .toEqual(parsed(CANONICAL[1]));
    const wider = parsed(CANONICAL[1].map((c) => (c.key === 'max_calls' ? { ...c, max_lifetime: 51 } : c)));
    expect(() => validateSubDelegation({ ...base, requestedConstraints: wider })).toThrow(DelegationChainError);
  });
});

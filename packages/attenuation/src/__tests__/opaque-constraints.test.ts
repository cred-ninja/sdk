import { describe, expect, it } from 'vitest';
import { constraintTypeOf, constraintsSubsume, parseConstraints } from '../constraints.js';
import { verifyDelegationChain } from '../chain-verify.js';

// Opaque constraints retain their wire shape; they are not executable policy.
describe('opaque constraints', () => {
  it('preserves one unknown typed member, including nested JSON values', () => {
    const constraints = [{ key: 'destination', vendor_policy: { z: [null, true, 1, 'x'], a: { b: 2 } } }];
    const parsed = parseConstraints(constraints);
    expect(parsed).toEqual({ ok: true, constraints });
    if (!parsed.ok) throw new Error(parsed.message);
    expect(constraintTypeOf(parsed.constraints[0]!)).toBe('vendor_policy');
  });

  it('rejects duplicate unknown (key, type) pairs without delimiter collisions', () => {
    expect(parseConstraints([{ key: 'x', future: 1 }, { key: 'x', future: 2 }]).ok).toBe(false);
    const distinct = [{ key: 'b\u0000c', a: 1 }, { key: 'c', ['a\u0000b']: 2 }];
    expect(parseConstraints(distinct)).toEqual({ ok: true, constraints: distinct });
  });

  it('rejects malformed known types, metadata and multiple unknown type members', () => {
    for (const constraint of [
      { key: 'x', max: '1' }, { key: 'x', rank: {} },
      { key: 'x', future: 1, note: 'metadata' },
      { key: 'x', future: 1, other_future: 2 },
      { key: 'x', future: 1, max: 1 },
      { key: '', future: 1 }, { future: 1 }, { key: 'x' },
    ]) expect(parseConstraints([constraint]).ok).toBe(false);
    expect(parseConstraints([{ key: 'tier', rank: 'low', order: ['low', 'high'] }]).ok).toBe(true);
  });

  it('rejects nested opaque values without a strict JSON/JCS representation', () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    for (const value of [
      NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '\ud800', undefined,
      1n, Symbol('x'), () => 1, new Date(0), [, 1], cycle,
      { child: undefined }, { ['\ud800']: 1 },
    ]) expect(parseConstraints([{ key: 'x', future: { nested: [value] } }]).ok).toBe(false);
  });

  it('rejects array subclasses before invoking inherited serialization', () => {
    let calls = 0;
    class LossyArray extends Array<number> {
      override map<U>(): U[] { calls++; return []; }
    }
    const result = parseConstraints([{ key: 'x', future: { nested: new LossyArray(1, 2) } }]);
    expect(result.ok).toBe(false);
    expect(calls).toBe(0);
  });

  it('rejects sparse arrays whose holes are disguised by non-index properties', () => {
    const sparse = new Array(1);
    Object.assign(sparse, { extra: true });
    expect(parseConstraints([{ key: 'x', future: { nested: sparse } }]).ok).toBe(false);
  });

  it('preserves prototype-named own keys and rejects an inherited key', () => {
    const constraints = JSON.parse('[{"key":"__proto__","__proto__":{"constructor":{"toString":true}}},{"key":"constructor","toString":null}]');
    const parsed = parseConstraints(constraints);
    expect(parsed).toEqual({ ok: true, constraints });
    if (!parsed.ok) throw new Error(parsed.message);
    expect(parsed.constraints.map(constraintTypeOf)).toEqual(['__proto__', 'toString']);
    expect(parseConstraints([Object.assign(Object.create({ key: 'x' }), { future: 1 })]).ok).toBe(false);
  });

  it('requires whole-constraint JCS equality for inherited unknown types', () => {
    const parent = [{ key: 'x', future: { a: 1, b: { x: true, y: [1, 2] } } }];
    const equivalent = [{ future: { b: { y: [1, 2], x: true }, a: 1 }, key: 'x' }];
    expect(constraintsSubsume(parent, equivalent)).toEqual({ ok: true });
    expect(constraintsSubsume([], parent)).toEqual({ ok: true });
    for (const child of [
      [], [{ key: 'x', future: { a: 1, b: { x: true, y: [2, 1] } } }],
      [{ key: 'x', future: { a: 2, b: { x: true, y: [1, 2] } } }],
      [{ key: 'x', other_future: parent[0]!.future }],
      [{ key: 'other', future: parent[0]!.future }],
    ]) expect(constraintsSubsume(parent, child).ok).toBe(false);
  });

  it('never covers a different tuple through NUL delimiter collisions', () => {
    const parent = [{ key: 'b\u0000c', a: 1 }];
    const child = [{ key: 'c', ['a\u0000b']: 1 }];
    expect(constraintsSubsume(parent, child).ok).toBe(false);
  });

  it('reports changed or dropped unknown native-chain constraints as not_narrower', () => {
    const hop = (chainDepth: number, constraints: unknown[]) => ({
      agentDid: `did:key:agent${chainDepth}`, delegationId: `del_${chainDepth}`,
      chainDepth, scopes: ['crm.read'], signatureValid: true, constraints,
    });
    for (const child of [[], [{ key: 'x', future: 2 }]]) {
      expect(verifyDelegationChain([
        hop(0, [{ key: 'x', future: 1 }]), hop(1, child),
      ], { requireParentHash: false })).toMatchObject({ ok: false, reason: 'not_narrower', hop: 1 });
    }
  });
});

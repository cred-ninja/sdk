/**
 * Delegation constraint ceilings that travel with a receipt.
 *
 * Shape and semantics follow draft-asor-wimse-agent-delegation-chain-01
 * sections 4.2 (constraint vocabulary) and 4.3 (subsumption rules), per the
 * Sep 2 decision recorded in docs/design/delegation-constraints.md (Option A):
 *
 * - A constraint is `{ key, max }` (numeric ceiling) or `{ key, rank }`
 *   (position in an ordered enum, lower = less privileged).
 * - Unknown entry shapes fail closed: a list containing one makes the whole
 *   list malformed, and a malformed list makes its token invalid before any
 *   subsumption is evaluated (asor-01 section 4.2, fail-closed rule).
 * - Subsumption (child within parent): every ceiling in the parent MUST
 *   appear in the child under the same key and comparator, at least as
 *   tight (child.max <= parent.max, child.rank <= parent.rank). A ceiling
 *   absent from the child means the child is unbounded on that dimension
 *   and therefore not narrower. The child MAY add ceilings the parent does
 *   not carry.
 *
 * Everything here is wire-format independent, like the rest of this package:
 * callers hand in plain parsed values.
 */

export interface MaxConstraint {
  key: string;
  max: number;
}

export interface RankConstraint {
  key: string;
  rank: number;
}

export type DelegationConstraint = MaxConstraint | RankConstraint;

export type ConstraintParseResult =
  | { ok: true; constraints: DelegationConstraint[] }
  | { ok: false; message: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Parse an untyped `constraints` value (e.g. straight out of a receipt
 * payload) into a validated list. Fail-closed: any entry that is not exactly
 * a known comparator shape with a non-empty key and a finite non-negative
 * number, or any duplicate key, rejects the whole list. `undefined` parses
 * to an empty list (no ceilings), matching legacy receipts minted before
 * this claim existed.
 */
export function parseConstraints(value: unknown): ConstraintParseResult {
  if (value === undefined) return { ok: true, constraints: [] };
  if (!Array.isArray(value)) {
    return { ok: false, message: 'constraints must be an array' };
  }
  const out: DelegationConstraint[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < value.length; i++) {
    const entry: unknown = value[i];
    if (!isPlainObject(entry)) {
      return { ok: false, message: `constraints[${i}] is not an object` };
    }
    const key = entry.key;
    if (typeof key !== 'string' || key.trim() === '') {
      return { ok: false, message: `constraints[${i}] has no key` };
    }
    if (seen.has(key)) {
      return { ok: false, message: `constraints has duplicate key '${key}'` };
    }
    seen.add(key);
    const hasMax = 'max' in entry;
    const hasRank = 'rank' in entry;
    const extraKeys = Object.keys(entry).filter((k) => k !== 'key' && k !== 'max' && k !== 'rank');
    if (hasMax === hasRank || extraKeys.length > 0) {
      // Neither, both, or an unknown member: an entry type this
      // implementation does not understand. Fail closed.
      return { ok: false, message: `constraints[${i}] ('${key}') is not a known constraint type` };
    }
    const bound = hasMax ? entry.max : entry.rank;
    if (typeof bound !== 'number' || !Number.isFinite(bound) || bound < 0) {
      return { ok: false, message: `constraints[${i}] ('${key}') bound must be a finite non-negative number` };
    }
    out.push(hasMax ? { key, max: bound } : { key, rank: bound });
  }
  return { ok: true, constraints: out };
}

export type ConstraintSubsumptionResult =
  | { ok: true }
  | { ok: false; key: string; message: string };

function boundOf(c: DelegationConstraint): { comparator: 'max' | 'rank'; value: number } {
  return 'max' in c
    ? { comparator: 'max', value: c.max }
    : { comparator: 'rank', value: c.rank };
}

/**
 * Is `child` within `parent`? Both lists must already be validated (use
 * parseConstraints on untrusted input). Every parent ceiling must appear in
 * the child under the same comparator, at least as tight; a parent key the
 * child omits means the child is unbounded there, which is wider, so it
 * fails. Child-only keys are added restrictions and pass.
 */
export function constraintsSubsume(
  parent: readonly DelegationConstraint[],
  child: readonly DelegationConstraint[],
): ConstraintSubsumptionResult {
  const childByKey = new Map(child.map((c) => [c.key, c]));
  for (const p of parent) {
    const c = childByKey.get(p.key);
    if (!c) {
      return {
        ok: false,
        key: p.key,
        message: `Child omits parent ceiling '${p.key}' and would be unbounded on it`,
      };
    }
    const pb = boundOf(p);
    const cb = boundOf(c);
    if (pb.comparator !== cb.comparator) {
      return {
        ok: false,
        key: p.key,
        message: `Child restates '${p.key}' under a different comparator`,
      };
    }
    if (cb.value > pb.value) {
      return {
        ok: false,
        key: p.key,
        message: `Child loosens '${p.key}' from ${pb.value} to ${cb.value}`,
      };
    }
  }
  return { ok: true };
}

/**
 * Delegation constraint ceilings that travel with a receipt.
 *
 * Shape and semantics follow draft-asor-wimse-agent-delegation-chain-01
 * sections 4.2 (constraint vocabulary) and 4.3 (subsumption rules), per the
 * Sep 2 decision recorded in docs/design/delegation-constraints.md (Option A).
 *
 * The six constraint types asor-01 section 4.2 defines (and section 10
 * registers) are all supported. Each entry is `{ key, <type>: <value> }`
 * with exactly one type member:
 *
 * - `max` (number): the constrained quantity MUST NOT exceed it.
 * - `min` (number): the constrained quantity MUST NOT be less than it.
 * - `one_of` (array): the constrained value MUST be a member.
 * - `not_one_of` (array): the constrained value MUST NOT be a member.
 * - `prefix` (string): the constrained value MUST start with it.
 * - `rank` (number or label): position in an ordered enumeration, lower =
 *   less privileged; the value's rank MUST NOT exceed the constraint's.
 *
 * Fail-closed rules (asor-01 section 4.2): an entry that is not exactly one
 * known type with a well-formed value, or a duplicate key, makes the whole
 * list malformed, and a malformed list makes its token invalid before any
 * subsumption is evaluated.
 *
 * Subsumption (child within parent, asor-01 section 4.3 rules 2 and 3):
 * every constraint in the parent MUST appear in the child under the same
 * key and type with an admissible set that is a subset of the parent's:
 * child.max <= parent.max, child.min >= parent.min, child.one_of is a subset
 * of parent.one_of, child.not_one_of is a superset of parent.not_one_of,
 * parent.prefix is a prefix of child.prefix, child.rank <= parent.rank. A
 * constraint absent from the child means the child is unbounded on that
 * dimension and therefore not narrower. The child MAY add constraints the
 * parent does not carry.
 *
 * Rank labels. asor-01 gives `rank` as "ordered enumerations (e.g. egress
 * none < internal < any)" and the published interop vectors carry labels
 * (`{"key": "egress", "rank": "any"}`), but the wire format does not carry
 * the ordering itself. Comparing two labels therefore needs an ordering
 * registered for that key, supplied by the caller via `rankOrderings`
 * (lowest to highest). `DEFAULT_RANK_ORDERINGS` seeds the one ordering the
 * draft names. A label under a key with no registered ordering, or a label
 * not in the ordering, cannot be compared and fails closed. Numeric ranks
 * compare directly and need no ordering. A numeric rank and a label under
 * the same key never compare.
 *
 * Everything here is wire-format independent, like the rest of this package:
 * callers hand in plain parsed values.
 */

export interface MaxConstraint {
  key: string;
  max: number;
}

export interface MinConstraint {
  key: string;
  min: number;
}

/** Member values that one_of / not_one_of sets may hold. */
export type ConstraintSetMember = string | number | boolean;

export interface OneOfConstraint {
  key: string;
  one_of: ConstraintSetMember[];
}

export interface NotOneOfConstraint {
  key: string;
  not_one_of: ConstraintSetMember[];
}

export interface PrefixConstraint {
  key: string;
  prefix: string;
}

export interface RankConstraint {
  key: string;
  rank: number | string;
}

export type DelegationConstraint =
  | MaxConstraint
  | MinConstraint
  | OneOfConstraint
  | NotOneOfConstraint
  | PrefixConstraint
  | RankConstraint;

export type DelegationConstraintType = 'max' | 'min' | 'one_of' | 'not_one_of' | 'prefix' | 'rank';

/** The registered constraint types, in asor-01 section 10 order. */
export const DELEGATION_CONSTRAINT_TYPES: readonly DelegationConstraintType[] =
  ['max', 'min', 'one_of', 'not_one_of', 'prefix', 'rank'];

/**
 * Orderings for rank labels, per constraint key, lowest to highest. A label's
 * rank is its index.
 */
export type RankOrderings = Readonly<Record<string, readonly string[]>>;

/**
 * The one ordering asor-01 section 4.2 names: egress none < internal < any.
 */
export const DEFAULT_RANK_ORDERINGS: RankOrderings = Object.freeze({
  egress: Object.freeze(['none', 'internal', 'any']),
});

export interface ConstraintSubsumptionOptions {
  /**
   * Label orderings for `rank` constraints, keyed by constraint key. Merged
   * over DEFAULT_RANK_ORDERINGS; a caller entry replaces the default for
   * that key.
   */
  rankOrderings?: RankOrderings;
}

export type ConstraintParseResult =
  | { ok: true; constraints: DelegationConstraint[] }
  | { ok: false; message: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

function isBoundNumber(v: unknown): v is number {
  return isFiniteNumber(v) && v >= 0;
}

function isSetMember(v: unknown): v is ConstraintSetMember {
  return typeof v === 'string' || typeof v === 'boolean'
    || (typeof v === 'number' && Number.isFinite(v));
}

/** Identity for set membership: distinguishes 1 from "1" and true from "true". */
function memberId(v: ConstraintSetMember): string {
  return `${typeof v}:${String(v)}`;
}

/**
 * Validate the members of a one_of / not_one_of set. Fail-closed: every
 * member must be a string, boolean, or finite number, with no duplicates.
 * An empty one_of is legal (it admits nothing); an empty not_one_of is
 * legal (it excludes nothing).
 */
function parseSet(value: unknown): { ok: true; members: ConstraintSetMember[] } | { ok: false; reason: string } {
  if (!Array.isArray(value)) return { ok: false, reason: 'must be an array' };
  const seen = new Set<string>();
  const members: ConstraintSetMember[] = [];
  for (const m of value as unknown[]) {
    if (!isSetMember(m)) return { ok: false, reason: 'members must be strings, booleans, or finite numbers' };
    const id = memberId(m);
    if (seen.has(id)) return { ok: false, reason: 'has duplicate members' };
    seen.add(id);
    members.push(m);
  }
  return { ok: true, members };
}

/**
 * Parse an untyped `constraints` value (e.g. straight out of a receipt
 * payload) into a validated list. Fail-closed: any entry that is not exactly
 * one known constraint type with a non-empty key and a well-formed value, or
 * any duplicate key, rejects the whole list. `undefined` parses to an empty
 * list (no ceilings), matching legacy receipts minted before this claim
 * existed.
 *
 * Numeric ceilings (max, numeric rank) must be finite and non-negative. A
 * min is a signed floor and must be finite. Rank labels must be non-empty
 * strings; whether a label is comparable is decided against the registered
 * ordering at subsumption time (constraintsSubsume) or, for an issuer that
 * wants to refuse to mint an uncomparable label, with
 * unresolvableRankLabels.
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

    const members = Object.keys(entry).filter((k) => k !== 'key');
    const typeMembers = members.filter((k): k is DelegationConstraintType =>
      (DELEGATION_CONSTRAINT_TYPES as readonly string[]).includes(k));
    if (typeMembers.length !== 1 || members.length !== 1) {
      // No type, more than one type, or an unregistered member: an entry
      // this implementation does not understand. Fail closed (asor-01 4.2).
      return { ok: false, message: `constraints[${i}] ('${key}') is not a known constraint type` };
    }
    const type = typeMembers[0]!;
    const raw = entry[type];

    switch (type) {
      case 'max': {
        if (!isBoundNumber(raw)) {
          return { ok: false, message: `constraints[${i}] ('${key}') max must be a finite non-negative number` };
        }
        out.push({ key, max: raw });
        break;
      }
      case 'min': {
        if (!isFiniteNumber(raw)) {
          return { ok: false, message: `constraints[${i}] ('${key}') min must be a finite number` };
        }
        out.push({ key, min: raw });
        break;
      }
      case 'one_of':
      case 'not_one_of': {
        const set = parseSet(raw);
        if (!set.ok) {
          return { ok: false, message: `constraints[${i}] ('${key}') ${type} ${set.reason}` };
        }
        out.push(type === 'one_of' ? { key, one_of: set.members } : { key, not_one_of: set.members });
        break;
      }
      case 'prefix': {
        if (typeof raw !== 'string') {
          return { ok: false, message: `constraints[${i}] ('${key}') prefix must be a string` };
        }
        out.push({ key, prefix: raw });
        break;
      }
      case 'rank': {
        if (typeof raw === 'string') {
          if (raw.trim() === '') {
            return { ok: false, message: `constraints[${i}] ('${key}') rank label must be non-empty` };
          }
          out.push({ key, rank: raw });
        } else if (isBoundNumber(raw)) {
          out.push({ key, rank: raw });
        } else {
          return { ok: false, message: `constraints[${i}] ('${key}') rank must be a finite non-negative number or a label` };
        }
        break;
      }
    }
  }
  return { ok: true, constraints: out };
}

export function constraintTypeOf(c: DelegationConstraint): DelegationConstraintType {
  if ('max' in c) return 'max';
  if ('min' in c) return 'min';
  if ('one_of' in c) return 'one_of';
  if ('not_one_of' in c) return 'not_one_of';
  if ('prefix' in c) return 'prefix';
  return 'rank';
}

export type ConstraintSubsumptionResult =
  | { ok: true }
  | { ok: false; key: string; message: string };

type RankResolution =
  | { ok: true; value: number }
  | { ok: false; message: string };

function mergeOrderings(options: ConstraintSubsumptionOptions): RankOrderings {
  return Object.assign(Object.create(null), DEFAULT_RANK_ORDERINGS, options.rankOrderings ?? {});
}

/**
 * Keys of rank-label constraints in `constraints` that cannot be compared
 * under the given orderings (no ordering registered for the key, or the label
 * is not in it). Parsing admits such labels because the wire format does not
 * carry the ordering; an issuer SHOULD refuse to mint them, otherwise every
 * later hop that restates the key fails subsumption (asor-01 section 4.2
 * fail-closed) and the chain is unusable. Numeric ranks never appear here.
 */
export function unresolvableRankLabels(
  constraints: readonly DelegationConstraint[],
  options: ConstraintSubsumptionOptions = {},
): string[] {
  const orderings = mergeOrderings(options);
  const out: string[] = [];
  for (const c of constraints) {
    if (!('rank' in c) || typeof c.rank !== 'string') continue;
    if (!resolveRank(c.key, c.rank, orderings).ok) out.push(c.key);
  }
  return out;
}

function resolveRank(key: string, rank: number | string, orderings: RankOrderings): RankResolution {
  if (typeof rank === 'number') return { ok: true, value: rank };
  // Own-property lookup only: constraint keys come off the wire, and a key
  // like 'constructor' or '__proto__' would otherwise resolve through
  // Object.prototype to something that is not an ordering.
  const ordering = Object.prototype.hasOwnProperty.call(orderings, key) ? orderings[key] : undefined;
  if (!Array.isArray(ordering)) {
    return { ok: false, message: `No rank ordering is registered for '${key}'; label '${rank}' cannot be compared` };
  }
  const idx = ordering.indexOf(rank);
  if (idx < 0) {
    return { ok: false, message: `Rank label '${rank}' is not in the ordering registered for '${key}'` };
  }
  return { ok: true, value: idx };
}

/**
 * Is `child` within `parent`? Both lists must already be validated (use
 * parseConstraints on untrusted input). Every parent constraint must appear
 * in the child under the same type with an admissible set that is a subset
 * of the parent's; a parent key the child omits means the child is unbounded
 * there, which is wider, so it fails. Child-only keys are added restrictions
 * and pass.
 *
 * Rank labels are compared through `options.rankOrderings` merged over
 * DEFAULT_RANK_ORDERINGS; an uncomparable label fails closed.
 */
export function constraintsSubsume(
  parent: readonly DelegationConstraint[],
  child: readonly DelegationConstraint[],
  options: ConstraintSubsumptionOptions = {},
): ConstraintSubsumptionResult {
  const orderings = mergeOrderings(options);
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
    const pt = constraintTypeOf(p);
    const ct = constraintTypeOf(c);
    if (pt !== ct) {
      return {
        ok: false,
        key: p.key,
        message: `Child restates '${p.key}' under a different comparator`,
      };
    }
    const loosened = (detail: string): ConstraintSubsumptionResult =>
      ({ ok: false, key: p.key, message: `Child loosens '${p.key}': ${detail}` });

    switch (pt) {
      case 'max': {
        const pv = (p as MaxConstraint).max;
        const cv = (c as MaxConstraint).max;
        if (cv > pv) return loosened(`max ${pv} to ${cv}`);
        break;
      }
      case 'min': {
        const pv = (p as MinConstraint).min;
        const cv = (c as MinConstraint).min;
        if (cv < pv) return loosened(`min ${pv} to ${cv}`);
        break;
      }
      case 'one_of': {
        const allowed = new Set((p as OneOfConstraint).one_of.map(memberId));
        for (const m of (c as OneOfConstraint).one_of) {
          if (!allowed.has(memberId(m))) return loosened(`one_of admits ${JSON.stringify(m)}, which the parent does not`);
        }
        break;
      }
      case 'not_one_of': {
        const excluded = new Set((c as NotOneOfConstraint).not_one_of.map(memberId));
        for (const m of (p as NotOneOfConstraint).not_one_of) {
          if (!excluded.has(memberId(m))) return loosened(`not_one_of drops ${JSON.stringify(m)}, which the parent excludes`);
        }
        break;
      }
      case 'prefix': {
        const pv = (p as PrefixConstraint).prefix;
        const cv = (c as PrefixConstraint).prefix;
        if (!cv.startsWith(pv)) return loosened(`prefix '${pv}' to '${cv}'`);
        break;
      }
      case 'rank': {
        const pr = (p as RankConstraint).rank;
        const cr = (c as RankConstraint).rank;
        if (typeof pr !== typeof cr) {
          return { ok: false, key: p.key, message: `Rank for '${p.key}' mixes a numeric rank and a label; they cannot be compared` };
        }
        const pres = resolveRank(p.key, pr, orderings);
        if (!pres.ok) return { ok: false, key: p.key, message: pres.message };
        const cres = resolveRank(c.key, cr, orderings);
        if (!cres.ok) return { ok: false, key: p.key, message: cres.message };
        if (cres.value > pres.value) return loosened(`rank ${String(pr)} to ${String(cr)}`);
        break;
      }
    }
  }
  return { ok: true };
}

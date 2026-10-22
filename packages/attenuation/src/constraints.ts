/**
 * Delegation constraint ceilings that travel with a receipt.
 *
 * Shape and semantics follow draft-asor-wimse-agent-delegation-chain-02
 * sections 4.2 (constraint vocabulary) and 4.3 (subsumption rules), per the
 * Sep 2 decision recorded in docs/design/delegation-constraints.md (Option A).
 * -02 keeps the -01 vocabulary and wire shape and adds the parts below that
 * are marked -02.
 *
 * Each entry is a closed object `{ key, <type>: <value> }` with exactly one
 * type member, plus `order` when the type is a label `rank` (-02). Types:
 *
 * - `max` (number): the constrained quantity MUST NOT exceed it.
 * - `min` (number): the constrained quantity MUST NOT be less than it.
 * - `one_of` (array): the constrained value MUST be a member.
 * - `not_one_of` (array): the constrained value MUST NOT be a member.
 * - `prefix` (string): the constrained value MUST start with it.
 * - `rank` (number or label): position in an ordered enumeration, lower =
 *   less privileged; the value's rank MUST NOT exceed the constraint's.
 * - `max_lifetime` (number, -02): the sum of the quantity over every action
 *   under the token MUST NOT exceed it. Cumulative.
 * - `max_subtree` (number, -02): the sum of the quantity over every action
 *   under the token and its descendants MUST NOT exceed it. Cumulative.
 *
 * `max` is per action only (-02 section 4.2). A producer MUST NOT express a
 * cumulative bound with it; see producerConstraintViolations.
 *
 * Fail-closed rules (-02 section 4.2): an entry that is not exactly one
 * known type with a well-formed value, that carries a member its type does
 * not define, or that repeats a (key, type) pair already in the list makes
 * the whole list malformed, and a malformed list makes its token invalid
 * before any subsumption is evaluated. Two entries with the same key and
 * different types (a `min` and a `max` forming a range) are allowed and are
 * evaluated independently.
 *
 * Subsumption (child within parent, -02 section 4.3 rules 2 and 3): every
 * constraint (key, type) in the parent MUST appear in the child under the
 * same key AND the same type with an admissible set that is a subset of the
 * parent's: child.max <= parent.max (likewise max_lifetime, max_subtree),
 * child.min >= parent.min, child.one_of is a subset of parent.one_of,
 * child.not_one_of is a superset of parent.not_one_of, parent.prefix is a
 * prefix of child.prefix, child.rank <= parent.rank. No inference is made
 * across types: a `max_lifetime` in the child does not satisfy a `max` in
 * the parent. A constraint absent from the child means the child is
 * unbounded on that dimension and therefore not narrower. The child MAY add
 * constraints the parent does not carry.
 *
 * Rank labels. -02 puts the ordering on the wire: a label `rank` carries an
 * `order` array, least to most permissive, of two or more distinct strings,
 * and the label MUST be a member of it. A child's `order` MUST equal its
 * parent's for the same key, element for element; otherwise the child is
 * not narrower. -02 treats a label `rank` without `order` as malformed.
 * Cred does not, because receipts minted under -01 carry bare labels: a
 * label without `order` still parses, and is compared through an ordering
 * registered for its key (`DEFAULT_RANK_ORDERINGS` plus the caller's
 * `rankOrderings`), failing closed when there is none. Numeric ranks
 * compare directly, never carry `order`, and never compare with a label.
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
  /**
   * The enumeration, least to most permissive (-02 section 4.2). Only on a
   * label rank. Absent on legacy (-01) label ranks, which resolve through a
   * registered ordering instead.
   */
  order?: string[];
}

/** -02: a per-token-lifetime cumulative bound. */
export interface MaxLifetimeConstraint {
  key: string;
  max_lifetime: number;
}

/** -02: a per-subtree cumulative bound. */
export interface MaxSubtreeConstraint {
  key: string;
  max_subtree: number;
}

export type DelegationConstraint =
  | MaxConstraint
  | MinConstraint
  | OneOfConstraint
  | NotOneOfConstraint
  | PrefixConstraint
  | RankConstraint
  | MaxLifetimeConstraint
  | MaxSubtreeConstraint;

export type DelegationConstraintType =
  | 'max' | 'min' | 'one_of' | 'not_one_of' | 'prefix' | 'rank' | 'max_lifetime' | 'max_subtree';

/** The registered constraint types: the asor-01 section 10 six, then the two -02 adds. */
export const DELEGATION_CONSTRAINT_TYPES: readonly DelegationConstraintType[] =
  ['max', 'min', 'one_of', 'not_one_of', 'prefix', 'rank', 'max_lifetime', 'max_subtree'];

/**
 * Types whose bound is a running total, checked only where that total is
 * held (-02 section 6, step 8). Everything else is decided per action.
 */
export const CUMULATIVE_CONSTRAINT_TYPES: readonly DelegationConstraintType[] = ['max_lifetime', 'max_subtree'];

/**
 * Members a constraint object may carry besides `key` and its type member.
 * The object is closed (-02 section 4.2): anything else is malformed.
 */
const EXTRA_MEMBERS: Readonly<Record<DelegationConstraintType, readonly string[]>> = Object.freeze({
  max: [], min: [], one_of: [], not_one_of: [], prefix: [], rank: ['order'], max_lifetime: [], max_subtree: [],
});

/**
 * Keys that name a quantity existing only as a running count. A per-action
 * `max` on one bounds nothing, since each action contributes one, so a
 * producer refuses to mint it and uses `max_lifetime` or `max_subtree`
 * (-02 section 4.2). The draft reserves no key names; this is Cred's list.
 */
export const DEFAULT_RUNNING_COUNT_KEYS: readonly string[] = Object.freeze(['max_calls']);

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

    const members = Object.keys(entry).filter((k) => k !== 'key');
    const typeMembers = members.filter((k): k is DelegationConstraintType =>
      (DELEGATION_CONSTRAINT_TYPES as readonly string[]).includes(k));
    if (typeMembers.length !== 1) {
      // No type, or more than one type: an entry this implementation does
      // not understand. Fail closed (-02 section 4.2).
      return { ok: false, message: `constraints[${i}] ('${key}') is not a known constraint type` };
    }
    const type = typeMembers[0]!;
    const extra = members.filter((k) => k !== type && !EXTRA_MEMBERS[type].includes(k));
    if (extra.length > 0) {
      // Closed object (-02 section 4.2): a member the type does not define.
      return { ok: false, message: `constraints[${i}] ('${key}') ${type} carries undefined member '${extra[0]}'` };
    }
    // Uniqueness is per (key, type), not per key (-02 section 4.2): a min and
    // a max on one key form a range; two maxes on one key are malformed.
    const id = `${type}\u0000${key}`;
    if (seen.has(id)) {
      return { ok: false, message: `constraints has duplicate (key, type) ('${key}', ${type})` };
    }
    seen.add(id);
    const raw = entry[type];

    switch (type) {
      case 'max':
      case 'max_lifetime':
      case 'max_subtree': {
        if (!isBoundNumber(raw)) {
          return { ok: false, message: `constraints[${i}] ('${key}') ${type} must be a finite non-negative number` };
        }
        out.push(type === 'max' ? { key, max: raw }
          : type === 'max_lifetime' ? { key, max_lifetime: raw }
            : { key, max_subtree: raw });
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
        const hasOrder = Object.prototype.hasOwnProperty.call(entry, 'order');
        if (typeof raw === 'string') {
          if (raw.trim() === '') {
            return { ok: false, message: `constraints[${i}] ('${key}') rank label must be non-empty` };
          }
          if (!hasOrder) {
            // Legacy (-01) label: resolved through a registered ordering at
            // subsumption time. -02 calls this malformed; Cred keeps it so
            // receipts minted before -02 still verify.
            out.push({ key, rank: raw });
            break;
          }
          const order = parseOrder(entry.order);
          if (!order.ok) {
            return { ok: false, message: `constraints[${i}] ('${key}') rank order ${order.reason}` };
          }
          if (!order.members.includes(raw)) {
            return { ok: false, message: `constraints[${i}] ('${key}') rank label '${raw}' is not in its order` };
          }
          out.push({ key, rank: raw, order: order.members });
        } else if (isBoundNumber(raw)) {
          if (hasOrder) {
            return { ok: false, message: `constraints[${i}] ('${key}') a numeric rank carries no order` };
          }
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

/**
 * Validate a rank `order`: an array of two or more distinct non-empty
 * strings (-02 section 4.2).
 */
function parseOrder(value: unknown): { ok: true; members: string[] } | { ok: false; reason: string } {
  if (!Array.isArray(value)) return { ok: false, reason: 'must be an array' };
  if (value.length < 2) return { ok: false, reason: 'must list at least two labels' };
  const seen = new Set<string>();
  for (const m of value as unknown[]) {
    if (typeof m !== 'string' || m.trim() === '') return { ok: false, reason: 'members must be non-empty strings' };
    if (seen.has(m)) return { ok: false, reason: 'has duplicate labels' };
    seen.add(m);
  }
  return { ok: true, members: [...(value as string[])] };
}

export function constraintTypeOf(c: DelegationConstraint): DelegationConstraintType {
  if ('max_lifetime' in c) return 'max_lifetime';
  if ('max_subtree' in c) return 'max_subtree';
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
    // A label carrying its own order was checked against it at parse time.
    if (c.order) continue;
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
 * in the child under the same key and the same type with an admissible set
 * that is a subset of the parent's; a parent (key, type) the child omits
 * means the child is unbounded there, which is wider, so it fails. No
 * inference across types. Child-only constraints are added restrictions and
 * pass.
 *
 * Rank labels with `order` compare through that order, and the child's
 * `order` must equal the parent's. Labels without `order` (legacy) compare
 * through `options.rankOrderings` merged over DEFAULT_RANK_ORDERINGS; an
 * uncomparable label fails closed. A label with `order` never compares with
 * one without.
 */
export function constraintsSubsume(
  parent: readonly DelegationConstraint[],
  child: readonly DelegationConstraint[],
  options: ConstraintSubsumptionOptions = {},
): ConstraintSubsumptionResult {
  const orderings = mergeOrderings(options);
  const childById = new Map(child.map((c) => [`${constraintTypeOf(c)}\u0000${c.key}`, c]));
  const childTypesByKey = new Map<string, DelegationConstraintType[]>();
  for (const c of child) childTypesByKey.set(c.key, [...(childTypesByKey.get(c.key) ?? []), constraintTypeOf(c)]);
  for (const p of parent) {
    const pt = constraintTypeOf(p);
    const c = childById.get(`${pt}\u0000${p.key}`);
    if (!c) {
      const others = childTypesByKey.get(p.key);
      if (others && others.length > 0) {
        return {
          ok: false,
          key: p.key,
          message: `Child restates '${p.key}' as ${others.join(', ')} but not as ${pt}; no inference is made across types`,
        };
      }
      return {
        ok: false,
        key: p.key,
        message: `Child omits parent ceiling '${p.key}' (${pt}) and would be unbounded on it`,
      };
    }
    const loosened = (detail: string): ConstraintSubsumptionResult =>
      ({ ok: false, key: p.key, message: `Child loosens '${p.key}': ${detail}` });

    switch (pt) {
      case 'max':
      case 'max_lifetime':
      case 'max_subtree': {
        const pv = boundOf(p);
        const cv = boundOf(c);
        if (cv > pv) return loosened(`${pt} ${pv} to ${cv}`);
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
        const pr = p as RankConstraint;
        const cr = c as RankConstraint;
        if (typeof pr.rank !== typeof cr.rank) {
          return { ok: false, key: p.key, message: `Rank for '${p.key}' mixes a numeric rank and a label; they cannot be compared` };
        }
        if (pr.order || cr.order) {
          // -02 section 4.3: the child's order is the parent's, element for
          // element, or the child is not narrower.
          if (!pr.order || !cr.order || pr.order.length !== cr.order.length
            || pr.order.some((label, idx) => label !== cr.order![idx])) {
            return { ok: false, key: p.key, message: `Rank order for '${p.key}' differs from the parent's` };
          }
          const pi = pr.order.indexOf(pr.rank as string);
          const ci = cr.order.indexOf(cr.rank as string);
          if (ci > pi) return loosened(`rank ${String(pr.rank)} to ${String(cr.rank)}`);
          break;
        }
        const pres = resolveRank(p.key, pr.rank, orderings);
        if (!pres.ok) return { ok: false, key: p.key, message: pres.message };
        const cres = resolveRank(c.key, cr.rank, orderings);
        if (!cres.ok) return { ok: false, key: p.key, message: cres.message };
        if (cres.value > pres.value) return loosened(`rank ${String(pr.rank)} to ${String(cr.rank)}`);
        break;
      }
    }
  }
  return { ok: true };
}

/** The numeric value of a max, max_lifetime or max_subtree constraint. */
function boundOf(c: DelegationConstraint): number {
  if ('max_lifetime' in c) return c.max_lifetime;
  if ('max_subtree' in c) return c.max_subtree;
  return (c as MaxConstraint).max;
}

/**
 * The cumulative constraints (`max_lifetime`, `max_subtree`) in a validated
 * list. -02 section 6 step 8: an action under any of these is permitted only
 * where the running total it is measured over is held. Cred has no
 * running-total store yet, so every caller that authorizes an action MUST
 * deny when this is non-empty (see CUMULATIVE_CONSTRAINT_UNENFORCEABLE).
 */
export function cumulativeConstraints(constraints: readonly DelegationConstraint[]): DelegationConstraint[] {
  return constraints.filter((c) => (CUMULATIVE_CONSTRAINT_TYPES as readonly string[]).includes(constraintTypeOf(c)));
}

/**
 * Reason code for an action denied because it falls under a cumulative
 * constraint and no component holds the running total. Distinct from a
 * ceiling being exceeded: the bound was never evaluated.
 */
export const CUMULATIVE_CONSTRAINT_UNENFORCEABLE = 'cumulative_constraint_unenforceable';

export interface ProducerConstraintOptions {
  /** Keys naming a running count. Defaults to DEFAULT_RUNNING_COUNT_KEYS. */
  runningCountKeys?: readonly string[];
  /**
   * The parent's constraints when minting a child. A constraint the child
   * carries unchanged from its parent (same key, type and value) is
   * inherited, not produced here, and is not re-judged, so a chain under a
   * receipt minted before this rule keeps working.
   */
  inherited?: readonly DelegationConstraint[];
}

/**
 * Producer rule (-02 section 4.2): `max` is per action only, so an issuer
 * MUST NOT express a cumulative bound with it. Returns a message per
 * constraint the issuer is about to mint that breaks the rule: a `max` on a
 * key that names a running count. Empty means the list is fine to mint.
 */
export function producerConstraintViolations(
  constraints: readonly DelegationConstraint[],
  options: ProducerConstraintOptions = {},
): string[] {
  const countKeys = options.runningCountKeys ?? DEFAULT_RUNNING_COUNT_KEYS;
  const inherited = new Set((options.inherited ?? []).map((c) => JSON.stringify([constraintTypeOf(c), c.key, c])));
  const out: string[] = [];
  for (const c of constraints) {
    if (constraintTypeOf(c) !== 'max' || !countKeys.includes(c.key)) continue;
    if (inherited.has(JSON.stringify(['max', c.key, c]))) continue;
    out.push(`'${c.key}' is a running count; a per-action max bounds nothing. Use max_lifetime or max_subtree`);
  }
  return out;
}

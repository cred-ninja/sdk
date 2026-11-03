/**
 * @credninja/guard — Patch: minimal, classified edits to a snapshot
 *
 * A patch is a list of JSON Pointer ops against a snapshot. `applyPatch`
 * is pure and all-or-nothing. `classifyPatch` says, per op, whether the edit
 * widens or narrows what the guard lets through, using the semantics of each
 * built-in kind; anything it cannot place is `unknown`, which callers should
 * treat as widening. `diffSnapshots` recovers the minimal patch between two
 * snapshots, so a reviewer sees leaves, not documents. Nothing here touches
 * a running guard.
 */

import type { ParameterValue } from '../types.js';
import { canonicalJson, finalizeSnapshot } from './snapshot.js';
import {
  countLeaves,
  escapePointerSegment,
  getAtPointer,
  isPlainObject,
  joinPointer,
  parsePointer,
  cloneParameters,
} from './params.js';
import type {
  ClassifiedOp,
  NewPolicyValue,
  OpEffect,
  PatchClassification,
  PatchOp,
  PolicyEntry,
  PolicyPatch,
  PolicySnapshot,
} from './types.js';

const ON_ERROR_VALUES = new Set(['deny', 'allow', 'log-and-deny']);

export class PatchError extends Error {
  constructor(
    message: string,
    readonly opIndex: number,
  ) {
    super(`patch op ${opIndex}: ${message}`);
    this.name = 'PatchError';
  }
}

/** Where an op's path lands. */
interface Target {
  kind: 'onError' | 'policy' | 'parameter';
  policyName?: string;
  /** JSON pointer relative to the policy's parameters (parameter targets). */
  relative?: string;
}

function resolveTarget(path: string, index: number): Target {
  let segments: string[];
  try {
    segments = parsePointer(path);
  } catch (error) {
    throw new PatchError(error instanceof Error ? error.message : String(error), index);
  }
  if (segments.length === 0) throw new PatchError('the root cannot be patched', index);
  if (segments[0] === 'onError') {
    if (segments.length !== 1) throw new PatchError('/onError has no children', index);
    return { kind: 'onError' };
  }
  if (segments.length === 1) return { kind: 'policy', policyName: segments[0] };
  return { kind: 'parameter', policyName: segments[0], relative: joinPointer(segments.slice(1)) };
}

function isNewPolicyValue(value: unknown): value is NewPolicyValue {
  return isPlainObject(value) && typeof value.kind === 'string' && isPlainObject(value.parameters);
}

/** Apply `patch` to `snapshot`, returning a new snapshot. Throws PatchError. */
export function applyPatch(snapshot: PolicySnapshot, patch: PolicyPatch, now: Date = new Date()): PolicySnapshot {
  if (!Array.isArray(patch)) throw new PatchError('patch must be an array of ops', 0);
  let onError = snapshot.onError;
  let policies: PolicyEntry[] = snapshot.policies.map((entry) => ({
    name: entry.name,
    descriptor: {
      ...entry.descriptor,
      parameters: cloneParameters(entry.descriptor.parameters) as Record<string, ParameterValue>,
    },
  }));

  patch.forEach((op, index) => {
    if (!op || typeof op !== 'object') throw new PatchError('op must be an object', index);
    if (!['add', 'remove', 'replace'].includes(op.op)) throw new PatchError(`unsupported op "${String(op.op)}"`, index);
    if (typeof op.path !== 'string') throw new PatchError('path must be a string', index);
    if (op.op !== 'remove' && op.value === undefined) throw new PatchError(`${op.op} needs a value`, index);

    const target = resolveTarget(op.path, index);

    if (target.kind === 'onError') {
      if (op.op !== 'replace') throw new PatchError('/onError can only be replaced', index);
      if (typeof op.value !== 'string' || !ON_ERROR_VALUES.has(op.value)) {
        throw new PatchError('/onError must be "deny", "allow" or "log-and-deny"', index);
      }
      onError = op.value as PolicySnapshot['onError'];
      return;
    }

    const position = policies.findIndex((entry) => entry.name === target.policyName);

    if (target.kind === 'policy') {
      if (op.op === 'remove') {
        if (position === -1) throw new PatchError(`no policy named "${target.policyName}"`, index);
        policies = policies.filter((_, i) => i !== position);
        return;
      }
      if (!isNewPolicyValue(op.value)) {
        throw new PatchError(`a policy value must be { kind, parameters }`, index);
      }
      const entry: PolicyEntry = {
        name: target.policyName!,
        descriptor: { kind: op.value.kind, parameters: cloneParameters(op.value.parameters) as Record<string, ParameterValue> },
      };
      if (op.op === 'add') {
        if (position !== -1) throw new PatchError(`policy "${target.policyName}" already exists; use replace`, index);
        policies = [...policies, entry];
      } else {
        if (position === -1) throw new PatchError(`no policy named "${target.policyName}"`, index);
        policies = policies.map((existing, i) => (i === position ? entry : existing));
      }
      return;
    }

    // parameter
    if (position === -1) throw new PatchError(`no policy named "${target.policyName}"`, index);
    const entry = policies[position];
    if (entry.descriptor.kind === 'opaque') {
      throw new PatchError(`policy "${entry.name}" is opaque; its parameters cannot be patched`, index);
    }
    if (entry.descriptor.opaquePaths?.some((opaque) => target.relative === opaque || target.relative!.startsWith(opaque + '/'))) {
      throw new PatchError(`${op.path} is an opaque value kept by reference and cannot be patched`, index);
    }
    try {
      entry.descriptor.parameters = editTree(entry.descriptor.parameters, target.relative!, op) as Record<string, ParameterValue>;
    } catch (error) {
      throw new PatchError(error instanceof Error ? error.message : String(error), index);
    }
  });

  return finalizeSnapshot({ version: 1, onError, policies }, now);
}

/** RFC 6902-style edit of a JSON tree at a pointer. Returns a new tree. */
function editTree(root: ParameterValue, pointer: string, op: PatchOp): ParameterValue {
  const segments = parsePointer(pointer);
  if (segments.length === 0) {
    if (op.op !== 'replace') throw new Error('the parameters root can only be replaced');
    return cloneParameters(op.value);
  }
  const parentPointer = joinPointer(segments.slice(0, -1));
  const key = segments[segments.length - 1];
  const parent = getAtPointer(root, parentPointer);
  if (parent === undefined) throw new Error(`no value at ${parentPointer || '/'}`);

  let newParent: ParameterValue;
  if (Array.isArray(parent)) {
    const items = [...parent];
    const index = key === '-' ? items.length : Number(key);
    if (!Number.isInteger(index) || index < 0) throw new Error(`"${key}" is not an array index`);
    if (op.op === 'add') {
      if (index > items.length) throw new Error(`index ${index} is past the end of the array`);
      items.splice(index, 0, cloneParameters(op.value));
    } else if (op.op === 'remove') {
      if (index >= items.length) throw new Error(`index ${index} does not exist`);
      items.splice(index, 1);
    } else {
      if (index >= items.length) throw new Error(`index ${index} does not exist`);
      items[index] = cloneParameters(op.value);
    }
    newParent = items;
  } else if (isPlainObject(parent)) {
    const record: { [key: string]: ParameterValue } = { ...(parent as { [key: string]: ParameterValue }) };
    const exists = Object.prototype.hasOwnProperty.call(record, key);
    if (op.op === 'add') {
      if (exists) throw new Error(`"${key}" already exists; use replace`);
      record[key] = cloneParameters(op.value);
    } else if (op.op === 'remove') {
      if (!exists) throw new Error(`"${key}" does not exist`);
      delete record[key];
    } else {
      if (!exists) throw new Error(`"${key}" does not exist; use add`);
      record[key] = cloneParameters(op.value);
    }
    newParent = record;
  } else {
    throw new Error(`${parentPointer || '/'} is a scalar and has no children`);
  }

  if (segments.length === 1) return newParent;
  return editTree(root, parentPointer, { op: 'replace', path: parentPointer, value: newParent });
}

// ── Diff ──────────────────────────────────────────────────────────────────────

/** The minimal patch that turns `base` into `target`. */
export function diffSnapshots(base: PolicySnapshot, target: PolicySnapshot): PolicyPatch {
  const ops: PolicyPatch = [];
  if (base.onError !== target.onError) ops.push({ op: 'replace', path: '/onError', value: target.onError });

  const baseByName = new Map(base.policies.map((entry) => [entry.name, entry]));
  const targetByName = new Map(target.policies.map((entry) => [entry.name, entry]));

  for (const entry of base.policies) {
    if (!targetByName.has(entry.name)) ops.push({ op: 'remove', path: joinPointer([entry.name]) });
  }
  for (const entry of target.policies) {
    const before = baseByName.get(entry.name);
    const prefix = joinPointer([entry.name]);
    if (!before) {
      ops.push({ op: 'add', path: prefix, value: { kind: entry.descriptor.kind, parameters: entry.descriptor.parameters } });
      continue;
    }
    if (before.descriptor.kind !== entry.descriptor.kind) {
      ops.push({ op: 'replace', path: prefix, value: { kind: entry.descriptor.kind, parameters: entry.descriptor.parameters } });
      continue;
    }
    diffTree(before.descriptor.parameters, entry.descriptor.parameters, prefix, ops);
  }
  return ops;
}

function diffTree(before: ParameterValue, after: ParameterValue, path: string, ops: PolicyPatch): void {
  if (canonicalJson(before) === canonicalJson(after)) return;
  if (isPlainObject(before) && isPlainObject(after)) {
    for (const key of Object.keys(before)) {
      if (!(key in after)) ops.push({ op: 'remove', path: `${path}/${escapePointerSegment(key)}` });
    }
    for (const key of Object.keys(after)) {
      const child = `${path}/${escapePointerSegment(key)}`;
      if (!(key in before)) ops.push({ op: 'add', path: child, value: after[key] });
      else diffTree(before[key], after[key], child, ops);
    }
    return;
  }
  if (Array.isArray(before) && Array.isArray(after)) {
    // Arrays of scalars (scopes, patterns) are compared as sets of members
    // so an added scope is one op. Anything else is replaced whole.
    const scalar = (items: ParameterValue[]) => items.every((item) => item === null || typeof item !== 'object');
    if (scalar(before) && scalar(after)) {
      const afterSet = new Set(after.map((item) => canonicalJson(item)));
      const beforeSet = new Set(before.map((item) => canonicalJson(item)));
      // Removals from the end first so earlier indexes stay valid.
      for (let i = before.length - 1; i >= 0; i -= 1) {
        if (!afterSet.has(canonicalJson(before[i]))) ops.push({ op: 'remove', path: `${path}/${i}` });
      }
      for (const item of after) {
        if (!beforeSet.has(canonicalJson(item))) ops.push({ op: 'add', path: `${path}/-`, value: item });
      }
      return;
    }
  }
  ops.push({ op: 'replace', path, value: after });
}

// ── Classification ────────────────────────────────────────────────────────────

/**
 * Classify a patch against the snapshot it applies to. Each op is placed by
 * the semantics of the policy kind it touches; see `classifyOp`.
 */
export function classifyPatch(base: PolicySnapshot, patch: PolicyPatch): PatchClassification {
  const ops: ClassifiedOp[] = [];
  let current = base;
  patch.forEach((op, index) => {
    const classified = classifyOp(current, op, index);
    ops.push(classified);
    current = applyPatch(current, [op]);
  });
  const touched = ops.reduce((sum, item) => sum + item.touched, 0);
  const total = base.parameterCount;
  const effects = new Set(ops.map((item) => item.effect));
  let effect: PatchClassification['effect'];
  if (ops.length === 0) effect = 'neutral';
  else if (effects.size === 1) effect = ops[0].effect;
  else if (effects.has('widening') || effects.has('unknown')) effect = effects.has('narrowing') ? 'mixed' : 'widening';
  else effect = effects.has('narrowing') ? 'narrowing' : 'neutral';
  return { effect, ops, magnitude: { touched, total, fraction: total === 0 ? 1 : touched / total } };
}

/** Kinds whose presence only ever removes requests (adding one narrows). */
const RESTRICTIVE_KINDS = new Set(['rate-limit', 'scope-filter', 'time-window', 'url-allowlist', 'web-bot-auth', 'receipt-claims']);

function classifyOp(snapshot: PolicySnapshot, op: PatchOp, index: number): ClassifiedOp {
  const target = resolveTarget(op.path, index);
  const before = getAtPointer(patchRootView(snapshot), op.path);
  const after = op.op === 'remove' ? undefined : op.value;
  const touched = Math.max(1, Math.max(before === undefined ? 0 : countLeaves(before), after === undefined ? 0 : countLeaves(after)));

  const result = (effect: OpEffect, rationale: string): ClassifiedOp => ({ op, effect, rationale, touched });

  if (target.kind === 'onError') {
    if (after === 'allow') return result('widening', 'a policy error would let the request through');
    if (before === 'allow') return result('narrowing', 'a policy error now denies the request');
    return result('neutral', 'both dispositions deny on error');
  }

  const entry = snapshot.policies.find((item) => item.name === target.policyName);
  const kind = entry?.descriptor.kind ?? (isNewPolicyValue(op.value) ? op.value.kind : undefined);

  if (target.kind === 'policy') {
    if (op.op === 'remove') return result('widening', `removing policy "${target.policyName}" drops every check it made`);
    if (op.op === 'add') {
      if (kind && RESTRICTIVE_KINDS.has(kind)) return result('narrowing', `adding a ${kind} policy only adds checks`);
      if (kind === 'max-ttl') return result('narrowing', 'a TTL cap only shortens delegations');
      return result('unknown', `policy kind "${kind}" has no known semantics`);
    }
    return result('unknown', `replacing policy "${target.policyName}" whole; review it as a new policy`);
  }

  // parameter edits
  const rel = target.relative!;
  const segments = parsePointer(rel);
  const key = segments[0];
  const added = op.op === 'add';
  const removed = op.op === 'remove';

  switch (kind) {
    case 'scope-filter': {
      if (key === 'allowedScopes') {
        if (segments.length === 2) {
          if (removed) return result('widening', `provider "${segments[1]}" loses its scope list, so scope-filter skips it`);
          if (added) return result('narrowing', `provider "${segments[1]}" gains a scope list where it had none`);
          return compareSets(before, after, result, 'scope');
        }
        if (segments.length === 3) {
          if (added) return result('widening', 'one more scope may be requested');
          if (removed) return result('narrowing', 'one scope may no longer be requested');
          return result('unknown', 'a scope was renamed; review as remove plus add');
        }
        if (segments.length === 1) return result('unknown', 'the whole scope table changed; review per provider');
      }
      if (key === 'narrowInsteadOfDeny') {
        return after === true ? result('widening', 'disallowed scopes are dropped instead of denying the request') : result('narrowing', 'disallowed scopes deny the request');
      }
      break;
    }
    case 'url-allowlist': {
      if (key === 'allowedUrls' || key === 'wildcardSubdomains') {
        if (segments.length === 2) {
          if (removed) return result('widening', `provider "${segments[1]}" loses its URL list; with no patterns left, url-allowlist skips it`);
          if (added) return result('narrowing', `provider "${segments[1]}" gains URL constraints`);
          return compareSets(before, after, result, 'pattern');
        }
        if (segments.length === 3) {
          if (added) return result('widening', 'one more URL pattern is reachable');
          if (removed) return result('narrowing', 'one URL pattern is no longer reachable');
          return result('unknown', 'a URL pattern was rewritten; review as remove plus add');
        }
      }
      break;
    }
    case 'rate-limit': {
      const numeric = (value: unknown) => (typeof value === 'number' ? value : undefined);
      if (key === 'maxRequests' && segments.length === 1) return compareNumbers(numeric(before), numeric(after), 'up', result, 'requests per window');
      if (key === 'windowMs' && segments.length === 1) return compareNumbers(numeric(before), numeric(after), 'down', result, 'window length');
      if (key === 'perProvider') {
        if (segments.length === 3 && segments[2] === 'maxRequests') return compareNumbers(numeric(before), numeric(after), 'up', result, `requests per window for ${segments[1]}`);
        if (segments.length === 3 && segments[2] === 'windowMs') return compareNumbers(numeric(before), numeric(after), 'down', result, `window length for ${segments[1]}`);
        // Adding, removing or replacing an override (or the whole override
        // table): compare, per provider, the limit in force before (the
        // override, else the global limit) with the limit in force after.
        const params = entry?.descriptor.parameters;
        const global = isPlainObject(params) ? { maxRequests: numeric(params.maxRequests), windowMs: numeric(params.windowMs) } : undefined;
        const limitOf = (value: unknown) =>
          isPlainObject(value) ? { maxRequests: numeric(value.maxRequests), windowMs: numeric(value.windowMs) } : global;
        const compareLimit = (provider: string, was: ReturnType<typeof limitOf>, now: ReturnType<typeof limitOf>): [OpEffect, string] => {
          if (!was || !now || was.maxRequests === undefined || now.maxRequests === undefined || was.windowMs === undefined || now.windowMs === undefined) {
            return ['unknown', `the limit for ${provider} cannot be compared with the global limit`];
          }
          const looser = now.maxRequests > was.maxRequests || now.windowMs < was.windowMs;
          const tighter = now.maxRequests < was.maxRequests || now.windowMs > was.windowMs;
          if (looser && tighter) return ['unknown', `the limit for ${provider} is looser in one dimension and tighter in the other`];
          const change = `${provider} goes from ${was.maxRequests}/${was.windowMs}ms to ${now.maxRequests}/${now.windowMs}ms`;
          return looser ? ['widening', change] : tighter ? ['narrowing', change] : ['neutral', `the limit for ${provider} is unchanged`];
        };
        if (segments.length === 2) {
          const [effect, rationale] = compareLimit(segments[1], limitOf(before), limitOf(after));
          return result(effect, rationale);
        }
        if (segments.length === 1) {
          const beforeTable = isPlainObject(before) ? before : {};
          const afterTable = isPlainObject(after) ? after : {};
          const providers = new Set([...Object.keys(beforeTable), ...Object.keys(afterTable)]);
          const effects = new Set<OpEffect>();
          const rationales: string[] = [];
          for (const provider of providers) {
            const [effect, rationale] = compareLimit(provider, limitOf(beforeTable[provider]), limitOf(afterTable[provider]));
            if (effect !== 'neutral') {
              effects.add(effect);
              rationales.push(rationale);
            }
          }
          if (effects.size === 0) return result('neutral', 'no per-provider limit changed');
          if (effects.size === 1) return result([...effects][0], rationales.join('; '));
          return result('unknown', `per-provider limits move in different directions: ${rationales.join('; ')}`);
        }
      }
      break;
    }
    case 'max-ttl': {
      const numeric = (value: unknown) => (typeof value === 'number' ? value : undefined);
      if (key === 'maxTtlSeconds') return compareNumbers(numeric(before), numeric(after), 'up', result, 'TTL ceiling');
      if (key === 'perProvider' && segments.length === 2) {
        if (removed || added) return result('unknown', `the TTL for ${segments[1]} now comes from a different source; compare the two values`);
        return compareNumbers(numeric(before), numeric(after), 'up', result, `TTL ceiling for ${segments[1]}`);
      }
      break;
    }
    case 'time-window': {
      if (key === 'allowedHours' && segments.length === 2) {
        const numeric = (value: unknown) => (typeof value === 'number' ? value : undefined);
        if (segments[1] === 'start') return compareNumbers(numeric(before), numeric(after), 'down', result, 'window start');
        if (segments[1] === 'end') return compareNumbers(numeric(before), numeric(after), 'up', result, 'window end');
      }
      if (key === 'allowedDays') {
        if (segments.length === 1 && removed) return result('widening', 'every weekday is allowed');
        if (segments.length === 1 && added) return result('narrowing', 'only listed weekdays are allowed');
        if (segments.length === 2 && added) return result('widening', 'one more weekday is allowed');
        if (segments.length === 2 && removed) return result('narrowing', 'one weekday is no longer allowed');
      }
      if (key === 'timezone') return result('unknown', 'the window moved to another zone; its hours mean different times');
      break;
    }
    case 'web-bot-auth': {
      if (key === 'requireKeyId') return after === true ? result('narrowing', 'a Web Bot Auth key is now required') : result('widening', 'a Web Bot Auth key is no longer required');
      if (key === 'allowedIdentitySources' || key === 'allowedSignatureAgentPrefixes') {
        if (segments.length === 1 && removed) return result('widening', `every ${key === 'allowedIdentitySources' ? 'identity source' : 'Signature-Agent'} is accepted`);
        if (segments.length === 1 && added) return result('narrowing', 'only the listed values are accepted');
        if (segments.length === 2 && added) return result('widening', 'one more value is accepted');
        if (segments.length === 2 && removed) return result('narrowing', 'one value is no longer accepted');
      }
      break;
    }
    case 'receipt-claims': {
      if (key === 'requiredClaims' || key === 'perProvider') {
        const leaf = key === 'requiredClaims' ? 2 : 3;
        if (segments.length === leaf && added) return result('narrowing', 'one more claim is required');
        if (segments.length === leaf && removed) return result('widening', 'one claim is no longer required');
        if (segments.length === leaf - 1 && removed) return result('widening', 'no claims are required there any more');
        if (segments.length === leaf - 1 && added) return result('narrowing', 'claims are now required there');
      }
      break;
    }
    default:
      break;
  }
  return result('unknown', `no classification rule for ${kind ?? 'this policy'} at ${rel}`);
}

function compareSets(
  before: unknown,
  after: unknown,
  result: (effect: OpEffect, rationale: string) => ClassifiedOp,
  noun: string,
): ClassifiedOp {
  if (!Array.isArray(before) || !Array.isArray(after)) return result('unknown', `the ${noun} list was replaced by something that is not a list`);
  const beforeSet = new Set(before.map((item) => canonicalJson(item)));
  const afterSet = new Set(after.map((item) => canonicalJson(item)));
  const gained = [...afterSet].some((item) => !beforeSet.has(item));
  const lost = [...beforeSet].some((item) => !afterSet.has(item));
  if (gained && lost) return result('unknown', `${noun}s were both added and removed; split the op to review each`);
  if (gained) return result('widening', `more ${noun}s are allowed`);
  if (lost) return result('narrowing', `fewer ${noun}s are allowed`);
  return result('neutral', `the ${noun} list is unchanged`);
}

function compareNumbers(
  before: number | undefined,
  after: number | undefined,
  widensWhen: 'up' | 'down',
  result: (effect: OpEffect, rationale: string) => ClassifiedOp,
  noun: string,
): ClassifiedOp {
  if (before === undefined || after === undefined) return result('unknown', `${noun} was added or removed rather than changed`);
  if (before === after) return result('neutral', `${noun} is unchanged`);
  const widened = widensWhen === 'up' ? after > before : after < before;
  return widened ? result('widening', `${noun} went from ${before} to ${after}`) : result('narrowing', `${noun} went from ${before} to ${after}`);
}

/** A snapshot viewed as the tree patch paths address. */
function patchRootView(snapshot: PolicySnapshot): Record<string, unknown> {
  const view: Record<string, unknown> = { onError: snapshot.onError };
  for (const entry of snapshot.policies) view[entry.name] = entry.descriptor.parameters;
  return view;
}

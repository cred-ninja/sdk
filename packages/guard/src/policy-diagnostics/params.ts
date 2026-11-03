/**
 * @credninja/guard — Parameter tree helpers
 *
 * Small validators and codecs shared by the built-in policies' `describe()`
 * and `withParameters()` implementations and by the policy diagnostics.
 * A policy's parameters are plain JSON so a diff tool, a reviewer or a CI
 * job can read them as data; the helpers here keep that boundary honest by
 * refusing anything that does not round-trip.
 */

import type { ParameterValue } from '../types.js';

/** The serialized form of a RegExp inside a parameter tree. */
export type EncodedRegExp = {
  $regex: string;
  flags: string;
};

/** The marker left in place of a value that cannot be serialized. */
export type OpaqueMarker = {
  $opaque: true;
};

export function encodeRegExp(pattern: RegExp): EncodedRegExp {
  return { $regex: pattern.source, flags: pattern.flags };
}

export function isEncodedRegExp(value: unknown): value is EncodedRegExp {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as EncodedRegExp).$regex === 'string' &&
    typeof (value as EncodedRegExp).flags === 'string'
  );
}

export function decodeRegExp(value: EncodedRegExp): RegExp {
  return new RegExp(value.$regex, value.flags);
}

export const OPAQUE: OpaqueMarker = { $opaque: true };

export function isOpaqueMarker(value: unknown): value is OpaqueMarker {
  return typeof value === 'object' && value !== null && (value as OpaqueMarker).$opaque === true;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

export function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

export function isPositiveInteger(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) > 0;
}

/** Throws unless `value` is a record whose values are all string arrays. */
export function requireStringArrayRecord(value: unknown, label: string): Record<string, string[]> {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  for (const [key, entry] of Object.entries(value)) {
    if (!isStringArray(entry)) throw new Error(`${label}.${key} must be an array of strings`);
  }
  return value as Record<string, string[]>;
}

export function requireOptionalStringArray(value: unknown, label: string): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isStringArray(value)) throw new Error(`${label} must be an array of strings`);
  return value;
}

export function requireOptionalBoolean(value: unknown, label: string): boolean | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'boolean') throw new Error(`${label} must be a boolean`);
  return value;
}

/**
 * Count the leaves of a parameter tree. This is the `parameterCount` a
 * snapshot reports: every scalar, every array element that is a
 * scalar, every encoded RegExp and every opaque marker counts as one.
 */
export function countLeaves(value: unknown): number {
  if (isEncodedRegExp(value) || isOpaqueMarker(value)) return 1;
  if (Array.isArray(value)) {
    return value.length === 0 ? 1 : value.reduce<number>((sum, item) => sum + countLeaves(item), 0);
  }
  if (isPlainObject(value)) {
    const entries = Object.values(value);
    return entries.length === 0 ? 1 : entries.reduce<number>((sum, item) => sum + countLeaves(item), 0);
  }
  return 1;
}

/**
 * Deep-clone a parameter tree, refusing anything that is not JSON data.
 * Functions, symbols, class instances and `undefined` inside arrays are
 * rejected so a descriptor can never carry a value that would not survive
 * the wire.
 */
export function cloneParameters(value: unknown, path = ''): ParameterValue {
  if (value === null) return null;
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`parameter ${path || '/'} must be a finite number`);
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => cloneParameters(item, `${path}/${index}`));
  }
  if (isPlainObject(value)) {
    const out: { [key: string]: ParameterValue } = {};
    for (const [key, entry] of Object.entries(value)) {
      if (entry === undefined) continue;
      out[key] = cloneParameters(entry, `${path}/${escapePointerSegment(key)}`);
    }
    return out;
  }
  throw new Error(`parameter ${path || '/'} is not JSON data (${typeof value})`);
}

// ── JSON Pointer (RFC 6901) ───────────────────────────────────────────────────

export function escapePointerSegment(segment: string): string {
  return segment.replace(/~/g, '~0').replace(/\//g, '~1');
}

export function unescapePointerSegment(segment: string): string {
  return segment.replace(/~1/g, '/').replace(/~0/g, '~');
}

/** Split a JSON pointer into its segments. The empty pointer is the root. */
export function parsePointer(pointer: string): string[] {
  if (pointer === '') return [];
  if (!pointer.startsWith('/')) throw new Error(`invalid JSON pointer "${pointer}": must start with "/"`);
  return pointer.slice(1).split('/').map(unescapePointerSegment);
}

export function joinPointer(segments: string[]): string {
  return segments.length === 0 ? '' : '/' + segments.map(escapePointerSegment).join('/');
}

/** Read the value at `pointer`, or `undefined` when the path does not exist. */
export function getAtPointer(root: unknown, pointer: string): unknown {
  let current: unknown = root;
  for (const segment of parsePointer(pointer)) {
    if (Array.isArray(current)) {
      const index = Number(segment);
      if (!Number.isInteger(index) || index < 0 || index >= current.length) return undefined;
      current = current[index];
    } else if (isPlainObject(current)) {
      if (!Object.prototype.hasOwnProperty.call(current, segment)) return undefined;
      current = current[segment];
    } else {
      return undefined;
    }
  }
  return current;
}

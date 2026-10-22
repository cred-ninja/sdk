/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) serialization.
 *
 * JCS is ECMAScript JSON.stringify for primitives (numbers in their shortest
 * round-trip form, strings with the minimal escapes) and object members
 * sorted by their UTF-16 code units, which is what Array.prototype.sort does
 * with no comparator. Non-finite numbers have no JCS form and throw, as do
 * strings containing a lone surrogate (RFC 8785 Section 3.2.2.2 requires
 * well-formed I-JSON input).
 */

export class CanonicalJsonError extends Error {
  constructor(message: string, public readonly code: 'non_finite' | 'unsupported') {
    super(message);
    this.name = 'CanonicalJsonError';
  }
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new CanonicalJsonError(`non-finite number ${String(value)}`, 'non_finite');
      return JSON.stringify(value);
    case 'string':
      if (LONE_SURROGATE.test(value)) throw new CanonicalJsonError('string contains a lone surrogate', 'unsupported');
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return `{${keys.map((k) => `${canonicalJson(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
    }
    default:
      throw new CanonicalJsonError(`${typeof value} has no JSON form`, 'unsupported');
  }
}

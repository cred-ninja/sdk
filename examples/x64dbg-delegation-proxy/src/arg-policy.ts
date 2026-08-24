/**
 * Argument-level policy.
 *
 * Scope enforcement decides *which* tools a credential may call. Argument policy
 * decides *how much* it may do within a granted tool: bound the size of a read,
 * confine a dump path to a sandbox prefix, restrict a register name, and so on.
 * This closes the "a read scope can read any address / dump anywhere" gap that
 * tool-name scoping alone leaves open.
 *
 * Constraints are declared per tool in the scope map (config/scope-map.json) and
 * are data, not code. Matching is fail-closed: an argument that cannot be
 * evaluated against its declared matcher is a violation.
 */

export interface ArgMatcher {
  /** The argument must be present. */
  required?: boolean;
  /** Value must be one of these (string/number equality). */
  enum?: Array<string | number>;
  /** Numeric upper bound (inclusive). Accepts decimal or 0x-hex strings. */
  max?: number;
  /** Numeric lower bound (inclusive). Accepts decimal or 0x-hex strings. */
  min?: number;
  /** String length upper bound (inclusive). */
  maxLength?: number;
  /** String must start with one of these prefixes (e.g. a sandbox dir). */
  prefixOneOf?: string[];
  /** String must fully match this regex. */
  pattern?: string;
  /** String must NOT match this regex anywhere. */
  denyPattern?: string;
}

export type ArgConstraints = Record<string, ArgMatcher>;

export interface ArgCheckResult {
  ok: boolean;
  violations: string[];
}

function parseNumeric(value: unknown): number | undefined {
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    const n = /^[-+]?0x[0-9a-f]+$/i.test(trimmed) ? Number.parseInt(trimmed, 16) : Number(trimmed);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

function checkOne(name: string, matcher: ArgMatcher, present: boolean, value: unknown): string | null {
  if (!present) {
    return matcher.required ? `missing required argument "${name}"` : null;
  }

  if (matcher.enum && !matcher.enum.some((v) => v === value)) {
    return `argument "${name}"=${JSON.stringify(value)} is not one of [${matcher.enum.join(', ')}]`;
  }

  if (matcher.max !== undefined || matcher.min !== undefined) {
    const n = parseNumeric(value);
    if (n === undefined) return `argument "${name}"=${JSON.stringify(value)} is not numeric`;
    if (matcher.max !== undefined && n > matcher.max) return `argument "${name}"=${n} exceeds max ${matcher.max}`;
    if (matcher.min !== undefined && n < matcher.min) return `argument "${name}"=${n} is below min ${matcher.min}`;
  }

  if (matcher.maxLength !== undefined) {
    const s = String(value);
    if (s.length > matcher.maxLength) return `argument "${name}" length ${s.length} exceeds ${matcher.maxLength}`;
  }

  if (matcher.prefixOneOf) {
    const s = String(value);
    if (!matcher.prefixOneOf.some((p) => s.startsWith(p))) {
      return `argument "${name}"=${JSON.stringify(s)} is not under an allowed prefix [${matcher.prefixOneOf.join(', ')}]`;
    }
  }

  if (matcher.pattern) {
    let re: RegExp;
    try {
      re = new RegExp(`^(?:${matcher.pattern})$`);
    } catch {
      return `argument "${name}" has an invalid pattern in the scope map`;
    }
    if (!re.test(String(value))) return `argument "${name}"=${JSON.stringify(value)} does not match ${matcher.pattern}`;
  }

  if (matcher.denyPattern) {
    let re: RegExp;
    try {
      re = new RegExp(matcher.denyPattern);
    } catch {
      return `argument "${name}" has an invalid denyPattern in the scope map`;
    }
    if (re.test(String(value))) return `argument "${name}"=${JSON.stringify(value)} matches a denied pattern`;
  }

  return null;
}

/**
 * Evaluate a tool call's arguments against the declared constraints.
 * Returns every violation found (empty = allowed).
 */
export function checkArgs(constraints: ArgConstraints | undefined, args: Record<string, unknown>): ArgCheckResult {
  if (!constraints) return { ok: true, violations: [] };
  const violations: string[] = [];
  for (const [name, matcher] of Object.entries(constraints)) {
    const present = Object.prototype.hasOwnProperty.call(args, name) && args[name] !== undefined;
    const violation = checkOne(name, matcher, present, args[name]);
    if (violation) violations.push(violation);
  }
  return { ok: violations.length === 0, violations };
}

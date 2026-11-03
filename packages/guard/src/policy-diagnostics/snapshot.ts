/**
 * @credninja/guard — Snapshot: read a guard's policy chain as data
 *
 * `snapshotGuard()` is the read primitive: it asks each policy to describe
 * itself and hashes the result canonically, so two guards with the same
 * configuration produce the same hash and a patch can name the exact state
 * it was written against. `materializePolicies()` is the inverse: it builds
 * a chain from a snapshot for dry-run replay, reusing every instance whose
 * parameters did not change.
 */

import { createHash } from 'node:crypto';
import type { CredGuard } from '../guard.js';
import type { CredPolicy, ParameterValue, PolicyDescriptor } from '../types.js';
import { MaxTtlPolicy } from '../policies/max-ttl.js';
import { RateLimitPolicy } from '../policies/rate-limit.js';
import { ScopeFilterPolicy } from '../policies/scope-filter.js';
import { TimeWindowPolicy } from '../policies/time-window.js';
import { UrlAllowlistPolicy } from '../policies/url-allowlist.js';
import { parseWebBotAuthParameters, webBotAuthPolicy } from '../policies/web-bot-auth.js';
import { parseReceiptClaimsParameters, receiptClaimsPolicy } from '../policies/receipt-claims.js';
import { cloneParameters, countLeaves, isPlainObject } from './params.js';
import type { PolicyEntry, PolicySnapshot } from './types.js';

export const OPAQUE_KIND = 'opaque';

/**
 * Canonical JSON: object keys sorted recursively, no whitespace. Arrays keep
 * their order, since order is meaningful (policy chain, pattern lists).
 */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
    return '{' + keys.map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
}

export function sha256Hex(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/** The hash of a snapshot's content (everything but `takenAt`, `hash` and the count). */
export function snapshotHash(snapshot: Pick<PolicySnapshot, 'version' | 'onError' | 'policies'>): string {
  return sha256Hex(canonicalJson({ version: snapshot.version, onError: snapshot.onError, policies: snapshot.policies }));
}

export function describePolicy(policy: CredPolicy): PolicyDescriptor {
  if (typeof policy.describe !== 'function') {
    return { kind: OPAQUE_KIND, parameters: {} };
  }
  const descriptor = policy.describe();
  if (!descriptor || typeof descriptor.kind !== 'string' || !isPlainObject(descriptor.parameters)) {
    throw new Error(`policy "${policy.name}" returned an invalid descriptor`);
  }
  return {
    kind: descriptor.kind,
    parameters: cloneParameters(descriptor.parameters) as Record<string, ParameterValue>,
    ...(descriptor.opaquePaths && descriptor.opaquePaths.length > 0 ? { opaquePaths: [...descriptor.opaquePaths] } : {}),
    ...(descriptor.stateful ? { stateful: true } : {}),
  };
}

/** Build a snapshot from policies and an error disposition. */
export function buildSnapshot(
  policies: readonly CredPolicy[],
  onError: PolicySnapshot['onError'],
  now: Date = new Date(),
): PolicySnapshot {
  const entries: PolicyEntry[] = policies.map((policy) => ({ name: policy.name, descriptor: describePolicy(policy) }));
  return finalizeSnapshot({ version: 1, onError, policies: entries }, now);
}

/** Recompute the derived fields of a snapshot whose content changed. */
export function finalizeSnapshot(
  content: Pick<PolicySnapshot, 'version' | 'onError' | 'policies'>,
  now: Date = new Date(),
): PolicySnapshot {
  const parameterCount = content.policies.reduce(
    (sum, entry) => sum + 1 + countLeaves(entry.descriptor.parameters),
    1, // onError
  );
  return {
    version: 1,
    takenAt: now.toISOString(),
    onError: content.onError,
    policies: content.policies,
    parameterCount,
    hash: snapshotHash(content),
  };
}

/** Read a live guard's chain as a snapshot. */
export function snapshotGuard(guard: CredGuard, now: Date = new Date()): PolicySnapshot {
  return buildSnapshot(guard.getPolicies(), guard.getOnError(), now);
}

/** Factories for the built-in kinds, so a patch can add a policy by kind. */
const BUILTIN_FACTORIES: Record<string, (parameters: Record<string, ParameterValue>) => CredPolicy> = {
  'rate-limit': (parameters) => new RateLimitPolicy(RateLimitPolicy.parseParameters(parameters)),
  'scope-filter': (parameters) => new ScopeFilterPolicy(ScopeFilterPolicy.parseParameters(parameters)),
  'time-window': (parameters) => new TimeWindowPolicy(TimeWindowPolicy.parseParameters(parameters)),
  'url-allowlist': (parameters) => new UrlAllowlistPolicy(UrlAllowlistPolicy.parseParameters(parameters)),
  'max-ttl': (parameters) => new MaxTtlPolicy(MaxTtlPolicy.parseParameters(parameters)),
  'web-bot-auth': (parameters) => webBotAuthPolicy(parseWebBotAuthParameters(parameters)),
  'receipt-claims': (parameters) => receiptClaimsPolicy(parseReceiptClaimsParameters(parameters)),
};

export function builtinPolicyKinds(): string[] {
  return Object.keys(BUILTIN_FACTORIES);
}

export interface MaterializeOptions {
  /**
   * The live chain the snapshot was derived from. Entries whose parameters
   * are unchanged reuse their instance; changed entries are rebuilt through
   * the instance's `withParameters`, which carries opaque values over. Needed
   * whenever the chain holds an opaque policy or an opaque value.
   */
  previous?: readonly CredPolicy[];
  /** Extra factories for custom kinds, keyed by kind. */
  factories?: Record<string, (parameters: Record<string, ParameterValue>) => CredPolicy>;
  /** Leave out policies whose descriptor is stateful (for replay). */
  excludeStateful?: boolean;
}

/**
 * Build a policy chain from a snapshot. Throws when an entry cannot be
 * built: an opaque policy with no previous instance, an unknown kind, or
 * parameters its policy rejects.
 */
export function materializePolicies(snapshot: PolicySnapshot, options: MaterializeOptions = {}): CredPolicy[] {
  const previousByName = new Map<string, CredPolicy>();
  for (const policy of options.previous ?? []) previousByName.set(policy.name, policy);
  const factories = { ...BUILTIN_FACTORIES, ...(options.factories ?? {}) };

  const out: CredPolicy[] = [];
  for (const entry of snapshot.policies) {
    if (options.excludeStateful && entry.descriptor.stateful) continue;
    const previous = previousByName.get(entry.name);

    if (entry.descriptor.kind === OPAQUE_KIND) {
      if (!previous) throw new Error(`policy "${entry.name}" is opaque and has no live instance to carry over`);
      out.push(previous);
      continue;
    }

    if (previous) {
      const previousDescriptor = describePolicy(previous);
      const unchanged =
        previousDescriptor.kind === entry.descriptor.kind &&
        canonicalJson(previousDescriptor.parameters) === canonicalJson(entry.descriptor.parameters);
      if (unchanged) {
        out.push(previous);
        continue;
      }
      if (previousDescriptor.kind === entry.descriptor.kind && typeof previous.withParameters === 'function') {
        const rebuilt = previous.withParameters(entry.descriptor.parameters);
        if (rebuilt.name !== entry.name) {
          throw new Error(`policy "${entry.name}" rebuilt under a different name "${rebuilt.name}"`);
        }
        out.push(rebuilt);
        continue;
      }
    }

    const factory = factories[entry.descriptor.kind];
    if (!factory) {
      throw new Error(`policy "${entry.name}": no factory for kind "${entry.descriptor.kind}"`);
    }
    const built = factory(entry.descriptor.parameters);
    if (built.name !== entry.name) {
      // A built-in's name is fixed by its kind. A snapshot may still carry a
      // different name for it (two rate limits in one chain, for example),
      // so wrap it to answer to the entry's name.
      out.push(renamed(built, entry.name));
    } else {
      out.push(built);
    }
  }
  return out;
}

function renamed(policy: CredPolicy, name: string): CredPolicy {
  return {
    name,
    evaluate: (ctx) => {
      const result = policy.evaluate(ctx);
      return result instanceof Promise ? result.then((r) => ({ ...r, policy: name })) : { ...result, policy: name };
    },
    describe: policy.describe ? () => policy.describe!() : undefined,
    withParameters: policy.withParameters ? (parameters) => renamed(policy.withParameters!(parameters), name) : undefined,
  };
}

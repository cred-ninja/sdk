/**
 * @credninja/guard — Max TTL Policy
 *
 * Cap how long a delegated token can live.
 * Always returns ALLOW (it narrows, doesn't deny).
 * Sets narrowedScopes metadata to indicate TTL enforcement.
 */

import type {
  CredPolicy,
  GuardContext,
  MaxTtlPolicyConfig,
  ParameterValue,
  PolicyDescriptor,
  PolicyResult,
} from '../types.js';
import { cloneParameters, isPlainObject, isPositiveInteger } from '../policy-diagnostics/params.js';

/**
 * Largest accepted TTL: 100 years in seconds. Far below the point where
 * `expiresAt` would leave the valid Date range and `evaluate` would throw,
 * which under `onError: 'allow'` would skip the cap entirely.
 */
export const MAX_TTL_SECONDS = 3_155_760_000;

function isTtlSeconds(value: unknown): value is number {
  return isPositiveInteger(value) && value <= MAX_TTL_SECONDS;
}

export interface MaxTtlPolicyResult extends PolicyResult {
  /** The enforced max TTL in seconds */
  maxTtlSeconds: number;
  /** ISO timestamp when the delegation should expire */
  expiresAt: string;
}

export class MaxTtlPolicy implements CredPolicy {
  readonly name = 'max-ttl';
  private readonly config: MaxTtlPolicyConfig;

  constructor(config: MaxTtlPolicyConfig) {
    this.config = config;
  }

  evaluate(ctx: GuardContext): MaxTtlPolicyResult {
    const { provider, timestamp } = ctx;

    // Get provider-specific or global TTL
    const maxTtlSeconds = this.config.perProvider?.[provider] ?? this.config.maxTtlSeconds;

    // Calculate expiration time
    const now = new Date(timestamp);
    const expiresAt = new Date(now.getTime() + maxTtlSeconds * 1000);

    return {
      decision: 'ALLOW',
      policy: this.name,
      reason: `Max TTL enforced: ${maxTtlSeconds}s`,
      maxTtlSeconds,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /** The configuration as a parameter tree (see CredPolicy.describe). */
  describe(): PolicyDescriptor {
    return { kind: this.name, parameters: cloneParameters(this.config) as Record<string, ParameterValue> };
  }

  withParameters(parameters: Record<string, ParameterValue>): MaxTtlPolicy {
    return new MaxTtlPolicy(MaxTtlPolicy.parseParameters(parameters));
  }

  static parseParameters(parameters: Record<string, ParameterValue>): MaxTtlPolicyConfig {
    if (!isPlainObject(parameters)) throw new Error('max-ttl parameters must be an object');
    if (!isTtlSeconds(parameters.maxTtlSeconds)) throw new Error(`max-ttl.maxTtlSeconds must be a positive integer up to ${MAX_TTL_SECONDS}`);
    const config: MaxTtlPolicyConfig = { maxTtlSeconds: parameters.maxTtlSeconds };
    const perProvider = parameters.perProvider;
    if (perProvider !== undefined && perProvider !== null) {
      if (!isPlainObject(perProvider)) throw new Error('max-ttl.perProvider must be an object');
      config.perProvider = {};
      for (const [provider, ttl] of Object.entries(perProvider)) {
        if (!isTtlSeconds(ttl)) throw new Error(`max-ttl.perProvider.${provider} must be a positive integer up to ${MAX_TTL_SECONDS}`);
        config.perProvider[provider] = ttl;
      }
    }
    return config;
  }
}

/**
 * Factory function to create a max TTL policy.
 */
export function maxTtlPolicy(config: MaxTtlPolicyConfig): MaxTtlPolicy {
  return new MaxTtlPolicy(config);
}

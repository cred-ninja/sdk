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
    if (!isPositiveInteger(parameters.maxTtlSeconds)) throw new Error('max-ttl.maxTtlSeconds must be a positive integer');
    const config: MaxTtlPolicyConfig = { maxTtlSeconds: parameters.maxTtlSeconds };
    const perProvider = parameters.perProvider;
    if (perProvider !== undefined && perProvider !== null) {
      if (!isPlainObject(perProvider)) throw new Error('max-ttl.perProvider must be an object');
      config.perProvider = {};
      for (const [provider, ttl] of Object.entries(perProvider)) {
        if (!isPositiveInteger(ttl)) throw new Error(`max-ttl.perProvider.${provider} must be a positive integer`);
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

/**
 * @credninja/guard — Max TTL Policy
 *
 * Cap how long a delegated token can live.
 * Always returns ALLOW (it narrows, doesn't deny).
 * Sets narrowedScopes metadata to indicate TTL enforcement.
 */

import type { CredPolicy, GuardContext, PolicyResult, MaxTtlPolicyConfig } from '../types.js';

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
}

/**
 * Factory function to create a max TTL policy.
 */
export function maxTtlPolicy(config: MaxTtlPolicyConfig): MaxTtlPolicy {
  return new MaxTtlPolicy(config);
}

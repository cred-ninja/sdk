/**
 * @credninja/guard — Rate Limit Policy
 *
 * Sliding-window rate limit per agent per provider.
 * In-memory counters, resets on server restart.
 */

import type { CredPolicy, GuardContext, PolicyResult, RateLimitPolicyConfig } from '../types.js';

interface RequestRecord {
  timestamps: number[];
}

export class RateLimitPolicy implements CredPolicy {
  readonly name = 'rate-limit';
  private readonly config: RateLimitPolicyConfig;
  private readonly requests: Map<string, RequestRecord> = new Map();

  constructor(config: RateLimitPolicyConfig) {
    this.config = config;
  }

  evaluate(ctx: GuardContext): PolicyResult {
    const { provider, agentTokenHash } = ctx;

    // Get provider-specific or global limits
    const limits = this.config.perProvider?.[provider] ?? {
      maxRequests: this.config.maxRequests,
      windowMs: this.config.windowMs,
    };

    // SKIP if provider not configured and no global limit
    if (!this.config.maxRequests && !this.config.perProvider?.[provider]) {
      return { decision: 'SKIP', policy: this.name, reason: 'No rate limit configured' };
    }

    const key = `${agentTokenHash}:${provider}`;
    const now = Date.now();
    const windowStart = now - limits.windowMs;

    // Get or create request record
    let record = this.requests.get(key);
    if (!record) {
      record = { timestamps: [] };
      this.requests.set(key, record);
    }

    // Filter to only timestamps within window (sliding window)
    record.timestamps = record.timestamps.filter((ts) => ts > windowStart);

    // Check if limit exceeded
    if (record.timestamps.length >= limits.maxRequests) {
      const oldestInWindow = record.timestamps[0];
      const retryAfterMs = oldestInWindow + limits.windowMs - now;
      const retryAfterSec = Math.ceil(retryAfterMs / 1000);

      return {
        decision: 'DENY',
        policy: this.name,
        reason: `Rate limit exceeded: ${limits.maxRequests} requests per ${limits.windowMs}ms. Retry after ${retryAfterSec}s`,
      };
    }

    // Record this request
    record.timestamps.push(now);

    return {
      decision: 'ALLOW',
      policy: this.name,
      reason: `${record.timestamps.length}/${limits.maxRequests} requests in window`,
    };
  }

  /**
   * Reset all rate limit counters. Useful for testing.
   */
  reset(): void {
    this.requests.clear();
  }

  /**
   * Get current request count for a specific agent/provider combo.
   */
  getCount(agentTokenHash: string, provider: string): number {
    const key = `${agentTokenHash}:${provider}`;
    const record = this.requests.get(key);
    if (!record) return 0;

    const now = Date.now();
    const limits = this.config.perProvider?.[provider] ?? {
      maxRequests: this.config.maxRequests,
      windowMs: this.config.windowMs,
    };
    const windowStart = now - limits.windowMs;

    return record.timestamps.filter((ts) => ts > windowStart).length;
  }
}

/**
 * Factory function to create a rate limit policy.
 */
export function rateLimitPolicy(config: RateLimitPolicyConfig): RateLimitPolicy {
  return new RateLimitPolicy(config);
}

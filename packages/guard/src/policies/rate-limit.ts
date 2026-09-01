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

export interface RateLimitPolicyResult extends PolicyResult {
  /** Requests allowed per window for this provider */
  limit: number;
  /** Window size in milliseconds for this provider */
  windowMs: number;
  /** Requests remaining in the current window (present on ALLOW) */
  remaining?: number;
  /** Seconds until the oldest in-window request ages out (present on DENY) */
  retryAfterSeconds?: number;
}

export class RateLimitPolicy implements CredPolicy {
  readonly name = 'rate-limit';
  private readonly config: RateLimitPolicyConfig;
  private readonly requests: Map<string, RequestRecord> = new Map();
  /** Largest configured window — the horizon past which a record is dead. */
  private readonly maxWindowMs: number;
  private lastSweepAt = 0;

  constructor(config: RateLimitPolicyConfig) {
    this.config = config;
    const windows: number[] = [];
    if (typeof config.windowMs === 'number') windows.push(config.windowMs);
    for (const limit of Object.values(config.perProvider ?? {})) {
      if (typeof limit?.windowMs === 'number') windows.push(limit.windowMs);
    }
    this.maxWindowMs = windows.length > 0 ? Math.max(...windows) : 0;
  }

  evaluate(ctx: GuardContext): RateLimitPolicyResult | PolicyResult {
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
    // Bound memory: without eviction the map grows once per unique
    // agent/provider pair forever. Sweep dead records at most once per window.
    this.evictStale(now);
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
      // Clamp to 0: the oldest in-window request can age out between the filter
      // above and this calculation, which would otherwise yield a negative value.
      const retryAfterMs = Math.max(0, oldestInWindow + limits.windowMs - now);
      const retryAfterSec = Math.ceil(retryAfterMs / 1000);

      return {
        decision: 'DENY',
        policy: this.name,
        reason: `Rate limit exceeded: ${limits.maxRequests} requests per ${limits.windowMs}ms. Retry after ${retryAfterSec}s`,
        limit: limits.maxRequests,
        windowMs: limits.windowMs,
        retryAfterSeconds: retryAfterSec,
      };
    }

    // Record this request
    record.timestamps.push(now);

    return {
      decision: 'ALLOW',
      policy: this.name,
      reason: `${record.timestamps.length}/${limits.maxRequests} requests in window`,
      limit: limits.maxRequests,
      windowMs: limits.windowMs,
      remaining: Math.max(0, limits.maxRequests - record.timestamps.length),
    };
  }

  /**
   * Drop records whose most recent request has aged out of the largest window.
   * Runs at most once per `maxWindowMs` to keep the amortized cost negligible.
   */
  private evictStale(now: number): void {
    if (this.maxWindowMs <= 0) return;
    if (now - this.lastSweepAt < this.maxWindowMs) return;
    this.lastSweepAt = now;
    const cutoff = now - this.maxWindowMs;
    for (const [key, record] of this.requests) {
      const newest = record.timestamps[record.timestamps.length - 1];
      if (newest === undefined || newest <= cutoff) {
        this.requests.delete(key);
      }
    }
  }

  /**
   * Number of agent/provider records currently tracked. Useful for tests and
   * for observing that eviction is bounding memory.
   */
  size(): number {
    return this.requests.size;
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

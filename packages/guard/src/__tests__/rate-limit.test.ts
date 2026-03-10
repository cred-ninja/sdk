import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { RateLimitPolicy, rateLimitPolicy } from '../policies/rate-limit.js';
import type { GuardContext } from '../types.js';

function makeContext(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'google',
    agentTokenHash: 'agent-hash-123',
    requestedScopes: ['read'],
    consentedScopes: ['read'],
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('RateLimitPolicy', () => {
  let policy: RateLimitPolicy;

  beforeEach(() => {
    policy = new RateLimitPolicy({
      maxRequests: 3,
      windowMs: 60_000,
    });
  });

  afterEach(() => {
    policy.reset();
  });

  describe('basic rate limiting', () => {
    it('allows requests under the limit', () => {
      const result1 = policy.evaluate(makeContext());
      const result2 = policy.evaluate(makeContext());
      const result3 = policy.evaluate(makeContext());

      expect(result1.decision).toBe('ALLOW');
      expect(result2.decision).toBe('ALLOW');
      expect(result3.decision).toBe('ALLOW');
    });

    it('denies requests over the limit', () => {
      policy.evaluate(makeContext());
      policy.evaluate(makeContext());
      policy.evaluate(makeContext());

      const result = policy.evaluate(makeContext());

      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('Rate limit exceeded');
      expect(result.reason).toContain('Retry after');
    });

    it('tracks requests per agent', () => {
      const agent1 = makeContext({ agentTokenHash: 'agent1' });
      const agent2 = makeContext({ agentTokenHash: 'agent2' });

      // Agent 1 uses 3 requests
      policy.evaluate(agent1);
      policy.evaluate(agent1);
      policy.evaluate(agent1);

      // Agent 2 should still have quota
      const result = policy.evaluate(agent2);
      expect(result.decision).toBe('ALLOW');
    });

    it('tracks requests per provider', () => {
      const google = makeContext({ provider: 'google' });
      const github = makeContext({ provider: 'github' });

      // Use all quota for google
      policy.evaluate(google);
      policy.evaluate(google);
      policy.evaluate(google);

      // github should still have quota
      const result = policy.evaluate(github);
      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('sliding window', () => {
    it('allows requests after window expires', () => {
      vi.useFakeTimers();

      try {
        // Use all quota
        policy.evaluate(makeContext());
        policy.evaluate(makeContext());
        policy.evaluate(makeContext());

        // Wait for window to expire
        vi.advanceTimersByTime(61_000);

        const result = policy.evaluate(makeContext());
        expect(result.decision).toBe('ALLOW');
      } finally {
        vi.useRealTimers();
      }
    });

    it('slides window correctly (removes old timestamps)', () => {
      vi.useFakeTimers();

      try {
        policy.evaluate(makeContext()); // t=0
        vi.advanceTimersByTime(30_000);
        policy.evaluate(makeContext()); // t=30s
        policy.evaluate(makeContext()); // t=30s (limit reached)

        // At t=30s, first request still in window
        expect(policy.evaluate(makeContext()).decision).toBe('DENY');

        // Advance to t=61s - first request should expire
        vi.advanceTimersByTime(31_000);

        const result = policy.evaluate(makeContext());
        expect(result.decision).toBe('ALLOW');
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe('per-provider config', () => {
    it('uses provider-specific limits', () => {
      const customPolicy = new RateLimitPolicy({
        maxRequests: 10,
        windowMs: 60_000,
        perProvider: {
          github: { maxRequests: 2, windowMs: 60_000 },
        },
      });

      const github = makeContext({ provider: 'github' });
      customPolicy.evaluate(github);
      customPolicy.evaluate(github);

      const result = customPolicy.evaluate(github);
      expect(result.decision).toBe('DENY');
    });

    it('falls back to global for unconfigured providers', () => {
      const customPolicy = new RateLimitPolicy({
        maxRequests: 1,
        windowMs: 60_000,
        perProvider: {
          github: { maxRequests: 10, windowMs: 60_000 },
        },
      });

      const google = makeContext({ provider: 'google' });
      customPolicy.evaluate(google);

      const result = customPolicy.evaluate(google);
      expect(result.decision).toBe('DENY');
    });
  });

  describe('getCount', () => {
    it('returns current request count', () => {
      const ctx = makeContext();

      expect(policy.getCount(ctx.agentTokenHash, ctx.provider)).toBe(0);

      policy.evaluate(ctx);
      expect(policy.getCount(ctx.agentTokenHash, ctx.provider)).toBe(1);

      policy.evaluate(ctx);
      expect(policy.getCount(ctx.agentTokenHash, ctx.provider)).toBe(2);
    });
  });

  describe('reset', () => {
    it('clears all counters', () => {
      policy.evaluate(makeContext());
      policy.evaluate(makeContext());

      policy.reset();

      expect(policy.getCount('agent-hash-123', 'google')).toBe(0);
    });
  });

  describe('factory function', () => {
    it('creates a RateLimitPolicy instance', () => {
      const created = rateLimitPolicy({ maxRequests: 5, windowMs: 1000 });
      expect(created).toBeInstanceOf(RateLimitPolicy);
      expect(created.name).toBe('rate-limit');
    });
  });

  describe('reason messages', () => {
    it('includes current count in allow reason', () => {
      const result = policy.evaluate(makeContext());
      expect(result.reason).toContain('1/3');
    });

    it('includes retry time in deny reason', () => {
      policy.evaluate(makeContext());
      policy.evaluate(makeContext());
      policy.evaluate(makeContext());

      const result = policy.evaluate(makeContext());
      expect(result.reason).toMatch(/Retry after \d+s/);
    });
  });
});

import { describe, it, expect } from 'vitest';
import { MaxTtlPolicy, maxTtlPolicy } from '../policies/max-ttl.js';
import type { GuardContext } from '../types.js';

function makeContext(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'google',
    agentTokenHash: 'agent-hash-123',
    requestedScopes: ['read'],
    consentedScopes: ['read'],
    timestamp: '2024-01-15T10:00:00.000Z',
    ...overrides,
  };
}

describe('MaxTtlPolicy', () => {
  describe('basic TTL enforcement', () => {
    it('always returns ALLOW', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 3600,
      });

      const result = policy.evaluate(makeContext());

      expect(result.decision).toBe('ALLOW');
    });

    it('calculates expiresAt correctly', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 3600, // 1 hour
      });

      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T10:00:00.000Z',
      }));

      expect(result.expiresAt).toBe('2024-01-15T11:00:00.000Z');
    });

    it('includes maxTtlSeconds in result', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 7200,
      });

      const result = policy.evaluate(makeContext());

      expect(result.maxTtlSeconds).toBe(7200);
    });

    it('includes informative reason', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 3600,
      });

      const result = policy.evaluate(makeContext());

      expect(result.reason).toContain('Max TTL enforced');
      expect(result.reason).toContain('3600s');
    });
  });

  describe('per-provider TTL', () => {
    it('uses provider-specific TTL when configured', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 3600,
        perProvider: {
          github: 1800, // 30 minutes
        },
      });

      const result = policy.evaluate(makeContext({
        provider: 'github',
        timestamp: '2024-01-15T10:00:00.000Z',
      }));

      expect(result.maxTtlSeconds).toBe(1800);
      expect(result.expiresAt).toBe('2024-01-15T10:30:00.000Z');
    });

    it('falls back to global TTL for unconfigured providers', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 3600,
        perProvider: {
          github: 1800,
        },
      });

      const result = policy.evaluate(makeContext({
        provider: 'google',
        timestamp: '2024-01-15T10:00:00.000Z',
      }));

      expect(result.maxTtlSeconds).toBe(3600);
      expect(result.expiresAt).toBe('2024-01-15T11:00:00.000Z');
    });
  });

  describe('edge cases', () => {
    it('handles short TTL (seconds)', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 60, // 1 minute
      });

      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T10:00:00.000Z',
      }));

      expect(result.expiresAt).toBe('2024-01-15T10:01:00.000Z');
    });

    it('handles long TTL (days)', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 86400 * 7, // 1 week
      });

      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T10:00:00.000Z',
      }));

      expect(result.expiresAt).toBe('2024-01-22T10:00:00.000Z');
    });

    it('handles zero TTL', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 0,
      });

      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T10:00:00.000Z',
      }));

      expect(result.maxTtlSeconds).toBe(0);
      expect(result.expiresAt).toBe('2024-01-15T10:00:00.000Z');
    });

    it('handles millisecond precision in timestamp', () => {
      const policy = new MaxTtlPolicy({
        maxTtlSeconds: 60,
      });

      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T10:00:30.500Z',
      }));

      expect(result.expiresAt).toBe('2024-01-15T10:01:30.500Z');
    });
  });

  describe('factory function', () => {
    it('creates a MaxTtlPolicy instance', () => {
      const created = maxTtlPolicy({ maxTtlSeconds: 3600 });
      expect(created).toBeInstanceOf(MaxTtlPolicy);
      expect(created.name).toBe('max-ttl');
    });
  });
});

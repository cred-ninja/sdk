import { describe, it, expect } from 'vitest';
import { TimeWindowPolicy, timeWindowPolicy } from '../policies/time-window.js';
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

describe('TimeWindowPolicy', () => {
  describe('hour window - normal range', () => {
    it('allows requests within the window (9-17)', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 9, end: 17 },
        timezone: 'UTC',
      });

      // 10:00 UTC
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T10:00:00Z',
      }));

      expect(result.decision).toBe('ALLOW');
    });

    it('allows at start of window', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 9, end: 17 },
        timezone: 'UTC',
      });

      // 9:00 UTC
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T09:00:00Z',
      }));

      expect(result.decision).toBe('ALLOW');
    });

    it('denies at end of window (end is exclusive)', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 9, end: 17 },
        timezone: 'UTC',
      });

      // 17:00 UTC
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T17:00:00Z',
      }));

      expect(result.decision).toBe('DENY');
    });

    it('denies requests outside the window', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 9, end: 17 },
        timezone: 'UTC',
      });

      // 8:00 UTC
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T08:00:00Z',
      }));

      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('Hour 8');
    });
  });

  describe('hour window - wrap-around (overnight)', () => {
    it('allows requests in overnight window (22-6)', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 22, end: 6 },
        timezone: 'UTC',
      });

      // 23:00 UTC
      const result1 = policy.evaluate(makeContext({
        timestamp: '2024-01-15T23:00:00Z',
      }));
      expect(result1.decision).toBe('ALLOW');

      // 02:00 UTC
      const result2 = policy.evaluate(makeContext({
        timestamp: '2024-01-15T02:00:00Z',
      }));
      expect(result2.decision).toBe('ALLOW');
    });

    it('denies requests outside overnight window', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 22, end: 6 },
        timezone: 'UTC',
      });

      // 12:00 UTC (noon)
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T12:00:00Z',
      }));

      expect(result.decision).toBe('DENY');
    });
  });

  describe('day of week filtering', () => {
    it('allows on allowed days', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 0, end: 24 },
        allowedDays: [1, 2, 3, 4, 5], // Mon-Fri
        timezone: 'UTC',
      });

      // Monday
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T12:00:00Z', // Monday
      }));

      expect(result.decision).toBe('ALLOW');
    });

    it('denies on disallowed days', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 0, end: 24 },
        allowedDays: [1, 2, 3, 4, 5], // Mon-Fri
        timezone: 'UTC',
      });

      // Saturday (Jan 13, 2024)
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-13T12:00:00Z', // Saturday
      }));

      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('Day 6');
    });

    it('allows all days when allowedDays not specified', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 0, end: 24 },
        timezone: 'UTC',
      });

      // Sunday
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-14T12:00:00Z', // Sunday
      }));

      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('timezone handling', () => {
    it('respects timezone for hour evaluation', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 9, end: 17 },
        timezone: 'America/New_York',
      });

      // 14:00 UTC = 9:00 EST (in window)
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T14:00:00Z',
      }));

      expect(result.decision).toBe('ALLOW');
    });

    it('defaults to UTC when timezone not specified', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 9, end: 17 },
      });

      // 10:00 UTC
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T10:00:00Z',
      }));

      expect(result.decision).toBe('ALLOW');
    });

    it('falls back to UTC for invalid timezone', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 9, end: 17 },
        timezone: 'Invalid/Timezone',
      });

      // Should not throw, falls back to UTC
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T10:00:00Z',
      }));

      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('edge cases', () => {
    it('denies on invalid timestamp', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 0, end: 24 },
      });

      const result = policy.evaluate(makeContext({
        timestamp: 'not-a-valid-timestamp',
      }));

      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('Invalid timestamp');
    });

    it('handles 24-hour window (always open)', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 0, end: 24 },
      });

      const result1 = policy.evaluate(makeContext({
        timestamp: '2024-01-15T00:00:00Z',
      }));
      expect(result1.decision).toBe('ALLOW');

      const result2 = policy.evaluate(makeContext({
        timestamp: '2024-01-15T23:59:59Z',
      }));
      expect(result2.decision).toBe('ALLOW');
    });

    it('handles empty allowedDays array', () => {
      const policy = new TimeWindowPolicy({
        allowedHours: { start: 0, end: 24 },
        allowedDays: [],
      });

      // Empty array means all days allowed (default behavior)
      const result = policy.evaluate(makeContext({
        timestamp: '2024-01-15T12:00:00Z',
      }));

      expect(result.decision).toBe('ALLOW');
    });
  });

  describe('factory function', () => {
    it('creates a TimeWindowPolicy instance', () => {
      const created = timeWindowPolicy({
        allowedHours: { start: 9, end: 17 },
      });
      expect(created).toBeInstanceOf(TimeWindowPolicy);
      expect(created.name).toBe('time-window');
    });
  });
});

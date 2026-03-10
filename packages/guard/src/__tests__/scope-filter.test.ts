import { describe, it, expect } from 'vitest';
import { ScopeFilterPolicy, scopeFilterPolicy } from '../policies/scope-filter.js';
import type { GuardContext } from '../types.js';

function makeContext(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'google',
    agentTokenHash: 'agent-hash-123',
    requestedScopes: ['gmail.readonly', 'calendar.readonly'],
    consentedScopes: ['gmail.readonly', 'calendar.readonly', 'drive.readonly'],
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('ScopeFilterPolicy', () => {
  describe('basic filtering', () => {
    it('allows when all requested scopes are in allowlist', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          google: ['gmail.readonly', 'calendar.readonly', 'drive.readonly'],
        },
      });

      const result = policy.evaluate(makeContext());

      expect(result.decision).toBe('ALLOW');
      expect(result.reason).toContain('All requested scopes are allowed');
    });

    it('denies when disallowed scopes are requested', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          google: ['gmail.readonly'],
        },
      });

      const result = policy.evaluate(makeContext({
        requestedScopes: ['gmail.readonly', 'calendar.readonly'],
      }));

      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('calendar.readonly');
    });

    it('SKIPs when provider not in config', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          github: ['repo'],
        },
      });

      const result = policy.evaluate(makeContext({ provider: 'google' }));

      expect(result.decision).toBe('SKIP');
      expect(result.reason).toContain('No scope restrictions');
    });
  });

  describe('narrowInsteadOfDeny mode', () => {
    it('narrows scopes instead of denying when enabled', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          google: ['gmail.readonly'],
        },
        narrowInsteadOfDeny: true,
      });

      const result = policy.evaluate(makeContext({
        requestedScopes: ['gmail.readonly', 'calendar.readonly', 'drive.readonly'],
      }));

      expect(result.decision).toBe('ALLOW');
      expect(result.narrowedScopes).toEqual(['gmail.readonly']);
      expect(result.reason).toContain('Narrowed scopes');
    });

    it('returns empty narrowedScopes when all scopes are disallowed', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          google: [],
        },
        narrowInsteadOfDeny: true,
      });

      const result = policy.evaluate(makeContext({
        requestedScopes: ['gmail.readonly'],
      }));

      expect(result.decision).toBe('ALLOW');
      expect(result.narrowedScopes).toEqual([]);
    });

    it('does not set narrowedScopes when all scopes are allowed', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          google: ['gmail.readonly', 'calendar.readonly'],
        },
        narrowInsteadOfDeny: true,
      });

      const result = policy.evaluate(makeContext({
        requestedScopes: ['gmail.readonly'],
      }));

      expect(result.decision).toBe('ALLOW');
      expect(result.narrowedScopes).toBeUndefined();
    });
  });

  describe('edge cases', () => {
    it('handles empty requested scopes', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          google: ['gmail.readonly'],
        },
      });

      const result = policy.evaluate(makeContext({
        requestedScopes: [],
      }));

      expect(result.decision).toBe('ALLOW');
    });

    it('handles empty allowedScopes list for provider', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          google: [],
        },
      });

      const result = policy.evaluate(makeContext({
        requestedScopes: ['gmail.readonly'],
      }));

      expect(result.decision).toBe('DENY');
    });

    it('is case-sensitive for scope matching', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          google: ['Gmail.Readonly'],
        },
      });

      const result = policy.evaluate(makeContext({
        requestedScopes: ['gmail.readonly'],
      }));

      expect(result.decision).toBe('DENY');
    });
  });

  describe('multiple disallowed scopes', () => {
    it('lists all disallowed scopes in reason', () => {
      const policy = new ScopeFilterPolicy({
        allowedScopes: {
          google: ['gmail.readonly'],
        },
      });

      const result = policy.evaluate(makeContext({
        requestedScopes: ['gmail.readonly', 'calendar.readonly', 'drive.readonly'],
      }));

      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('calendar.readonly');
      expect(result.reason).toContain('drive.readonly');
    });
  });

  describe('factory function', () => {
    it('creates a ScopeFilterPolicy instance', () => {
      const created = scopeFilterPolicy({ allowedScopes: {} });
      expect(created).toBeInstanceOf(ScopeFilterPolicy);
      expect(created.name).toBe('scope-filter');
    });
  });
});

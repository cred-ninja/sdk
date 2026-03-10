import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CredGuard } from '../guard.js';
import type { CredPolicy, GuardContext, PolicyResult } from '../types.js';

function makeContext(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'google',
    agentTokenHash: 'abc123hash',
    requestedScopes: ['read', 'write'],
    consentedScopes: ['read', 'write'],
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makePolicy(name: string, decision: 'ALLOW' | 'DENY' | 'SKIP', options: Partial<PolicyResult> = {}): CredPolicy {
  return {
    name,
    evaluate: () => ({ decision, policy: name, ...options }),
  };
}

describe('CredGuard', () => {
  describe('evaluate', () => {
    it('returns ALLOW when no policies are registered', async () => {
      const guard = new CredGuard({ policies: [] });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(true);
      expect(result.results).toHaveLength(0);
      expect(result.effectiveScopes).toEqual(['read', 'write']);
    });

    it('returns ALLOW when all policies ALLOW', async () => {
      const guard = new CredGuard({
        policies: [
          makePolicy('policy1', 'ALLOW'),
          makePolicy('policy2', 'ALLOW'),
        ],
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(true);
      expect(result.results).toHaveLength(2);
      expect(result.deniedBy).toBeUndefined();
    });

    it('returns ALLOW when all policies SKIP', async () => {
      const guard = new CredGuard({
        policies: [
          makePolicy('policy1', 'SKIP'),
          makePolicy('policy2', 'SKIP'),
        ],
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(true);
    });

    it('returns ALLOW when mix of ALLOW and SKIP', async () => {
      const guard = new CredGuard({
        policies: [
          makePolicy('policy1', 'ALLOW'),
          makePolicy('policy2', 'SKIP'),
          makePolicy('policy3', 'ALLOW'),
        ],
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(true);
      expect(result.results).toHaveLength(3);
    });

    it('returns DENY on first DENY and short-circuits', async () => {
      const policy3 = vi.fn().mockReturnValue({ decision: 'ALLOW', policy: 'policy3' });
      const guard = new CredGuard({
        policies: [
          makePolicy('policy1', 'ALLOW'),
          makePolicy('policy2', 'DENY', { reason: 'test deny' }),
          { name: 'policy3', evaluate: policy3 },
        ],
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(false);
      expect(result.results).toHaveLength(2); // policy3 not evaluated
      expect(result.deniedBy?.policy).toBe('policy2');
      expect(result.deniedBy?.reason).toBe('test deny');
      expect(policy3).not.toHaveBeenCalled();
    });

    it('handles async policies', async () => {
      const guard = new CredGuard({
        policies: [
          {
            name: 'async-policy',
            evaluate: async () => {
              await new Promise(r => setTimeout(r, 10));
              return { decision: 'ALLOW', policy: 'async-policy' };
            },
          },
        ],
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(true);
      expect(result.evaluationMs).toBeGreaterThan(0);
    });

    it('handles scope narrowing', async () => {
      const guard = new CredGuard({
        policies: [
          {
            name: 'narrower',
            evaluate: () => ({
              decision: 'ALLOW',
              policy: 'narrower',
              narrowedScopes: ['read'],
            }),
          },
        ],
      });
      const result = await guard.evaluate(makeContext({ requestedScopes: ['read', 'write'] }));

      expect(result.allowed).toBe(true);
      expect(result.effectiveScopes).toEqual(['read']);
    });

    it('passes narrowed scopes to subsequent policies', async () => {
      const secondPolicy = vi.fn().mockReturnValue({ decision: 'ALLOW', policy: 'second' });
      const guard = new CredGuard({
        policies: [
          {
            name: 'narrower',
            evaluate: () => ({
              decision: 'ALLOW',
              policy: 'narrower',
              narrowedScopes: ['read'],
            }),
          },
          { name: 'second', evaluate: secondPolicy },
        ],
      });
      await guard.evaluate(makeContext({ requestedScopes: ['read', 'write'] }));

      expect(secondPolicy).toHaveBeenCalledWith(expect.objectContaining({
        requestedScopes: ['read'],
      }));
    });

    it('records evaluation time for each policy', async () => {
      const guard = new CredGuard({
        policies: [makePolicy('policy1', 'ALLOW')],
      });
      const result = await guard.evaluate(makeContext());

      expect(result.results[0].durationMs).toBeDefined();
      expect(result.results[0].durationMs).toBeGreaterThanOrEqual(0);
    });

    it('calls onDecision callback with results', async () => {
      const onDecision = vi.fn();
      const guard = new CredGuard({
        policies: [makePolicy('policy1', 'ALLOW')],
        onDecision,
      });
      const ctx = makeContext();
      await guard.evaluate(ctx);

      expect(onDecision).toHaveBeenCalledWith(ctx, expect.any(Array));
    });
  });

  describe('error handling', () => {
    it('denies by default when policy throws', async () => {
      const guard = new CredGuard({
        policies: [
          {
            name: 'throwing-policy',
            evaluate: () => { throw new Error('Policy error'); },
          },
        ],
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(false);
      expect(result.deniedBy?.reason).toContain('Policy error');
    });

    it('allows when onError is "allow"', async () => {
      const guard = new CredGuard({
        policies: [
          {
            name: 'throwing-policy',
            evaluate: () => { throw new Error('Policy error'); },
          },
        ],
        onError: 'allow',
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(true);
      expect(result.results[0].reason).toContain('allowed');
    });

    it('logs and denies when onError is "log-and-deny"', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const guard = new CredGuard({
        policies: [
          {
            name: 'throwing-policy',
            evaluate: () => { throw new Error('Policy error'); },
          },
        ],
        onError: 'log-and-deny',
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(false);
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it('treats invalid policy results as DENY', async () => {
      const guard = new CredGuard({
        policies: [
          {
            name: 'bad-policy',
            evaluate: () => ({ decision: 'INVALID' as any, policy: 'bad-policy' }),
          },
        ],
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(false);
      expect(result.deniedBy?.reason).toContain('Invalid policy result');
    });

    it('treats null result as DENY', async () => {
      const guard = new CredGuard({
        policies: [
          {
            name: 'null-policy',
            evaluate: () => null as any,
          },
        ],
      });
      const result = await guard.evaluate(makeContext());

      expect(result.allowed).toBe(false);
    });
  });

  describe('addPolicy', () => {
    it('appends policy to end of chain', async () => {
      const guard = new CredGuard({ policies: [makePolicy('first', 'ALLOW')] });
      guard.addPolicy(makePolicy('second', 'ALLOW'));

      const result = await guard.evaluate(makeContext());

      expect(result.results).toHaveLength(2);
      expect(result.results[0].policy).toBe('first');
      expect(result.results[1].policy).toBe('second');
    });
  });

  describe('removePolicy', () => {
    it('removes policy by name', async () => {
      const guard = new CredGuard({
        policies: [
          makePolicy('first', 'ALLOW'),
          makePolicy('second', 'ALLOW'),
        ],
      });
      const removed = guard.removePolicy('first');

      expect(removed).toBe(true);
      const result = await guard.evaluate(makeContext());
      expect(result.results).toHaveLength(1);
      expect(result.results[0].policy).toBe('second');
    });

    it('returns false if policy not found', () => {
      const guard = new CredGuard({ policies: [] });
      const removed = guard.removePolicy('nonexistent');

      expect(removed).toBe(false);
    });
  });

  describe('getPolicyNames', () => {
    it('returns policy names in order', () => {
      const guard = new CredGuard({
        policies: [
          makePolicy('first', 'ALLOW'),
          makePolicy('second', 'ALLOW'),
        ],
      });

      expect(guard.getPolicyNames()).toEqual(['first', 'second']);
    });
  });
});

import { describe, it, expect, afterEach, vi } from 'vitest';
import { AmountLimitPolicy, amountLimitPolicy, InMemoryAmountLimitStore } from '../policies/amount-limit.js';
import { CredGuard } from '../guard.js';
import type { AmountLimitPolicyConfig, AmountLimitStore, GuardContext } from '../types.js';

const DAY_MS = 24 * 60 * 60 * 1000;

function makeContext(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'stripe',
    agentTokenHash: 'agent-hash-123',
    requestedScopes: ['write'],
    consentedScopes: ['write'],
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function pay(amount: unknown, currency: unknown = 'USD', overrides: Partial<GuardContext> = {}): GuardContext {
  return makeContext({ metadata: { amount, currency }, ...overrides });
}

function makePolicy(overrides: Partial<AmountLimitPolicyConfig> = {}): AmountLimitPolicy {
  return new AmountLimitPolicy({
    currency: 'USD',
    maxPerRequest: 10_000,
    maxPerPeriod: 25_000,
    ...overrides,
  });
}

describe('AmountLimitPolicy', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  describe('per-request limit', () => {
    it('allows an amount under the limit', async () => {
      const result = await makePolicy().evaluate(pay(5_000));

      expect(result.decision).toBe('ALLOW');
      expect(result.policy).toBe('amount-limit');
      expect(result.amount).toBe(5_000);
      expect(result.periodTotal).toBe(5_000);
      expect(result.remaining).toBe(20_000);
    });

    it('allows an amount exactly at the limit', async () => {
      const result = await makePolicy().evaluate(pay(10_000));

      expect(result.decision).toBe('ALLOW');
    });

    it('denies an amount one minor unit over the limit', async () => {
      const result = await makePolicy().evaluate(pay(10_001));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('amount_exceeds_per_request');
      expect(result.maxPerRequest).toBe(10_000);
    });

    it('allows a zero amount', async () => {
      const result = await makePolicy().evaluate(pay(0));

      expect(result.decision).toBe('ALLOW');
    });

    it('works with only a per-request limit', async () => {
      const policy = new AmountLimitPolicy({ currency: 'USD', maxPerRequest: 100 });

      expect((await policy.evaluate(pay(100))).decision).toBe('ALLOW');
      expect((await policy.evaluate(pay(100))).decision).toBe('ALLOW');
      expect((await policy.evaluate(pay(101))).code).toBe('amount_exceeds_per_request');
    });

    it('does not count a per-request denial toward the period', async () => {
      const policy = makePolicy();
      await policy.evaluate(pay(20_000));

      expect(await policy.getPeriodTotal('agent-hash-123')).toBe(0);
    });
  });

  describe('period limit', () => {
    it('allows amounts up to exactly the period limit', async () => {
      const policy = makePolicy();
      await policy.evaluate(pay(10_000));
      await policy.evaluate(pay(10_000));
      const result = await policy.evaluate(pay(5_000));

      expect(result.decision).toBe('ALLOW');
      expect(result.periodTotal).toBe(25_000);
      expect(result.remaining).toBe(0);
    });

    it('denies an amount that would exceed the period limit', async () => {
      const policy = makePolicy();
      await policy.evaluate(pay(10_000));
      await policy.evaluate(pay(10_000));
      const result = await policy.evaluate(pay(5_001));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('amount_exceeds_period');
      expect(result.periodTotal).toBe(20_000);
      expect(result.remaining).toBe(5_000);
    });

    it('does not count denied amounts toward the period', async () => {
      const policy = makePolicy();
      await policy.evaluate(pay(10_000));
      await policy.evaluate(pay(10_000));
      await policy.evaluate(pay(6_000)); // denied
      const result = await policy.evaluate(pay(5_000));

      expect(result.decision).toBe('ALLOW');
      expect(await policy.getPeriodTotal('agent-hash-123')).toBe(25_000);
    });

    it('does not count invalid or mismatched requests toward the period', async () => {
      const policy = makePolicy();
      await policy.evaluate(pay(1.5));
      await policy.evaluate(pay(1_000, 'EUR'));

      expect(await policy.getPeriodTotal('agent-hash-123')).toBe(0);
    });

    it('tracks totals per agent', async () => {
      const policy = makePolicy();
      await policy.evaluate(pay(10_000, 'USD', { agentTokenHash: 'agent1' }));
      await policy.evaluate(pay(10_000, 'USD', { agentTokenHash: 'agent1' }));

      const agent1 = await policy.evaluate(pay(10_000, 'USD', { agentTokenHash: 'agent1' }));
      const agent2 = await policy.evaluate(pay(10_000, 'USD', { agentTokenHash: 'agent2' }));

      expect(agent1.decision).toBe('DENY');
      expect(agent2.decision).toBe('ALLOW');
    });

    it('frees amounts as they roll out of the period', async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-01-15T10:00:00Z'));
      const policy = makePolicy();
      await policy.evaluate(pay(10_000));

      vi.setSystemTime(new Date('2026-01-15T20:00:00Z'));
      await policy.evaluate(pay(10_000));
      await policy.evaluate(pay(5_000));
      expect((await policy.evaluate(pay(1))).decision).toBe('DENY');

      // The first amount ages out exactly one period after it was recorded
      vi.setSystemTime(new Date('2026-01-16T10:00:00Z'));
      const result = await policy.evaluate(pay(10_000));

      expect(result.decision).toBe('ALLOW');
      expect(result.periodTotal).toBe(25_000);
    });

    it('keeps an amount one millisecond before the period ends', async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-01-15T10:00:00Z'));
      const policy = makePolicy({ maxPerPeriod: 10_000 });
      await policy.evaluate(pay(10_000));

      vi.setSystemTime(new Date('2026-01-15T10:00:00Z').getTime() + DAY_MS - 1);
      expect((await policy.evaluate(pay(1))).code).toBe('amount_exceeds_period');

      vi.advanceTimersByTime(1);
      expect((await policy.evaluate(pay(1))).decision).toBe('ALLOW');
    });

    it('uses a custom periodMs', async () => {
      vi.useFakeTimers();
      const policy = makePolicy({ maxPerPeriod: 100, maxPerRequest: undefined, periodMs: 60_000 });
      await policy.evaluate(pay(100));
      expect((await policy.evaluate(pay(1))).decision).toBe('DENY');

      vi.advanceTimersByTime(60_000);
      expect((await policy.evaluate(pay(100))).decision).toBe('ALLOW');
    });
  });

  describe('per-agent overrides', () => {
    it('applies an override by agentTokenHash', async () => {
      const policy = makePolicy({ perAgent: { 'agent-hash-123': { maxPerRequest: 500 } } });

      expect((await policy.evaluate(pay(501))).code).toBe('amount_exceeds_per_request');
      expect((await policy.evaluate(pay(501, 'USD', { agentTokenHash: 'other' }))).decision).toBe('ALLOW');
    });

    it('applies an override by agentDid when trustAgentDid is set', async () => {
      const policy = makePolicy({
        perAgent: { 'did:web:agent.example': { maxPerRequest: 50_000, maxPerPeriod: 50_000 } },
        trustAgentDid: true,
      });
      const result = await policy.evaluate(pay(40_000, 'USD', { agentDid: 'did:web:agent.example' }));

      expect(result.decision).toBe('ALLOW');
      expect(result.maxPerPeriod).toBe(50_000);
    });

    it('ignores a request-claimed DID with a permissive override by default', async () => {
      const policy = makePolicy({
        perAgent: { 'did:web:agent.example': { maxPerRequest: 50_000, maxPerPeriod: 50_000 } },
      });
      const result = await policy.evaluate(pay(40_000, 'USD', { agentDid: 'did:web:agent.example' }));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('amount_exceeds_per_request');
      expect(result.maxPerRequest).toBe(10_000);
    });

    it('falls back to the defaults for fields the override leaves unset', async () => {
      const policy = makePolicy({ perAgent: { 'agent-hash-123': { maxPerRequest: 20_000 } } });
      const result = await policy.evaluate(pay(20_000));

      expect(result.decision).toBe('ALLOW');
      expect(result.maxPerPeriod).toBe(25_000);
    });

    it('applies the lower value when agentTokenHash and agentDid both match', async () => {
      const policy = makePolicy({
        perAgent: {
          'agent-hash-123': { maxPerRequest: 1_000, maxPerPeriod: 90_000 },
          'did:web:agent.example': { maxPerRequest: 9_000, maxPerPeriod: 3_000 },
        },
        trustAgentDid: true,
      });
      const result = await policy.evaluate(pay(1_000, 'USD', { agentDid: 'did:web:agent.example' }));

      expect(result.maxPerRequest).toBe(1_000);
      expect(result.maxPerPeriod).toBe(3_000);
    });

    it('does not treat inherited object keys as agents', async () => {
      const policy = makePolicy({ perAgent: {} });
      const result = await policy.evaluate(pay(10_000, 'USD', { agentTokenHash: 'constructor' }));

      expect(result.decision).toBe('ALLOW');
      expect(result.maxPerRequest).toBe(10_000);
    });
  });

  describe('missing and invalid amounts', () => {
    it('denies a missing amount by default', async () => {
      const result = await makePolicy().evaluate(makeContext());

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('amount_missing');
    });

    it('treats null as missing', async () => {
      const result = await makePolicy().evaluate(pay(null));

      expect(result.code).toBe('amount_missing');
    });

    it('skips a missing amount when onMissing is skip', async () => {
      const result = await makePolicy({ onMissing: 'skip' }).evaluate(makeContext({ metadata: {} }));

      expect(result.decision).toBe('SKIP');
    });

    it.each([
      ['a decimal', 10.5],
      ['a negative amount', -1],
      ['a numeric string', '100'],
      ['NaN', Number.NaN],
      ['Infinity', Number.POSITIVE_INFINITY],
      ['an unsafe integer', Number.MAX_SAFE_INTEGER + 1],
    ])('denies %s', async (_label, amount) => {
      const result = await makePolicy().evaluate(pay(amount));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('amount_invalid');
    });

    it('still denies an invalid amount when onMissing is skip', async () => {
      const result = await makePolicy({ onMissing: 'skip' }).evaluate(pay('ten'));

      expect(result.code).toBe('amount_invalid');
    });

    it('uses resolveAmount', async () => {
      const policy = makePolicy({
        resolveAmount: (ctx) => {
          const payment = ctx.metadata?.payment as { cents?: number; ccy?: string } | undefined;
          return { amount: payment?.cents, currency: payment?.ccy };
        },
      });
      const result = await policy.evaluate(makeContext({ metadata: { payment: { cents: 10_001, ccy: 'USD' } } }));

      expect(result.code).toBe('amount_exceeds_per_request');
    });

    it('denies when resolveAmount throws', async () => {
      const policy = makePolicy({
        resolveAmount: () => {
          throw new Error('bad body');
        },
      });
      const result = await policy.evaluate(makeContext());

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('amount_invalid');
    });
  });

  describe('currency', () => {
    it('denies a different currency', async () => {
      const result = await makePolicy().evaluate(pay(100, 'EUR'));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('currency_mismatch');
    });

    it('denies a missing currency', async () => {
      const result = await makePolicy().evaluate(makeContext({ metadata: { amount: 100 } }));

      expect(result.code).toBe('currency_mismatch');
    });

    it('compares currency codes case-insensitively', async () => {
      const policy = makePolicy({ currency: 'usd' });

      expect((await policy.evaluate(pay(100, 'USD'))).decision).toBe('ALLOW');
      expect((await policy.evaluate(pay(100, 'Usd'))).decision).toBe('ALLOW');
    });
  });

  describe('store', () => {
    it('uses an injected store', async () => {
      const store = new InMemoryAmountLimitStore();
      const policy = makePolicy({ store });
      await policy.evaluate(pay(7_000));

      expect(store.total('agent-hash-123', 0)).toBe(7_000);
      expect(store.size()).toBe(1);
    });

    it('supports an async store', async () => {
      const inner = new InMemoryAmountLimitStore();
      const store: AmountLimitStore = {
        consume: async (...args) => inner.consume(...args),
        total: async (...args) => inner.total(...args),
      };
      const policy = makePolicy({ store, maxPerPeriod: 10_000 });

      expect((await policy.evaluate(pay(10_000))).decision).toBe('ALLOW');
      expect((await policy.evaluate(pay(1))).code).toBe('amount_exceeds_period');
    });

    it('denies when the store fails', async () => {
      const store: AmountLimitStore = {
        consume: () => Promise.reject(new Error('redis down')),
        total: () => 0,
      };
      const result = await makePolicy({ store }).evaluate(pay(100));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('amount_store_error');
    });

    it('keeps no entries for zero amounts', async () => {
      const store = new InMemoryAmountLimitStore();
      for (let i = 0; i < 100; i++) {
        const result = store.consume('agent', 0, 1_000 + i, 0, 10);
        expect(result).toEqual({ recorded: true, total: 0 });
      }
      expect(store.size()).toBe(0);

      store.consume('agent', 5, 2_000, 0, 10);
      for (let i = 0; i < 100; i++) {
        expect(store.consume('agent', 0, 2_001 + i, 0, 10)).toEqual({ recorded: true, total: 5 });
      }
      // Only the one non-zero entry is stored
      expect(store.size()).toBe(1);
      expect(store.total('agent', 0)).toBe(5);
    });

    it('allows zero amounts through the policy without growing the store', async () => {
      const store = new InMemoryAmountLimitStore();
      const policy = makePolicy({ store });
      for (let i = 0; i < 50; i++) {
        expect((await policy.evaluate(pay(0))).decision).toBe('ALLOW');
      }

      expect(store.size()).toBe(0);
    });

    it.each([
      ['undefined', undefined],
      ['null', null],
      ['a NaN total', { recorded: true, total: Number.NaN }],
      ['a non-boolean recorded', { recorded: 'yes', total: 1 }],
      ['an infinite total', { recorded: true, total: Number.POSITIVE_INFINITY }],
    ])('denies when the store resolves %s', async (_label, value) => {
      const store = {
        consume: async () => value,
        total: () => 0,
      } as unknown as AmountLimitStore; // deliberately malformed store
      const result = await makePolicy({ store }).evaluate(pay(100));

      expect(result.decision).toBe('DENY');
      expect(result.code).toBe('amount_store_error');
      expect(result.reason).toBe('Amount store returned an invalid result');
    });

    it('does not touch the store without a period limit', async () => {
      const consume = vi.fn();
      const policy = new AmountLimitPolicy({
        currency: 'USD',
        maxPerRequest: 100,
        store: { consume, total: () => 0 },
      });
      await policy.evaluate(pay(50));

      expect(consume).not.toHaveBeenCalled();
    });

    it('evicts keys whose entries have aged out', async () => {
      vi.useFakeTimers();
      const store = new InMemoryAmountLimitStore();
      const policy = makePolicy({ store, periodMs: 60_000 });
      await policy.evaluate(pay(100, 'USD', { agentTokenHash: 'a' }));
      await policy.evaluate(pay(100, 'USD', { agentTokenHash: 'b' }));
      expect(store.size()).toBe(2);

      vi.advanceTimersByTime(60_000);
      await policy.evaluate(pay(100, 'USD', { agentTokenHash: 'c' }));

      expect(store.size()).toBe(1);
    });
  });

  describe('configuration', () => {
    it('requires a currency', () => {
      expect(() => makePolicy({ currency: '' })).toThrow(TypeError);
    });

    it('requires at least one limit', () => {
      expect(() => new AmountLimitPolicy({ currency: 'USD' })).toThrow(/maxPerRequest or maxPerPeriod/);
    });

    it('rejects non-integer limits', () => {
      expect(() => makePolicy({ maxPerRequest: 10.5 })).toThrow(/minor units/);
      expect(() => makePolicy({ perAgent: { a: { maxPerPeriod: -1 } } })).toThrow(/perAgent/);
    });

    it('rejects a non-positive periodMs', () => {
      expect(() => makePolicy({ periodMs: 0 })).toThrow(/periodMs/);
    });
  });

  describe('factory function', () => {
    it('creates a policy via factory', () => {
      const policy = amountLimitPolicy({ currency: 'USD', maxPerRequest: 100 });

      expect(policy).toBeInstanceOf(AmountLimitPolicy);
      expect(policy.name).toBe('amount-limit');
    });
  });

  describe('with CredGuard', () => {
    it('surfaces the typed code on deniedBy', async () => {
      const guard = new CredGuard({ policies: [makePolicy()] });
      const decision = await guard.evaluate(pay(10_001));

      expect(decision.allowed).toBe(false);
      expect(decision.deniedBy?.code).toBe('amount_exceeds_per_request');
    });

    it('stays closed on store errors even with onError allow', async () => {
      const store: AmountLimitStore = {
        consume: () => {
          throw new Error('boom');
        },
        total: () => 0,
      };
      const guard = new CredGuard({ policies: [makePolicy({ store })], onError: 'allow' });
      const decision = await guard.evaluate(pay(100));

      expect(decision.allowed).toBe(false);
      expect(decision.deniedBy?.code).toBe('amount_store_error');
    });

    it('stays closed on an invalid store result even with onError allow', async () => {
      const store = {
        consume: async () => null,
        total: () => 0,
      } as unknown as AmountLimitStore; // deliberately malformed store
      const guard = new CredGuard({ policies: [makePolicy({ store })], onError: 'allow' });
      const decision = await guard.evaluate(pay(100));

      expect(decision.allowed).toBe(false);
      expect(decision.deniedBy?.code).toBe('amount_store_error');
      expect(decision.deniedBy?.reason).toBe('Amount store returned an invalid result');
    });
  });
});

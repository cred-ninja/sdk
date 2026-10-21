/**
 * @credninja/guard: Amount Limit Policy
 *
 * Limit the monetary amounts an agent may act on: a per-request maximum and
 * a rolling per-period total per agent, in one currency. Amounts are integer
 * minor units (1050 is USD 10.50). Only allowed amounts count toward the
 * period total.
 *
 * Fails closed: missing amounts (unless onMissing: 'skip'), invalid amounts,
 * currency mismatches and store errors are DENY, and the policy never
 * throws, so GuardConfig.onError: 'allow' cannot turn an error into access.
 *
 * Period totals live in an AmountLimitStore. The default is in-memory and
 * resets on server restart; plug in a shared store for multiple instances.
 */

import type {
  AmountLimitConsumeResult,
  AmountLimitDenyCode,
  AmountLimitPolicyConfig,
  AmountLimitStore,
  AmountLimits,
  CredPolicy,
  GuardContext,
  PolicyResult,
} from '../types.js';

const DEFAULT_PERIOD_MS = 24 * 60 * 60 * 1000;

export interface AmountLimitPolicyResult extends PolicyResult {
  /** Set on every DENY */
  code?: AmountLimitDenyCode;
  /** The requested amount in minor units (present once it parsed) */
  amount?: number;
  /** The configured currency */
  currency: string;
  /** Per-request maximum that applied to this agent */
  maxPerRequest?: number;
  /** Period maximum that applied to this agent */
  maxPerPeriod?: number;
  /** Rolling period in milliseconds */
  periodMs: number;
  /** Agent's period total after this request (present when maxPerPeriod applies) */
  periodTotal?: number;
  /** Amount still available in the period (present when maxPerPeriod applies) */
  remaining?: number;
}

interface AmountEntry {
  at: number;
  amount: number;
}

/**
 * Default AmountLimitStore: per-key entry lists in memory. Resets on server
 * restart and is not shared between processes. consume is atomic because it
 * runs synchronously.
 */
export class InMemoryAmountLimitStore implements AmountLimitStore {
  private readonly entries: Map<string, AmountEntry[]> = new Map();
  private lastSweepAt = 0;

  consume(key: string, amount: number, at: number, since: number, max: number): AmountLimitConsumeResult {
    // Bound memory: sweep dead keys at most once per period
    this.evictStale(at, since);
    const live = (this.entries.get(key) ?? []).filter((entry) => entry.at > since);
    const total = sum(live);
    if (total + amount > max) {
      this.store(key, live);
      return { recorded: false, total };
    }
    // A zero amount changes no total, so keep no entry for it
    if (amount === 0) {
      this.store(key, live);
      return { recorded: true, total };
    }
    live.push({ at, amount });
    this.store(key, live);
    return { recorded: true, total: total + amount };
  }

  total(key: string, since: number): number {
    return sum((this.entries.get(key) ?? []).filter((entry) => entry.at > since));
  }

  /** Number of keys currently tracked. Useful for tests and for observing eviction. */
  size(): number {
    return this.entries.size;
  }

  /** Clear all totals. Useful for testing. */
  reset(): void {
    this.entries.clear();
  }

  private store(key: string, live: AmountEntry[]): void {
    if (live.length === 0) {
      this.entries.delete(key);
    } else {
      this.entries.set(key, live);
    }
  }

  private evictStale(now: number, since: number): void {
    if (now - this.lastSweepAt < now - since) return;
    this.lastSweepAt = now;
    for (const [key, list] of this.entries) {
      const newest = list[list.length - 1];
      if (newest === undefined || newest.at <= since) {
        this.entries.delete(key);
      }
    }
  }
}

export class AmountLimitPolicy implements CredPolicy {
  readonly name = 'amount-limit';
  private readonly config: AmountLimitPolicyConfig;
  private readonly currency: string;
  private readonly periodMs: number;
  private readonly store: AmountLimitStore;

  constructor(config: AmountLimitPolicyConfig) {
    if (typeof config?.currency !== 'string' || config.currency.trim().length === 0) {
      throw new TypeError('amountLimitPolicy requires a currency');
    }
    if (config.maxPerRequest === undefined && config.maxPerPeriod === undefined) {
      throw new TypeError('amountLimitPolicy requires maxPerRequest or maxPerPeriod');
    }
    validateLimits('amountLimitPolicy', config);
    for (const [id, limits] of Object.entries(config.perAgent ?? {})) {
      validateLimits(`amountLimitPolicy perAgent["${id}"]`, limits);
    }
    const periodMs = config.periodMs ?? DEFAULT_PERIOD_MS;
    if (!Number.isSafeInteger(periodMs) || periodMs <= 0) {
      throw new TypeError('amountLimitPolicy: periodMs must be a positive integer');
    }
    this.config = config;
    this.currency = config.currency.trim().toUpperCase();
    this.periodMs = periodMs;
    this.store = config.store ?? new InMemoryAmountLimitStore();
  }

  async evaluate(ctx: GuardContext): Promise<AmountLimitPolicyResult> {
    const base = { policy: this.name, currency: this.currency, periodMs: this.periodMs };

    let input: { amount?: unknown; currency?: unknown } | undefined;
    try {
      input = this.config.resolveAmount
        ? this.config.resolveAmount(ctx)
        : { amount: ctx.metadata?.amount, currency: ctx.metadata?.currency };
    } catch (error) {
      return { ...base, ...deny('amount_invalid', `Amount resolver failed: ${errorMessage(error)}`) };
    }

    const amount = input?.amount;
    if (amount === undefined || amount === null) {
      if (this.config.onMissing === 'skip') {
        return { ...base, decision: 'SKIP', reason: 'No amount present' };
      }
      return { ...base, ...deny('amount_missing', 'No amount present') };
    }
    if (typeof amount !== 'number' || !Number.isSafeInteger(amount) || amount < 0) {
      return {
        ...base,
        ...deny('amount_invalid', 'Amount must be a non-negative integer in minor units'),
      };
    }

    const currency = input?.currency;
    if (typeof currency !== 'string' || currency.trim().toUpperCase() !== this.currency) {
      const got = typeof currency === 'string' ? currency : 'none';
      return {
        ...base,
        amount,
        ...deny('currency_mismatch', `Currency ${got} does not match ${this.currency}`),
      };
    }

    const { maxPerRequest, maxPerPeriod } = this.resolveLimits(ctx);
    const limits = { ...base, amount, maxPerRequest, maxPerPeriod };

    if (maxPerRequest !== undefined && amount > maxPerRequest) {
      return {
        ...limits,
        ...deny(
          'amount_exceeds_per_request',
          `Amount ${amount} exceeds per-request limit ${maxPerRequest} ${this.currency}`,
        ),
      };
    }

    if (maxPerPeriod === undefined) {
      return {
        ...limits,
        decision: 'ALLOW',
        reason: `Amount ${amount} within per-request limit ${maxPerRequest} ${this.currency}`,
      };
    }

    // Check and record in one store call so only allowed amounts count
    const now = Date.now();
    let consumed: unknown;
    try {
      consumed = await this.store.consume(ctx.agentTokenHash, amount, now, now - this.periodMs, maxPerPeriod);
    } catch (error) {
      return { ...limits, ...deny('amount_store_error', `Amount store failed: ${errorMessage(error)}`) };
    }
    // Stores may be third-party code: never trust the result's shape
    if (!isConsumeResult(consumed)) {
      return { ...limits, ...deny('amount_store_error', 'Amount store returned an invalid result') };
    }

    const periodTotal = consumed.total;
    const remaining = Math.max(0, maxPerPeriod - periodTotal);
    if (!consumed.recorded) {
      return {
        ...limits,
        periodTotal,
        remaining,
        ...deny(
          'amount_exceeds_period',
          `Amount ${amount} would exceed period limit ${maxPerPeriod} ${this.currency} per ${this.periodMs}ms (used ${periodTotal})`,
        ),
      };
    }

    return {
      ...limits,
      periodTotal,
      remaining,
      decision: 'ALLOW',
      reason: `${periodTotal}/${maxPerPeriod} ${this.currency} used in period`,
    };
  }

  /**
   * Current period total for an agent token hash.
   */
  async getPeriodTotal(agentTokenHash: string): Promise<number> {
    return this.store.total(agentTokenHash, Date.now() - this.periodMs);
  }

  /**
   * Limits for this agent: policy defaults, overridden per field by perAgent
   * entries for agentTokenHash or, with trustAgentDid, agentDid (the lower
   * value when both match).
   */
  private resolveLimits(ctx: GuardContext): AmountLimits {
    const perAgent = this.config.perAgent ?? {};
    const ids = this.config.trustAgentDid ? [ctx.agentTokenHash, ctx.agentDid] : [ctx.agentTokenHash];
    const overrides = ids
      .filter((id): id is string => typeof id === 'string' && Object.hasOwn(perAgent, id))
      .map((id) => perAgent[id]);
    return {
      maxPerRequest: pickLimit(this.config.maxPerRequest, overrides.map((o) => o.maxPerRequest)),
      maxPerPeriod: pickLimit(this.config.maxPerPeriod, overrides.map((o) => o.maxPerPeriod)),
    };
  }
}

function isConsumeResult(value: unknown): value is AmountLimitConsumeResult {
  if (typeof value !== 'object' || value === null) return false;
  const { recorded, total } = value as Partial<Record<keyof AmountLimitConsumeResult, unknown>>; // narrowed by the checks below
  return typeof recorded === 'boolean' && typeof total === 'number' && Number.isFinite(total);
}

function pickLimit(fallback: number | undefined, overrides: Array<number | undefined>): number | undefined {
  const set = overrides.filter((value): value is number => value !== undefined);
  return set.length > 0 ? Math.min(...set) : fallback;
}

function validateLimits(label: string, limits: AmountLimits): void {
  for (const field of ['maxPerRequest', 'maxPerPeriod'] as const) {
    const value = limits?.[field];
    if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) {
      throw new TypeError(`${label}: ${field} must be a non-negative integer in minor units`);
    }
  }
}

function deny(code: AmountLimitDenyCode, reason: string): { decision: 'DENY'; code: AmountLimitDenyCode; reason: string } {
  return { decision: 'DENY', code, reason };
}

function sum(entries: AmountEntry[]): number {
  return entries.reduce((total, entry) => total + entry.amount, 0);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Factory function to create an amount limit policy.
 */
export function amountLimitPolicy(config: AmountLimitPolicyConfig): AmountLimitPolicy {
  return new AmountLimitPolicy(config);
}

/**
 * @credninja/guard — CredGuard class
 *
 * Policy evaluation engine for credential delegation guardrails.
 */

import type {
  CredPolicy,
  GuardAuditEvent,
  GuardConfig,
  GuardContext,
  GuardDecision,
  PolicyResult,
} from './types.js';
import { buildAuditEvent } from './audit.js';

export class CredGuard {
  private readonly policies: CredPolicy[];
  private readonly onError: 'deny' | 'allow' | 'log-and-deny';
  private readonly onDecision?: (ctx: GuardContext, results: PolicyResult[]) => void;
  private readonly decisionHistorySize: number;
  private readonly decisionHistory: GuardAuditEvent[] = [];

  constructor(config: GuardConfig) {
    this.policies = [...config.policies];
    this.onError = config.onError ?? 'deny';
    this.onDecision = config.onDecision;
    const size = config.decisionHistorySize ?? 0;
    this.decisionHistorySize = Number.isInteger(size) && size > 0 ? size : 0;
  }

  /**
   * Evaluate all policies against a request context.
   * Returns final decision with all policy results.
   */
  async evaluate(ctx: GuardContext): Promise<GuardDecision> {
    const startTime = performance.now();
    const results: PolicyResult[] = [];
    let effectiveScopes = [...ctx.requestedScopes];
    let deniedBy: PolicyResult | undefined;

    // No policies = ALLOW (opt-in guardrails)
    if (this.policies.length === 0) {
      const decision: GuardDecision = {
        allowed: true,
        results: [],
        effectiveScopes,
        evaluationMs: performance.now() - startTime,
      };
      this.remember(ctx, decision);
      this.onDecision?.(ctx, results);
      return decision;
    }

    // Evaluate policies in order
    for (const policy of this.policies) {
      const policyStart = performance.now();
      let result: PolicyResult;

      try {
        const evalResult = policy.evaluate({
          ...ctx,
          requestedScopes: effectiveScopes,
        });
        result = evalResult instanceof Promise ? await evalResult : evalResult;
        result.durationMs = performance.now() - policyStart;
      } catch (error) {
        // Handle policy errors based on config
        const errorMessage = error instanceof Error ? error.message : String(error);

        if (this.onError === 'allow') {
          result = {
            decision: 'ALLOW',
            policy: policy.name,
            reason: `Policy error (allowed): ${errorMessage}`,
            durationMs: performance.now() - policyStart,
          };
        } else {
          // 'deny' or 'log-and-deny'
          if (this.onError === 'log-and-deny') {
            console.error(`[guard] Policy "${policy.name}" threw:`, error);
          }
          result = {
            decision: 'DENY',
            policy: policy.name,
            reason: `Policy error: ${errorMessage}`,
            durationMs: performance.now() - policyStart,
          };
        }
      }

      // Validate result - invalid results are treated as DENY (fail-closed)
      if (!this.isValidResult(result)) {
        result = {
          decision: 'DENY',
          policy: policy.name,
          reason: 'Invalid policy result (fail-closed)',
          durationMs: result.durationMs,
        };
      }

      results.push(result);

      // Handle scope narrowing
      if (result.narrowedScopes) {
        effectiveScopes = result.narrowedScopes;
      }

      // First DENY short-circuits
      if (result.decision === 'DENY') {
        deniedBy = result;
        break;
      }
    }

    const decision: GuardDecision = {
      allowed: !deniedBy,
      results,
      deniedBy,
      effectiveScopes,
      evaluationMs: performance.now() - startTime,
    };

    this.remember(ctx, decision);
    this.onDecision?.(ctx, results);

    return decision;
  }

  /**
   * The most recent decisions, oldest first, when `decisionHistorySize` is
   * set. Empty otherwise. Read-only copies: mutating the result changes nothing.
   */
  recentDecisions(): GuardAuditEvent[] {
    return this.decisionHistory.map((event) => structuredClone(event));
  }

  /** The configured error disposition (`deny` by default). */
  getOnError(): 'deny' | 'allow' | 'log-and-deny' {
    return this.onError;
  }

  /**
   * The policy instances in evaluation order. Read-only view: the array is a
   * copy, the instances are the live ones.
   */
  getPolicies(): readonly CredPolicy[] {
    return [...this.policies];
  }

  private remember(ctx: GuardContext, decision: GuardDecision): void {
    if (this.decisionHistorySize === 0) return;
    this.decisionHistory.push(buildAuditEvent(ctx, decision));
    if (this.decisionHistory.length > this.decisionHistorySize) {
      this.decisionHistory.splice(0, this.decisionHistory.length - this.decisionHistorySize);
    }
  }

  /**
   * Add a policy at runtime (appended to end of chain).
   */
  addPolicy(policy: CredPolicy): void {
    this.policies.push(policy);
  }

  /**
   * Remove a policy by name.
   * Returns true if a policy was removed.
   */
  removePolicy(name: string): boolean {
    const index = this.policies.findIndex((p) => p.name === name);
    if (index !== -1) {
      this.policies.splice(index, 1);
      return true;
    }
    return false;
  }

  /**
   * Get current policy names in evaluation order.
   */
  getPolicyNames(): string[] {
    return this.policies.map((p) => p.name);
  }

  private isValidResult(result: PolicyResult): boolean {
    if (!result || typeof result !== 'object') return false;
    if (!['ALLOW', 'DENY', 'SKIP'].includes(result.decision)) return false;
    if (typeof result.policy !== 'string') return false;
    return true;
  }
}

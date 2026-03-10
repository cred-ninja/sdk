/**
 * @credninja/guard — CredGuard class
 *
 * Policy evaluation engine for credential delegation guardrails.
 */

import type {
  CredPolicy,
  GuardConfig,
  GuardContext,
  GuardDecision,
  PolicyResult,
} from './types.js';

export class CredGuard {
  private readonly policies: CredPolicy[];
  private readonly onError: 'deny' | 'allow' | 'log-and-deny';
  private readonly onDecision?: (ctx: GuardContext, results: PolicyResult[]) => void;

  constructor(config: GuardConfig) {
    this.policies = [...config.policies];
    this.onError = config.onError ?? 'deny';
    this.onDecision = config.onDecision;
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

    this.onDecision?.(ctx, results);

    return decision;
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

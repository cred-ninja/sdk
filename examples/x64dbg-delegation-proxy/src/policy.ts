/**
 * Per-tool-call authorization, built on @credninja/guard.
 *
 * We reuse Cred's policy engine rather than writing a parallel scope check:
 *   - scopeFilterPolicy does the subset check. We invert its usual framing:
 *     the "allowlist" for the service is the token's *granted* scopes, and the
 *     single "requested" scope is the scope this tool requires. scope-filter
 *     then denies exactly when requiredScope is not in the granted set.
 *   - a small custom tool-disposition policy handles deny/unknown tools before
 *     the subset check, so denials like ExecuteDebuggerCommand appear as their
 *     own line in the audit chain.
 *
 * The chain is fail-closed: guard treats a thrown/invalid policy result as DENY,
 * and the first DENY short-circuits.
 */

import {
  CredGuard,
  scopeFilterPolicy,
  buildAuditEvent,
  type CredPolicy,
  type GuardContext,
  type GuardAuditEvent,
} from '@credninja/guard';
import type { ScopeMap } from './scope-map.js';
import type { VerifiedToken } from './receipt.js';
import { checkArgs } from './arg-policy.js';

export interface ToolDecision {
  allowed: boolean;
  tool: string;
  requiredScope?: string;
  /** Reason from the deciding policy. */
  reason: string;
  /** Name of the policy that decided (e.g. tool-disposition, scope-filter). */
  policy: string;
  /** Structured guard event (reused for the audit line). */
  guardEvent: GuardAuditEvent;
}

/** Deny catch-all / unmapped tools before the scope subset check. */
function toolDispositionPolicy(map: ScopeMap): CredPolicy {
  return {
    name: 'tool-disposition',
    evaluate(ctx: GuardContext) {
      const tool = typeof ctx.metadata?.tool === 'string' ? ctx.metadata.tool : '';
      const disp = map.resolve(tool);
      if (disp.kind === 'deny') {
        return { decision: 'DENY', policy: this.name, reason: disp.reason };
      }
      if (disp.kind === 'unknown') {
        // unmappedPolicy=allow: defer to the scope check (which will allow when
        // no scope is required).
        return { decision: 'ALLOW', policy: this.name, reason: `unmapped tool "${tool}" (unmappedPolicy=allow)` };
      }
      return { decision: 'ALLOW', policy: this.name, reason: `${tool} requires ${disp.scope}` };
    },
  };
}

/**
 * Argument-level policy: after scope passes, bound *how much* the call may do.
 * Runs last so it only sees calls the scope already permits, and denies with the
 * specific argument violation.
 */
function argumentPolicy(map: ScopeMap): CredPolicy {
  return {
    name: 'argument-policy',
    evaluate(ctx: GuardContext) {
      const tool = typeof ctx.metadata?.tool === 'string' ? ctx.metadata.tool : '';
      const args = (ctx.metadata?.args ?? {}) as Record<string, unknown>;
      const result = checkArgs(map.argConstraints(tool), args);
      if (!result.ok) {
        return { decision: 'DENY', policy: this.name, reason: result.violations.join('; ') };
      }
      return { decision: 'ALLOW', policy: this.name, reason: 'arguments within policy' };
    },
  };
}

export async function evaluateToolCall(
  tool: string,
  args: Record<string, unknown>,
  token: VerifiedToken,
  service: string,
  map: ScopeMap,
): Promise<ToolDecision> {
  const disp = map.resolve(tool);
  const requiredScope = disp.kind === 'scope' ? disp.scope : undefined;

  const guard = new CredGuard({
    policies: [
      toolDispositionPolicy(map),
      scopeFilterPolicy({ allowedScopes: { [service]: token.scopes } }),
      argumentPolicy(map),
    ],
    onError: 'deny',
  });

  const ctx: GuardContext = {
    provider: service,
    agentTokenHash: token.tokenHash,
    requestedScopes: requiredScope ? [requiredScope] : [],
    consentedScopes: token.scopes,
    timestamp: new Date().toISOString(),
    delegationId: token.payload.delegationId,
    agentDid: token.subject,
    identitySource: 'did',
    metadata: { tool, args },
  };

  const decision = await guard.evaluate(ctx);
  const guardEvent = buildAuditEvent(ctx, decision);
  const deciding = decision.deniedBy ?? decision.results[decision.results.length - 1];

  return {
    allowed: decision.allowed,
    tool,
    requiredScope,
    reason: deciding?.reason ?? (decision.allowed ? 'allowed' : 'denied'),
    policy: deciding?.policy ?? 'none',
    guardEvent,
  };
}

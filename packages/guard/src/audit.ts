/**
 * @credninja/guard — Audit Event Builder
 *
 * Builds structured GuardAuditEvent objects for the audit pipeline.
 */

import type { GuardContext, GuardDecision, GuardAuditEvent } from './types.js';

/**
 * Build a structured audit event from a guard context and decision.
 * Compatible with the existing Ed25519 audit receipt chain.
 */
export function buildAuditEvent(ctx: GuardContext, decision: GuardDecision): GuardAuditEvent {
  return {
    type: 'guard.decision',
    timestamp: ctx.timestamp,
    agentTokenHash: ctx.agentTokenHash,
    provider: ctx.provider,
    allowed: decision.allowed,
    policies: decision.results.map((result) => ({
      name: result.policy,
      decision: result.decision,
      reason: result.reason,
      durationMs: result.durationMs ?? 0,
    })),
    requestedScopes: ctx.requestedScopes,
    effectiveScopes: decision.effectiveScopes,
    targetUrl: ctx.targetUrl,
    targetMethod: ctx.targetMethod,
  };
}

/**
 * Create a simple JSON log line for the guard decision.
 * Useful for structured logging.
 */
export function formatAuditLog(event: GuardAuditEvent): string {
  return JSON.stringify(event);
}

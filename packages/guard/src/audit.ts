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
  // `code`, `link` and the approval fields are spread in only when present,
  // so events for calls that involve none of them keep exactly their
  // previous shape.
  const approvedBy = decision.results.flatMap((result) =>
    result.decision === 'ALLOW' && typeof result.approvedBy === 'string' ? [result.approvedBy] : []);
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
      ...(typeof result.code === 'string' ? { code: result.code } : {}),
      durationMs: result.durationMs ?? 0,
    })),
    ...(typeof decision.deniedBy?.code === 'string' ? { code: decision.deniedBy.code } : {}),
    ...(decision.approvalRequired ? { approvalRequired: { ...decision.approvalRequired } } : {}),
    ...(approvedBy.length > 0 ? { approvedBy } : {}),
    ...(ctx.link ? { link: { ...ctx.link } } : {}),
    requestedScopes: ctx.requestedScopes,
    effectiveScopes: decision.effectiveScopes,
    targetUrl: ctx.targetUrl,
    targetMethod: ctx.targetMethod,
    identitySource: ctx.identitySource,
    agentDid: ctx.agentDid,
    tofuFingerprint: ctx.tofuFingerprint,
    webBotAuthKeyId: ctx.webBotAuthKeyId,
    signatureAgent: ctx.signatureAgent,
  };
}

/**
 * Create a simple JSON log line for the guard decision.
 * Useful for structured logging.
 */
export function formatAuditLog(event: GuardAuditEvent): string {
  return JSON.stringify(event);
}

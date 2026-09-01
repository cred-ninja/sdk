/**
 * Guard wiring for packages/mcp — bridges CredGuard policy evaluation into the
 * MCP tool layer via @credninja/guard's wrapMcpToolHandler.
 *
 * See docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md (U1) for
 * the scoping rules this file implements: which tools get wrapped in which
 * mode, why read-only introspection tools stay unwrapped, and why allow-path
 * responses must surface guard's computed TTL/rate-limit context.
 */

import crypto from 'node:crypto';
import { wrapMcpToolHandler } from '@credninja/guard';
import type {
  CredGuard,
  CredToolInput,
  McpToolContext,
  GuardDecision,
  MaxTtlPolicyResult,
  RateLimitPolicyResult,
} from '@credninja/guard';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

/** guard's own CallToolResult is a looser, package-local shape used only at
 * the wrapMcpToolHandler boundary; the MCP SDK's CallToolResult (above) is
 * what every real tool handler in this package actually returns and what
 * the server must register. The two are structurally compatible at runtime
 * (both are `{ content, isError? }`) — cast at the boundary rather than
 * letting guard's local type leak into this package's public surface. */
type GuardCallToolResult = import('@credninja/guard').CallToolResult;

/** Read-only self-diagnostic tools — never guard-wrapped, in either mode, so
 * they stay available to diagnose a guard-subsystem outage (see U1's Key
 * Technical Decisions). */
const GUARD_EXEMPT_TOOLS = new Set(['cred_audit_log', 'cred_whoami']);

/** Tools already covered by packages/server's own guard middleware in cloud
 * mode (/api/v1/delegate, /api/v1/subdelegate) — wrapping them again here
 * would create a second, independently-configured enforcement point that can
 * drift out of sync with the server-side one (see U1's Non-Goals). Keep this
 * in sync with `delegateRouteHandlers`/`subdelegateRouteHandlers` in
 * packages/server/src/server.ts, which carries the matching cross-reference
 * comment — if a new agent-facing route there gets `guardMiddleware`, its
 * corresponding MCP tool name belongs in this Set too. */
const CLOUD_SERVER_GUARDED_TOOLS = new Set(['cred_delegate', 'cred_subdelegate']);

export function shouldWrapWithGuard(toolName: string, mode: 'cloud' | 'local'): boolean {
  if (GUARD_EXEMPT_TOOLS.has(toolName)) return false;
  if (mode === 'cloud' && CLOUD_SERVER_GUARDED_TOOLS.has(toolName)) return false;
  return true;
}

/** Deterministic per-tool provider bucket for tools with no natural OAuth
 * provider dimension (status, capabilities, identity-lifecycle tools) — keeps
 * their rate-limit accounting independent of each other and of real
 * providers, rather than colliding under a single shared sentinel. */
export function syntheticProvider(toolName: string): string {
  return `_${toolName}`;
}

/**
 * Local mode has no agent token (it authenticates via vaultPassphrase), but
 * wrapMcpToolHandler hard-requires ctx.agentTokenHash. Derive a stable hash
 * from the configured agentDid so local-mode guard wrapping has an identity
 * to key rate limits on. Callers must treat an undefined agentDid as "skip
 * guard wrapping for this server instance" (see U1's Key Technical
 * Decisions) — this function does not handle that fallback itself.
 */
export function agentTokenHashForLocalMode(agentDid: string): string {
  return crypto.createHash('sha256').update(`agent-did:${agentDid}`).digest('hex');
}

/**
 * Cloud mode's identity source (the agent's Bearer token) is already what
 * `wrapMcpToolHandler` hashes internally (`ctx.agentTokenHash ||
 * hashToken(ctx.agentToken)`) when a tool call is guard-wrapped — this
 * mirrors that exact algorithm (sha256 of the raw token) so a value
 * precomputed here and placed on `toolContext.agentTokenHash` keys to the
 * same rate-limit bucket a guarded tool call would use. Needed so
 * `cred_whoami` (never wrapped) can read the same agent's rate-limit
 * counters directly, without guessing at a hash guard's own middleware
 * computes lazily per-call.
 */
export function agentTokenHashForCloudMode(agentToken: string): string {
  return crypto.createHash('sha256').update(agentToken).digest('hex');
}

export interface GuardResponseSummary {
  ttl?: { maxTtlSeconds: number; expiresAt: string };
  rateLimit?: { limit: number; windowMs: number; remaining: number };
}

/**
 * Extracts the structured TTL/rate-limit-headroom fields guard computed for
 * an allowed request, if the corresponding policies are configured. Tool
 * handlers call this with their own `context` (post `wrapMcpToolHandler`
 * mutates it with `guardDecision`) to surface the values in their success
 * response — wrapMcpToolHandler stashes the decision but does not itself
 * inject anything into the handler's response.
 */
export function summarizeGuardDecision(context: unknown): GuardResponseSummary | undefined {
  const decision = (context as { guardDecision?: GuardDecision } | undefined)?.guardDecision;
  if (!decision) return undefined;

  const summary: GuardResponseSummary = {};
  for (const result of decision.results) {
    if (result.decision !== 'ALLOW') continue;
    if (result.policy === 'max-ttl') {
      const r = result as MaxTtlPolicyResult;
      if (typeof r.maxTtlSeconds === 'number' && typeof r.expiresAt === 'string') {
        summary.ttl = { maxTtlSeconds: r.maxTtlSeconds, expiresAt: r.expiresAt };
      }
    }
    if (result.policy === 'rate-limit') {
      const r = result as RateLimitPolicyResult;
      if (typeof r.limit === 'number' && typeof r.windowMs === 'number' && typeof r.remaining === 'number') {
        summary.rateLimit = { limit: r.limit, windowMs: r.windowMs, remaining: r.remaining };
      }
    }
  }
  return summary.ttl || summary.rateLimit ? summary : undefined;
}

/** Structured denial payload instead of wrapMcpToolHandler's default
 * prose-only "Request denied by policy: X. Reason: Y" string, so an agent can
 * branch on `policy`/`reason` programmatically (mirrors U3's structured
 * CredError.code work for the same boundary). */
export function mcpOnDeny(
  _input: CredToolInput,
  _ctx: unknown,
  decision: GuardDecision,
): GuardCallToolResult {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          error: 'policy_denied',
          policy: decision.deniedBy?.policy,
          reason: decision.deniedBy?.reason,
        }),
      },
    ],
    isError: true,
  };
}

/**
 * Wraps `handler` with guard policy evaluation when `guard` is configured and
 * this tool is in scope for wrapping (see shouldWrapWithGuard); otherwise
 * returns `handler` unchanged, so registration is identical whether or not
 * guard is configured. `toGuardInput` adapts the tool's real input/context
 * into the `provider`/`scopes`/`targetUrl` shape wrapMcpToolHandler requires.
 */
export function wireGuardedTool<TInput extends object, TContext>(
  toolName: string,
  mode: 'cloud' | 'local',
  guard: CredGuard | undefined,
  handler: (input: TInput, ctx: TContext) => Promise<CallToolResult>,
  toGuardInput: (input: TInput, ctx: TContext) => Partial<CredToolInput>,
): (input: TInput, ctx: TContext) => Promise<CallToolResult> {
  if (!guard || !shouldWrapWithGuard(toolName, mode)) {
    return handler;
  }

  const wrapped = wrapMcpToolHandler(
    guard,
    handler as unknown as (input: CredToolInput, ctx: McpToolContext) => Promise<GuardCallToolResult>,
    { onDeny: mcpOnDeny },
  );

  return async (input: TInput, ctx: TContext): Promise<CallToolResult> => {
    const guardInput = { ...input, ...toGuardInput(input, ctx) } as unknown as CredToolInput;
    // wrapMcpToolHandler mutates its ctx argument in place (sets
    // guardDecision/guardAuditEvent) before calling the wrapped handler. `ctx`
    // here is normally the single toolContext object built once per MCP
    // server instance and shared across every call — mutating it directly
    // would let concurrent in-flight tool calls (the MCP SDK does not
    // serialize CallToolRequestSchema dispatch) clobber each other's guard
    // decision before the handler reads it back via summarizeGuardDecision.
    // A per-call shallow copy isolates each call's guard state while still
    // sharing the same underlying services (cred, tokenCache, etc.) by
    // reference.
    const perCallCtx = { ...ctx } as TContext;
    const result = await wrapped(guardInput, perCallCtx as unknown as McpToolContext);
    return result as unknown as CallToolResult;
  };
}

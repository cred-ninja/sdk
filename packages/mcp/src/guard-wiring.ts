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
 * drift out of sync with the server-side one (see U1's Non-Goals). */
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
    const result = await wrapped(guardInput, ctx as unknown as McpToolContext);
    return result as unknown as CallToolResult;
  };
}

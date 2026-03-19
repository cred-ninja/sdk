/**
 * @credninja/guard — MCP Tool Wrapper Adapter
 *
 * Wraps MCP tool handlers (cred_delegate, cred_use) with guard policy evaluation.
 */

import { createHash } from 'node:crypto';
import { CredGuard } from '../guard.js';
import type { GuardContext, GuardDecision } from '../types.js';
import { buildAuditEvent } from '../audit.js';

/** MCP tool result structure */
export interface CallToolResult {
  content: Array<{ type: string; text?: string; [key: string]: unknown }>;
  isError?: boolean;
}

/** MCP context passed to tool handlers */
export interface McpToolContext {
  /** Agent token (will be hashed) */
  agentToken?: string;
  /** Pre-hashed agent token */
  agentTokenHash?: string;
  /** Additional context from MCP server */
  [key: string]: unknown;
}

/** Input structure for credential tools */
export interface CredToolInput {
  provider: string;
  scopes?: string[];
  targetUrl?: string;
  targetMethod?: string;
  delegationId?: string;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

/** Options for MCP tool wrapper */
export interface McpWrapperOptions {
  /**
   * Called when guard allows the request.
   * Default: calls the wrapped handler.
   */
  onAllow?: (
    input: CredToolInput,
    ctx: McpToolContext,
    decision: GuardDecision,
    guardCtx: GuardContext
  ) => void;

  /**
   * Called when guard denies the request.
   * Default: returns error result.
   */
  onDeny?: (
    input: CredToolInput,
    ctx: McpToolContext,
    decision: GuardDecision,
    guardCtx: GuardContext
  ) => CallToolResult;
}

/**
 * Create a wrapped MCP tool handler with guard policy evaluation.
 */
export function wrapMcpToolHandler<TInput extends CredToolInput>(
  guard: CredGuard,
  handler: (input: TInput, ctx: McpToolContext) => Promise<CallToolResult>,
  options: McpWrapperOptions = {}
): (input: TInput, ctx: McpToolContext) => Promise<CallToolResult> {
  const { onDeny = defaultOnDeny } = options;

  return async (input: TInput, ctx: McpToolContext): Promise<CallToolResult> => {
    try {
      // Get or compute agent token hash
      const agentTokenHash = ctx.agentTokenHash || (ctx.agentToken ? hashToken(ctx.agentToken) : '');

      if (!agentTokenHash) {
        return {
          content: [{ type: 'text', text: 'Missing agent token' }],
          isError: true,
        };
      }

      // Build guard context
      const guardCtx: GuardContext = {
        provider: input.provider,
        agentTokenHash,
        requestedScopes: input.scopes || [],
        consentedScopes: input.scopes || [], // In MCP, scopes are pre-validated
        timestamp: new Date().toISOString(),
        targetUrl: input.targetUrl,
        targetMethod: input.targetMethod,
        delegationId: input.delegationId,
        metadata: input.metadata,
      };

      // Evaluate policies
      const decision = await guard.evaluate(guardCtx);

      // Attach audit event to context for logging
      const auditEvent = buildAuditEvent(guardCtx, decision);
      (ctx as any).guardAuditEvent = auditEvent;
      (ctx as any).guardDecision = decision;

      if (!decision.allowed) {
        return onDeny(input, ctx, decision, guardCtx);
      }

      // Update scopes if narrowed
      if (decision.effectiveScopes.length !== input.scopes?.length) {
        input.scopes = decision.effectiveScopes;
      }

      // Call the wrapped handler
      return await handler(input, ctx);
    } catch (error) {
      // Fail-closed: return error on guard failures
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: 'text', text: `Guard evaluation failed: ${message}` }],
        isError: true,
      };
    }
  };
}

function defaultOnDeny(
  _input: CredToolInput,
  _ctx: McpToolContext,
  decision: GuardDecision,
  _guardCtx: GuardContext
): CallToolResult {
  return {
    content: [
      {
        type: 'text',
        text: `Request denied by policy: ${decision.deniedBy?.policy}. Reason: ${decision.deniedBy?.reason}`,
      },
    ],
    isError: true,
  };
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Extend CredGuard class with MCP wrapper method.
 */
declare module '../guard.js' {
  interface CredGuard {
    wrapMcpTool<TInput extends CredToolInput>(
      handler: (input: TInput, ctx: McpToolContext) => Promise<CallToolResult>,
      options?: McpWrapperOptions
    ): (input: TInput, ctx: McpToolContext) => Promise<CallToolResult>;
  }
}

// Add method to prototype
CredGuard.prototype.wrapMcpTool = function <TInput extends CredToolInput>(
  this: CredGuard,
  handler: (input: TInput, ctx: McpToolContext) => Promise<CallToolResult>,
  options?: McpWrapperOptions
): (input: TInput, ctx: McpToolContext) => Promise<CallToolResult> {
  return wrapMcpToolHandler(this, handler, options);
};

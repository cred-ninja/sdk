/**
 * @credninja/guard — MCP Tool Wrapper Adapter
 *
 * Wraps MCP tool handlers (cred_delegate, cred_use) with guard policy evaluation.
 */

import { createHash } from 'node:crypto';
import { CredGuard } from '../guard.js';
import type { GuardContext, GuardDecision, GuardLinkContext } from '../types.js';
import { buildAuditEvent } from '../audit.js';
import { APPROVAL_REQUIRED_CODE, toGuardApproval } from '../policies/approval-required.js';

/** MCP tool result structure */
export interface CallToolResult {
  content: Array<{ type: string; text?: string; [key: string]: unknown }>;
  isError?: boolean;
  /** Machine-readable result (MCP structuredContent). The default deny sets it when the denying policy has a code. */
  structuredContent?: Record<string, unknown>;
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
  /** A human approval presented on retry (see approvalRequiredPolicy). Untrusted until verified. */
  approval?: unknown;
  [key: string]: unknown;
}

/** Options for MCP tool wrapper */
export interface McpWrapperOptions {
  /**
   * Supply the Cred Link context for calls that name a Link connection.
   * Build it from the MCP server's verified context only (`agentId` is the
   * authenticated principal), never from tool input. Default: none, so Link
   * policies SKIP.
   */
  resolveLinkContext?: (
    input: CredToolInput,
    ctx: McpToolContext,
  ) => GuardLinkContext | undefined | Promise<GuardLinkContext | undefined>;

  /**
   * Read the human approval presented with the call, if any. Values that are
   * not a well-formed GuardApproval are dropped; the policy verifies the rest.
   * Default: `input.approval`.
   */
  extractApproval?: (input: CredToolInput, ctx: McpToolContext) => unknown;

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

  /**
   * Called when the call is refused only because it needs human approval
   * (`decision.approvalRequired` is set; any DENY goes to onDeny instead).
   * Default: a custom onDeny when one is given, else an error result whose
   * structuredContent is `{ error: 'approval_required', code, approval, ... }`.
   */
  onApprovalRequired?: (
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
  const { onDeny = defaultOnDeny, resolveLinkContext, extractApproval = defaultExtractApproval } = options;
  // A custom onDeny keeps handling every refusal unless onApprovalRequired is given.
  const onApprovalRequired = options.onApprovalRequired
    ?? (options.onDeny ? options.onDeny : defaultOnApprovalRequired);

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

      const link = resolveLinkContext ? await resolveLinkContext(input, ctx) : undefined;
      const approval = toGuardApproval(extractApproval(input, ctx));

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
        identitySource: getStringMetadata(input.metadata, 'identitySource') as GuardContext['identitySource'] ?? 'agent-token',
        agentDid: getStringMetadata(input.metadata, 'agentDid'),
        tofuFingerprint: getStringMetadata(input.metadata, 'tofuFingerprint'),
        webBotAuthKeyId: getStringMetadata(input.metadata, 'webBotAuthKeyId'),
        signatureAgent: getStringMetadata(input.metadata, 'signatureAgent'),
        receiptClaims: getStringArrayMetadata(input.metadata, 'receiptClaims'),
        ...(link ? { link } : {}),
        ...(approval ? { approval } : {}),
      };

      // Evaluate policies
      const decision = await guard.evaluate(guardCtx);

      // Attach audit event to context for logging
      const auditEvent = buildAuditEvent(guardCtx, decision);
      (ctx as any).guardAuditEvent = auditEvent;
      (ctx as any).guardDecision = decision;

      if (!decision.allowed) {
        if (decision.approvalRequired) {
          return onApprovalRequired(input, ctx, decision, guardCtx);
        }
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
  const code = decision.deniedBy?.code;
  if (typeof code !== 'string') {
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
  return {
    content: [
      {
        type: 'text',
        text: `Request denied by policy: ${decision.deniedBy?.policy}. Reason: ${decision.deniedBy?.reason}. Code: ${code}`,
      },
    ],
    structuredContent: {
      error: 'policy_denied',
      code,
      policy: decision.deniedBy?.policy,
      reason: decision.deniedBy?.reason,
    },
    isError: true,
  };
}

function defaultExtractApproval(input: CredToolInput, _ctx: McpToolContext): unknown {
  return input.approval;
}

function defaultOnApprovalRequired(
  _input: CredToolInput,
  _ctx: McpToolContext,
  decision: GuardDecision,
  _guardCtx: GuardContext
): CallToolResult {
  const approval = decision.approvalRequired;
  return {
    content: [
      {
        type: 'text',
        text: `Approval required by policy: ${approval?.policy}. Reason: ${approval?.reason}. Code: ${APPROVAL_REQUIRED_CODE}`,
      },
    ],
    structuredContent: {
      error: APPROVAL_REQUIRED_CODE,
      code: APPROVAL_REQUIRED_CODE,
      policy: approval?.policy,
      reason: approval?.reason,
      approval,
    },
    isError: true,
  };
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function getStringMetadata(metadata: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = metadata?.[key];
  return typeof value === 'string' ? value : undefined;
}

function getStringArrayMetadata(metadata: Record<string, unknown> | undefined, key: string): string[] | undefined {
  const value = metadata?.[key];
  if (!Array.isArray(value)) {
    return undefined;
  }
  const claims = value.filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0);
  return claims.length > 0 ? claims : undefined;
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

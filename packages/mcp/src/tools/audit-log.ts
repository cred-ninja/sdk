/**
 * cred_audit_log Tool
 *
 * Read the calling agent's own audit trail. Wraps `Cred.getAuditLog`
 * (already implemented in packages/sdk) so an agent can inspect its own
 * history through its normal tool surface instead of an operator
 * hand-writing calls against GET /api/v1/audit.
 *
 * Read-only self-diagnostic tool — per U1's Key Technical Decisions
 * (docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md), this
 * tool is never guard-wrapped in either mode, so it stays available to
 * diagnose a guard-subsystem outage. It therefore has no `guardDecision` on
 * its context and does not call `summarizeGuardDecision`.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred } from '@credninja/sdk';
import { toolErrorResult } from '../tool-errors.js';

export const AUDIT_LOG_TOOL_NAME = 'cred_audit_log';

export const AUDIT_LOG_TOOL_DEFINITION = {
  name: AUDIT_LOG_TOOL_NAME,
  description:
    'Read the calling agent\'s own audit trail. ' +
    'Returns recent audit events (delegate, use, revoke, etc.), optionally filtered by service and capped by limit.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      user_id: {
        type: 'string',
        description: 'User identifier to read audit events for',
      },
      service: {
        type: 'string',
        description: 'Optional service slug to filter events by (e.g., "google", "github")',
      },
      limit: {
        type: 'number',
        description: 'Optional maximum number of events to return (server enforces its own cap)',
      },
    },
    required: ['user_id'],
  },
};

export interface AuditLogToolInput {
  user_id: string;
  service?: string;
  limit?: number;
}

export interface AuditLogToolContext {
  cred: Cred;
  appClientId: string;
}

export async function handleAuditLog(
  input: AuditLogToolInput,
  context: AuditLogToolContext,
): Promise<CallToolResult> {
  try {
    const entries = await context.cred.getAuditLog({
      userId: input.user_id,
      appClientId: context.appClientId,
      service: input.service,
      limit: input.limit,
    });

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ entries }, null, 2),
        },
      ],
    };
  } catch (error) {
    return toolErrorResult(error);
  }
}

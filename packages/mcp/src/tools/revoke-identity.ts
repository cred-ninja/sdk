/**
 * cred_revoke_identity Tool
 *
 * Revoke the calling agent's own identity (emergency self-revocation).
 * Defaults its target agentId to `context.selfAgentId` when the caller
 * doesn't supply one, matching cred_rotate_key's self-targeting default.
 *
 * Prerequisite (U4, per U1's Key Technical Decisions): this tool calls the
 * `revoke-all` HTTP route hardened by the companion ownership-check plan
 * (docs/plans/2026-08-31-002-fix-agent-ownership-check-plan.md), which
 * requires a verified identity for every caller including self-action. That
 * route only verifies a request when the MCP server itself is configured
 * with `webBotAuth` — without it, this tool returns a `403` even when
 * targeting the caller's own identity.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred, CredError } from '@credninja/sdk';
import { summarizeGuardDecision } from '../guard-wiring.js';
import { toolErrorResult } from '../tool-errors.js';

export const REVOKE_IDENTITY_TOOL_NAME = 'cred_revoke_identity';

export const REVOKE_IDENTITY_TOOL_DEFINITION = {
  name: REVOKE_IDENTITY_TOOL_NAME,
  description:
    'Revoke this agent\'s own identity (emergency self-revocation). ' +
    'Defaults to the MCP server\'s configured self agent identity when agent_id is omitted. ' +
    'After this call, subsequent delegate() calls with this agent\'s identity fail.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      agent_id: {
        type: 'string',
        description: 'Agent identity to revoke. Defaults to the server-configured self agent identity.',
      },
    },
  },
};

export interface RevokeIdentityToolInput {
  agent_id?: string;
}

export interface RevokeIdentityToolContext {
  cred: Cred;
  selfAgentId?: string;
}

export async function handleRevokeIdentity(
  input: RevokeIdentityToolInput,
  context: RevokeIdentityToolContext,
): Promise<CallToolResult> {
  try {
    const agentId = input.agent_id ?? context.selfAgentId;
    if (!agentId) {
      throw new CredError(
        'No agent_id provided and no selfAgentId configured on the MCP server.',
        'missing_agent_id',
        400,
      );
    }

    await context.cred.revokeAgent(agentId);

    const guard = summarizeGuardDecision(context);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            revoked: true,
            agentId,
            ...(guard ? { guard } : {}),
          }),
        },
      ],
    };
  } catch (error) {
    return toolErrorResult(error);
  }
}

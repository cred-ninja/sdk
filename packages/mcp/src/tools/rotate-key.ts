/**
 * cred_rotate_key Tool
 *
 * Rotate the calling agent's own Web Bot Auth signing key. Defaults its
 * target agentId to `context.selfAgentId` when the caller doesn't supply
 * one, so an agent can rotate its own key without knowing (or being trusted
 * to supply) any other agent's identifier.
 *
 * Prerequisite (U4, per U1's Key Technical Decisions): this tool calls the
 * `rotate` HTTP route hardened by the companion ownership-check plan
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

export const ROTATE_KEY_TOOL_NAME = 'cred_rotate_key';

export const ROTATE_KEY_TOOL_DEFINITION = {
  name: ROTATE_KEY_TOOL_NAME,
  description:
    'Rotate this agent\'s own Web Bot Auth signing key. ' +
    'Defaults to the MCP server\'s configured self agent identity when agent_id is omitted. ' +
    'Returns the new key\'s metadata plus the previous key\'s grace-period expiry.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      public_key: {
        type: 'string',
        description: 'Base64-encoded Ed25519 public key to rotate in',
      },
      agent_id: {
        type: 'string',
        description: 'Agent identity to rotate the key for. Defaults to the server-configured self agent identity.',
      },
      grace_period_hours: {
        type: 'number',
        description: 'How long the previous key remains valid after rotation, in hours',
      },
    },
    required: ['public_key'],
  },
};

export interface RotateKeyToolInput {
  public_key: string;
  agent_id?: string;
  grace_period_hours?: number;
}

export interface RotateKeyToolContext {
  cred: Cred;
  selfAgentId?: string;
}

export async function handleRotateKey(
  input: RotateKeyToolInput,
  context: RotateKeyToolContext,
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

    const identity = await context.cred.rotateWebBotAuthKey({
      agentId,
      publicKey: input.public_key,
      gracePeriodHours: input.grace_period_hours,
    });

    const guard = summarizeGuardDecision(context);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            ...identity,
            ...(guard ? { guard } : {}),
          }),
        },
      ],
    };
  } catch (error) {
    return toolErrorResult(error);
  }
}

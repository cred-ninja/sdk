/**
 * cred_status Tool
 *
 * Check the status of a user's service connections.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred } from '@credninja/sdk';
import { summarizeGuardDecision } from '../guard-wiring.js';
import { toolErrorResult } from '../tool-errors.js';

export const STATUS_TOOL_NAME = 'cred_status';

export const STATUS_TOOL_DEFINITION = {
  name: STATUS_TOOL_NAME,
  description:
    'Check the status of a user\'s service connections. ' +
    'Returns a list of connected services and their granted scopes.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      user_id: {
        type: 'string',
        description: 'User identifier to check connections for',
      },
    },
    required: ['user_id'],
  },
};

export interface StatusToolInput {
  user_id: string;
}

export interface StatusToolContext {
  cred: Cred;
  appClientId: string;
}

export async function handleStatus(
  input: StatusToolInput,
  context: StatusToolContext,
): Promise<CallToolResult> {
  try {
    const connections = await context.cred.getUserConnections(
      input.user_id,
      context.appClientId,
    );

    const guard = summarizeGuardDecision(context);
    const guardSuffix = guard ? `\n\nguard=${JSON.stringify(guard)}` : '';

    if (connections.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `No connected services found for this user.${guardSuffix}`,
          },
        ],
      };
    }

    // Format connections as a readable list
    const formatted = connections
      .map((conn) => {
        const scopes = conn.scopesGranted.length > 0
          ? conn.scopesGranted.join(', ')
          : 'no scopes';
        return `- ${conn.slug}: ${scopes}`;
      })
      .join('\n');

    return {
      content: [
        {
          type: 'text',
          text: `Connected services:\n${formatted}${guardSuffix}`,
        },
      ],
    };
  } catch (error) {
    return toolErrorResult(error);
  }
}

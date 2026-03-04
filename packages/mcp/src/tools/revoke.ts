/**
 * cred_revoke Tool
 *
 * Revoke a user's connection to a service.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred } from '@credninja/sdk';

export const REVOKE_TOOL_NAME = 'cred_revoke';

export const REVOKE_TOOL_DEFINITION = {
  name: REVOKE_TOOL_NAME,
  description:
    'Revoke a user\'s connection to a service. ' +
    'This removes the stored tokens and requires the user to re-authorize.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      user_id: {
        type: 'string',
        description: 'User identifier whose connection to revoke',
      },
      service: {
        type: 'string',
        description: 'Service slug to revoke (e.g., "google", "github")',
      },
    },
    required: ['user_id', 'service'],
  },
};

export interface RevokeToolInput {
  user_id: string;
  service: string;
}

export interface RevokeToolContext {
  cred: Cred;
  appClientId: string;
}

export async function handleRevoke(
  input: RevokeToolInput,
  context: RevokeToolContext,
): Promise<CallToolResult> {
  try {
    await context.cred.revoke({
      userId: input.user_id,
      service: input.service,
      appClientId: context.appClientId,
    });

    return {
      content: [
        {
          type: 'text',
          text: `Successfully revoked ${input.service} connection for user.`,
        },
      ],
    };
  } catch (error) {
    // Handle errors — return error message, don't crash
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${message}`,
        },
      ],
      isError: true,
    };
  }
}

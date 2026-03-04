/**
 * cred_delegate Tool
 *
 * Request a delegated access token for a service on behalf of a user.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred, ConsentRequiredError } from '@credninja/sdk';

export const DELEGATE_TOOL_NAME = 'cred_delegate';

export const DELEGATE_TOOL_DEFINITION = {
  name: DELEGATE_TOOL_NAME,
  description:
    'Request a delegated OAuth2 access token for a service on behalf of a user. ' +
    'Returns the access token if the user has granted consent, or a consent URL if not.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      user_id: {
        type: 'string',
        description: 'The user to delegate for',
      },
      service: {
        type: 'string',
        description: 'Service name: google, github, slack, notion, salesforce',
      },
      scopes: {
        type: 'array',
        items: { type: 'string' },
        description: 'OAuth scopes to request',
      },
    },
    required: ['user_id', 'service'],
  },
};

export interface DelegateToolInput {
  user_id: string;
  service: string;
  scopes?: string[];
}

export interface DelegateToolContext {
  cred: Cred;
  appClientId: string;
}

export async function handleDelegate(
  input: DelegateToolInput,
  context: DelegateToolContext,
): Promise<CallToolResult> {
  try {
    const result = await context.cred.delegate({
      userId: input.user_id,
      service: input.service,
      appClientId: context.appClientId,
      scopes: input.scopes,
    });

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            accessToken: result.accessToken,
            expiresIn: result.expiresIn,
          }),
        },
      ],
    };
  } catch (error) {
    // Handle consent required — return consent URL, don't throw
    if (error instanceof ConsentRequiredError) {
      return {
        content: [
          {
            type: 'text',
            text: `User needs to authorize. Send them to: ${error.consentUrl}`,
          },
        ],
      };
    }

    // Handle other errors — return error message, don't crash
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

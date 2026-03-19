/**
 * cred_delegate Tool
 *
 * Request a delegated access token for a service on behalf of a user.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred, ConsentRequiredError } from '@credninja/sdk';
import { TokenCache } from '../token-cache.js';

export const DELEGATE_TOOL_NAME = 'cred_delegate';

export const DELEGATE_TOOL_DEFINITION = {
  name: DELEGATE_TOOL_NAME,
  description:
    'Request delegated OAuth2 access for a service on behalf of a user. ' +
    'Returns a delegation handle (not the raw token) if consent has been granted, ' +
    'or a consent URL if the user needs to authorize. ' +
    'Pass the handle to cred_use to make authenticated API calls.',
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
  tokenCache: TokenCache;
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

    // Store the token in the local cache — never return the raw token to the LLM.
    // The LLM gets a delegation handle only. It passes this to cred_use to make
    // actual API calls. This prevents prompt injection from extracting the token.
    const now = Date.now();
    const expiresIn = result.expiresIn ?? 3600;
    const delegationId = context.tokenCache.store({
      accessToken: result.accessToken,
      service: input.service,
      userId: input.user_id,
      expiresAt: now + expiresIn * 1000,
    });

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            delegationId,
            service: result.service,
            expiresIn,
            note: 'Pass delegationId to cred_use to make authenticated API calls.',
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

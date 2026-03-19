/**
 * Cred Vercel AI SDK integration.
 *
 * Returns a Vercel AI SDK tool that agents can call to get delegated OAuth tokens.
 * The tool schema matches the Cred MCP tool spec:
 *
 *   name:   cred_delegate
 *   params: { service: string, scopes: string[] }
 *
 * userId and appClientId are pre-configured at factory time and are not
 * agent-controlled inputs.
 */

import { tool } from 'ai';
import { z } from 'zod';
import { Cred } from '@credninja/sdk';

export interface CredDelegateToolOptions {
  /** Agent token issued by Cred (starts with cred_at_) */
  agentToken: string;
  /** The user whose credentials to delegate */
  userId: string;
  /** The Cred app client ID to delegate for */
  appClientId: string;
  /** Your Cred server URL (e.g. https://cred.example.com or http://localhost:3456) */
  baseUrl?: string;
}

/**
 * Create a Vercel AI SDK tool for credential delegation.
 *
 * The returned tool is pre-configured with the user's identity and app context.
 * At runtime, the agent supplies `service` and `scopes`.
 *
 * @example
 * ```typescript
 * import { credDelegateTool } from '@credninja/ai';
 * import { generateText } from 'ai';
 *
 * const tool = credDelegateTool({
 *   agentToken: process.env.CRED_AGENT_TOKEN!,
 *   userId: 'user_123',
 *   appClientId: 'my_app',
 * });
 *
 * const result = await generateText({
 *   model: yourModel,
 *   tools: { cred_delegate: tool },
 *   prompt: 'Get my Google Calendar events',
 * });
 * ```
 */
export function credDelegateTool(options: CredDelegateToolOptions) {
  const { agentToken, userId, appClientId, baseUrl } = options;

  const cred = new Cred({
    agentToken,
    ...(baseUrl ? { baseUrl } : {}),
  });

  return tool({
    description:
      'Get a delegated OAuth access token for a third-party service ' +
      'on behalf of the current user. ' +
      'Returns access_token, token_type, expires_in, service, scopes, and delegation_id. ' +
      'Raises an error with consent_url if the user has not connected the service.',
    parameters: z.object({
      service: z
        .string()
        .describe("Service slug to get a token for (e.g. 'google', 'github', 'google-calendar')."),
      scopes: z
        .array(z.string())
        .describe(
          "OAuth scopes to request (e.g. ['calendar.readonly']). " +
            'Pass an empty array to use all consented scopes.',
        ),
    }),
    execute: async ({ service, scopes }) => {
      const result = await cred.delegate({
        service,
        userId,
        appClientId,
        scopes: scopes.length > 0 ? scopes : undefined,
      });

      return {
        accessToken: result.accessToken,
        tokenType: result.tokenType,
        expiresIn: result.expiresIn,
        service: result.service,
        scopes: result.scopes,
        delegationId: result.delegationId,
      };
    },
  });
}

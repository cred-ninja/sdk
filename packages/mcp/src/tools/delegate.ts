/**
 * cred_delegate Tool
 *
 * Request a delegated access token for a service on behalf of a user.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred, ConsentRequiredError } from '@credninja/sdk';
import { TokenCache } from '../token-cache.js';
import { summarizeGuardDecision } from '../guard-wiring.js';
import { toolErrorResult } from '../tool-errors.js';

export const DELEGATE_TOOL_NAME = 'cred_delegate';

export const DELEGATE_TOOL_DEFINITION = {
  name: DELEGATE_TOOL_NAME,
  description:
    'Request delegated OAuth2 access for a service on behalf of a user. ' +
    'Returns a delegation handle (not the raw token) and, when the MCP server is configured with an agent identity, a signed delegation receipt for handoff/sub-delegation. ' +
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
      constraints: {
        type: 'array',
        items: { type: 'object' },
        description: 'Constraint wire objects. Unknown types are preserved but cannot be exercised.',
      },
    },
    required: ['user_id', 'service'],
  },
};

export interface DelegateToolInput {
  user_id: string;
  service: string;
  scopes?: string[];
  constraints?: unknown[];
}

export interface DelegateToolContext {
  cred: Cred;
  appClientId: string;
  agentDid?: string;
  tokenCache: TokenCache;
  useServerBroker?: boolean;
  /**
   * This agent's own identity (cloud mode, CRED_AGENT_PRIVATE_KEY_HEX).
   * A brokered handle is bound to its key: the server requires a DPoP proof
   * by it when the handle is issued and each time it is used.
   */
  delegatorIdentity?: { did: string; privateKey: Uint8Array };
}

export async function handleDelegate(
  input: DelegateToolInput,
  context: DelegateToolContext,
): Promise<CallToolResult> {
  try {
    const request = {
      userId: input.user_id,
      service: input.service,
      appClientId: context.appClientId,
      scopes: input.scopes,
      agentDid: context.agentDid,
      ...(input.constraints !== undefined ? { constraints: input.constraints } : {}),
    };
    const result = context.useServerBroker
      ? await context.cred.delegateHandle({
        ...request,
        ...(context.delegatorIdentity ? { agentIdentity: context.delegatorIdentity } : {}),
      })
      : await context.cred.delegate(request);

    // Store either the local token or the server-side broker handle in the local
    // cache — never return a raw provider token to the LLM.
    const now = Date.now();
    const expiresIn = result.expiresIn ?? 3600;
    const delegationId = context.tokenCache.store(context.useServerBroker
      ? {
          brokered: true,
          serverDelegationId: result.delegationId,
          ...(input.constraints !== undefined ? { constraints: input.constraints } : {}),
          service: input.service,
          userId: input.user_id,
          scopes: result.scopes,
          expiresAt: now + expiresIn * 1000,
        }
      : {
          accessToken: (result as Awaited<ReturnType<Cred['delegate']>>).accessToken,
          ...(input.constraints !== undefined ? { constraints: input.constraints } : {}),
          service: input.service,
          userId: input.user_id,
          scopes: result.scopes,
          expiresAt: now + expiresIn * 1000,
        });

    const guard = summarizeGuardDecision(context);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            delegationId,
            service: result.service,
            expiresIn,
            ...(result.receipt ? { receipt: result.receipt } : {}),
            ...(guard ? { guard } : {}),
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

    // Handle other errors — return a structured error, don't crash
    return toolErrorResult(error);
  }
}

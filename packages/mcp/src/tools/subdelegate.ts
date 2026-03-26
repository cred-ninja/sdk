/**
 * cred_subdelegate Tool
 *
 * Creates a child delegation from a signed parent receipt and returns a new
 * delegation handle plus the attenuated child receipt.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred } from '@credninja/sdk';
import { TokenCache } from '../token-cache.js';

export const SUBDELEGATE_TOOL_NAME = 'cred_subdelegate';

export const SUBDELEGATE_TOOL_DEFINITION = {
  name: SUBDELEGATE_TOOL_NAME,
  description:
    'Create a child delegation from a signed parent receipt. ' +
    'Returns a delegation handle for local token use plus a child receipt for further handoff.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      parent_receipt: {
        type: 'string',
        description: 'Signed parent delegation receipt.',
      },
      agent_did: {
        type: 'string',
        description: 'Stable identifier for the child agent receiving the delegation.',
      },
      user_id: {
        type: 'string',
        description: 'The user to delegate for.',
      },
      service: {
        type: 'string',
        description: 'Service name: google, github, slack, notion, salesforce',
      },
      scopes: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional subset of the parent receipt scopes.',
      },
    },
    required: ['parent_receipt', 'agent_did', 'user_id', 'service'],
  },
};

export interface SubdelegateToolInput {
  parent_receipt: string;
  agent_did: string;
  user_id: string;
  service: string;
  scopes?: string[];
}

export interface SubdelegateToolContext {
  cred: Cred;
  appClientId: string;
  tokenCache: TokenCache;
}

export async function handleSubdelegate(
  input: SubdelegateToolInput,
  context: SubdelegateToolContext,
): Promise<CallToolResult> {
  try {
    const result = await context.cred.subDelegate({
      parentReceipt: input.parent_receipt,
      agentDid: input.agent_did,
      userId: input.user_id,
      service: input.service,
      appClientId: context.appClientId,
      scopes: input.scopes,
    });

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
            receipt: result.receipt,
            chainDepth: result.chainDepth,
            parentDelegationId: result.parentDelegationId,
            note: 'Pass delegationId to cred_use to make authenticated API calls.',
          }),
        },
      ],
    };
  } catch (error) {
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

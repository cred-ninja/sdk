/**
 * cred_register_identity Tool
 *
 * Register (or import) a Web Bot Auth signing key for this agent's own
 * identity, so it can be recognized and rate/scope-limited on future
 * delegation requests without an operator hand-writing the registration
 * HTTP call.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred } from '@credninja/sdk';
import { summarizeGuardDecision } from '../guard-wiring.js';
import { toolErrorResult } from '../tool-errors.js';

export const REGISTER_IDENTITY_TOOL_NAME = 'cred_register_identity';

export const REGISTER_IDENTITY_TOOL_DEFINITION = {
  name: REGISTER_IDENTITY_TOOL_NAME,
  description:
    'Register or import a Web Bot Auth public signing key for this agent. ' +
    'Returns the registered key\'s metadata (agentId, fingerprint, keyId, status).',
  inputSchema: {
    type: 'object' as const,
    properties: {
      public_key: {
        type: 'string',
        description: 'Base64-encoded Ed25519 public key to register',
      },
      initial_scopes: {
        type: 'array',
        items: { type: 'string' },
        description: 'Scopes this identity is initially permitted to request',
      },
      metadata: {
        type: 'object',
        description: 'Arbitrary operator-supplied metadata to associate with this identity',
      },
    },
    required: ['public_key'],
  },
};

export interface RegisterIdentityToolInput {
  public_key: string;
  initial_scopes?: string[];
  metadata?: Record<string, unknown>;
}

export interface RegisterIdentityToolContext {
  cred: Cred;
}

export async function handleRegisterIdentity(
  input: RegisterIdentityToolInput,
  context: RegisterIdentityToolContext,
): Promise<CallToolResult> {
  try {
    const identity = await context.cred.registerWebBotAuthKey({
      publicKey: input.public_key,
      initialScopes: input.initial_scopes,
      metadata: input.metadata,
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

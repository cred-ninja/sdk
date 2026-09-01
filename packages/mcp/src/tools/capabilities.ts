/**
 * cred_capabilities Tool
 *
 * Discover which providers (and their default scopes) are configured on this
 * deployment. Wraps `Cred.listProviders` so an agent can learn what's
 * available before calling cred_delegate/cred_subdelegate, instead of
 * guessing from static tool-description text and only finding out about a
 * mismatch via a consent_required/scope_ceiling_exceeded error.
 *
 * Unlike cred_audit_log/cred_whoami, this tool has no natural read-only
 * exemption from guard — it's guard-wrapped from day one (per U1's Key
 * Technical Decisions), using a synthetic provider bucket since discovery
 * itself has no single provider dimension to key on.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { Cred } from '@credninja/sdk';
import { summarizeGuardDecision } from '../guard-wiring.js';
import { toolErrorResult } from '../tool-errors.js';

export const CAPABILITIES_TOOL_NAME = 'cred_capabilities';

export const CAPABILITIES_TOOL_DEFINITION = {
  name: CAPABILITIES_TOOL_NAME,
  description:
    'Discover which providers are configured on this deployment, and their default scopes. ' +
    'Use this before cred_delegate/cred_subdelegate to avoid guessing a provider slug or scope set.',
  inputSchema: {
    type: 'object' as const,
    properties: {},
  },
};

export type CapabilitiesToolInput = Record<string, never>;

export interface CapabilitiesToolContext {
  cred: Cred;
}

export async function handleCapabilities(
  _input: CapabilitiesToolInput,
  context: CapabilitiesToolContext,
): Promise<CallToolResult> {
  try {
    const providers = await context.cred.listProviders();
    const guard = summarizeGuardDecision(context);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(guard ? { providers, guard } : { providers }, null, 2),
        },
      ],
    };
  } catch (error) {
    return toolErrorResult(error);
  }
}

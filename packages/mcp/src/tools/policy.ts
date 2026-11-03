/**
 * cred_policy_inspect / cred_policy_propose / cred_policy_apply
 *
 * The weight-space surface of the guard, exposed to the agent. All three
 * exist only when the operator configures a `PolicyWeightSpaceEditor` on
 * the MCP server (`config.policyEditor`); a server without one lists none
 * of them, so the default surface is unchanged.
 *
 * - `cred_policy_inspect` reads the live policy chain as data, what it
 *   means, and where it disagrees with recent traffic. Read-only and, like
 *   `cred_whoami`, never guard-wrapped: diagnosing a guard outage is what
 *   it is for.
 * - `cred_policy_propose` dry-runs a minimal patch: validates it, classifies
 *   it (widening or narrowing), measures it (leaves touched over leaves
 *   total), and replays recorded decisions through the patched chain. It
 *   never changes the guard. Guard-wrapped and rate-limited like any other
 *   mutating tool.
 * - `cred_policy_apply` applies a pending proposal under the editor's
 *   approval rules. The agent can carry a human's signed approval, but it
 *   cannot produce one: approval keys never live on the agent's host.
 */

import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { PolicyPatch, PolicyWeightSpaceEditor, ProposalApproval } from '@credninja/guard';
import { PatchError } from '@credninja/guard';
import { toolErrorResult } from '../tool-errors.js';

export const POLICY_INSPECT_TOOL_NAME = 'cred_policy_inspect';
export const POLICY_PROPOSE_TOOL_NAME = 'cred_policy_propose';
export const POLICY_APPLY_TOOL_NAME = 'cred_policy_apply';

const PATCH_OP_SCHEMA = {
  type: 'object' as const,
  properties: {
    op: { type: 'string', enum: ['add', 'remove', 'replace'] },
    path: {
      type: 'string',
      description:
        'JSON Pointer: "/onError", "/<policy>" for a whole policy ({ kind, parameters }), or ' +
        '"/<policy>/<pointer into its parameters>" such as "/scope-filter/allowedScopes/github/-".',
    },
    value: { description: 'The value for add and replace. Omit for remove.' },
  },
  required: ['op', 'path'],
};

export const POLICY_INSPECT_TOOL_DEFINITION = {
  name: POLICY_INSPECT_TOOL_NAME,
  description:
    'Read the guard\'s policy chain as data: a hashed snapshot of every policy\'s parameters, a plain-language ' +
    'interpretation of what each provider may do, and findings where the configuration disagrees with recent ' +
    'traffic (unused scopes, unhit URL patterns, unconstrained providers, slack rate limits, repeated denials), ' +
    'each with the smallest patch that addresses it. Read-only; always available.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      include: {
        type: 'array',
        items: { type: 'string', enum: ['snapshot', 'interpretation', 'diagnosis'] },
        description: 'Sections to return. Default: all three.',
      },
    },
  },
};

export const POLICY_PROPOSE_TOOL_DEFINITION = {
  name: POLICY_PROPOSE_TOOL_NAME,
  description:
    'Dry-run a minimal patch to the guard\'s policy chain. Returns a proposal with its id, the snapshot hash it ' +
    'applies to, its effect (widening, narrowing, neutral, unknown, mixed), its magnitude (parameters touched ' +
    'over parameters total), and a replay of recent decisions showing which would flip. Never changes the guard. ' +
    'Prefer one-leaf ops (add one scope, remove one pattern) over replacing whole tables.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      patch: { type: 'array', items: PATCH_OP_SCHEMA, description: 'Ops applied in order, all or nothing.' },
      rationale: { type: 'string', description: 'Why this change, in one or two sentences, for the approver.' },
    },
    required: ['patch', 'rationale'],
  },
};

export const POLICY_APPLY_TOOL_DEFINITION = {
  name: POLICY_APPLY_TOOL_NAME,
  description:
    'Apply a pending proposal from cred_policy_propose, under the editor\'s approval rules. By default every patch ' +
    'needs a signed approval from a configured approver (an Ed25519 signature over the proposal hash, made ' +
    'outside this agent). The proposal must still match the live chain; if the chain changed, propose again.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      proposal_id: { type: 'string', description: 'The id returned by cred_policy_propose (pp_...).' },
      approvals: {
        type: 'array',
        description: 'Signed approvals, each { approver, signature, signedAt }, produced by an approver key holder.',
        items: {
          type: 'object' as const,
          properties: {
            approver: { type: 'string' },
            signature: { type: 'string', description: 'base64url Ed25519 signature over "cred-policy-proposal-v1:" + proposal hash' },
            signedAt: { type: 'string' },
          },
          required: ['approver', 'signature', 'signedAt'],
        },
      },
    },
    required: ['proposal_id'],
  },
};

export interface PolicyInspectToolInput {
  include?: Array<'snapshot' | 'interpretation' | 'diagnosis'>;
}

export interface PolicyProposeToolInput {
  patch: PolicyPatch;
  rationale: string;
}

export interface PolicyApplyToolInput {
  proposal_id: string;
  approvals?: ProposalApproval[];
}

export interface PolicyToolContext {
  policyEditor?: PolicyWeightSpaceEditor;
  /** The calling agent's identity, recorded as the proposer. */
  agentDid?: string;
  selfAgentId?: string;
  agentTokenHash?: string;
}

function json(value: unknown, isError = false): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }], ...(isError ? { isError: true } : {}) };
}

function noEditor(): CallToolResult {
  return json({ error: 'policy_editor_not_configured', message: 'This server has no PolicyWeightSpaceEditor configured.' }, true);
}

function proposerFor(context: PolicyToolContext): string {
  return context.agentDid ?? context.selfAgentId ?? (context.agentTokenHash ? `agent-token:${context.agentTokenHash.slice(0, 16)}` : 'mcp-agent');
}

export async function handlePolicyInspect(input: PolicyInspectToolInput, context: PolicyToolContext): Promise<CallToolResult> {
  try {
    if (!context.policyEditor) return noEditor();
    const sections = new Set(input?.include && input.include.length > 0 ? input.include : ['snapshot', 'interpretation', 'diagnosis']);
    const result = context.policyEditor.inspect();
    return json({
      ...(sections.has('snapshot') ? { snapshot: result.snapshot } : { snapshotHash: result.snapshot.hash }),
      ...(sections.has('interpretation') ? { interpretation: result.interpretation } : {}),
      ...(sections.has('diagnosis') ? { diagnosis: result.diagnosis } : {}),
    });
  } catch (error) {
    return toolErrorResult(error);
  }
}

export async function handlePolicyPropose(input: PolicyProposeToolInput, context: PolicyToolContext): Promise<CallToolResult> {
  try {
    if (!context.policyEditor) return noEditor();
    if (!Array.isArray(input?.patch) || input.patch.length === 0) {
      return json({ error: 'invalid_patch', message: 'patch must be a non-empty array of ops' }, true);
    }
    if (typeof input.rationale !== 'string' || input.rationale.trim().length === 0) {
      return json({ error: 'invalid_rationale', message: 'rationale is required' }, true);
    }
    const proposal = await context.policyEditor.propose({ patch: input.patch, rationale: input.rationale, proposer: proposerFor(context) });
    return json({
      proposal,
      approvalRequired: context.policyEditor.approvalRequired(proposal),
      next:
        'Review the classification and dryRun. ' +
        (context.policyEditor.approvalRequired(proposal)
          ? 'Hand the proposal id and hash to an approver; call cred_policy_apply with their signed approval.'
          : 'Call cred_policy_apply with the proposal id.'),
    });
  } catch (error) {
    if (error instanceof PatchError) {
      return json({ error: 'invalid_patch', opIndex: error.opIndex, message: error.message }, true);
    }
    if (error instanceof Error && /must be|cannot be|no factory|not a valid|is not an? /.test(error.message)) {
      return json({ error: 'invalid_patch', message: error.message }, true);
    }
    return toolErrorResult(error);
  }
}

export async function handlePolicyApply(input: PolicyApplyToolInput, context: PolicyToolContext): Promise<CallToolResult> {
  try {
    if (!context.policyEditor) return noEditor();
    if (typeof input?.proposal_id !== 'string') {
      return json({ error: 'invalid_input', message: 'proposal_id is required' }, true);
    }
    const approvals = Array.isArray(input.approvals) ? input.approvals : [];
    for (const approval of approvals) {
      if (!approval || typeof approval.approver !== 'string' || typeof approval.signature !== 'string' || typeof approval.signedAt !== 'string') {
        return json({ error: 'invalid_input', message: 'each approval needs approver, signature and signedAt' }, true);
      }
    }
    const result = await context.policyEditor.apply(input.proposal_id, approvals);
    if (!result.applied) {
      return json({ error: result.code, message: result.message, ...(result.proposal ? { proposalId: result.proposal.id } : {}) }, true);
    }
    return json({
      applied: true,
      proposalId: result.proposal.id,
      approvers: result.approvers,
      rebuilt: result.rebuilt,
      kept: result.kept,
      snapshotHash: result.snapshot.hash,
      policies: result.snapshot.policies.map((entry) => entry.name),
    });
  } catch (error) {
    return toolErrorResult(error);
  }
}

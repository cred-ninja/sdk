/**
 * cred_whoami Tool
 *
 * Read-only self-introspection: reports the calling agent's active guard
 * policy names, remaining rate-limit headroom, and (best-effort, cloud mode
 * only) its own effective delegated scopes — so an agent or operator can
 * answer "what am I currently allowed to do" at runtime. Distinct from the
 * existing cred_status, which reports a *user's* connection state, not the
 * calling agent's own permission state.
 *
 * Read-only self-diagnostic tool — per U1's Key Technical Decisions
 * (docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md), this
 * tool is never guard-wrapped in either mode, so it stays available to
 * diagnose a guard-subsystem outage. It therefore has no `guardDecision` on
 * its context and does not call `summarizeGuardDecision`.
 *
 * Because it must survive a guard outage, its guard-derived fields are read
 * directly off the `CredGuard`/`RateLimitPolicy` instances' live state
 * rather than by calling `guard.evaluate()` — an `evaluate()` call could
 * itself be denied, or consume a rate-limit slot just to report how many
 * are left, exactly the failure this tool exists to diagnose around.
 * `CredGuard` exposes policy *names* via the public `getPolicyNames()`, but
 * has no public accessor for a configured policy *instance* (there's no
 * `guard.getPolicy(name)`). Reaching into the private `policies` array via a
 * type cast is the direct-read path U10 calls for — the only way to reach
 * live per-agent rate-limit counters without a full `evaluate()` call, and
 * without adding new public surface to `@credninja/guard` for a single
 * introspection caller.
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { CredGuard } from '@credninja/guard';
import { RateLimitPolicy } from '@credninja/guard';
import { Cred } from '@credninja/sdk';
import { toolErrorResult } from '../tool-errors.js';

export const WHOAMI_TOOL_NAME = 'cred_whoami';

export const WHOAMI_TOOL_DEFINITION = {
  name: WHOAMI_TOOL_NAME,
  description:
    'Introspect the calling agent\'s own runtime permission state: active guard policy names, ' +
    'remaining rate-limit headroom, and (where available) its own effective delegated scopes. ' +
    'Read-only and always available, including during a guard-subsystem outage.',
  inputSchema: {
    type: 'object' as const,
    properties: {},
  },
};

export type WhoamiToolInput = Record<string, never>;

export interface WhoamiToolContext {
  cred?: Cred;
  guard?: CredGuard;
  agentTokenHash?: string;
  selfAgentId?: string;
}

interface RateLimitHeadroom {
  /** The provider/synthetic bucket this counter is scoped to (see
   *  `syntheticProvider()` in guard-wiring.ts for non-OAuth tools). */
  provider: string;
  limit: number;
  windowMs: number;
  remaining: number;
}

/**
 * Minimal shape of RateLimitPolicy's private fields this direct-read path
 * needs. Kept narrow and local to this file rather than exported from
 * @credninja/guard, since it's a read-only introspection shortcut, not a
 * contract other callers should depend on.
 */
interface RateLimitPolicyInternals {
  requests: Map<string, { timestamps: number[] }>;
  config: {
    maxRequests: number;
    windowMs: number;
    perProvider?: Record<string, { maxRequests: number; windowMs: number }>;
  };
}

/**
 * Reads current rate-limit usage directly off the guard's configured
 * RateLimitPolicy (if any is present among `guard`'s policies), for every
 * provider bucket this agent has already made a request against. Returns
 * `[]` when guard has no rate-limit policy configured — distinct from
 * `undefined`, which callers use to mean "no guard at all."
 */
function getRateLimitHeadroom(guard: CredGuard, agentTokenHash: string): RateLimitHeadroom[] {
  const policies = (guard as unknown as { policies: Array<{ name: string }> }).policies ?? [];
  const rateLimit = policies.find((p) => p.name === 'rate-limit') as RateLimitPolicy | undefined;
  if (!rateLimit) return [];

  const internals = rateLimit as unknown as RateLimitPolicyInternals;
  const prefix = `${agentTokenHash}:`;
  const providers = new Set<string>();
  for (const key of internals.requests.keys()) {
    if (key.startsWith(prefix)) {
      providers.add(key.slice(prefix.length));
    }
  }

  return [...providers].map((provider) => {
    const limits = internals.config.perProvider?.[provider] ?? {
      maxRequests: internals.config.maxRequests,
      windowMs: internals.config.windowMs,
    };
    const used = rateLimit.getCount(agentTokenHash, provider);
    return {
      provider,
      limit: limits.maxRequests,
      windowMs: limits.windowMs,
      remaining: Math.max(0, limits.maxRequests - used),
    };
  });
}

export async function handleWhoami(
  _input: WhoamiToolInput,
  context: WhoamiToolContext,
): Promise<CallToolResult> {
  try {
    const response: {
      guardPolicies?: string[];
      rateLimit?: RateLimitHeadroom[];
      effectiveScopes?: string[];
    } = {};

    if (context.guard) {
      response.guardPolicies = context.guard.getPolicyNames();

      if (context.agentTokenHash) {
        try {
          response.rateLimit = getRateLimitHeadroom(context.guard, context.agentTokenHash);
        } catch {
          // Reading guard's internal state is a best-effort direct-read
          // shortcut (see file header) — never fail whoami over it, that
          // would defeat the tool's entire outage-survival purpose.
        }
      }
    }

    // Best-effort "effective scopes": the union of allowedScopes across every
    // Permission record for this agent. Cloud-mode-only (listPermissions
    // throws in local mode) and requires selfAgentId to be configured, so
    // this silently omits rather than errors when either is unavailable —
    // there's no single, always-available "current effective scopes" source
    // outside of an actual delegation context (see U10's note in the plan).
    if (context.cred && context.selfAgentId) {
      try {
        const permissions = await context.cred.listPermissions(context.selfAgentId);
        const scopes = new Set<string>();
        for (const permission of permissions) {
          for (const scope of permission.allowedScopes) scopes.add(scope);
        }
        response.effectiveScopes = [...scopes];
      } catch {
        // Local mode, or no permissions endpoint available — omit the field.
      }
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(response, null, 2),
        },
      ],
    };
  } catch (error) {
    return toolErrorResult(error);
  }
}

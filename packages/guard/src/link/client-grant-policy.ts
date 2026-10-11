/**
 * @credninja/guard: Client Grant Policy (Cred Link, spec 6).
 *
 * For deployments that configure a Guard: run it first in the chain. It
 * SKIPs every call whose GuardContext has no `link` (anything that names no
 * Link connection) and otherwise delegates to LinkHooks.checkLinkAccess, the
 * one source of truth for Link access. On allow it narrows the scopes to the
 * effective scopes; on deny it returns DENY with `code` set to the machine
 * code.
 *
 * The server runs checkLinkAccess itself on every Link call whether or not
 * a Guard exists; this policy only makes Guard's view (audit events,
 * effective scopes for later policies) agree with that check. It never
 * throws: a failing check is a DENY, so GuardConfig.onError: 'allow' cannot
 * turn an error into access.
 */

import { LINK_MACHINE_ERROR_STATUS, isLinkMachineErrorCode } from '@credninja/protocol';
import type { LinkAccessCheckInput, LinkHooks, LinkMachineErrorCode } from '@credninja/protocol';
import type { CredPolicy, GuardContext, PolicyResult } from '../types.js';
import { LINK_CHECK_ERROR_CODE } from './hooks.js';

/** Policy name used in results and audit events. */
export const CLIENT_GRANT_POLICY_NAME = 'client-grant';

/** clientGrantPolicy configuration. */
export interface ClientGrantPolicyConfig {
  /** The hooks from createLinkHooks (only checkLinkAccess is used). */
  hooks: Pick<LinkHooks, 'checkLinkAccess'>;
  /** Clock for LinkAccessCheckInput.now. Default: ctx.timestamp, else the current time. */
  now?: () => Date;
}

/** PolicyResult with the extra Link fields this policy sets. */
export interface ClientGrantPolicyResult extends PolicyResult {
  /** On DENY: the Link machine code (same value as `code`). */
  code?: LinkMachineErrorCode;
  /** On DENY: LINK_MACHINE_ERROR_STATUS[code]. */
  httpStatus?: number;
  /** On DENY with insufficient_scope or permission_required: the scopes not covered. */
  missingScopes?: string[];
  /** On ALLOW: ids the server may use (for example to mint a handle bound to the grant). */
  connectionId?: string;
  grantId?: string;
  grantVersion?: number;
  permissionId?: string;
}

/**
 * Create the client grant policy. Place it first in GuardConfig.policies.
 */
export function clientGrantPolicy(config: ClientGrantPolicyConfig): CredPolicy {
  if (!config || !config.hooks || typeof config.hooks.checkLinkAccess !== 'function') {
    throw new TypeError('clientGrantPolicy requires { hooks } with checkLinkAccess');
  }
  const { hooks } = config;

  return {
    name: CLIENT_GRANT_POLICY_NAME,
    async evaluate(ctx: GuardContext): Promise<ClientGrantPolicyResult> {
      const link = ctx.link;
      if (link === undefined || link === null) {
        return { decision: 'SKIP', policy: CLIENT_GRANT_POLICY_NAME, reason: 'Not a Link call' };
      }

      // Everything below runs inside one guarded region: building the input,
      // calling the hook and reading its result. Any throw or unexpected
      // shape is a DENY, so GuardConfig.onError cannot see an error here.
      try {
        if (typeof link !== 'object' || (link.operation !== 'delegate' && link.operation !== 'use')) {
          return denyResult(LINK_CHECK_ERROR_CODE);
        }

        const input: LinkAccessCheckInput = {
          operation: link.operation,
          connection_id: link.connectionId,
          agent_id: link.agentId ?? null,
          provider: ctx.provider,
          requested_scopes: Array.isArray(ctx.requestedScopes) ? ctx.requestedScopes : [],
          ...(link.grantId !== undefined ? { grant_id: link.grantId } : {}),
          ...(link.grantVersion !== undefined ? { grant_version: link.grantVersion } : {}),
          now: resolveNow(config.now, ctx.timestamp),
        };

        const result: unknown = await hooks.checkLinkAccess(input);
        return toPolicyResult(result);
      } catch {
        return denyResult(LINK_CHECK_ERROR_CODE);
      }
    },
  };
}

/**
 * Map a checkLinkAccess result to a policy result, validating its shape.
 * Anything that is not exactly a well-formed allow or deny is a DENY.
 */
function toPolicyResult(result: unknown): ClientGrantPolicyResult {
  if (!isRecord(result)) return denyResult(LINK_CHECK_ERROR_CODE);

  if (result.ok === true) {
    const { effective_scopes, connection, grant, permission } = result;
    if (
      !isStringArray(effective_scopes)
      || effective_scopes.length === 0
      || !isRecord(connection) || typeof connection.id !== 'string'
      || !isRecord(grant) || typeof grant.id !== 'string' || typeof grant.version !== 'number'
      || !isRecord(permission) || typeof permission.id !== 'string'
    ) {
      return denyResult(LINK_CHECK_ERROR_CODE);
    }
    return {
      decision: 'ALLOW',
      policy: CLIENT_GRANT_POLICY_NAME,
      reason: 'Link grant and agent permission cover the request',
      narrowedScopes: [...effective_scopes],
      connectionId: connection.id,
      grantId: grant.id,
      grantVersion: grant.version,
      permissionId: permission.id,
    };
  }

  if (result.ok === false && isLinkMachineErrorCode(result.code)) {
    const missing = isStringArray(result.missing_scopes) ? result.missing_scopes : undefined;
    return denyResult(result.code, missing);
  }

  return denyResult(LINK_CHECK_ERROR_CODE);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object';
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function resolveNow(now: (() => Date) | undefined, timestamp: string | undefined): string {
  if (now) return now().toISOString();
  if (typeof timestamp === 'string' && !Number.isNaN(Date.parse(timestamp))) {
    return new Date(timestamp).toISOString();
  }
  return new Date().toISOString();
}

/** DENY with the machine code; httpStatus always comes from LINK_MACHINE_ERROR_STATUS. */
function denyResult(code: LinkMachineErrorCode, missing?: string[]): ClientGrantPolicyResult {
  const httpStatus = LINK_MACHINE_ERROR_STATUS[code];
  const reason = missing && missing.length > 0
    ? `Link access denied: ${code} (${missing.join(' ')})`
    : `Link access denied: ${code}`;
  return {
    decision: 'DENY',
    policy: CLIENT_GRANT_POLICY_NAME,
    reason,
    code,
    httpStatus,
    ...(missing && missing.length > 0 ? { missingScopes: [...missing] } : {}),
  };
}

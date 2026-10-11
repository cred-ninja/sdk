/**
 * @credninja/guard: Cred Link policy hooks (spec 3, 4, 6).
 *
 * Implements @credninja/protocol's LinkHooks over a LinkStore (read methods
 * only) and a LinkPermissionPort (for example `vault.getLinkPermissionPort()`).
 * Nothing here depends on a CredGuard: the server runs checkLinkAccess on
 * every /api/v1/delegate and /api/v1/use call that names a Link connection,
 * whether or not a Guard is configured.
 *
 * Invariants kept by this module:
 *   - Grants carry no agent; agents are bound only through Permission rows.
 *   - Deny by default per agent: no Permission row, no access.
 *   - Permission.allowedScopes stays within grant.scopes after every hook,
 *     and checkLinkAccess re-checks it at call time regardless.
 *   - checkLinkAccess fails closed: any thrown error becomes a denial.
 *   - No identity is derived here: agent ids come from the caller, which
 *     must take them from verified request state.
 */

import {
  LINK_API_ERROR_STATUS,
  LINK_MACHINE_CODE_FOR_CONNECTION_STATUS,
  LINK_MACHINE_CODE_FOR_GRANT_STATUS,
  LINK_MACHINE_ERROR_STATUS,
  LINK_OPAQUE_FAILURE_STATUS,
  LINK_PERMISSION_DEFAULTS,
  canonicalScope,
  canonicalScopeSet,
  intersectScopes,
  isConnectionId,
  isLinkMachineErrorCode,
  isScopeSubset,
  scopeDifference,
  scopeSetsEqual,
} from '@credninja/protocol';
import type {
  ClientGrant,
  Connection,
  LinkAccessCheckInput,
  LinkAccessResult,
  LinkActivateHookInput,
  LinkGrantUpdatedHookInput,
  LinkHooks,
  LinkHooksFactory,
  LinkMachineErrorCode,
  LinkPermission,
  LinkPermissionPort,
  LinkSetAgentPermissionInput,
  LinkSetAgentPermissionResult,
  LinkStore,
} from '@credninja/protocol';

/**
 * Code checkLinkAccess returns when the store or the permission port throws
 * (or the input is malformed). LinkAccessResult only admits machine codes,
 * and none of them means "temporarily unavailable", so the check denies with
 * the code that grants nothing and asks for nothing destructive: the agent
 * is simply not authorized for this call right now.
 */
export const LINK_CHECK_ERROR_CODE: LinkMachineErrorCode = 'permission_required';

/**
 * Code used when a stored status is not one the protocol maps (corrupt
 * row): fail closed as if the grant were revoked.
 */
const UNKNOWN_STATUS_CODE: LinkMachineErrorCode = 'grant_revoked';

/** How many get/update/create rounds an upsert tries before giving up. */
const UPSERT_ATTEMPTS = 3;

/** The two dependencies LinkHooksFactory takes. */
export type LinkHooksDeps = Parameters<LinkHooksFactory>[0];

/** Optional knobs for createLinkHooks. Not part of the protocol contract. */
export interface LinkHooksOptions {
  /**
   * Called when checkLinkAccess caught an error and denied with
   * LINK_CHECK_ERROR_CODE. Use it to log or alert: without it a store
   * outage looks exactly like an authorization denial to the caller.
   * Must not throw; if it does, the error is ignored.
   */
  onCheckError?: (error: unknown, input: LinkAccessCheckInput) => void;
}

/**
 * Build the Link hooks. Assignable to protocol's LinkHooksFactory (the
 * optional second argument is ignored by callers that only know the
 * factory type).
 */
export function createLinkHooks(deps: LinkHooksDeps, options: LinkHooksOptions = {}): LinkHooks {
  const { store, permissions } = deps;
  if (!store || !permissions) {
    throw new TypeError('createLinkHooks requires { store, permissions }');
  }

  async function checkLinkAccess(input: LinkAccessCheckInput): Promise<LinkAccessResult> {
    try {
      return await evaluateLinkAccess(store, permissions, input);
    } catch (error) {
      try {
        options.onCheckError?.(error, input);
      } catch {
        // Reporting must never turn a denial into anything else.
      }
      return deny(LINK_CHECK_ERROR_CODE);
    }
  }

  async function onActivate(input: LinkActivateHookInput): Promise<void> {
    const agentId = input.agent_id;
    if (agentId === null || agentId === undefined || agentId === '') return;
    if (typeof agentId !== 'string') {
      throw new TypeError('onActivate: agent_id must be a string or null');
    }
    const { connection, grant } = input;
    if (grant.connection_id !== connection.id) {
      throw new Error('onActivate: grant does not belong to the connection');
    }
    await upsertLinkPermission(permissions, {
      agentId,
      connectionId: connection.id,
      scopes: canonicalScopeSet(grant.scopes),
      actor: input.actor,
    });
    await reconcileWithCurrentGrant(store, permissions, connection.id);
  }

  /**
   * Clip every Permission on the connection to grant.scopes ∩ previous_scopes,
   * in one store operation. A Permission is never wider than the grant it was
   * written under, so the previous_scopes bound changes nothing unless an
   * earlier onGrantUpdated was missed; then it removes what that call should
   * have removed before a widened grant could hand it back. An intersect can
   * only narrow. A caller that only re-applies the current grant passes
   * previous_scopes = grant.scopes, which is the plain grant intersect.
   */
  async function onGrantUpdated(input: LinkGrantUpdatedHookInput): Promise<void> {
    const { grant, previous_scopes } = input;
    if (!Array.isArray(previous_scopes) || !previous_scopes.every((s) => typeof s === 'string')) {
      // Fail loudly rather than skip the previous bound: the server keeps the
      // activation unsettled and its heal runs this again.
      throw new TypeError('onGrantUpdated: previous_scopes must be a string array');
    }
    const bound = intersectScopes(canonicalScopeSet(grant.scopes), canonicalScopeSet(previous_scopes));
    await permissions.intersectForConnection(grant.connection_id, bound);
  }

  async function setAgentPermission(input: LinkSetAgentPermissionInput): Promise<LinkSetAgentPermissionResult> {
    if (typeof input.agent_id !== 'string' || input.agent_id === '') {
      throw new TypeError('setAgentPermission: agent_id must be a non-empty string');
    }
    if (
      !Array.isArray(input.scopes)
      || !input.scopes.every((s) => typeof s === 'string')
      || hasBlankScope(input.scopes)
    ) {
      return fail('invalid_scope');
    }

    const connection = isConnectionId(input.connection_id)
      ? await store.getClientConnection({ client_id: input.client_id, connection_id: input.connection_id })
      : null;
    if (!connection || connection.client_id !== input.client_id) {
      return opaqueFailure();
    }

    if (connection.status !== 'active') {
      return fail(connectionStatusCode(connection));
    }

    const grant = await store.getGrantForConnection(connection.id);
    if (!grant || grant.connection_id !== connection.id) return fail('grant_revoked');
    if (grant.client_id !== input.client_id) return opaqueFailure();
    const grantDenial = grantStatusCode(grant, new Date().toISOString());
    if (grantDenial) return fail(grantDenial);

    const scopes = canonicalScopeSet(input.scopes);
    if (!isScopeSubset(scopes, grant.scopes)) {
      return fail('invalid_scope');
    }

    const permission = await upsertLinkPermission(permissions, {
      agentId: input.agent_id,
      connectionId: connection.id,
      scopes,
      actor: input.actor,
    });
    const narrowed = await reconcileWithCurrentGrant(store, permissions, connection.id);
    const final = narrowed.find((p) => p.id === permission.id) ?? permission;
    return { ok: true, permission: final };
  }

  return { checkLinkAccess, onActivate, onGrantUpdated, setAgentPermission };
}

// Compile-time proof that createLinkHooks satisfies the protocol factory type.
const _createLinkHooksIsFactory: LinkHooksFactory = createLinkHooks;
void _createLinkHooksIsFactory;

// ── checkLinkAccess ──────────────────────────────────────────────────────────

/**
 * The decision table from LinkHooks.checkLinkAccess, row for row, in order.
 * Throws on store or port errors; the caller turns that into a denial.
 */
async function evaluateLinkAccess(
  store: LinkStore,
  permissions: LinkPermissionPort,
  input: LinkAccessCheckInput,
): Promise<LinkAccessResult> {
  if (!input || typeof input !== 'object') throw new TypeError('checkLinkAccess: input required');
  if (input.operation !== 'delegate' && input.operation !== 'use') {
    throw new TypeError('checkLinkAccess: operation must be delegate or use');
  }
  if (!Array.isArray(input.requested_scopes) || !input.requested_scopes.every((s) => typeof s === 'string')) {
    throw new TypeError('checkLinkAccess: requested_scopes must be a string array');
  }
  const nowMs = Date.parse(input.now);
  if (Number.isNaN(nowMs)) throw new TypeError('checkLinkAccess: now must be an ISO timestamp');

  // Row 1: a blank requested scope is malformed, never "everything".
  if (hasBlankScope(input.requested_scopes)) return deny('permission_required');

  // Row 2: unknown connection or provider mismatch.
  const connection = isConnectionId(input.connection_id) ? await store.getConnection(input.connection_id) : null;
  if (!connection || connection.id !== input.connection_id) return deny('permission_required');
  if (input.provider !== undefined && input.provider !== connection.provider) return deny('permission_required');

  // Row 3: the connection's client is unknown or not active (for example
  // disabled by an operator).
  const client = await store.getClient(connection.client_id);
  if (!client || client.client_id !== connection.client_id || client.status !== 'active') {
    return deny('grant_revoked');
  }

  // Row 4: connection status not active.
  if (connection.status !== 'active') return deny(connectionStatusCode(connection));

  // Row 5: grant missing.
  const grant = await store.getGrantForConnection(connection.id);
  if (!grant || grant.connection_id !== connection.id) return deny('grant_revoked');

  // Row 6: grant status not active, or expires_at passed.
  const grantDenial = grantStatusCode(grant, input.now);
  if (grantDenial) return deny(grantDenial);

  // Row 7: use, grant_id differs (a missing grant_id differs too).
  if (input.operation === 'use' && input.grant_id !== grant.id) return deny('grant_revoked');

  const requested = canonicalScopeSet(input.requested_scopes);

  // Row 8: no verified agent, no Permission, or an expired Permission.
  const agentId = input.agent_id;
  if (typeof agentId !== 'string' || agentId === '') return deny('permission_required', requested);
  const permission = await permissions.get(agentId, connection.id);
  if (!isUsablePermission(permission, agentId, connection.id, nowMs)) {
    return deny('permission_required', requested);
  }

  // Row 9: requested scope outside grant.scopes.
  const outsideGrant = scopeDifference(requested, grant.scopes);
  if (outsideGrant.length > 0) return deny('insufficient_scope', outsideGrant);

  // Row 10: requested scope outside the permission.
  const outsidePermission = scopeDifference(requested, permission.allowedScopes);
  if (outsidePermission.length > 0) return deny('permission_required', outsidePermission);

  // effective = requested (or all, when requested is empty) ∩ grant ∩ permission.
  const base = requested.length > 0 ? requested : canonicalScopeSet(grant.scopes);
  const effective = intersectScopes(intersectScopes(base, grant.scopes), permission.allowedScopes);

  // Not a table row: an empty request that resolves to no scopes at all is
  // denied, so no caller can mistake [] for "everything stored".
  if (effective.length === 0) return deny('permission_required');

  return { ok: true, connection, grant, permission, effective_scopes: effective };
}

/**
 * True when any entry canonicalizes to the empty string (empty, whitespace
 * only, or a lone slash). canonicalScopeSet would silently drop it, turning
 * a malformed request into an empty one, which means "everything".
 */
function hasBlankScope(scopes: readonly string[]): boolean {
  return scopes.some((scope) => canonicalScope(scope) === '');
}

function isUsablePermission(
  permission: LinkPermission | null,
  agentId: string,
  connectionId: string,
  nowMs: number,
): permission is LinkPermission {
  if (!permission) return false;
  if (permission.agentId !== agentId || permission.connectionId !== connectionId) return false;
  if (!Array.isArray(permission.allowedScopes)) return false;
  if (permission.expiresAt !== undefined && permission.expiresAt !== null) {
    const expiresMs = permission.expiresAt instanceof Date
      ? permission.expiresAt.getTime()
      : Date.parse(String(permission.expiresAt));
    // An unreadable expiry counts as expired.
    if (Number.isNaN(expiresMs) || expiresMs <= nowMs) return false;
  }
  return true;
}

/** Row 4 code: the connection's own status_reason wins, else the status map. */
function connectionStatusCode(connection: Connection): LinkMachineErrorCode {
  if (isLinkMachineErrorCode(connection.status_reason)) return connection.status_reason;
  const mapped = (LINK_MACHINE_CODE_FOR_CONNECTION_STATUS as Record<string, LinkMachineErrorCode | null | undefined>)[
    connection.status
  ];
  return mapped ?? UNKNOWN_STATUS_CODE;
}

/** Row 6 code, or null when the grant is active and unexpired. */
function grantStatusCode(grant: ClientGrant, now: string): LinkMachineErrorCode | null {
  if (grant.status !== 'active') {
    const mapped = (LINK_MACHINE_CODE_FOR_GRANT_STATUS as Record<string, LinkMachineErrorCode | null | undefined>)[
      grant.status
    ];
    return mapped ?? UNKNOWN_STATUS_CODE;
  }
  if (grant.expires_at !== undefined && grant.expires_at !== null) {
    const expiresMs = Date.parse(grant.expires_at);
    const nowMs = Date.parse(now);
    if (Number.isNaN(expiresMs) || Number.isNaN(nowMs) || expiresMs <= nowMs) return 'grant_expired';
  }
  return null;
}

function deny(code: LinkMachineErrorCode, missing?: readonly string[]): LinkAccessResult {
  const status = LINK_MACHINE_ERROR_STATUS[code];
  if (missing && missing.length > 0 && (code === 'insufficient_scope' || code === 'permission_required')) {
    return { ok: false, code, status, missing_scopes: [...missing] };
  }
  return { ok: false, code, status };
}

// ── setAgentPermission helpers ───────────────────────────────────────────────

function fail(error: 'invalid_scope' | LinkMachineErrorCode): LinkSetAgentPermissionResult {
  const status = error === 'invalid_scope' ? LINK_API_ERROR_STATUS.invalid_scope : LINK_MACHINE_ERROR_STATUS[error];
  return { ok: false, error, status };
}

/**
 * Unknown or foreign connection. The result type has no access_denied, so
 * this is permission_required with the opaque failure's status (401); the
 * server must answer it with LINK_OPAQUE_FAILURE_BODY (spec 5 Enumeration).
 */
function opaqueFailure(): LinkSetAgentPermissionResult {
  return { ok: false, error: 'permission_required', status: LINK_OPAQUE_FAILURE_STATUS };
}

// ── Permission writes ────────────────────────────────────────────────────────

interface UpsertInput {
  agentId: string;
  connectionId: string;
  /** Canonical. */
  scopes: string[];
  actor: string;
}

/**
 * Upsert one agent's Permission on a connection with exactly `scopes` and
 * LINK_PERMISSION_DEFAULTS. Never creates a second row for the same
 * (agent, connection): it updates when a row exists, and when a concurrent
 * writer wins the create (unique-constraint error, or an id replaced under
 * us) it re-reads and updates instead. Operator-set limits still in force
 * (rateLimit, ttlOverride, a future expiresAt) are kept; an expiry already
 * passed is cleared, since the call is an explicit grant.
 */
async function upsertLinkPermission(permissions: LinkPermissionPort, input: UpsertInput): Promise<LinkPermission> {
  let lastError: unknown;
  for (let attempt = 0; attempt < UPSERT_ATTEMPTS; attempt++) {
    const existing = await permissions.get(input.agentId, input.connectionId);
    try {
      if (existing) {
        const expired = existing.expiresAt instanceof Date && existing.expiresAt.getTime() <= Date.now();
        await permissions.update(existing.id, {
          allowedScopes: input.scopes,
          delegatable: LINK_PERMISSION_DEFAULTS.delegatable,
          maxDelegationDepth: LINK_PERMISSION_DEFAULTS.maxDelegationDepth,
          requiresApproval: LINK_PERMISSION_DEFAULTS.requiresApproval,
          ...(expired ? { expiresAt: undefined } : {}),
        });
      } else {
        await permissions.create({
          agentId: input.agentId,
          connectionId: input.connectionId,
          allowedScopes: input.scopes,
          delegatable: LINK_PERMISSION_DEFAULTS.delegatable,
          maxDelegationDepth: LINK_PERMISSION_DEFAULTS.maxDelegationDepth,
          requiresApproval: LINK_PERMISSION_DEFAULTS.requiresApproval,
          createdBy: input.actor,
        });
      }
    } catch (error) {
      lastError = error;
      continue;
    }
    // Read back so the caller sees the row as stored (a concurrent upsert
    // may have replaced the id the write above returned).
    const stored = await permissions.get(input.agentId, input.connectionId);
    if (stored && scopeSetsEqual(stored.allowedScopes, input.scopes)) return stored;
    if (!stored) {
      lastError = new Error('Permission vanished during upsert');
      continue;
    }
    // A concurrent writer set different scopes; it is at least as valid
    // as ours (every writer is bounded by the grant). Report what is stored.
    return stored;
  }
  throw lastError instanceof Error ? lastError : new Error('Permission upsert failed');
}

/**
 * Close the window between reading the grant and writing a Permission: if
 * the grant narrowed meanwhile, intersect every Permission on the
 * connection with its current scopes. When the grant is gone or inactive,
 * nothing is widened and checkLinkAccess denies at call time anyway.
 * Returns the permissions that changed.
 */
async function reconcileWithCurrentGrant(
  store: LinkStore,
  permissions: LinkPermissionPort,
  connectionId: string,
): Promise<LinkPermission[]> {
  const grant = await store.getGrantForConnection(connectionId);
  if (!grant) return [];
  return permissions.intersectForConnection(connectionId, canonicalScopeSet(grant.scopes));
}

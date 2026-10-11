/**
 * Cred Link server: the client-authenticated API (PAR and connection
 * management, spec 2 and 4) and the admin client registration routes
 * (decision 2).
 *
 * Every client authentication failure, and every lookup of a connection
 * that is unknown or belongs to another client (or, where a subject is
 * involved, another subject), answers with exactly LINK_OPAQUE_FAILURE_BODY,
 * status 401 and a Cred-Request-Id header.
 */

import type { NextFunction, Request, Response } from 'express';
import {
  LINK_API_ERROR_STATUS,
  LINK_CLIENT_AUTH_METHODS,
  LINK_DEFAULT_ORG_ID,
  LINK_ID_PREFIXES,
  LINK_OPAQUE_FAILURE_STATUS,
  LINK_PROVIDERS,
  LINK_REDIRECT_PARAMS,
  LINK_MACHINE_CODE_FOR_CONNECTION_STATUS,
  LINK_MACHINE_CODE_FOR_GRANT_STATUS,
  LINK_MACHINE_ERROR_STATUS,
  LINK_TRANSACTION_TTL_SECONDS,
  canonicalScope,
  canonicalScopeSet,
  findScopeCatalogEntry,
  linkNarrowEnforcementFor,
  scopeDifference,
  isConnectionId,
  isLinkActivationCode,
  isLinkClientId,
  isLinkIntent,
  isLinkProviderSlug,
  isLinkSubjectType,
  isScopeSubset,
  sanitizeLinkTheme,
  scopeSetsEqual,
  unionScopes,
} from '@credninja/protocol';
import type {
  ClientGrant,
  Connection,
  LinkApiErrorCode,
  LinkClient,
  LinkConnectionView,
  LinkIntent,
  LinkNarrowEnforcement,
  LinkPermission,
  LinkPermissionView,
  LinkProviderSlug,
  LinkScopeMap,
  NarrowConnectionResponse,
  ParResponse,
  RevokeConnectionResponse,
} from '@credninja/protocol';
import { LinkStoreError } from '@credninja/vault';
import type { LinkContext } from './core.js';
import { cleanupEndedTransaction, mintTransaction, revokeAtProviderIfSafe, writeGrantAudit } from './core.js';
import { validateClientJwks } from './client-auth.js';
import { validateRequestedScopes } from './scopes.js';
import { googleRemovalIsBrokerEnforced } from '../google-scopes.js';
import {
  boundedString,
  hasControlCharacter,
  isLoopbackHost,
  newId,
  newSecret,
  nowIso,
  requestId,
  sendLinkError,
  sendOpaqueFailure,
  sha256Hex,
} from './util.js';

const MAX_SUBJECT_LENGTH = 256;
const MAX_STATE_LENGTH = 512;
const MAX_AGENT_ID_LENGTH = 256;
const MAX_URIS = 20;

/** Request with the authenticated Link client attached. */
type ClientRequest = Request & { credLinkClient?: LinkClient };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function clientOf(req: Request): LinkClient {
  const client = (req as ClientRequest).credLinkClient;
  if (!client) throw new Error('Link client missing on request');
  return client;
}

/** Express middleware: authenticate the Link client or answer the opaque failure. */
export function requireLinkClient(ctx: LinkContext) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    requestId(req, res);
    let client: LinkClient | null = null;
    try {
      client = await ctx.clientAuth.authenticate(req);
    } catch {
      client = null;
    }
    if (!client) {
      sendOpaqueFailure(req, res);
      return;
    }
    (req as ClientRequest).credLinkClient = client;
    next();
  };
}

// ── Views ────────────────────────────────────────────────────────────────────

export function connectionView(connection: Connection, grant: ClientGrant | null): LinkConnectionView {
  const view: LinkConnectionView = {
    connection_id: connection.id,
    provider: connection.provider,
    subject: connection.subject,
    subject_type: connection.subject_type,
    status: connection.status,
    provider_account_id: connection.provider_account_id,
    audience: connection.audience,
    provider_scopes: [...connection.provider_scopes],
    created_at: connection.created_at,
    updated_at: connection.updated_at,
    grant: grant
      ? {
          grant_id: grant.id,
          scopes: [...grant.scopes],
          status: grant.status,
          version: grant.version,
          granted_at: grant.granted_at,
          updated_at: grant.updated_at,
          ...(grant.expires_at ? { expires_at: grant.expires_at } : {}),
        }
      : null,
  };
  if (connection.status_reason) view.status_reason = connection.status_reason;
  if (connection.account_label) view.account_label = connection.account_label;
  return view;
}

function permissionView(permission: LinkPermission): LinkPermissionView {
  return {
    permission_id: permission.id,
    agent_id: permission.agentId,
    connection_id: permission.connectionId as LinkPermissionView['connection_id'],
    scopes: [...permission.allowedScopes],
    delegatable: permission.delegatable,
    max_delegation_depth: permission.maxDelegationDepth,
    created_at: permission.createdAt instanceof Date ? permission.createdAt.toISOString() : String(permission.createdAt),
    updated_at: permission.updatedAt,
  };
}

// ── Pushed authorization request ─────────────────────────────────────────────

type PushOutcome =
  | { ok: true; response: ParResponse }
  | { ok: false; opaque: true }
  | { ok: false; opaque: false; error: LinkApiErrorCode; message: string };

function invalid(error: LinkApiErrorCode, message: string): PushOutcome {
  return { ok: false, opaque: false, error, message };
}

function optionalString(value: unknown, max: number): { ok: true; value?: string } | { ok: false } {
  if (value === undefined || value === null) return { ok: true };
  const s = boundedString(value, max);
  return s === null ? { ok: false } : { ok: true, value: s };
}

/** Validate a scope map against the allowed providers; canonical result. */
function validateScopeMap(value: unknown, allowed: readonly LinkProviderSlug[]): { ok: true; map: LinkScopeMap } | { ok: false; error: LinkApiErrorCode } {
  if (value === undefined) return { ok: true, map: {} };
  if (!isPlainObject(value)) return { ok: false, error: 'invalid_request' };
  const map: LinkScopeMap = {};
  for (const key of Object.keys(value)) {
    if (!isLinkProviderSlug(key) || !allowed.includes(key)) return { ok: false, error: 'invalid_request' };
    const checked = validateRequestedScopes(key, value[key]);
    if (!checked.ok) return { ok: false, error: checked.error };
    map[key] = checked.scopes;
  }
  return { ok: true, map };
}

/**
 * Validate a pushed request (PAR body, or the reauth route's sugar) for an
 * authenticated client and create its transaction.
 */
export async function pushAuthorizationRequest(ctx: LinkContext, client: LinkClient, body: Record<string, unknown>): Promise<PushOutcome> {
  const intent = body.intent;
  if (!isLinkIntent(intent)) return invalid('invalid_request', 'intent must be connect, update or reauth');
  const subject = boundedString(body.subject, MAX_SUBJECT_LENGTH);
  if (!subject) return invalid('invalid_request', 'subject is required');
  const subjectType = body.subject_type;
  if (!isLinkSubjectType(subjectType)) return invalid('invalid_request', 'subject_type must be user or client');
  if (typeof body.redirect_uri !== 'string' || !client.redirect_uris.includes(body.redirect_uri)) {
    return invalid('invalid_request', 'redirect_uri is not registered for this client');
  }
  if (typeof body.origin !== 'string' || !client.origins.includes(body.origin)) {
    return invalid('invalid_request', 'origin is not registered for this client');
  }
  const state = optionalString(body.state, MAX_STATE_LENGTH);
  if (!state.ok) return invalid('invalid_request', 'state must be a printable string');
  const agentId = optionalString(body.agent_id, MAX_AGENT_ID_LENGTH);
  if (!agentId.ok) return invalid('invalid_request', 'agent_id must be a printable string');
  const details = body.authorization_details;
  if (details !== undefined && !(Array.isArray(details) && details.length === 0)) {
    return invalid('invalid_request', 'authorization_details is not supported');
  }

  if (intent === 'connect') {
    if (body.connection_id !== undefined && body.connection_id !== null) {
      return invalid('invalid_request', 'connect does not take connection_id');
    }
    const providersRaw = body.providers;
    if (!Array.isArray(providersRaw) || providersRaw.length === 0 || providersRaw.length > LINK_PROVIDERS.length) {
      return invalid('invalid_request', 'providers must be a non-empty list');
    }
    if (!providersRaw.every(isLinkProviderSlug)) return invalid('invalid_request', 'providers must be Link provider slugs');
    const providers = LINK_PROVIDERS.filter((p) => (providersRaw as string[]).includes(p));
    if (!providers.every((p) => ctx.providers.isConfigured(p))) {
      return invalid('invalid_request', 'a provider is not configured on this server');
    }
    if (!isPlainObject(body.scopes)) return invalid('invalid_request', 'scopes is required');
    const scopes = validateScopeMap(body.scopes, providers);
    if (!scopes.ok) return invalid(scopes.error, 'scopes are not valid for these providers');
    const required = validateScopeMap(body.required_scopes, providers);
    if (!required.ok) return invalid(required.error, 'required_scopes are not valid for these providers');
    for (const p of providers) {
      if (!isScopeSubset(required.map[p] ?? [], scopes.map[p] ?? [])) {
        return invalid('invalid_request', 'required_scopes must be a subset of scopes');
      }
    }
    const { request_uri } = await mintTransaction(ctx, {
      client,
      intent,
      subject,
      subject_type: subjectType,
      providers,
      requested_scopes: scopes.map,
      required_scopes: required.map,
      redirect_uri: body.redirect_uri,
      origin: body.origin,
      ...(state.value !== undefined ? { client_state: state.value } : {}),
      ...(agentId.value !== undefined ? { agent_id: agentId.value } : {}),
    });
    return { ok: true, response: { request_uri, expires_in: LINK_TRANSACTION_TTL_SECONDS } };
  }

  // update and reauth: the connection must belong to (client, subject).
  if (typeof body.connection_id !== 'string' || !isConnectionId(body.connection_id)) return { ok: false, opaque: true };
  const connection = await ctx.store.getSubjectConnection({
    client_id: client.client_id,
    subject,
    connection_id: body.connection_id,
  });
  if (!connection) return { ok: false, opaque: true };
  if (connection.status === 'revoked' || connection.status === 'pending') {
    return invalid('invalid_request', 'the connection cannot be updated in its current status');
  }
  const provider = connection.provider;
  if (body.providers !== undefined) {
    if (!Array.isArray(body.providers) || body.providers.length !== 1 || body.providers[0] !== provider) {
      return invalid('invalid_request', 'providers must name the connection provider only');
    }
  }
  if (!ctx.providers.isConfigured(provider)) return invalid('invalid_request', 'the provider is not configured on this server');
  const grant = await ctx.store.getGrantForConnection(connection.id);
  if (!grant || grant.status === 'revoked') return invalid('invalid_request', 'the connection has no usable grant');
  const scopes = validateScopeMap(body.scopes, [provider]);
  if (!scopes.ok) return invalid(scopes.error, 'scopes are not valid for this connection');
  const required = validateScopeMap(body.required_scopes, [provider]);
  if (!required.ok) return invalid(required.error, 'required_scopes are not valid for this connection');
  const requested = intent === 'update'
    ? unionScopes(grant.scopes, scopes.map[provider] ?? [])
    : (scopes.map[provider] ?? grant.scopes);
  if (!isScopeSubset(required.map[provider] ?? [], requested)) {
    return invalid('invalid_request', 'required_scopes must be a subset of scopes');
  }
  const { request_uri } = await mintTransaction(ctx, {
    client,
    intent: intent as Exclude<LinkIntent, 'connect'>,
    subject,
    subject_type: subjectType,
    providers: [provider],
    requested_scopes: { [provider]: requested },
    required_scopes: { [provider]: required.map[provider] ?? [] },
    redirect_uri: body.redirect_uri,
    origin: body.origin,
    connection_id: connection.id,
    grant_id: grant.id,
    ...(state.value !== undefined ? { client_state: state.value } : {}),
    ...(agentId.value !== undefined ? { agent_id: agentId.value } : {}),
  });
  return { ok: true, response: { request_uri, expires_in: LINK_TRANSACTION_TTL_SECONDS } };
}

function sendPushOutcome(req: Request, res: Response, outcome: PushOutcome): void {
  if (outcome.ok) {
    requestId(req, res);
    res.setHeader('Cache-Control', 'no-store');
    res.status(201).json(outcome.response);
    return;
  }
  if (outcome.opaque) {
    sendOpaqueFailure(req, res);
    return;
  }
  sendLinkError(req, res, LINK_API_ERROR_STATUS[outcome.error], outcome.error, { message: outcome.message });
}

/** POST /link/v1/par */
export async function handlePar(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const body = isPlainObject(req.body) ? req.body : {};
  try {
    sendPushOutcome(req, res, await pushAuthorizationRequest(ctx, clientOf(req), body));
  } catch (error) {
    console.error('[link] PAR failed', { kind: error instanceof Error ? error.name : 'unknown' });
    sendLinkError(req, res, 500, 'server_error');
  }
}

// ── Connection management ────────────────────────────────────────────────────

async function ownedConnection(ctx: LinkContext, req: Request): Promise<Connection | null> {
  const id = req.params.id;
  if (typeof id !== 'string' || !isConnectionId(id)) return null;
  return ctx.store.getClientConnection({ client_id: clientOf(req).client_id, connection_id: id });
}

/** GET /link/v1/connections?subject= */
export async function handleListConnections(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const subject = boundedString(typeof req.query.subject === 'string' ? req.query.subject : undefined, MAX_SUBJECT_LENGTH);
  if (!subject) {
    sendLinkError(req, res, 400, 'invalid_request', { message: 'subject is required' });
    return;
  }
  const connections = await ctx.store.listConnections({ client_id: clientOf(req).client_id, subject });
  const views: LinkConnectionView[] = [];
  for (const c of connections) views.push(connectionView(c, await ctx.store.getGrantForConnection(c.id)));
  res.setHeader('Cache-Control', 'no-store');
  res.json({ connections: views });
}

/** GET /link/v1/connections/:id */
export async function handleGetConnection(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const connection = await ownedConnection(ctx, req);
  if (!connection) {
    sendOpaqueFailure(req, res);
    return;
  }
  res.setHeader('Cache-Control', 'no-store');
  res.json(connectionView(connection, await ctx.store.getGrantForConnection(connection.id)));
}

/** Write a pending or success audit record for an operation on a grant or permission. Throws on failure. */
function writeOperationAudit(
  ctx: LinkContext,
  input: {
    action: 'update' | 'revoke' | 'create';
    outcome: 'pending' | 'success';
    resource: { type: 'grant' | 'permission'; id: string };
    actor: string;
    correlationId: string;
    metadata: Record<string, unknown>;
  },
): void {
  ctx.vault.writeAuditEvent({
    id: newId(LINK_ID_PREFIXES.auditEvent),
    timestamp: new Date(),
    actor: { type: 'system', id: input.actor },
    action: input.action,
    resource: input.resource,
    outcome: input.outcome,
    correlationId: input.correlationId,
    metadata: input.metadata,
  });
}

/**
 * POST /link/v1/connections/:id/activate (decision 12, revised).
 *
 * Order: claimActivation; a pending audit record (fail closed: if it cannot
 * be written nothing changes); store.commitActivation (the database commit,
 * before any token moves, so a refused activation never touches a live
 * connection's tokens); secrets.commitStaged under the connection's token
 * lock; the success audit record; onGrantUpdated (only when the previous
 * scopes exist and differ); onActivate. Every failure answers with the
 * opaque failure.
 */
export async function handleActivate(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const client = clientOf(req);
  const body = isPlainObject(req.body) ? req.body : {};
  const id = req.params.id;
  const code = body.code;
  const subject = boundedString(body.subject, MAX_SUBJECT_LENGTH);
  if (typeof id !== 'string' || !isConnectionId(id) || !isLinkActivationCode(code) || !subject) {
    sendOpaqueFailure(req, res);
    return;
  }
  const claim = await ctx.store.claimActivation({
    client_id: client.client_id,
    connection_id: id,
    activation_code_hash: sha256Hex(code),
    subject,
    now: nowIso(),
  });
  if (!claim.ok) {
    // The store already ended the transaction (and revoked what it created)
    // on expiry or a subject mismatch; the staged tokens go too.
    if ('transaction' in claim) await cleanupEndedTransaction(ctx, claim.transaction);
    sendOpaqueFailure(req, res);
    return;
  }
  const tx = claim.transaction;
  const connectionId = tx.connection_id as Connection['id'];
  const actor = `link:${client.client_id}`;

  try {
    writeOperationAudit(ctx, {
      action: 'update',
      outcome: 'pending',
      resource: { type: 'grant', id: tx.grant_id ?? connectionId },
      actor,
      correlationId: tx.tid,
      metadata: { reason: 'activate', connection_id: connectionId, client_id: client.client_id, tid: tx.tid },
    });
  } catch {
    // Nothing changed; the claimed transaction ends at expiry through the sweep.
    sendOpaqueFailure(req, res);
    return;
  }

  // The connection's token lock is held from the database commit through
  // the token commit, so a refresh either finishes entirely before the
  // activation or starts after the new tokens are in place. Cleanup that
  // needs the same lock runs after it is released.
  type ActivationStep =
    | { kind: 'refused'; storeEnded: boolean }
    | { kind: 'tokens_failed'; connection: Connection; grant: ClientGrant; previous: string[] | null; createsConnection: boolean }
    | { kind: 'ok'; connection: Connection; grant: ClientGrant; previous: string[] | null };
  const step = await ctx.locks.run(connectionId, async (): Promise<ActivationStep> => {
    let activated;
    try {
      activated = await ctx.store.commitActivation({ tid: tx.tid, now: nowIso() });
    } catch (error) {
      // Refusals the store already ended the transaction for. grant_changed:
      // the grant's scopes differ from what the confirmation screen showed
      // (a narrow, a provider scope reduction or another activation since);
      // a status change alone never refuses.
      const storeEnded = error instanceof LinkStoreError
        && (error.code === 'activation_superseded' || error.code === 'connection_unavailable' || error.code === 'grant_changed');
      if (!storeEnded) {
        console.error('[link] activation commit failed', { tid: tx.tid, kind: error instanceof Error ? error.name : 'unknown' });
      }
      return { kind: 'refused', storeEnded };
    }
    let moved = false;
    try {
      moved = await ctx.secrets.commitStaged(tx.tid, activated.connection.id);
    } catch {
      moved = false;
    }
    if (!moved) {
      // The database says active but the tokens did not move: never leave an
      // active connection without (or with the wrong) tokens.
      await ctx.store.setConnectionStatus({
        connection_id: activated.connection.id,
        status: 'needs_reauth',
        reason: 'reauth_required',
        now: nowIso(),
      }).catch(() => null);
      return {
        kind: 'tokens_failed',
        connection: activated.connection,
        grant: activated.grant,
        previous: activated.previous_grant_scopes,
        createsConnection: tx.creates_connection === true,
      };
    }
    // The move finished: mark it settled so the startup heal leaves it alone.
    // If this write is lost, the heal finds the tokens moved and settles it.
    await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() }).catch(() => false);
    return { kind: 'ok', connection: activated.connection, grant: activated.grant, previous: activated.previous_grant_scopes };
  });

  if (step.kind === 'refused') {
    if (step.storeEnded) {
      // The store ended the transaction and revoked the pending rows it created.
      const ended = await ctx.store.getTransaction(tx.tid);
      if (ended) await cleanupEndedTransaction(ctx, ended);
    } else {
      // Nothing changed in the store; end the claimed transaction.
      const ended = await ctx.store.endTransaction({ tid: tx.tid, outcome: 'failed', error: 'server_error', now: nowIso() }).catch(() => null);
      if (ended) await cleanupEndedTransaction(ctx, ended);
    }
    sendOpaqueFailure(req, res);
    return;
  }
  if (step.kind === 'tokens_failed') {
    // The database commit stands (the grant may have been narrowed), so the
    // Permissions must not stay wider than it: run the intersect with the
    // committed grant. Best effort; it never changes the response.
    try {
      await ctx.hooks.onGrantUpdated({ grant: step.grant, previous_scopes: step.previous ?? step.grant.scopes, reason: 'activate' });
    } catch (error) {
      console.error('[link] permission intersect after a failed token move failed', { tid: tx.tid, kind: error instanceof Error ? error.name : 'unknown' });
    }
    // Discard the staged tokens under the revocation rule. A connection this
    // transaction created holds no tokens, so it does not block revocation;
    // a live connection (update, reauth) does, since revoking the new token
    // could end the whole authorization its old tokens still use.
    const staged = await ctx.secrets.getStaged(tx.tid).catch(() => null);
    if (staged && tx.provider) {
      await revokeAtProviderIfSafe(ctx, staged, {
        provider: tx.provider,
        provider_account_id: tx.provider_account_id,
        exclude_connection_ids: step.createsConnection ? [step.connection.id] : [],
        exclude_tid: tx.tid,
      });
    }
    const deleted = await ctx.secrets.deleteStaged(tx.tid).then(() => true, () => false);
    // Resolved in process (the connection is needs_reauth); a staged copy
    // that could not be deleted is left for the startup heal.
    if (deleted) await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() }).catch(() => false);
    sendOpaqueFailure(req, res);
    return;
  }
  const { connection, grant, previous } = step;

  // The pending record already made this fail closed: a failure of the
  // success record is logged and does not abort the activation.
  try {
    writeGrantAudit(ctx, {
      action: 'update',
      grant,
      provider: connection.provider,
      before_scopes: previous,
      before_status: previous === null ? 'pending' : null,
      reason: 'activate',
      tid: tx.tid,
    });
  } catch (error) {
    console.error('[link] activation success audit failed', { tid: tx.tid, kind: error instanceof Error ? error.name : 'unknown' });
  }
  try {
    if (previous !== null && !scopeSetsEqual(previous, grant.scopes)) {
      await ctx.hooks.onGrantUpdated({ grant, previous_scopes: previous, reason: 'activate' });
    }
    await ctx.hooks.onActivate({
      intent: tx.intent,
      connection,
      grant,
      agent_id: tx.agent_id ?? null,
      tid: tx.tid,
      actor,
    });
  } catch (error) {
    console.error('[link] activation hooks failed', { tid: tx.tid, kind: error instanceof Error ? error.name : 'unknown' });
    sendOpaqueFailure(req, res);
    return;
  }
  res.setHeader('Cache-Control', 'no-store');
  res.json(connectionView(connection, grant));
}

/**
 * DELETE /link/v1/connections/:id: revoke at the provider (when the
 * revocation rule allows it), delete secrets, revoke the grant. Runs under
 * the connection's token lock; a pending audit record is written first and
 * the deletion is aborted if it cannot be.
 */
export async function handleRevokeConnection(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const connection = await ownedConnection(ctx, req);
  if (!connection) {
    sendOpaqueFailure(req, res);
    return;
  }
  const actor = `link:${clientOf(req).client_id}`;
  const correlationId = requestId(req, res);
  let providerRevoked = false;
  if (connection.status !== 'revoked') {
    try {
      writeOperationAudit(ctx, {
        action: 'revoke',
        outcome: 'pending',
        resource: { type: 'grant', id: connection.id },
        actor,
        correlationId,
        metadata: { reason: 'revoke', connection_id: connection.id, client_id: connection.client_id },
      });
    } catch {
      sendLinkError(req, res, 500, 'server_error');
      return;
    }
    const outcome = await ctx.locks.run(connection.id, async () => {
      const before = await ctx.store.getGrantForConnection(connection.id);
      const tokens = await ctx.secrets.get(connection.id).catch(() => null);
      const updated = await ctx.store.setConnectionStatus({ connection_id: connection.id, status: 'revoked', now: nowIso() });
      let revoked = false;
      if (tokens) {
        revoked = await revokeAtProviderIfSafe(ctx, tokens, {
          provider: connection.provider,
          provider_account_id: connection.provider_account_id,
          exclude_connection_ids: [connection.id],
        });
      }
      await ctx.secrets.delete(connection.id).catch(() => undefined);
      return { before, updated, revoked };
    });
    providerRevoked = outcome.revoked;
    try {
      for (const p of await ctx.permissions.listForConnection(connection.id)) await ctx.permissions.revoke(p.id);
    } catch {
      // Permissions on a revoked connection grant nothing; checkLinkAccess denies.
    }
    if (outcome.updated?.grant) {
      try {
        writeGrantAudit(ctx, {
          action: 'revoke',
          grant: outcome.updated.grant,
          provider: connection.provider,
          before_scopes: outcome.before?.scopes ?? null,
          before_status: outcome.before?.status ?? null,
          reason: 'revoke',
          actor,
        });
      } catch {
        sendLinkError(req, res, 500, 'server_error');
        return;
      }
    }
  }
  res.setHeader('Cache-Control', 'no-store');
  const response: RevokeConnectionResponse = { connection_id: connection.id, status: 'revoked', provider_revoked: providerRevoked };
  res.json(response);
}

/** POST /link/v1/connections/:id/refresh: force refresh, status only. */
export async function handleRefreshConnection(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const connection = await ownedConnection(ctx, req);
  if (!connection) {
    sendOpaqueFailure(req, res);
    return;
  }
  if (connection.status === 'active') {
    const result = await ctx.tokens.load(connection, { force: true });
    if (!result.ok && result.kind === 'unavailable') {
      sendLinkError(req, res, 503, 'temporarily_unavailable');
      return;
    }
  }
  const current = (await ctx.store.getConnection(connection.id)) ?? connection;
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    connection_id: current.id,
    status: current.status,
    ...(current.status_reason ? { status_reason: current.status_reason } : {}),
  });
}

/** POST /link/v1/connections/:id/reauth: PAR sugar with intent 'reauth'. */
export async function handleReauthConnection(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const client = clientOf(req);
  const body = isPlainObject(req.body) ? req.body : {};
  const id = req.params.id;
  const subject = boundedString(body.subject, MAX_SUBJECT_LENGTH);
  if (typeof id !== 'string' || !isConnectionId(id) || !subject) {
    sendOpaqueFailure(req, res);
    return;
  }
  const connection = await ctx.store.getSubjectConnection({ client_id: client.client_id, subject, connection_id: id });
  if (!connection) {
    sendOpaqueFailure(req, res);
    return;
  }
  const redirectUri = body.redirect_uri ?? (client.redirect_uris.length === 1 ? client.redirect_uris[0] : undefined);
  const origin = body.origin ?? (client.origins.length === 1 ? client.origins[0] : undefined);
  try {
    sendPushOutcome(req, res, await pushAuthorizationRequest(ctx, client, {
      intent: 'reauth',
      subject,
      subject_type: connection.subject_type,
      connection_id: id,
      redirect_uri: redirectUri,
      origin,
      ...(body.state !== undefined ? { state: body.state } : {}),
      ...(body.agent_id !== undefined ? { agent_id: body.agent_id } : {}),
    }));
  } catch (error) {
    console.error('[link] reauth failed', { kind: error instanceof Error ? error.name : 'unknown' });
    sendLinkError(req, res, 500, 'server_error');
  }
}

/**
 * POST /link/v1/connections/:id/narrow { subject, scopes } (spec 6).
 *
 * Shrinks the grant to exactly `scopes` with no provider round trip and no
 * token change. Ownership as update and reauth: (client, subject), else the
 * opaque failure. Rejected requests change nothing. Idempotent and self-
 * healing: scopes equal to the current grant answer changed: false without
 * touching the grant, its version or the audit log, but still intersect
 * every Permission, so a narrow whose intersect step failed is repaired by
 * repeating it.
 */
export async function handleNarrowConnection(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const client = clientOf(req);
  const body = isPlainObject(req.body) ? req.body : {};
  const id = req.params.id;
  const subject = boundedString(body.subject, MAX_SUBJECT_LENGTH);
  if (typeof id !== 'string' || !isConnectionId(id) || !subject) {
    sendOpaqueFailure(req, res);
    return;
  }
  const connection = await ctx.store.getSubjectConnection({ client_id: client.client_id, subject, connection_id: id });
  if (!connection) {
    sendOpaqueFailure(req, res);
    return;
  }
  const scopes = body.scopes;
  // Every entry is checked in canonical form: an entry such as "/" is not
  // blank but canonicalizes to nothing, and must not shrink the grant.
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.length > 64
    || !scopes.every((s) => typeof s === 'string' && s.length <= 256 && canonicalScope(s) !== '')) {
    sendLinkError(req, res, 400, 'invalid_scope', { message: 'scopes must be a non-empty list of scope strings; delete the connection to remove all access' });
    return;
  }
  if (connection.status !== 'active') {
    const code = connection.status_reason ?? LINK_MACHINE_CODE_FOR_CONNECTION_STATUS[connection.status] ?? 'grant_revoked';
    sendLinkError(req, res, LINK_MACHINE_ERROR_STATUS[code], code);
    return;
  }
  const grant = await ctx.store.getGrantForConnection(connection.id);
  if (!grant || grant.status !== 'active') {
    const code = grant ? (LINK_MACHINE_CODE_FOR_GRANT_STATUS[grant.status] ?? 'grant_revoked') : 'grant_revoked';
    sendLinkError(req, res, LINK_MACHINE_ERROR_STATUS[code], code);
    return;
  }
  const wanted = canonicalScopeSet(scopes as string[]);
  if (wanted.length === 0) {
    sendLinkError(req, res, 400, 'invalid_scope', { message: 'scopes must be a non-empty list of scope strings; delete the connection to remove all access' });
    return;
  }
  if (!isScopeSubset(wanted, grant.scopes)) {
    sendLinkError(req, res, 400, 'invalid_scope', { message: 'scopes must be a subset of the current grant' });
    return;
  }
  const locked = grant.scopes.filter((s) => findScopeCatalogEntry(connection.provider, s)?.flags.includes('always_required'));
  if (!isScopeSubset(locked, wanted)) {
    sendLinkError(req, res, 400, 'invalid_scope', { message: 'scopes must keep every always-required scope' });
    return;
  }
  const actor = `link:${client.client_id}`;
  const correlationId = requestId(req, res);
  const changed = !scopeSetsEqual(wanted, grant.scopes);

  type NarrowStep =
    | { kind: 'audit_failed' }
    | { kind: 'moved' }
    | { kind: 'hook_failed' }
    | { kind: 'ok'; grant: ClientGrant; removed: string[] };
  const step = await ctx.locks.run(connection.id, async (): Promise<NarrowStep> => {
    if (!changed) {
      // Repair path: no write, no version change, no audit; intersect only,
      // with the grant as it stands now (re-read under the lock). If the
      // connection or grant moved since the checks above, the caller
      // retries and the checks run again.
      const currentConnection = await ctx.store.getConnection(connection.id);
      const current = await ctx.store.getGrantForConnection(connection.id);
      if (!currentConnection || currentConnection.status !== 'active' || !current || current.status !== 'active'
        || current.id !== grant.id || !scopeSetsEqual(current.scopes, wanted)) {
        return { kind: 'moved' };
      }
      try {
        await ctx.hooks.onGrantUpdated({ grant: current, previous_scopes: current.scopes, reason: 'narrow' });
      } catch {
        return { kind: 'hook_failed' };
      }
      return { kind: 'ok', grant: current, removed: [] };
    }
    try {
      writeOperationAudit(ctx, {
        action: 'update',
        outcome: 'pending',
        resource: { type: 'grant', id: grant.id },
        actor,
        correlationId,
        metadata: { reason: 'narrow', connection_id: connection.id, before_scopes: grant.scopes, after_scopes: wanted, version: grant.version },
      });
    } catch {
      return { kind: 'audit_failed' };
    }
    const narrowed = await ctx.store.narrowGrant({ grant_id: grant.id, scopes: wanted, expected_version: grant.version, now: nowIso() });
    if (!narrowed) return { kind: 'moved' };
    let hookFailed = false;
    try {
      await ctx.hooks.onGrantUpdated({ grant: narrowed.grant, previous_scopes: narrowed.previous_scopes, reason: 'narrow' });
    } catch {
      hookFailed = true;
    }
    // The grant changed either way, so the success record is written; its
    // failure is logged and does not abort (the pending record exists).
    try {
      writeGrantAudit(ctx, {
        action: 'update',
        grant: narrowed.grant,
        provider: connection.provider,
        before_scopes: narrowed.previous_scopes,
        before_status: 'active',
        reason: 'narrow',
        actor,
      });
    } catch (error) {
      console.error('[link] narrow success audit failed', { grant_id: grant.id, kind: error instanceof Error ? error.name : 'unknown' });
    }
    if (hookFailed) return { kind: 'hook_failed' };
    return { kind: 'ok', grant: narrowed.grant, removed: scopeDifference(narrowed.previous_scopes, narrowed.grant.scopes) };
  });

  switch (step.kind) {
    case 'audit_failed':
      sendLinkError(req, res, 500, 'server_error');
      return;
    case 'moved':
      // The grant changed underneath this request: nothing else was written.
      sendLinkError(req, res, 503, 'temporarily_unavailable', { message: 'the grant changed; retry' });
      return;
    case 'hook_failed':
      // The grant is narrowed (or unchanged); repeating the same request
      // repairs the permission intersect.
      sendLinkError(req, res, 500, 'server_error', { message: 'retry the same request to finish' });
      return;
    case 'ok': {
      const current = (await ctx.store.getConnection(connection.id)) ?? connection;
      const response: NarrowConnectionResponse = {
        connection: connectionView(current, step.grant),
        changed,
        removed_scopes: step.removed,
        // Narrowing never changes the provider token: say what enforces it.
        enforcement: narrowEnforcement(current, step.grant, changed ? step.removed : null),
      };
      res.setHeader('Cache-Control', 'no-store');
      res.json(response);
    }
  }
}

/**
 * What stops an agent from exercising the scopes a narrow removed. The
 * provider's upper bound comes from linkNarrowEnforcementFor; within it,
 * the broker only tells Google API families apart (google-scopes.ts, the
 * same table and matcher the broker uses). So 'broker' only when every
 * removed scope belongs to a family that no remaining scope unlocks; a
 * removed scope that shares a family with a remaining one (gmail.send
 * removed, gmail.readonly kept) or belongs to no family answers 'record'.
 *
 * An unchanged (idempotent) narrow removed nothing in this call, so it is
 * judged on what the provider token carries beyond the grant: the
 * non-hidden catalog scopes the provider granted that the grant lacks.
 * That matches the original narrow's answer when the grant was cut from
 * the token, and it never claims more than the broker enforces.
 */
function narrowEnforcement(connection: Connection, grant: ClientGrant, removed: string[] | null): LinkNarrowEnforcement {
  if (linkNarrowEnforcementFor(connection.provider) !== 'broker') return 'record';
  if (connection.provider !== 'google') return 'record';
  const beyond = removed ?? scopeDifference(
    canonicalScopeSet(connection.provider_scopes).filter((s) => {
      const entry = findScopeCatalogEntry(connection.provider, s);
      return entry !== null && entry.enforced_by === 'provider' && !entry.flags.includes('hidden');
    }),
    grant.scopes,
  );
  return googleRemovalIsBrokerEnforced(beyond, grant.scopes) ? 'broker' : 'record';
}

/** POST /link/v1/connections/:id/permissions (decision 14). */
export async function handleSetPermission(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const client = clientOf(req);
  const body = isPlainObject(req.body) ? req.body : {};
  const id = req.params.id;
  if (typeof id !== 'string' || !isConnectionId(id)) {
    sendOpaqueFailure(req, res);
    return;
  }
  const agentId = boundedString(body.agent_id, MAX_AGENT_ID_LENGTH);
  const scopes = body.scopes;
  if (!agentId) {
    sendLinkError(req, res, 400, 'invalid_request', { message: 'agent_id is required' });
    return;
  }
  if (!Array.isArray(scopes) || scopes.length > 64 || !scopes.every((s) => typeof s === 'string' && s !== '' && s.length <= 256)) {
    sendLinkError(req, res, 400, 'invalid_request', { message: 'scopes must be a list of scope strings' });
    return;
  }
  // Ownership first, so the audit trail never names foreign connections.
  if (!(await ctx.store.getClientConnection({ client_id: client.client_id, connection_id: id }))) {
    sendOpaqueFailure(req, res);
    return;
  }
  const actor = `link:${client.client_id}`;
  const correlationId = requestId(req, res);
  const audit = (outcome: 'pending' | 'success', extra: Record<string, unknown> = {}) => writeOperationAudit(ctx, {
    action: 'update',
    outcome,
    resource: { type: 'permission', id: `${id}/${agentId}` },
    actor,
    correlationId,
    metadata: { connection_id: id, agent_id: agentId, scopes: canonicalScopeSet(scopes as string[]), ...extra },
  });
  try {
    audit('pending');
  } catch {
    sendLinkError(req, res, 500, 'server_error');
    return;
  }
  const result = await ctx.hooks.setAgentPermission({
    client_id: client.client_id,
    connection_id: id,
    agent_id: agentId,
    scopes: scopes as string[],
    actor,
  });
  if (result.ok) {
    try {
      audit('success', { permission_id: result.permission.id });
    } catch {
      sendLinkError(req, res, 500, 'server_error');
      return;
    }
    res.setHeader('Cache-Control', 'no-store');
    res.json({ permission: permissionView(result.permission) });
    return;
  }
  if (result.status === LINK_OPAQUE_FAILURE_STATUS) {
    sendOpaqueFailure(req, res);
    return;
  }
  sendLinkError(req, res, result.status, result.error);
}

// ── Admin client registration ────────────────────────────────────────────────

const REDIRECT_PARAM_KEYS = new Set<string>(Object.values(LINK_REDIRECT_PARAMS));

function validateRedirectUri(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048 || hasControlCharacter(value)) return null;
  if (value.includes('#')) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.username || url.password || url.hash) return null;
  const loopback = isLoopbackHost(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) return null;
  for (const key of url.searchParams.keys()) {
    if (REDIRECT_PARAM_KEYS.has(key)) return null;
  }
  return value;
}

function validateOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.origin !== value) return null;
  const loopback = isLoopbackHost(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) return null;
  return value;
}

function validateList(value: unknown, check: (v: unknown) => string | null): string[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_URIS) return null;
  const out: string[] = [];
  for (const v of value) {
    const ok = check(v);
    if (!ok) return null;
    if (!out.includes(ok)) out.push(ok);
  }
  return out;
}

/** Client as shown to the operator: never the secret hash. */
export function clientView(client: LinkClient): Record<string, unknown> {
  return {
    client_id: client.client_id,
    name: client.name,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    redirect_uris: [...client.redirect_uris],
    origins: [...client.origins],
    ...(client.theme ? { theme: client.theme } : {}),
    allow_raw_tokens: client.allow_raw_tokens,
    status: client.status,
    ...(client.token_endpoint_auth_method === 'private_key_jwt' ? { jwks: client.jwks } : {}),
    created_at: client.created_at,
    updated_at: client.updated_at,
  };
}

/** POST /admin/link/clients */
export async function handleAdminCreateClient(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const body = isPlainObject(req.body) ? req.body : {};
  const bad = (message: string) => res.status(400).json({ error: 'invalid_request', message });
  const clientId = body.client_id === undefined ? `lc_${newSecret().replace(/[^A-Za-z0-9]/g, '').slice(0, 24)}` : body.client_id;
  if (!isLinkClientId(clientId)) return void bad('client_id is malformed');
  // The display name identifies the app on the consent pages: required, and
  // held to the theme appName rules (no control, invisible or bidi characters).
  const name = typeof body.name === 'string' ? sanitizeLinkTheme({ appName: body.name }).appName : undefined;
  if (!name || name !== body.name) {
    return void bad('name is required: printable text of at most 64 characters, no invisible or bidirectional characters, no surrounding spaces');
  }
  const redirectUris = validateList(body.redirect_uris, validateRedirectUri);
  if (!redirectUris) {
    return void bad('redirect_uris must be https (or loopback http) URLs without a fragment or Link result parameters');
  }
  const origins = validateList(body.origins, validateOrigin);
  if (!origins) return void bad('origins must be https (or loopback http) origins');
  const method = body.token_endpoint_auth_method ?? 'client_secret_basic';
  if (typeof method !== 'string' || !(LINK_CLIENT_AUTH_METHODS as readonly string[]).includes(method)) {
    return void bad('token_endpoint_auth_method must be client_secret_basic or private_key_jwt');
  }
  if (body.allow_raw_tokens !== undefined && typeof body.allow_raw_tokens !== 'boolean') {
    return void bad('allow_raw_tokens must be a boolean');
  }
  if (await ctx.store.getClient(clientId)) {
    res.status(409).json({ error: 'invalid_request', message: 'client_id is already registered' });
    return;
  }
  const theme = body.theme === undefined ? undefined : sanitizeLinkTheme(body.theme);
  const now = nowIso();
  const base = {
    client_id: clientId,
    org_id: LINK_DEFAULT_ORG_ID,
    name,
    redirect_uris: redirectUris,
    origins,
    ...(theme && Object.keys(theme).length > 0 ? { theme } : {}),
    allow_raw_tokens: body.allow_raw_tokens === true,
    status: 'active' as const,
    created_at: now,
    updated_at: now,
  };
  let client: LinkClient;
  let secret: string | undefined;
  if (method === 'private_key_jwt') {
    const jwks = validateClientJwks(body.jwks);
    if (!jwks) return void bad('jwks must hold 1 to 10 public RSA, EC or Ed25519 keys');
    client = { ...base, token_endpoint_auth_method: 'private_key_jwt', jwks };
  } else {
    if (body.jwks !== undefined) return void bad('jwks is only valid with private_key_jwt');
    secret = `cred_lcs_${newSecret()}`;
    client = { ...base, token_endpoint_auth_method: 'client_secret_basic', client_secret_hash: sha256Hex(secret) };
  }
  await ctx.store.putClient(client);
  res.setHeader('Cache-Control', 'no-store');
  res.status(201).json({ client: clientView(client), ...(secret ? { client_secret: secret } : {}) });
}

/** GET /admin/link/clients */
export async function handleAdminListClients(ctx: LinkContext, _req: Request, res: Response): Promise<void> {
  const clients = await ctx.store.listClients();
  res.setHeader('Cache-Control', 'no-store');
  res.json({ clients: clients.map(clientView) });
}

/** POST /admin/link/clients/:client_id/disable and /enable */
export async function handleAdminSetClientStatus(ctx: LinkContext, req: Request, res: Response, status: LinkClient['status']): Promise<void> {
  const id = req.params.client_id;
  const client = typeof id === 'string' && isLinkClientId(id) ? await ctx.store.getClient(id) : null;
  if (!client) {
    res.status(404).json({ error: 'Link client not found' });
    return;
  }
  const updated: LinkClient = { ...client, status, updated_at: nowIso() };
  await ctx.store.putClient(updated);
  res.setHeader('Cache-Control', 'no-store');
  res.json({ client: clientView(updated) });
}

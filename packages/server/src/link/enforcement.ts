/**
 * Cred Link server: enforcement on /api/v1/delegate and /api/v1/use
 * (decisions 5 and 6), independent of Guard.
 *
 * Agent identity for Link checks comes only from verified request state:
 *
 *   1. A custom agentRequestVerifier is configured: its principal's
 *      `principalId` (no principalId means no identity, so every Link call
 *      is denied with permission_required).
 *   2. Otherwise (the static AGENT_TOKEN bearer):
 *      a. delegate only: a TOFU proof in the body (tofu_fingerprint,
 *         tofu_payload, tofu_signature), signature-verified, gives
 *         `tofu:<agentId>`. For Link calls the signed payload binds
 *         service = the `service` field, userId = the connection_id,
 *         appClientId = the `appClientId` field (default 'local') and the
 *         requested scopes.
 *      b. a verified Web Bot Auth signature whose key belongs to a local
 *         TOFU agent gives `tofu:<agentId>` (the same id space).
 *      c. otherwise the fixed id 'server-agent', the server's audit actor
 *         fallback: a single-agent deployment passes agent_id
 *         'server-agent' in PAR.
 *      If a TOFU proof and a Web Bot Auth identity disagree, the call is
 *      denied. TOFU agents use Web Bot Auth on /api/v1/use, which carries
 *      no TOFU proof.
 * Body fields such as agent_id, agent_did or web_bot_auth_key_id never
 * establish identity.
 */

import type { NextFunction, Request, Response } from 'express';
import type { AgentVault } from '@credninja/tofu';
import {
  LINK_ID_PREFIXES,
  LINK_MACHINE_ERROR_STATUS,
  canonicalScopeSet,
  findScopeCatalogEntry,
  intersectScopes,
  scopeDifference,
} from '@credninja/protocol';
import type { Connection, LinkAccessResult, LinkMachineErrorCode, LinkProviderSlug } from '@credninja/protocol';
import { linkVaultUserId } from '@credninja/vault';
import type { RequestAgentPrincipal } from '../config.js';
import { resolveTofuPrincipal, toTofuPrincipalId } from '../tofu-bridge.js';
import type { LinkContext } from './core.js';
import { mintAgentReauthUrl } from './core.js';
import { NON_EXPIRING_LINK_PROVIDERS } from './providers.js';
import { newId, nowIso, requestId, sendLinkError } from './util.js';

/** The fixed agent id of the static-bearer deployment. */
export const STATIC_BEARER_AGENT_ID = 'server-agent';

/** What a Delegation Token for a Link connection is bound to, recorded with its grant. */
export interface LinkHandleBinding {
  connectionId: string;
  clientId: string;
  grantId: string;
  grantVersion: number;
  agentId: string;
}

/** What the delegate precheck leaves on the request for the guard and the handler. */
export interface LinkDelegateState {
  access: Extract<LinkAccessResult, { ok: true }>;
  agentId: string;
}

type LinkRequest = Request & { credLinkDelegate?: LinkDelegateState };

export interface LinkEnforcementDeps {
  ctx: LinkContext;
  tofu: AgentVault;
  /** True when config.agentRequestVerifier is set. */
  customVerifier: boolean;
}

type IdentityResult = { ok: true; agentId: string | null } | { ok: false };

function webBotAuthAgentId(req: Request): string | null {
  const identity = (req as { webBotAuthIdentity?: { agentId?: string } }).webBotAuthIdentity;
  return identity && typeof identity.agentId === 'string' && identity.agentId !== ''
    ? toTofuPrincipalId(identity.agentId)
    : null;
}

/** Agent id for a Link check, from verified request state only (see the module comment). */
export async function resolveLinkAgentId(
  deps: LinkEnforcementDeps,
  req: Request,
  tofuExpectation?: { service: string; userId: string; appClientId: string; requestedScopes?: string[] },
): Promise<IdentityResult> {
  const principal = (req as { agentPrincipal?: RequestAgentPrincipal }).agentPrincipal;
  if (deps.customVerifier) {
    if (!principal || principal.type === 'static-bearer') return { ok: true, agentId: null };
    return { ok: true, agentId: typeof principal.principalId === 'string' && principal.principalId !== '' ? principal.principalId : null };
  }
  if (!principal || principal.type !== 'static-bearer') return { ok: true, agentId: null };

  const wba = webBotAuthAgentId(req);
  const body = req.body && typeof req.body === 'object' ? req.body as Record<string, unknown> : {};
  const hasProof = body.tofu_fingerprint !== undefined || body.tofu_payload !== undefined || body.tofu_signature !== undefined;
  if (hasProof) {
    if (!tofuExpectation
      || typeof body.tofu_fingerprint !== 'string'
      || typeof body.tofu_payload !== 'string'
      || typeof body.tofu_signature !== 'string') {
      return { ok: false };
    }
    let tofuId: string;
    try {
      const resolved = await resolveTofuPrincipal(deps.tofu, {
        fingerprint: body.tofu_fingerprint,
        payloadBase64: body.tofu_payload,
        signatureBase64: body.tofu_signature,
      }, tofuExpectation);
      tofuId = resolved.principal.principalId;
    } catch {
      return { ok: false };
    }
    if (wba !== null && wba !== tofuId) return { ok: false };
    return { ok: true, agentId: tofuId };
  }
  return { ok: true, agentId: wba ?? STATIC_BEARER_AGENT_ID };
}

/**
 * Requested scopes of a Link delegate call. Absent or [] means "everything
 * the agent may use", so a malformed entry must never collapse into that:
 * a blank or whitespace-only entry, or an empty comma segment, is refused.
 */
export function normalizeLinkScopes(value: unknown): string[] | null {
  if (value === undefined) return [];
  const list = typeof value === 'string' ? value.split(',') : value;
  if (!Array.isArray(list) || list.length > 64) return null;
  if (!list.every((s) => typeof s === 'string' && s.trim() !== '' && s.length <= 256)) return null;
  return canonicalScopeSet(list as string[]);
}

const REAUTH_CODES = new Set<LinkMachineErrorCode>(['reauth_required', 'grant_revoked', 'grant_expired']);

/**
 * Deny a Link call with `{ error, request_id, scope? , reauth_url? }`. A
 * reauth_url is minted only for a needs_reauth connection and only for an
 * agent that holds a Permission on it.
 */
async function sendLinkDenial(
  deps: LinkEnforcementDeps,
  req: Request,
  res: Response,
  denial: { code: LinkMachineErrorCode; status: number; missing_scopes?: string[] },
  connectionId: string,
  agentId: string | null,
): Promise<void> {
  let reauthUrl: string | null = null;
  if (REAUTH_CODES.has(denial.code) && agentId) {
    try {
      const connection = await deps.ctx.store.getConnection(connectionId);
      const client = connection ? await deps.ctx.store.getClient(connection.client_id) : null;
      // Only for a needs_reauth connection of an active client, and only for
      // an agent that holds a Permission on it.
      if (connection && client && client.status === 'active' && connection.status === 'needs_reauth'
        && await deps.ctx.permissions.get(agentId, connection.id)) {
        reauthUrl = await mintAgentReauthUrl(deps.ctx, connection);
      }
    } catch {
      reauthUrl = null;
    }
  }
  sendLinkError(req, res, denial.status, denial.code, {
    ...(denial.missing_scopes && denial.missing_scopes.length > 0 ? { scope: denial.missing_scopes.join(' ') } : {}),
    ...(reauthUrl ? { reauth_url: reauthUrl } : {}),
  });
}

/**
 * The non-hidden catalog scopes the provider actually granted for a
 * connection (what a raw provider token can exercise and a grant can hold).
 * Cred-enforced scopes are not provider-granted and are left out.
 */
function providerGrantedGrantable(provider: LinkProviderSlug, providerScopes: readonly string[]): string[] {
  const out: string[] = [];
  for (const scope of canonicalScopeSet(providerScopes)) {
    const entry = findScopeCatalogEntry(provider, scope);
    if (entry && entry.enforced_by === 'provider' && !entry.flags.includes('hidden')) out.push(entry.scope);
  }
  return canonicalScopeSet(out);
}

/**
 * Middleware for POST /api/v1/delegate, after agent auth and Web Bot Auth
 * and before Guard and any vault access. A no-op unless the body names
 * `connection_id`; then it runs checkLinkAccess and either denies with the
 * typed code or records the allowed access for the guard and the handler.
 */
export function linkDelegatePrecheck(deps: LinkEnforcementDeps) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const body = req.body && typeof req.body === 'object' ? req.body as Record<string, unknown> : null;
    if (!body || body.connection_id === undefined) {
      next();
      return;
    }
    try {
      requestId(req, res);
      const connectionId = body.connection_id;
      if (typeof connectionId !== 'string' || connectionId.length > 128) {
        sendLinkError(req, res, 400, 'invalid_request', { message: 'connection_id must be a string' });
        return;
      }
      if (body.user_id !== undefined) {
        sendLinkError(req, res, 400, 'invalid_request', { message: 'user_id cannot be combined with connection_id' });
        return;
      }
      if (body.service !== undefined && typeof body.service !== 'string') {
        sendLinkError(req, res, 400, 'invalid_request', { message: 'service must be a string' });
        return;
      }
      const requested = normalizeLinkScopes(body.scopes);
      if (requested === null) {
        sendLinkError(req, res, 400, 'invalid_request', { message: 'scopes must be a list of non-blank scope strings' });
        return;
      }
      const appClientId = typeof body.appClientId === 'string' ? body.appClientId : 'local';
      const identity = await resolveLinkAgentId(deps, req, typeof body.service === 'string'
        ? { service: body.service, userId: connectionId, appClientId, requestedScopes: Array.isArray(body.scopes) ? body.scopes as string[] : undefined }
        : undefined);
      if (!identity.ok) {
        sendLinkError(req, res, LINK_MACHINE_ERROR_STATUS.permission_required, 'permission_required');
        return;
      }
      const access = await deps.ctx.hooks.checkLinkAccess({
        operation: 'delegate',
        connection_id: connectionId,
        agent_id: identity.agentId,
        ...(typeof body.service === 'string' ? { provider: body.service } : {}),
        requested_scopes: requested,
        now: nowIso(),
      });
      if (!access.ok) {
        await sendLinkDenial(deps, req, res, access, connectionId, identity.agentId);
        return;
      }
      (req as LinkRequest).credLinkDelegate = { access, agentId: identity.agentId as string };
      // Name the provider for the Guard middleware when the call did not.
      if (body.service === undefined) body.service = access.connection.provider;
      next();
    } catch (error) {
      console.error('[link] delegate check failed', { kind: error instanceof Error ? error.name : 'unknown' });
      sendLinkError(req, res, 500, 'server_error');
    }
  };
}

/** The Link state left by linkDelegatePrecheck, if this is a Link delegate call. */
export function linkDelegateState(req: Request): LinkDelegateState | undefined {
  return (req as LinkRequest).credLinkDelegate;
}

export interface LinkDelegateHandlerDeps extends LinkEnforcementDeps {
  /**
   * The agent's did:key, proven by a DPoP proof on this request, or null
   * once the refusal is sent. Checked before anything is recorded.
   */
  checkAgentKey: (req: Request, res: Response, resourceId: string) => string | null;
  /**
   * Record the delegation and send its Delegation Token, bound to
   * `agentDid`'s key and to `link`; `extra` joins the response.
   */
  issueToken: (req: Request, res: Response, input: {
    delegationId: string;
    agentDid: string;
    service: string;
    userId: string;
    appClientId: string;
    scopes: string[];
    expiresIn: number;
    link: LinkHandleBinding;
    extra: Record<string, unknown>;
  }) => Promise<void>;
  handleTtlSeconds: number;
  /** CRED_ALLOW_RAW_TOKENS: a raw provider token needs this and the client's allow_raw_tokens. */
  allowRawTokens: boolean;
}

/**
 * The Link branch of POST /api/v1/delegate. Delegates exactly the
 * effective scopes (narrowed further by Guard when one ran), defaults to a
 * Delegation Token bound to the agent's did:key, and issues a raw provider
 * token only when the client allows it and the provider's tokens expire
 * and refresh.
 */
export async function handleLinkDelegate(deps: LinkDelegateHandlerDeps, req: Request, res: Response, state: LinkDelegateState): Promise<void> {
  const { ctx } = deps;
  const body = req.body as Record<string, unknown>;
  const connection = state.access.connection;
  const grant = state.access.grant;
  const guardDecision = (req as { guardDecision?: { effectiveScopes?: string[] } }).guardDecision;
  const scopes = guardDecision && Array.isArray(guardDecision.effectiveScopes)
    ? intersectScopes(state.access.effective_scopes, guardDecision.effectiveScopes)
    : [...state.access.effective_scopes];
  if (scopes.length === 0) {
    sendLinkError(req, res, LINK_MACHINE_ERROR_STATUS.insufficient_scope, 'insufficient_scope');
    return;
  }
  const format = body.token_format === undefined ? 'handle' : body.token_format;
  if (format !== 'handle' && format !== 'raw') {
    sendLinkError(req, res, 400, 'invalid_request', { message: 'token_format must be handle or raw' });
    return;
  }

  if (format === 'raw' && !deps.allowRawTokens) {
    sendLinkError(req, res, 400, 'invalid_request', { message: 'This server does not hand out provider tokens (CRED_ALLOW_RAW_TOKENS is off); request a handle' });
    return;
  }
  // The token binds the agent's key, but which Link agent it acts for comes
  // from the caller's identity: the shared static Bearer names no one, so
  // anyone holding it could bind a token to a key of their own.
  const principal = (req as { agentPrincipal?: RequestAgentPrincipal }).agentPrincipal;
  if (format === 'handle' && state.agentId === STATIC_BEARER_AGENT_ID && principal?.type === 'static-bearer') {
    sendLinkError(req, res, 400, 'invalid_request', {
      message: 'A Link Delegation Token is issued only to an identified agent (a TOFU agent signing with Web Bot Auth, or a verified principal), not to the shared Bearer identity',
    });
    return;
  }
  // The Delegation Token is bound to the agent's key (DPoP): the agent's
  // Bearer alone cannot exercise it.
  let agentDid: string | null = null;
  if (format === 'handle') {
    agentDid = deps.checkAgentKey(req, res, `${connection.provider}/${linkVaultUserId(connection.id)}`);
    if (agentDid === null) return;
  }

  const loaded = await ctx.tokens.load(connection);
  if (!loaded.ok) {
    await sendTokenLoadFailure(deps, req, res, connection, loaded, state.agentId);
    return;
  }

  const delegationId = newId('del_');
  if (format === 'raw') {
    const client = await ctx.store.getClient(connection.client_id);
    const refreshable = ctx.providers.supportsRefresh(connection.provider)
      && !NON_EXPIRING_LINK_PROVIDERS.has(connection.provider)
      && typeof loaded.tokens.expires_at === 'string';
    if (!client || !client.allow_raw_tokens || !refreshable) {
      sendLinkError(req, res, 400, 'invalid_request', { message: 'raw tokens are not available for this connection' });
      return;
    }
    // A raw provider token carries everything the provider granted. Issue
    // one only when the delegated scopes cover every grantable scope the
    // provider granted for this connection; anything narrower (a narrowed
    // grant, a Permission or request for fewer scopes) gets a handle only.
    const uncovered = scopeDifference(providerGrantedGrantable(connection.provider, connection.provider_scopes), scopes);
    if (uncovered.length > 0) {
      sendLinkError(req, res, 400, 'invalid_request', {
        message: 'raw tokens are issued only for every scope the provider granted; request a handle',
      });
      return;
    }
    const expiresIn = Math.max(1, Math.floor((Date.parse(loaded.tokens.expires_at as string) - Date.now()) / 1000));
    // Its own audit event per raw issuance (spec 4); fail closed.
    ctx.vault.writeAuditEvent({
      id: newId(LINK_ID_PREFIXES.auditEvent),
      timestamp: new Date(),
      actor: { type: 'agent', id: state.agentId },
      action: 'delegate',
      resource: { type: 'token', id: delegationId },
      outcome: 'success',
      scopesRequested: scopes,
      scopesGranted: scopes,
      correlationId: requestId(req, res),
      metadata: {
        link_raw_token: true,
        connection_id: connection.id,
        grant_id: grant.id,
        grant_version: grant.version,
        client_id: connection.client_id,
        provider: connection.provider,
      },
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      access_token: loaded.tokens.access_token,
      token_type: 'Bearer',
      expires_in: expiresIn,
      service: connection.provider,
      connection_id: connection.id,
      grant_id: grant.id,
      grant_version: grant.version,
      scopes,
      delegation_id: delegationId,
    });
    return;
  }

  // Audit first (fail closed): no token exists without its record.
  ctx.vault.writeAuditEvent({
    id: newId(LINK_ID_PREFIXES.auditEvent),
    timestamp: new Date(),
    actor: { type: 'agent', id: state.agentId },
    action: 'delegate',
    resource: { type: 'token', id: delegationId },
    outcome: 'success',
    scopesRequested: scopes,
    scopesGranted: scopes,
    correlationId: requestId(req, res),
    metadata: { connection_id: connection.id, grant_id: grant.id, grant_version: grant.version, client_id: connection.client_id },
  });
  await deps.issueToken(req, res, {
    delegationId,
    agentDid: agentDid!,
    service: connection.provider,
    userId: linkVaultUserId(connection.id),
    appClientId: connection.client_id,
    scopes,
    expiresIn: deps.handleTtlSeconds,
    link: {
      connectionId: connection.id,
      clientId: connection.client_id,
      grantId: grant.id,
      grantVersion: grant.version,
      agentId: state.agentId,
    },
    extra: { connection_id: connection.id, grant_id: grant.id, grant_version: grant.version },
  });
}

async function sendTokenLoadFailure(
  deps: LinkEnforcementDeps,
  req: Request,
  res: Response,
  connection: Connection,
  loaded: Exclude<Awaited<ReturnType<LinkContext['tokens']['load']>>, { ok: true }>,
  agentId: string,
): Promise<void> {
  if (loaded.kind === 'reauth') {
    await sendLinkDenial(deps, req, res, { code: loaded.code, status: LINK_MACHINE_ERROR_STATUS[loaded.code] }, connection.id, agentId);
    return;
  }
  if (loaded.kind === 'unavailable') {
    sendLinkError(req, res, 503, 'temporarily_unavailable');
    return;
  }
  sendLinkError(req, res, 500, 'server_error');
}

/**
 * The Link check of POST /api/v1/use for a handle minted for a Link
 * connection: the caller must be the handle's agent, and checkLinkAccess
 * runs again (operation 'use', the handle's scopes, grant id and version),
 * so a revoked, narrowed or needs_reauth connection is refused at once.
 * Returns the allowed access, or null after sending the denial.
 */
export async function authorizeLinkUse(
  deps: LinkEnforcementDeps,
  req: Request,
  res: Response,
  handle: { service: string; scopes: string[]; link: LinkHandleBinding },
  /**
   * True only once the caller presented the delegation's Delegation Token
   * and proved its key (DPoP): the token then names the Link agent it was
   * issued to. Otherwise the caller's own identity must be that agent.
   */
  tokenVerified: boolean,
): Promise<Extract<LinkAccessResult, { ok: true }> | null> {
  requestId(req, res);
  let agentId: string | null = handle.link.agentId;
  if (!tokenVerified) {
    const identity = await resolveLinkAgentId(deps, req);
    agentId = identity.ok ? identity.agentId : null;
  }
  if (!agentId || agentId !== handle.link.agentId) {
    sendLinkError(req, res, LINK_MACHINE_ERROR_STATUS.permission_required, 'permission_required');
    return null;
  }
  const check = (scopes: string[]) => deps.ctx.hooks.checkLinkAccess({
    operation: 'use',
    connection_id: handle.link.connectionId,
    agent_id: agentId,
    provider: handle.service,
    requested_scopes: scopes,
    grant_id: handle.link.grantId,
    grant_version: handle.link.grantVersion,
    now: nowIso(),
  });
  let access = await check(handle.scopes);
  // After a narrow (or a permission change) the handle keeps working for
  // the scopes that remain: re-check with them. The broker URL check then
  // runs against the remaining effective scopes only. That check is per
  // Google API family (google-scopes.ts), not per scope and not read versus
  // write: a call is refused only when no remaining scope unlocks its
  // family. gmail.readonly and gmail.send, calendar.readonly and
  // calendar.events, drive.file and drive, spreadsheets.readonly and
  // spreadsheets, documents.readonly and documents, contacts.readonly and
  // contacts are not separated, and other providers have no URL-to-scope
  // check at all (the narrow response says 'record' in those cases).
  if (!access.ok && (access.code === 'insufficient_scope' || access.code === 'permission_required')
    && access.missing_scopes && access.missing_scopes.length > 0) {
    const remaining = scopeDifference(handle.scopes, access.missing_scopes);
    if (remaining.length > 0) {
      const retry = await check(remaining);
      if (retry.ok) access = retry;
    }
  }
  if (!access.ok) {
    await sendLinkDenial(deps, req, res, access, handle.link.connectionId, agentId);
    return null;
  }
  return access;
}

/** Load the provider token for a Link use call, or send the typed failure and return null. */
export async function loadLinkUseToken(
  deps: LinkEnforcementDeps,
  req: Request,
  res: Response,
  connection: Connection,
  agentId: string,
): Promise<string | null> {
  const loaded = await deps.ctx.tokens.load(connection);
  if (loaded.ok) return loaded.tokens.access_token;
  await sendTokenLoadFailure(deps, req, res, connection, loaded, agentId);
  return null;
}

/** Salesforce Link delegations are pinned to the connection's own instance host. */
export function linkUpstreamAllowed(connection: Connection, upstreamUrl: string): boolean {
  if (connection.provider !== 'salesforce') return true;
  try {
    return new URL(upstreamUrl).host === new URL(connection.audience).host;
  } catch {
    return false;
  }
}

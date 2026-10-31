/**
 * Cred Link Phase 1 for @credninja/server: one entry point that wires the
 * storage, the policy hooks, the hosted flow, the client API and the admin
 * client registration into the existing Express app.
 *
 * Routes (see packages/server/README.md for the full table):
 *   POST   /link/v1/par                              client auth
 *   GET    /link/v1/authorize                        browser (request_uri)
 *   POST   /link/v1/picker                           browser (envelope + cookie)
 *   GET    /link/v1/callback/:provider               browser (provider state)
 *   POST   /link/v1/confirm                          browser (envelope + cookie)
 *   GET    /link/v1/connections?subject=             client auth
 *   GET    /link/v1/connections/:id                  client auth
 *   DELETE /link/v1/connections/:id                  client auth
 *   POST   /link/v1/connections/:id/activate         client auth
 *   POST   /link/v1/connections/:id/refresh          client auth
 *   POST   /link/v1/connections/:id/reauth           client auth
 *   POST   /link/v1/connections/:id/narrow           client auth
 *   POST   /link/v1/connections/:id/permissions      client auth
 *   POST   /admin/link/clients                       admin auth
 *   GET    /admin/link/clients                       admin auth
 *   POST   /admin/link/clients/:client_id/disable    admin auth
 *   POST   /admin/link/clients/:client_id/enable     admin auth
 */

import type { Express, NextFunction, Request, RequestHandler, Response } from 'express';
import { createLinkHooks } from '@credninja/guard';
import type { GuardLinkContext } from '@credninja/guard';
import { LINK_PATHS, scopeSetsEqual } from '@credninja/protocol';
import { createLinkStorage } from '@credninja/vault';
import type { CredVault } from '@credninja/vault';
import type { AgentVault } from '@credninja/tofu';
import type { ProviderConfig } from '../config.js';
import {
  handleActivate,
  handleAdminCreateClient,
  handleAdminListClients,
  handleAdminSetClientStatus,
  handleGetConnection,
  handleListConnections,
  handleNarrowConnection,
  handlePar,
  handleReauthConnection,
  handleRefreshConnection,
  handleRevokeConnection,
  handleSetPermission,
  requireLinkClient,
} from './api.js';
import { LinkClientAuthenticator } from './client-auth.js';
import type { LinkContext } from './core.js';
import { sweepExpired, writeGrantAuditBestEffort } from './core.js';
import {
  authorizeLinkUse,
  handleLinkDelegate,
  linkDelegatePrecheck,
  linkDelegateState,
  linkUpstreamAllowed,
  loadLinkUseToken,
} from './enforcement.js';
import type { LinkEnforcementDeps, LinkHandleBinding } from './enforcement.js';
import { handleAuthorize, handleCallback, handleConfirm, handlePicker } from './flow.js';
import { healUnsettledActivations } from './heal.js';
import type { LinkHealFollowUpReport, LinkHealReport } from './heal.js';
import { sendLocalErrorPage } from './pages.js';
import { LinkProviderRuntime } from './providers.js';
import { ConnectionLocks, ConnectionQuarantine, LinkTokenLoader } from './tokens.js';
import { sendLinkError, trimTrailingSlashes } from './util.js';

export type { LinkHandleBinding } from './enforcement.js';
export type { LinkHealFollowUpOutcome, LinkHealFollowUpReport, LinkHealOutcome, LinkHealReport } from './heal.js';
export { STATIC_BEARER_AGENT_ID } from './enforcement.js';

/** Default lifetime of a Link brokered handle, seconds. */
export const LINK_HANDLE_TTL_DEFAULT_SECONDS = 300;
/** Ceiling on a Link brokered handle's lifetime, seconds. */
export const LINK_HANDLE_TTL_MAX_SECONDS = 900;

/** Interval of the expiry sweep. */
export const LINK_SWEEP_INTERVAL_MS = 60_000;

export interface CreateLinkServiceOptions {
  vault: CredVault;
  tofu: AgentVault;
  providers: ProviderConfig[];
  /** Public base URL for Link pages and the provider callback. */
  baseUrl: string;
  /** The server's redirectBaseUri (also accepted as client assertion audience). */
  redirectBaseUri: string;
  /** Path of the Link SQLite file. */
  storePath: string;
  /** True when config.agentRequestVerifier is set. */
  customVerifier: boolean;
  /** Checks the agent's did:key and its DPoP proof on a Link delegate call. */
  checkAgentKey: Parameters<typeof handleLinkDelegate>[0]['checkAgentKey'];
  /** Records a Link delegation and sends its Delegation Token. */
  issueToken: Parameters<typeof handleLinkDelegate>[0]['issueToken'];
  /** CRED_ALLOW_RAW_TOKENS (default false). */
  allowRawTokens?: boolean;
  /** Lifetime of Link Delegation Tokens, seconds (default 300, capped at 900). */
  handleTtlSeconds?: number;
  makeRateLimiter: (max: number) => RequestHandler;
  /** Start the unref'd expiry sweep interval. Default true. */
  startSweep?: boolean;
}

export interface LinkService {
  context: LinkContext;
  /** Mount every Link route on the app. */
  mount(app: Express, adminAuth: RequestHandler): void;
  /** Middleware for /api/v1/delegate (after agent auth, before Guard). */
  delegatePrecheck: RequestHandler;
  /** Guard's resolveLinkContext for /api/v1/delegate, from verified state only. */
  resolveGuardLinkContext(req: Request): GuardLinkContext | undefined;
  /** The Link branch of /api/v1/delegate; returns false when the call names no connection. */
  handleDelegate(req: Request, res: Response): Promise<boolean>;
  /** The Link check of /api/v1/use; null after sending a denial. */
  authorizeUse(req: Request, res: Response, handle: { service: string; scopes: string[]; link: LinkHandleBinding }, tokenVerified: boolean): ReturnType<typeof authorizeLinkUse>;
  /** Load the provider token for a use call; null after sending the failure. */
  loadUseToken(req: Request, res: Response, access: { connection: Parameters<typeof loadLinkUseToken>[3] }, agentId: string): Promise<string | null>;
  /** Salesforce instance pinning for brokered calls. */
  upstreamAllowed: typeof linkUpstreamAllowed;
  /** One expiry sweep pass (also run on an interval). */
  sweep(nowMs?: number): Promise<number>;
  /**
   * Resolves when the startup heal of unfinished activations has run
   * (spec 10). Every Link route and the Link branches of /api/v1/delegate
   * and /api/v1/use wait on it; no other route does.
   */
  ready: Promise<LinkHealReport>;
  /**
   * Resolves when the heal's background phase (provider revocation and
   * staged-token deletion, after the gate opened) has finished too.
   */
  healed: Promise<LinkHealFollowUpReport>;
  /** Stop the sweep and close the store. */
  close(): void;
}

/** Build the Link service. Requires a vault with permission storage (the SQLite backend). */
export function createLinkService(options: CreateLinkServiceOptions): LinkService {
  const baseUrl = trimTrailingSlashes(options.baseUrl);
  const selfOrigin = new URL(baseUrl).origin;
  const { store, secrets } = createLinkStorage({ vault: options.vault, path: options.storePath });
  const permissions = options.vault.getLinkPermissionPort();
  const hooks = createLinkHooks({ store, permissions }, {
    onCheckError: (error) => console.error('[link] access check error', { kind: error instanceof Error ? error.name : 'unknown' }),
  });
  const providers = new LinkProviderRuntime({ providers: options.providers, baseUrl });
  const clientAuth = new LinkClientAuthenticator({ store, audiences: [options.redirectBaseUri, baseUrl] });
  // The loader reports to the audit log through the context built below.
  let ctx!: LinkContext;
  const locks = new ConnectionLocks();
  const quarantine = new ConnectionQuarantine();
  const tokens = new LinkTokenLoader({
    store,
    secrets,
    providers,
    locks,
    quarantine,
    // Spec 7 provider_scope_changed: a refresh that reports fewer scopes
    // narrows the connection and intersects the grant (never widens).
    onProviderScopes: async (connection, scopes) => {
      const applied = await store.applyProviderScopes({ connection_id: connection.id, provider_scopes: scopes, now: new Date().toISOString() });
      if (!applied?.grant || !applied.previous_grant_scopes) return;
      if (scopeSetsEqual(applied.previous_grant_scopes, applied.grant.scopes)) return;
      writeGrantAuditBestEffort(ctx, {
        action: 'update',
        grant: applied.grant,
        provider: connection.provider,
        before_scopes: applied.previous_grant_scopes,
        before_status: applied.grant.status,
        reason: 'provider_scope_changed',
        actor: 'link:token-refresh',
      });
      await hooks.onGrantUpdated({ grant: applied.grant, previous_scopes: applied.previous_grant_scopes, reason: 'provider_scope_changed' });
    },
    onReauthRequired: (connection) => {
      void store.getGrantForConnection(connection.id).then((grant) => {
        if (grant) {
          writeGrantAuditBestEffort(ctx, {
            action: 'update',
            grant,
            provider: connection.provider,
            before_scopes: grant.scopes,
            before_status: 'active',
            reason: 'reauth_required',
            actor: 'link:token-refresh',
          });
        }
      }).catch(() => undefined);
    },
  });
  ctx = { store, secrets, hooks, permissions, providers, tokens, locks, quarantine, clientAuth, vault: options.vault, baseUrl, selfOrigin };

  // The heal starts now; requests that touch Link wait for it (gate below).
  const heal = healUnsettledActivations(ctx);
  const ready = heal.ready;
  const gate: RequestHandler = (_req, _res, next) => {
    ready.then(() => next(), () => next());
  };

  const enforcement: LinkEnforcementDeps = { ctx, tofu: options.tofu, customVerifier: options.customVerifier };
  const delegateDeps = {
    ...enforcement,
    checkAgentKey: options.checkAgentKey,
    issueToken: options.issueToken,
    allowRawTokens: options.allowRawTokens ?? false,
    handleTtlSeconds: Math.min(Math.max(1, Math.floor(options.handleTtlSeconds ?? LINK_HANDLE_TTL_DEFAULT_SECONDS)), LINK_HANDLE_TTL_MAX_SECONDS),
  };

  let timer: ReturnType<typeof setInterval> | null = null;
  if (options.startSweep !== false) {
    timer = setInterval(() => {
      sweepExpired(ctx).catch((error) => console.error('[link] sweep failed', { kind: error instanceof Error ? error.name : 'unknown' }));
    }, LINK_SWEEP_INTERVAL_MS);
    if (typeof timer.unref === 'function') timer.unref();
  }

  type Handler = (ctx: LinkContext, req: Request, res: Response) => Promise<void>;
  const page = (fn: Handler): RequestHandler => (req: Request, res: Response, _next: NextFunction) => {
    fn(ctx, req, res).catch((error) => {
      console.error('[link] page error', { path: req.path, kind: error instanceof Error ? error.name : 'unknown' });
      if (!res.headersSent) sendLocalErrorPage(req, res, 500);
    });
  };
  const api = (fn: Handler): RequestHandler => (req: Request, res: Response, _next: NextFunction) => {
    fn(ctx, req, res).catch((error) => {
      console.error('[link] api error', { path: req.path, kind: error instanceof Error ? error.name : 'unknown' });
      if (!res.headersSent) sendLinkError(req, res, 500, 'server_error');
    });
  };
  const admin = (fn: Handler): RequestHandler => (req: Request, res: Response, _next: NextFunction) => {
    fn(ctx, req, res).catch((error) => {
      console.error('[link] admin error', { path: req.path, kind: error instanceof Error ? error.name : 'unknown' });
      if (!res.headersSent) res.status(500).json({ error: 'Link client registration failed' });
    });
  };

  return {
    context: ctx,
    mount(app, adminAuth) {
      const parLimiter = options.makeRateLimiter(60);
      const pageLimiter = options.makeRateLimiter(120);
      const apiLimiter = options.makeRateLimiter(120);
      const adminLimiter = options.makeRateLimiter(30);
      const clientAuthMw = requireLinkClient(ctx);

      app.post(LINK_PATHS.par, parLimiter, gate, clientAuthMw, api(handlePar));
      app.get(LINK_PATHS.authorize, pageLimiter, gate, page(handleAuthorize));
      app.post(LINK_PATHS.picker, pageLimiter, gate, page(handlePicker));
      app.get(LINK_PATHS.callback, pageLimiter, gate, page(handleCallback));
      app.post(LINK_PATHS.confirm, pageLimiter, gate, page(handleConfirm));

      app.get(LINK_PATHS.connections, apiLimiter, gate, clientAuthMw, api(handleListConnections));
      app.get(LINK_PATHS.connection, apiLimiter, gate, clientAuthMw, api(handleGetConnection));
      app.delete(LINK_PATHS.connection, apiLimiter, gate, clientAuthMw, api(handleRevokeConnection));
      app.post(LINK_PATHS.activate, apiLimiter, gate, clientAuthMw, api(handleActivate));
      app.post(LINK_PATHS.refresh, apiLimiter, gate, clientAuthMw, api(handleRefreshConnection));
      app.post(LINK_PATHS.reauth, apiLimiter, gate, clientAuthMw, api(handleReauthConnection));
      app.post(LINK_PATHS.narrow, apiLimiter, gate, clientAuthMw, api(handleNarrowConnection));
      app.post(LINK_PATHS.permissions, apiLimiter, gate, clientAuthMw, api(handleSetPermission));

      app.post('/admin/link/clients', adminLimiter, gate, adminAuth, admin(handleAdminCreateClient));
      app.get('/admin/link/clients', adminLimiter, gate, adminAuth, admin(handleAdminListClients));
      app.post('/admin/link/clients/:client_id/disable', adminLimiter, gate, adminAuth, admin((c, req, res) => handleAdminSetClientStatus(c, req, res, 'disabled')));
      app.post('/admin/link/clients/:client_id/enable', adminLimiter, gate, adminAuth, admin((c, req, res) => handleAdminSetClientStatus(c, req, res, 'active')));
    },
    delegatePrecheck: (() => {
      const precheck = linkDelegatePrecheck(enforcement);
      // Only calls naming a Link connection wait for the heal.
      return (req: Request, res: Response, next: NextFunction) => {
        const body = req.body && typeof req.body === 'object' ? req.body as Record<string, unknown> : null;
        if (!body || body.connection_id === undefined) {
          next();
          return;
        }
        ready.then(() => precheck(req, res, next), () => precheck(req, res, next));
      };
    })(),
    resolveGuardLinkContext(req) {
      const state = linkDelegateState(req);
      return state ? { connectionId: state.access.connection.id, agentId: state.agentId, operation: 'delegate' } : undefined;
    },
    async handleDelegate(req, res) {
      const state = linkDelegateState(req);
      if (!state) return false;
      await handleLinkDelegate(delegateDeps, req, res, state);
      return true;
    },
    async authorizeUse(req, res, handle, tokenVerified) {
      await ready.catch(() => undefined);
      return authorizeLinkUse(enforcement, req, res, handle, tokenVerified);
    },
    loadUseToken(req, res, access, agentId) {
      return loadLinkUseToken(enforcement, req, res, access.connection, agentId);
    },
    upstreamAllowed: linkUpstreamAllowed,
    ready,
    healed: heal.done,
    sweep(nowMs) {
      return sweepExpired(ctx, nowMs);
    },
    close() {
      if (timer) clearInterval(timer);
      timer = null;
      store.close();
    },
  };
}

/**
 * Cred Link server: the hosted flow (spec 2).
 *
 *   GET  /link/v1/authorize            enter by request_uri, render the current step
 *   POST /link/v1/picker               choose provider and permissions, go to the provider
 *   GET  /link/v1/callback/:provider   exchange the code (exactly once), render confirmation
 *   POST /link/v1/confirm              confirm (may narrow), back, or cancel
 *
 * Every hop enters the transaction through the store, which consumes the
 * presented handle atomically and issues a new one. A consumed handle with
 * the matching binding cookie is re-entry: the current step is rendered
 * again with a fresh handle and nothing with an effect runs. Effects are
 * keyed by tid in the store (advanceTransaction compare-and-set,
 * commitConfirm once), so the exchange and the grant write never run twice.
 *
 * Fail-closed split: anything that cannot be tied to a validated
 * transaction renders the local error page (generic text, request id);
 * errors of a validated transaction go back to the client with its state.
 */

import type { Request, Response } from 'express';
import {
  LINK_ACTIVATION_CODE_PREFIX,
  LINK_DEFAULT_ORG_POLICY,
  LINK_DEFAULT_WIDGET_MODE,
  LINK_FORM_FIELDS,
  LINK_ID_PREFIXES,
  LINK_POPUP_ACK_TIMEOUT_MS,
  LINK_PROVIDERS,
  LINK_REDIRECT_ONLY_STORAGE_KEY,
  LINK_REDIRECT_ONLY_TTL_DAYS,
  LINK_REDIRECT_VIA_POPUP,
  LINK_TX_COOKIE_NAME,
  appendLinkRedirectResult,
  canonicalScopeSet,
  decodeLinkEnvelope,
  encodeLinkEnvelope,
  findScopeCatalogEntry,
  isLinkBindingCookieValue,
  isLinkProviderSlug,
  isScopeSubset,
  linkAudienceFor,
  linkScopeCatalogFor,
  parseLinkAuthorizeQuery,
  intersectScopes,
  sanitizeLinkCosmeticTheme,
  sanitizeLinkTheme,
  unionScopes,
} from '@credninja/protocol';
import type {
  ConnectionId,
  GrantId,
  LinkClient,
  LinkErrorCode,
  LinkExitStep,
  LinkProviderSlug,
  LinkResult,
  LinkTheme,
  LinkTransaction,
  LinkTransactionEntry,
} from '@credninja/protocol';
import { LinkStoreError } from '@credninja/vault';
import type { LinkContext } from './core.js';
import { cleanupEndedTransaction, revokeAtProviderIfSafe, writeGrantAudit } from './core.js';
import {
  LINK_PICKER_OPENER_FIELD,
  LINK_RECONNECT_BASIS_FIELD,
  sendConfirmPage,
  sendLocalErrorPage,
  sendPickerPage,
  sendResultPage,
  setNoStoreHeaders,
} from './pages.js';
import type { LabeledScope, LinkPageContext, LinkPageScriptConfig, PickerProviderView, ReconnectView } from './pages.js';
import { LinkProviderError } from './providers.js';
import { grantableScopes, providerRequestScopes } from './scopes.js';
import {
  newId,
  newSecret,
  nowIso,
  parseCookieHeader,
  repeatedField,
  requestId,
  sha256Hex,
  singleField,
  originOf,
} from './util.js';

const MAX_CODE_LENGTH = 4096;

interface HopState {
  tx: LinkTransaction;
  client: LinkClient;
  /** The handle the rendered page carries (already stored as the outstanding handle). */
  handle: string;
  context: LinkPageContext;
}

// ── Cookie binding ───────────────────────────────────────────────────────────

function presentedCookie(req: Request): string | null {
  const value = parseCookieHeader(req.headers.cookie).get(LINK_TX_COOKIE_NAME);
  return value !== undefined && isLinkBindingCookieValue(value) ? value : null;
}

/**
 * The binding cookie for this browser: the presented one when valid (so
 * parallel flows in one browser share it), else a new 256-bit value.
 */
function bindingCandidate(req: Request): string {
  return presentedCookie(req) ?? newSecret();
}

function setBindingCookie(res: Response, value: string, tx: LinkTransaction): void {
  const maxAge = Math.max(1, Math.floor((Date.parse(tx.expires_at) - Date.now()) / 1000));
  res.append('Set-Cookie', `${LINK_TX_COOKIE_NAME}=${value}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`);
}

/**
 * Redirect-only memory guard (popup fallback). The page script may write
 * the browser's redirect-only memory for a provider only when the window
 * demonstrably started this flow with an opener and then lost it. The
 * picker form reports whether the window had an opener when the user
 * submitted (LINK_PICKER_OPENER_FIELD, set by the page script; the handoff
 * fetch reports 'handoff'); the picker response then sets this short-lived,
 * HttpOnly cookie bound to the transaction, and the result page enables the
 * memory write only when the cookie matches the transaction. In embedded
 * mode the top-level picker submission always comes from the window the
 * iframe opened with an opener. A popup-mode URL opened directly in a tab,
 * and the top window that completes a handoff, never get the cookie.
 */
export const LINK_OPENER_COOKIE_NAME = '__Host-cred_link_op';

function openerMark(tx: LinkTransaction): string {
  return sha256Hex(`cred-link-opener:${tx.tid}`);
}

function setOpenerCookie(res: Response, tx: LinkTransaction): void {
  const maxAge = Math.max(1, Math.floor((Date.parse(tx.expires_at) - Date.now()) / 1000));
  res.append('Set-Cookie', `${LINK_OPENER_COOKIE_NAME}=${openerMark(tx)}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`);
}

function clearOpenerCookie(req: Request, res: Response): void {
  if (!parseCookieHeader(req.headers.cookie).has(LINK_OPENER_COOKIE_NAME)) return;
  res.append('Set-Cookie', `${LINK_OPENER_COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`);
}

function startedWithOpener(req: Request, tx: LinkTransaction): boolean {
  return parseCookieHeader(req.headers.cookie).get(LINK_OPENER_COOKIE_NAME) === openerMark(tx);
}


// ── Helpers ──────────────────────────────────────────────────────────────────

function envelopeFor(tx: LinkTransaction, handle: string): string {
  return encodeLinkEnvelope({ h: handle, tid: tx.tid, cid: tx.client_id });
}

/**
 * The theme a hosted page renders. The app name and logo identify the app
 * on the consent pages, so they come only from the client's registration
 * (registered theme, else the registered client name); nothing from the
 * authorize query can change them. Cosmetic fields: query, then registered.
 */
function themeFor(client: LinkClient, tx: LinkTransaction): LinkTheme {
  const registered = sanitizeLinkTheme(client.theme ?? {});
  const theme: LinkTheme = {
    ...sanitizeLinkCosmeticTheme(client.theme ?? {}),
    ...sanitizeLinkCosmeticTheme(tx.theme ?? {}),
  };
  const appName = registered.appName ?? sanitizeLinkTheme({ appName: client.name }).appName;
  if (appName) theme.appName = appName;
  if (registered.logoUrl) theme.logoUrl = registered.logoUrl;
  return theme;
}

/**
 * Scopes the confirmation may offer and accept: in the transaction's
 * requested scopes for the provider (the browser can only narrow what the
 * backend pushed) and grantable from what the provider returned. Anything
 * the provider returned that nobody requested is shown nowhere and enters
 * no grant.
 */
function confirmableScopes(tx: LinkTransaction, provider: LinkProviderSlug): string[] {
  return intersectScopes(tx.requested_scopes[provider] ?? [], grantableScopes(provider, tx.provider_granted_scopes ?? []));
}

function modeOf(tx: LinkTransaction) {
  return tx.mode ?? LINK_DEFAULT_WIDGET_MODE;
}

function scriptConfig(ctx: LinkContext, tx: LinkTransaction, context: LinkPageContext, step?: LinkExitStep, provider?: LinkProviderSlug): LinkPageScriptConfig {
  const embedded = modeOf(tx) === 'embedded';
  const config: LinkPageScriptConfig = {
    context,
    mode: modeOf(tx),
    target: context === 'top' && embedded ? ctx.selfOrigin : tx.origin,
    self_origin: ctx.selfOrigin,
    ack_timeout_ms: LINK_POPUP_ACK_TIMEOUT_MS,
    storage_key: LINK_REDIRECT_ONLY_STORAGE_KEY,
    redirect_only_ttl_ms: LINK_REDIRECT_ONLY_TTL_DAYS * 24 * 60 * 60 * 1000,
  };
  if (context === 'iframe') config.parent_origin = tx.origin;
  if (step) config.step = step;
  if (provider) config.provider = provider;
  return config;
}

/** Origins a form submission on this transaction's pages may be redirected to. */
function formActionOrigins(ctx: LinkContext, tx: LinkTransaction, providers: LinkProviderSlug[]): string[] {
  const out = new Set<string>();
  for (const p of providers) {
    const origin = ctx.providers.authorizationOrigin(p);
    if (origin) out.add(origin);
  }
  if (modeOf(tx) === 'redirect') {
    const origin = originOf(tx.redirect_uri);
    if (origin) out.add(origin);
  }
  return [...out];
}

async function loadClient(ctx: LinkContext, tx: LinkTransaction): Promise<LinkClient | null> {
  const client = await ctx.store.getClient(tx.client_id);
  return client && client.status === 'active' ? client : null;
}

// ── Results ──────────────────────────────────────────────────────────────────

function deliverResult(ctx: LinkContext, req: Request, res: Response, hop: Pick<HopState, 'tx' | 'client' | 'context'>, result: LinkResult): void {
  const { tx, client, context } = hop;
  if (modeOf(tx) === 'redirect') {
    requestId(req, res);
    setNoStoreHeaders(res);
    res.redirect(303, appendLinkRedirectResult(tx.redirect_uri, result));
    return;
  }
  const script: Omit<LinkPageScriptConfig, 'result'> = scriptConfig(ctx, tx, context);
  if (context === 'top') {
    // Popup fallback: the result page (a popup, or the top-level window the
    // embedded picker opened) falls back to redirect delivery to the
    // registered redirect_uri, marked cred_link_via=popup and bound to this
    // flow (cred_link_flow = request_uri_hash) for the widget's relay.
    script.fallback_url = appendLinkRedirectResult(tx.redirect_uri, result, {
      via: LINK_REDIRECT_VIA_POPUP,
      flow_id: tx.request_uri_hash,
    });
    // Redirect-only memory only for a window that started with an opener.
    const provider = result.outcome === 'error' ? tx.provider : result.provider ?? tx.provider;
    if (provider && startedWithOpener(req, tx)) script.memory_provider = provider;
  }
  clearOpenerCookie(req, res);
  sendResultPage(req, res, {
    result,
    theme: themeFor(client, tx),
    script,
    frameAncestor: context === 'iframe' ? tx.origin : null,
  });
}

/** End the transaction with a widget error code and return it to the client. */
async function failToClient(ctx: LinkContext, req: Request, res: Response, hop: Pick<HopState, 'tx' | 'client' | 'context'>, code: LinkErrorCode): Promise<void> {
  const ended = await ctx.store.endTransaction({ tid: hop.tx.tid, outcome: 'failed', error: code, now: nowIso() }).catch(() => null);
  if (!ended) {
    sendLocalErrorPage(req, res);
    return;
  }
  await cleanupEndedTransaction(ctx, ended);
  const result: LinkResult = { outcome: 'error', error: code, request_id: requestId(req, res) };
  if (ended.client_state !== undefined) result.state = ended.client_state;
  deliverResult(ctx, req, res, { ...hop, tx: ended }, result);
}

/** End the transaction as cancelled and report an exit. */
async function exitToClient(ctx: LinkContext, req: Request, res: Response, hop: Pick<HopState, 'tx' | 'client' | 'context'>, step: LinkExitStep): Promise<void> {
  const ended = await ctx.store.endTransaction({ tid: hop.tx.tid, outcome: 'cancelled', now: nowIso() }).catch(() => null);
  if (!ended) {
    sendLocalErrorPage(req, res);
    return;
  }
  await cleanupEndedTransaction(ctx, ended);
  const result: LinkResult = { outcome: 'exit', step };
  if (ended.provider && step !== 'picker') result.provider = ended.provider;
  if (ended.client_state !== undefined) result.state = ended.client_state;
  deliverResult(ctx, req, res, { ...hop, tx: ended }, result);
}

function successResult(tx: LinkTransaction, code: string): LinkResult | null {
  if (!tx.connection_id || !tx.grant_id || !tx.provider) return null;
  const result: LinkResult = {
    outcome: 'success',
    connection_id: tx.connection_id as ConnectionId,
    code,
    grant_id: tx.grant_id as GrantId,
    provider: tx.provider,
    scopes: [...(tx.confirmed_scopes ?? [])],
  };
  if (tx.client_state !== undefined) result.state = tx.client_state;
  return result;
}

function newActivationCode(): string {
  return `${LINK_ACTIVATION_CODE_PREFIX}${newSecret()}`;
}

// ── Rendering the current step (no effects) ──────────────────────────────────

function pickerView(tx: LinkTransaction): PickerProviderView[] {
  const prefill = tx.intent !== 'connect';
  return tx.providers.map((provider) => {
    const requested = new Set(tx.requested_scopes[provider] ?? []);
    const required = new Set(tx.required_scopes[provider] ?? []);
    const entries = linkScopeCatalogFor(provider)
      .filter((e) => requested.has(e.scope) && !e.flags.includes('hidden'))
      .map((entry) => {
        const locked = required.has(entry.scope);
        const checked = locked || prefill || entry.flags.includes('preferred_default');
        return { entry, checked, locked };
      });
    return { provider, entries };
  });
}

function sendPicker(ctx: LinkContext, req: Request, res: Response, hop: HopState): void {
  const { tx, client, context } = hop;
  const embeddedIframe = modeOf(tx) === 'embedded' && context === 'iframe';
  const handoff = modeOf(tx) === 'popup' && context === 'top';
  const formActions = formActionOrigins(ctx, tx, tx.providers);
  sendPickerPage(req, res, {
    envelope: envelopeFor(tx, hop.handle),
    mode: modeOf(tx),
    context,
    theme: themeFor(client, tx),
    providers: pickerView(tx),
    // The popup picker may record a redirect-only handoff with fetch: only
    // this page gets connect-src 'self'.
    security: { frameAncestor: embeddedIframe ? tx.origin : null, formActions, ...(handoff ? { connectSelf: true } : {}) },
    script: { ...scriptConfig(ctx, tx, context, 'picker'), ...(handoff ? { handoff: true } : {}) },
    ...(tx.intent !== 'connect' ? { intentNote: 'Reconnect the same account you connected before.' } : {}),
  });
}

function labeled(provider: LinkProviderSlug, scope: string): LabeledScope {
  return { scope, label: findScopeCatalogEntry(provider, scope)?.label ?? scope };
}

/** A grant a confirmation screen was rendered against. */
interface ReconnectBasis {
  grant_id: string;
  scopes: string[];
}

/**
 * The confirm form's value for a basis: which grant and which scopes the
 * screen was rendered against, or none. Scopes, not the grant version, so
 * a status-only change (the old token died) does not count as a change,
 * the same rule the store applies at activation.
 */
function basisToken(basis: ReconnectBasis | null): string {
  return basis ? `${basis.grant_id}:${basis.scopes.join(' ')}` : 'none';
}

/**
 * The scopes a live connection grants today when this connect flow lands on
 * an account already connected for the transaction's own client and
 * subject (the store will stage onto it). Strictly the transaction's
 * client, subject, provider, audience and the account the provider just
 * returned; never another subject's or client's connection. null for a
 * first connection, update and reauth.
 */
async function reconnectToday(ctx: LinkContext, tx: LinkTransaction, provider: LinkProviderSlug): Promise<ReconnectBasis | null> {
  if (tx.intent !== 'connect' || !tx.provider_account_id) return null;
  const audience = linkAudienceFor(provider, tx.instance_url ?? null);
  const live = (await ctx.store.listConnections({ client_id: tx.client_id, subject: tx.subject })).find((c) => (
    c.client_id === tx.client_id
    && c.subject === tx.subject
    && c.provider === provider
    && c.audience === audience
    && c.provider_account_id === tx.provider_account_id
    && c.status !== 'pending'
    && c.status !== 'revoked'
  ));
  if (!live) return null;
  const grant = await ctx.store.getGrantForConnection(live.id);
  if (!grant) return { grant_id: 'none', scopes: [] };
  return { grant_id: grant.id, scopes: canonicalScopeSet(grant.status !== 'revoked' ? grant.scopes : []) };
}

/**
 * The current grant a confirmation screen is rendered against: for connect,
 * the live connection the flow would land on (reconnectToday, shown as the
 * diff); for update and reauth, the target connection's grant (not shown
 * as a diff, but recorded the same way so a grant that moves between the
 * screen and the commit is caught). null when there is none.
 */
async function shownGrant(ctx: LinkContext, tx: LinkTransaction, provider: LinkProviderSlug): Promise<ReconnectBasis | null> {
  if (tx.intent === 'connect') return reconnectToday(ctx, tx, provider);
  if (!tx.connection_id) return null;
  const grant = await ctx.store.getGrantForConnection(tx.connection_id);
  if (!grant) return null;
  return { grant_id: grant.id, scopes: canonicalScopeSet(grant.status !== 'revoked' ? grant.scopes : []) };
}

async function sendConfirm(ctx: LinkContext, req: Request, res: Response, hop: HopState, notice?: string): Promise<void> {
  const { tx, client } = hop;
  const provider = tx.provider as LinkProviderSlug;
  const selected = new Set(tx.selected_scopes ?? []);
  const required = new Set(tx.required_scopes[provider] ?? []);
  const entries = confirmableScopes(tx, provider).map((scope) => {
    const entry = findScopeCatalogEntry(provider, scope)!;
    const locked = required.has(scope);
    return { entry, checked: locked || selected.has(scope), locked };
  });
  const script = scriptConfig(ctx, tx, 'top', 'confirm', provider);
  let reconnect: ReconnectView | undefined;
  const basis = await shownGrant(ctx, tx, provider);
  // The diff is shown only for a connect that lands on a live connection.
  const today = tx.intent === 'connect' && basis ? basis.scopes : null;
  if (today) {
    // Replace semantics: after confirming, the grant is exactly the checked
    // toggles. Held today but not offered here (not requested, or not
    // granted this time) is removed unconditionally.
    const checked = new Set(entries.filter((e) => e.checked).map((e) => e.entry.scope));
    reconnect = {
      today: today.map((s) => labeled(provider, s)),
      kept: today.filter((s) => checked.has(s)).map((s) => labeled(provider, s)),
      added: [...checked].filter((s) => !today.includes(s)).sort().map((s) => labeled(provider, s)),
      removed: today.filter((s) => !checked.has(s)).map((s) => labeled(provider, s)),
    };
    const labels: Record<string, string> = {};
    for (const s of [...today, ...entries.map((e) => e.entry.scope)]) labels[s] = labeled(provider, s).label;
    script.reconnect = { today, labels };
  }
  sendConfirmPage(req, res, {
    envelope: envelopeFor(tx, hop.handle),
    provider,
    theme: themeFor(client, tx),
    ...(tx.account_label ? { accountLabel: tx.account_label } : {}),
    entries,
    ...(reconnect ? { reconnect } : {}),
    reconnectBasis: basisToken(basis),
    ...(notice ? { notice } : {}),
    security: { frameAncestor: null, formActions: formActionOrigins(ctx, tx, [provider]) },
    script,
  });
}

function redirectToProvider(ctx: LinkContext, req: Request, res: Response, tx: LinkTransaction, handle: string): void {
  const provider = tx.provider as LinkProviderSlug;
  const url = ctx.providers.authorizationUrl(provider, {
    scopes: tx.provider_requested_scopes ?? [],
    state: envelopeFor(tx, handle),
    pkceVerifier: tx.pkce_verifier ?? null,
  });
  requestId(req, res);
  setNoStoreHeaders(res);
  res.redirect(303, url);
}

/** Re-render the transaction's current step with the fresh handle. */
async function renderCurrentStep(ctx: LinkContext, req: Request, res: Response, hop: HopState): Promise<void> {
  const { tx } = hop;
  switch (tx.step) {
    case 'picker':
      sendPicker(ctx, req, res, hop);
      return;
    case 'provider':
      if (!tx.provider) {
        sendLocalErrorPage(req, res);
        return;
      }
      redirectToProvider(ctx, req, res, tx, hop.handle);
      return;
    case 'confirm':
      await sendConfirm(ctx, req, res, hop);
      return;
    case 'done': {
      // A repeated confirm returns the first result. Only the code hash is
      // stored, so the code is replaced and handed out again.
      if (tx.activation_claimed_at) {
        sendLocalErrorPage(req, res);
        return;
      }
      const code = newActivationCode();
      const replaced = await ctx.store.replaceActivationCode({ tid: tx.tid, activation_code_hash: sha256Hex(code), now: nowIso() });
      const result = replaced ? successResult(tx, code) : null;
      if (!result) {
        sendLocalErrorPage(req, res);
        return;
      }
      deliverResult(ctx, req, res, { ...hop, context: 'top' }, result);
      return;
    }
  }
}

// ── Entering by envelope ─────────────────────────────────────────────────────

async function enterByEnvelope(
  ctx: LinkContext,
  req: Request,
  res: Response,
  rawEnvelope: unknown,
  topLevel: boolean,
): Promise<{ entry: Exclude<LinkTransactionEntry, { kind: 'rejected' }>; client: LinkClient; handle: string } | null> {
  const envelope = decodeLinkEnvelope(rawEnvelope);
  if (!envelope) return null;
  const cookie = presentedCookie(req);
  const candidate = topLevel ? bindingCandidate(req) : null;
  const handle = newSecret();
  const entry = await ctx.store.enterByHandle({
    tid: envelope.tid,
    client_id: envelope.cid,
    handle_hash: sha256Hex(envelope.h),
    presented_cookie_hash: cookie ? sha256Hex(cookie) : null,
    new_handle_hash: sha256Hex(handle),
    ...(candidate ? { new_binding_cookie_hash: sha256Hex(candidate) } : {}),
    now: nowIso(),
  });
  if (entry.kind === 'rejected') return null;
  if (candidate && entry.transaction.binding_cookie_hash === sha256Hex(candidate)) {
    setBindingCookie(res, candidate, entry.transaction);
  }
  const client = await loadClient(ctx, entry.transaction);
  if (!client) return null;
  return { entry, client, handle };
}

// ── Route handlers ───────────────────────────────────────────────────────────

/** GET /link/v1/authorize */
export async function handleAuthorize(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const query = parseLinkAuthorizeQuery(req.query as Record<string, unknown>);
  if (!query) {
    sendLocalErrorPage(req, res);
    return;
  }
  const topLevel = query.mode !== 'embedded';
  const cookie = presentedCookie(req);
  const candidate = topLevel ? bindingCandidate(req) : null;
  const handle = newSecret();
  const narrowed = query.providers !== undefined || query.scopes !== undefined
    ? { providers: query.providers ?? [...LINK_PROVIDERS], requested_scopes: query.scopes ?? {} }
    : undefined;
  const entry = await ctx.store.enterByRequestUri({
    request_uri_hash: sha256Hex(query.request_uri),
    ...(query.client_id !== undefined ? { client_id: query.client_id } : {}),
    presented_cookie_hash: cookie ? sha256Hex(cookie) : null,
    new_handle_hash: sha256Hex(handle),
    ...(candidate ? { new_binding_cookie_hash: sha256Hex(candidate) } : {}),
    mode: query.mode,
    ...(query.theme ? { theme: query.theme } : {}),
    ...(narrowed ? { narrowed } : {}),
    now: nowIso(),
  });
  if (entry.kind === 'rejected') {
    sendLocalErrorPage(req, res);
    return;
  }
  const tx = entry.transaction;
  if (candidate && tx.binding_cookie_hash === sha256Hex(candidate)) setBindingCookie(res, candidate, tx);
  const client = await loadClient(ctx, tx);
  if (!client) {
    sendLocalErrorPage(req, res);
    return;
  }
  const context: LinkPageContext = modeOf(tx) === 'embedded' ? 'iframe' : 'top';
  const hop: HopState = { tx, client, handle, context };
  if (entry.kind === 'fresh' && tx.providers.length === 0) {
    await failToClient(ctx, req, res, hop, 'invalid_scope');
    return;
  }
  await renderCurrentStep(ctx, req, res, hop);
}

/** POST /link/v1/picker */
export async function handlePicker(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const inIframe = req.query.frame === 'iframe';
  // The embedded iframe may only render and cancel. Advancing to the
  // provider happens only from the top-level window (target=_blank), which
  // sets and from then on requires the binding cookie.
  if (inIframe && singleField(body[LINK_FORM_FIELDS.action]) !== 'cancel') {
    sendLocalErrorPage(req, res);
    return;
  }
  const entered = await enterByEnvelope(ctx, req, res, singleField(body[LINK_FORM_FIELDS.envelope]), !inIframe);
  if (!entered) {
    sendLocalErrorPage(req, res);
    return;
  }
  const { entry, client, handle } = entered;
  const tx = entry.transaction;
  const context: LinkPageContext = inIframe && modeOf(tx) === 'embedded' ? 'iframe' : 'top';
  const hop: HopState = { tx, client, handle, context };
  if (entry.kind === 'reentry' || tx.step !== 'picker') {
    await renderCurrentStep(ctx, req, res, { ...hop, context: tx.step === 'picker' ? context : 'top' });
    return;
  }

  const action = singleField(body[LINK_FORM_FIELDS.action]);
  if (action === 'cancel') {
    await exitToClient(ctx, req, res, hop, 'picker');
    return;
  }
  if (action !== 'continue') {
    await renderCurrentStep(ctx, req, res, hop);
    return;
  }

  const provider = singleField(body[LINK_FORM_FIELDS.provider]);
  if (!isLinkProviderSlug(provider) || !tx.providers.includes(provider) || !ctx.providers.isConfigured(provider)) {
    await failToClient(ctx, req, res, { ...hop, context: 'top' }, 'invalid_scope');
    return;
  }
  const submitted = canonicalScopeSet(repeatedField(body[LINK_FORM_FIELDS.scope]));
  const requested = tx.requested_scopes[provider] ?? [];
  if (!isScopeSubset(submitted, requested)) {
    await failToClient(ctx, req, res, { ...hop, context: 'top' }, 'invalid_scope');
    return;
  }
  // Required scopes are locked on the page; the server adds them regardless.
  const selected = unionScopes(submitted, tx.required_scopes[provider] ?? []);
  const providerScopes = providerRequestScopes(provider, selected);
  const verifier = ctx.providers.newPkceVerifier(provider);
  const advanced = await ctx.store.advanceTransaction({
    tid: tx.tid,
    from: 'picker',
    to: 'provider',
    patch: {
      provider,
      selected_scopes: selected,
      provider_requested_scopes: providerScopes,
      pkce_verifier: verifier,
      provider_attempt: tx.provider_attempt + 1,
    },
    now: nowIso(),
  });
  if (!advanced) {
    sendLocalErrorPage(req, res);
    return;
  }
  // Record whether this window started the flow with an opener (see
  // LINK_OPENER_COOKIE_NAME). A handoff fetch never records it.
  const opener = singleField(body[LINK_PICKER_OPENER_FIELD]);
  const hadOpener = modeOf(advanced) === 'embedded' ? !inIframe : modeOf(advanced) === 'popup' && opener === '1';
  if (hadOpener) setOpenerCookie(res, advanced);
  else clearOpenerCookie(req, res);
  redirectToProvider(ctx, req, res, advanced, handle);
}

/** Revoke (when the revocation rule allows it) and forget tokens obtained by a failed exchange step. */
async function discardFreshTokens(ctx: LinkContext, tx: LinkTransaction, provider: LinkProviderSlug, accountId: string, tokens: Parameters<LinkContext['providers']['revoke']>[1]): Promise<void> {
  await revokeAtProviderIfSafe(ctx, tokens, { provider, provider_account_id: accountId, exclude_tid: tx.tid });
}

/** GET /link/v1/callback/:provider */
export async function handleCallback(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const providerParam = req.params.provider;
  const query = req.query as Record<string, unknown>;
  if (!isLinkProviderSlug(providerParam)) {
    sendLocalErrorPage(req, res);
    return;
  }
  const entered = await enterByEnvelope(ctx, req, res, singleField(query.state), true);
  if (!entered) {
    sendLocalErrorPage(req, res);
    return;
  }
  const { entry, client, handle } = entered;
  const tx = entry.transaction;
  const hop: HopState = { tx, client, handle, context: 'top' };
  if (entry.kind === 'reentry' || tx.step !== 'provider') {
    await renderCurrentStep(ctx, req, res, hop);
    return;
  }
  if (tx.provider !== providerParam) {
    sendLocalErrorPage(req, res);
    return;
  }
  const provider = tx.provider;

  // Provider-reported errors are mapped to a code; their text is never shown.
  const providerError = singleField(query.error);
  if (providerError !== undefined) {
    await failToClient(ctx, req, res, hop, providerError === 'access_denied' ? 'access_denied' : 'provider_error');
    return;
  }
  const code = singleField(query.code);
  if (typeof code !== 'string' || code === '' || code.length > MAX_CODE_LENGTH) {
    await failToClient(ctx, req, res, hop, 'provider_error');
    return;
  }

  // Without an identity the account is unknown, so the revocation rule
  // cannot be checked: fresh tokens are then only discarded, never revoked.
  let exchanged;
  try {
    exchanged = await ctx.providers.exchange(provider, code, tx.pkce_verifier ?? null, { revokeOnIdentityFailure: false });
  } catch (error) {
    await failToClient(ctx, req, res, hop, error instanceof LinkProviderError ? error.code : 'provider_error');
    return;
  }
  const { tokens, identity } = exchanged;

  // update and reauth must finish on the same provider account (spec 6).
  if (tx.intent !== 'connect') {
    const target = tx.connection_id ? await ctx.store.getConnection(tx.connection_id) : null;
    if (!target || target.provider !== provider || target.provider_account_id !== identity.provider_account_id) {
      await discardFreshTokens(ctx, tx, provider, identity.provider_account_id, tokens);
      await failToClient(ctx, req, res, hop, 'access_denied');
      return;
    }
  }

  const granted = canonicalScopeSet(exchanged.granted_scopes ?? tx.provider_requested_scopes ?? []);
  const required = tx.required_scopes[provider] ?? [];
  if (!isScopeSubset(required, grantableScopes(provider, granted))) {
    await discardFreshTokens(ctx, tx, provider, identity.provider_account_id, tokens);
    await failToClient(ctx, req, res, hop, 'required_scope_declined');
    return;
  }
  if (provider === 'salesforce' && !linkAudienceFor('salesforce', identity.instance_url ?? null)) {
    await discardFreshTokens(ctx, tx, provider, identity.provider_account_id, tokens);
    await failToClient(ctx, req, res, hop, 'provider_error');
    return;
  }

  try {
    await ctx.secrets.putStaged(tx.tid, tokens);
  } catch {
    await discardFreshTokens(ctx, tx, provider, identity.provider_account_id, tokens);
    await failToClient(ctx, req, res, hop, 'server_error');
    return;
  }
  const advanced = await ctx.store.advanceTransaction({
    tid: tx.tid,
    from: 'provider',
    to: 'confirm',
    patch: {
      exchanged_at: nowIso(),
      provider_granted_scopes: granted,
      provider_account_id: identity.provider_account_id,
      account_label: identity.account_label ?? null,
      instance_url: identity.instance_url ?? null,
      // The verifier has done its job; never keep it past the exchange.
      pkce_verifier: null,
    },
    now: nowIso(),
  }).catch(() => null);
  if (!advanced) {
    const current = await ctx.store.getTransaction(tx.tid);
    if (current) await cleanupEndedTransaction(ctx, { ...current, provider_account_id: identity.provider_account_id });
    sendLocalErrorPage(req, res);
    return;
  }
  await sendConfirm(ctx, req, res, { ...hop, tx: advanced });
}

/** POST /link/v1/confirm */
export async function handleConfirm(ctx: LinkContext, req: Request, res: Response): Promise<void> {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const entered = await enterByEnvelope(ctx, req, res, singleField(body[LINK_FORM_FIELDS.envelope]), true);
  if (!entered) {
    sendLocalErrorPage(req, res);
    return;
  }
  const { entry, client, handle } = entered;
  const tx = entry.transaction;
  const hop: HopState = { tx, client, handle, context: 'top' };
  if (entry.kind === 'reentry' || tx.step !== 'confirm' || !tx.provider) {
    await renderCurrentStep(ctx, req, res, hop);
    return;
  }
  const provider = tx.provider;
  const action = singleField(body[LINK_FORM_FIELDS.action]);

  if (action === 'cancel') {
    await exitToClient(ctx, req, res, hop, 'confirm');
    return;
  }

  if (action === 'back') {
    // Restart the provider hop with a new PKCE pair; the earlier pending
    // tokens are revoked (when that cannot hit a live connection) and deleted.
    const staged = await ctx.secrets.getStaged(tx.tid).catch(() => null);
    if (staged) {
      await revokeAtProviderIfSafe(ctx, staged, { provider, provider_account_id: tx.provider_account_id, exclude_tid: tx.tid });
    }
    await ctx.secrets.deleteStaged(tx.tid).catch(() => undefined);
    const advanced = await ctx.store.advanceTransaction({
      tid: tx.tid,
      from: 'confirm',
      to: 'provider',
      patch: {
        pkce_verifier: ctx.providers.newPkceVerifier(provider),
        provider_attempt: tx.provider_attempt + 1,
        exchanged_at: null,
        provider_granted_scopes: null,
        provider_account_id: null,
        account_label: null,
        instance_url: null,
      },
      now: nowIso(),
    });
    if (!advanced) {
      sendLocalErrorPage(req, res);
      return;
    }
    redirectToProvider(ctx, req, res, advanced, handle);
    return;
  }

  if (action !== 'confirm') {
    await renderCurrentStep(ctx, req, res, hop);
    return;
  }

  const confirmed = canonicalScopeSet(repeatedField(body[LINK_FORM_FIELDS.scope]));
  if (!isScopeSubset(confirmed, confirmableScopes(tx, provider))) {
    await failToClient(ctx, req, res, hop, 'invalid_scope');
    return;
  }
  // The locked toggle is only a hint: dropping a required scope ends the flow.
  if (!isScopeSubset(tx.required_scopes[provider] ?? [], confirmed)) {
    await failToClient(ctx, req, res, hop, 'required_scope_declined');
    return;
  }
  const audience = linkAudienceFor(provider, tx.instance_url ?? null);
  if (!audience || !tx.provider_account_id) {
    await failToClient(ctx, req, res, hop, 'server_error');
    return;
  }
  // The page was rendered against one grant and its scopes (or none). If
  // the grant is different now (another flow was activated, or its scopes
  // changed), show the current picture instead of committing what the user
  // did not see. What passed this check is handed to commitConfirm as
  // shown_grant_scopes, so a change between here and the commit is
  // refused at activation.
  const shown = singleField(body[LINK_RECONNECT_BASIS_FIELD]);
  const basis = await shownGrant(ctx, tx, provider);
  if (shown !== basisToken(basis)) {
    await sendConfirm(ctx, req, res, hop, 'The access this app has to this account changed while this page was open. Review it and confirm again.');
    return;
  }

  const code = newActivationCode();
  let commit;
  try {
    commit = await ctx.store.commitConfirm({
      tid: tx.tid,
      confirmed_scopes: confirmed,
      activation_code_hash: sha256Hex(code),
      new_connection: {
        id: newId(LINK_ID_PREFIXES.connection) as ConnectionId,
        audience,
        provider_account_id: tx.provider_account_id,
        ...(tx.account_label ? { account_label: tx.account_label } : {}),
        // The store takes provider_scopes from the transaction; pass the same value.
        provider_scopes: tx.provider_granted_scopes ?? [],
        ...(provider === 'salesforce' && tx.instance_url ? { instance_url: audience } : {}),
        custody: 'self',
      },
      new_grant: {
        id: newId(LINK_ID_PREFIXES.grant) as GrantId,
        org_policy: { ...LINK_DEFAULT_ORG_POLICY },
        authorization_details_types: [],
      },
      // connect: the live grant shown in the diff, or null for "a new
      // connection" (activation then refuses if the flow lands on a live
      // one after all). update and reauth: the target grant rendered
      // against; omitted when there was none (the store then records the
      // grant as of the commit).
      ...(tx.intent === 'connect'
        ? { shown_grant_scopes: basis ? basis.scopes : null }
        : basis ? { shown_grant_scopes: basis.scopes } : {}),
      now: nowIso(),
    });
  } catch (error) {
    const code: LinkErrorCode = error instanceof LinkStoreError && error.code === 'invalid_scopes' ? 'invalid_scope' : 'server_error';
    await failToClient(ctx, req, res, hop, code);
    return;
  }

  switch (commit.kind) {
    case 'committed': {
      const committed = commit.transaction;
      if (committed.creates_connection && committed.grant_id) {
        try {
          const grant = await ctx.store.getGrant(committed.grant_id);
          if (!grant) throw new Error('grant missing after confirm');
          writeGrantAudit(ctx, {
            action: 'create',
            grant,
            provider,
            before_scopes: null,
            before_status: null,
            reason: 'confirm',
            tid: committed.tid,
          });
        } catch {
          await failToClient(ctx, req, res, { ...hop, tx: committed }, 'server_error');
          return;
        }
      }
      const result = successResult(committed, code);
      if (!result) {
        await failToClient(ctx, req, res, { ...hop, tx: committed }, 'server_error');
        return;
      }
      deliverResult(ctx, req, res, { ...hop, tx: committed }, result);
      return;
    }
    case 'already_committed':
      await renderCurrentStep(ctx, req, res, { ...hop, tx: commit.transaction });
      return;
    case 'account_mismatch':
    case 'connection_unavailable':
      await failToClient(ctx, req, res, { ...hop, tx: commit.transaction }, 'access_denied');
      return;
  }
}

import {
  LINK_DEFAULT_BASE_URL,
  LINK_DEFAULT_WIDGET_MODE,
  LINK_PATHS,
  buildLinkAuthorizeQuery,
  canonicalScopeSet,
  isLinkProviderSlug,
  isLinkRequestUri,
  isLinkWidgetMode,
  sanitizeLinkCosmeticTheme,
} from '@credninja/protocol';
import type {
  LinkErrorPayload,
  LinkExitPayload,
  LinkProviderSlug,
  LinkScopeMap,
  LinkSuccessPayload,
  LinkTheme,
  LinkWidgetMode,
} from '@credninja/protocol';
import { CredLinkError } from './errors.js';

/** Callbacks shared by Cred.link() and handleRedirect(). */
export interface CredLinkCallbacks {
  /**
   * The user finished the flow. The connection is still pending: send
   * `connection_id` and `code` to your backend, which activates it with
   * POST /link/v1/connections/:id/activate and the subject from its own
   * session. `state` is your PAR state, echoed back.
   */
  onSuccess?(result: LinkSuccessPayload): void;
  /** The flow ended with a Link error code. `request_id` is for support. */
  onError?(error: LinkErrorPayload): void;
  /**
   * The user left before finishing. `step` is the last step the hosted
   * pages reported. `state` is present only when the Link service reported
   * the exit itself (the user pressed cancel); it is absent when the widget
   * detected the exit (popup closed, or close() called).
   */
  onExit?(exit: LinkExitPayload): void;
}

/**
 * Options for Cred.link() (spec section 1). There is deliberately no
 * client_id, subject, redirect_uri, origin or state: those are pushed by
 * your backend in the PAR request and never come from the browser.
 */
export interface CredLinkOptions extends CredLinkCallbacks {
  /** The PAR request_uri your backend received (urn:cred:link:...). Single use, 10 minutes. */
  token: string;
  /** Default 'popup'. */
  mode?: LinkWidgetMode;
  /** Required for 'embedded': the element the picker iframe is appended to. Ignored otherwise. */
  container?: HTMLElement | null;
  /** Default https://link.cred.ninja, or your self-hosted Cred server. */
  baseUrl?: string;
  /** Narrowing only: limit the picker to these providers. Cannot add providers the PAR did not push. */
  providers?: LinkProviderSlug[];
  /** Narrowing only: limit the offered scopes per provider. Cannot add scopes the PAR did not push. */
  scopes?: LinkScopeMap;
  /**
   * Cosmetic styling of the hosted pages: accent, radius, font and
   * colorScheme. Invalid fields are dropped (sanitizeLinkCosmeticTheme).
   * appName and logoUrl are accepted for type compatibility with LinkTheme
   * but IGNORED: they never leave the browser. The app name and logo shown
   * on the consent pages come only from your client registration on the
   * Cred server, so no page can relabel who is asking for consent.
   */
  theme?: LinkTheme;
}

/** The options that shape the authorize URL (no callbacks, no container). */
export type CredLinkUrlOptions = Pick<CredLinkOptions, 'token' | 'mode' | 'baseUrl' | 'providers' | 'scopes' | 'theme'>;

/**
 * Fields the widget refuses outright. They belong in the backend's PAR
 * request; accepting them here would suggest the browser has a say.
 */
const FORBIDDEN_OPTION_KEYS = [
  'client_id',
  'clientId',
  'subject',
  'subject_type',
  'redirect_uri',
  'redirectUri',
  'origin',
  'state',
  'required_scopes',
  'agent_id',
  'connection_id',
  'intent',
] as const;

/** A validated, normalized widget configuration. */
export interface ResolvedLinkConfig {
  token: string;
  mode: LinkWidgetMode;
  container: HTMLElement | null;
  /** Origin of baseUrl: the only origin messages are accepted from. */
  origin: string;
  /** Absolute GET /link/v1/authorize URL for this token and mode. */
  authorizeUrl: string;
  /**
   * The same authorize URL with mode 'redirect': same token, narrowing and
   * theme. Used when a popup flow hands off to redirect mode.
   */
  handoffUrl: string;
}

function invalid(message: string): CredLinkError {
  return new CredLinkError('invalid_options', message);
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost'
    || hostname.endsWith('.localhost')
    || hostname === '127.0.0.1'
    || hostname === '[::1]';
}

/**
 * Parse baseUrl. https only, except plain http on loopback for local
 * development. No credentials, query or fragment. A path prefix is kept
 * (a self-hosted server behind a reverse proxy subpath).
 */
export function resolveBaseUrl(baseUrl: string | undefined): { origin: string; prefix: string } {
  const raw = baseUrl ?? LINK_DEFAULT_BASE_URL;
  if (typeof raw !== 'string' || raw.trim() === '') throw invalid('baseUrl must be a non-empty string');
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw invalid('baseUrl must be an absolute URL');
  }
  const secure = url.protocol === 'https:' || (url.protocol === 'http:' && isLoopbackHost(url.hostname));
  if (!secure) throw invalid('baseUrl must use https (plain http is allowed only for localhost)');
  if (url.username !== '' || url.password !== '') throw invalid('baseUrl must not contain credentials');
  if (url.search !== '' || url.hash !== '') throw invalid('baseUrl must not contain a query or fragment');
  const prefix = url.pathname.replace(/\/+$/, '');
  return { origin: url.origin, prefix };
}

function normalizeProviders(providers: unknown): LinkProviderSlug[] | undefined {
  if (providers === undefined || providers === null) return undefined;
  if (!Array.isArray(providers)) throw invalid('providers must be an array of provider slugs');
  // An empty narrowing list would be dropped from the query and read as "no narrowing", which widens.
  if (providers.length === 0) throw invalid('providers must not be empty; omit it to offer every pushed provider');
  const out: LinkProviderSlug[] = [];
  for (const p of providers) {
    if (!isLinkProviderSlug(p)) throw invalid(`providers: unknown provider ${JSON.stringify(p)}`);
    if (!out.includes(p)) out.push(p);
  }
  return out;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function normalizeScopes(scopes: unknown): LinkScopeMap | undefined {
  if (scopes === undefined || scopes === null) return undefined;
  if (!isPlainRecord(scopes)) throw invalid('scopes must be an object of {provider: string[]}');
  const out: LinkScopeMap = {};
  for (const key of Object.keys(scopes)) {
    if (!isLinkProviderSlug(key)) throw invalid(`scopes: unknown provider ${JSON.stringify(key)}`);
    const list = scopes[key];
    if (list === undefined) continue;
    if (!Array.isArray(list) || !list.every((s) => typeof s === 'string' && s.trim() !== '')) {
      throw invalid(`scopes.${key} must be an array of non-empty strings`);
    }
    out[key] = canonicalScopeSet(list);
  }
  return out;
}

function normalizeMode(mode: unknown): LinkWidgetMode {
  if (mode === undefined || mode === null) return LINK_DEFAULT_WIDGET_MODE;
  if (!isLinkWidgetMode(mode)) throw invalid(`mode must be 'popup', 'redirect' or 'embedded'`);
  return mode;
}

function assertToken(token: unknown): asserts token is string {
  if (!isLinkRequestUri(token)) {
    throw new CredLinkError('invalid_token', 'token must be the request_uri returned by POST /link/v1/par (urn:cred:link:...)');
  }
}

function isElement(value: unknown): value is HTMLElement {
  return typeof value === 'object' && value !== null
    && (value as { nodeType?: unknown }).nodeType === 1 // Narrowing an unknown to read one DOM field.
    && typeof (value as { appendChild?: unknown }).appendChild === 'function';
}

/**
 * Build the absolute GET /link/v1/authorize URL for a token. Pure; usable
 * on a server. The query is produced by the contracts helper
 * buildLinkAuthorizeQuery, so the hosted side parses exactly what is sent.
 */
export function buildAuthorizeUrl(options: CredLinkUrlOptions): string {
  if (!isPlainRecord(options)) throw invalid('options must be an object');
  assertToken(options.token);
  const mode = normalizeMode(options.mode);
  const { origin, prefix } = resolveBaseUrl(options.baseUrl);
  const providers = normalizeProviders(options.providers);
  const scopes = normalizeScopes(options.scopes);
  // Cosmetic fields only: appName and logoUrl are dropped here and again by the contracts helper.
  const theme = options.theme === undefined ? undefined : sanitizeLinkCosmeticTheme(options.theme);
  const query = buildLinkAuthorizeQuery({
    request_uri: options.token,
    mode,
    ...(providers ? { providers } : {}),
    ...(scopes ? { scopes } : {}),
    ...(theme && Object.keys(theme).length > 0 ? { theme } : {}),
  });
  return `${origin}${prefix}${LINK_PATHS.authorize}?${query}`;
}

/** Validate the full option object for Cred.link(). Throws CredLinkError. */
export function resolveLinkConfig(options: CredLinkOptions): ResolvedLinkConfig {
  if (!isPlainRecord(options)) throw invalid('Cred.link() expects an options object');
  for (const key of FORBIDDEN_OPTION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(options, key)) {
      throw invalid(`${key} is not a widget option: your backend sends it in POST /link/v1/par, never the browser`);
    }
  }
  for (const name of ['onSuccess', 'onError', 'onExit'] as const) {
    const cb = options[name];
    if (cb !== undefined && typeof cb !== 'function') throw invalid(`${name} must be a function`);
  }
  const authorizeUrl = buildAuthorizeUrl(options);
  const mode = normalizeMode(options.mode);
  const { origin } = resolveBaseUrl(options.baseUrl);
  let container: HTMLElement | null = null;
  if (mode === 'embedded') {
    if (!isElement(options.container)) throw invalid("mode 'embedded' requires container to be an HTMLElement");
    container = options.container;
  }
  const handoffUrl = mode === 'redirect' ? authorizeUrl : buildAuthorizeUrl({ ...options, mode: 'redirect' });
  return { token: options.token, mode, container, origin, authorizeUrl, handoffUrl };
}

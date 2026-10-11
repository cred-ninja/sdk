/**
 * Cred Link server: the provider hop (authorize URL, code exchange,
 * provider identity, refresh, revocation).
 *
 * Every outbound URL here is a constant pinned in code or an adapter's own
 * constant endpoint. Nothing is ever built from provider-returned data, with
 * one exception: the Salesforce `instance_url`, which must pass the broker's
 * Salesforce host grammar (linkAudienceFor) and is only stored, never
 * fetched here.
 *
 * Provider identity (decision 9):
 *   google      sub and email from the OpenID userinfo endpoint (hidden
 *               openid and email scopes are always requested)
 *   github      numeric user id and login from GET /user
 *   slack       `<team.id>/<bot_user_id>` and the team name, from the token
 *               response. Phase 1 installs a bot token (the adapter sends
 *               the catalog scopes as bot scopes); user tokens are not used.
 *   notion      `<workspace_id>/<bot_id>` and the workspace name, from the
 *               token response
 *   salesforce  `<org id>/<user id>` parsed (never fetched) from the token
 *               response `id` URL; label and audience from `instance_url`
 *   linear      viewer id and email from the GraphQL API
 *   hubspot     `<hub_id>/<user_id>` and the hub domain from the token
 *               metadata endpoint, which also reports the granted scopes
 */

import {
  OAuthClient,
  computeChallenge,
  createAdapter,
  generateVerifier,
  getRawTokenResponse,
  isOAuthTokenError,
} from '@credninja/oauth';
import type { RefreshResponse, ServiceAdapter, TokenResponse } from '@credninja/oauth';
import { linkAudienceFor } from '@credninja/protocol';
import type { LinkErrorCode, LinkProviderSlug, LinkTokenSet } from '@credninja/protocol';
import type { ProviderConfig } from '../config.js';
import { hasControlCharacter } from './util.js';
import { parseGrantedScopeString } from './scopes.js';

export const GOOGLE_USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';
export const GITHUB_USER_URL = 'https://api.github.com/user';
export const LINEAR_GRAPHQL_URL = 'https://api.linear.app/graphql';
export const HUBSPOT_TOKEN_INFO_URL = 'https://api.hubapi.com/oauth/v1/access-tokens/';

/**
 * Providers whose tokens never expire in Phase 1 (Slack bot tokens, Notion
 * tokens, GitHub OAuth App tokens). Raw issuance is never allowed for them.
 */
export const NON_EXPIRING_LINK_PROVIDERS: ReadonlySet<LinkProviderSlug> = new Set(['slack', 'notion', 'github']);

/** OAuth `error` codes on refresh that mean the grant is gone (decision 7). */
const REAUTH_OAUTH_ERRORS = new Set(['invalid_grant', 'bad_refresh_token']);

const IDENTITY_TIMEOUT_MS = 10_000;

/**
 * Upper bound on a provider refresh or revocation. Both can run while a
 * connection's token lock is held, so a stalled provider must not block
 * DELETE and every other caller of that connection. After the timeout the
 * caller gets a transient failure and a late response is ignored.
 */
export const LINK_PROVIDER_CALL_TIMEOUT_MS = 15_000;

/** Thrown when a provider refresh or revocation exceeds the call timeout. */
export class LinkProviderTimeoutError extends Error {
  constructor() {
    super('provider call timed out');
    this.name = 'LinkProviderTimeoutError';
  }
}

/** Race `work` against a timer; the timer is always cleared. */
async function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new LinkProviderTimeoutError()), ms);
  });
  try {
    return await Promise.race([work, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    // A late rejection of the abandoned call must not surface as unhandled.
    work.catch(() => undefined);
  }
}

/** Typed failure of the provider hop; `code` is what the widget receives. */
export class LinkProviderError extends Error {
  readonly code: Extract<LinkErrorCode, 'access_denied' | 'provider_error' | 'temporarily_unavailable'>;

  constructor(code: LinkProviderError['code'], message: string) {
    super(message);
    this.name = 'LinkProviderError';
    this.code = code;
  }
}

/** Provider account identity established at the exchange. */
export interface LinkProviderIdentity {
  provider_account_id: string;
  account_label?: string;
  /** Salesforce only: normalized `https://<host>`. */
  instance_url?: string;
}

/** Result of a successful exchange plus identity lookup. */
export interface LinkExchangeResult {
  tokens: LinkTokenSet;
  /** Canonical scopes the provider reported, or null when it reported none. */
  granted_scopes: string[] | null;
  identity: LinkProviderIdentity;
}

/** How a refresh failed. */
export type LinkRefreshFailure = 'reauth' | 'transient';

/** Classify a refresh error: 'reauth' only for an OAuth invalid_grant style answer. */
export function classifyRefreshError(error: unknown): LinkRefreshFailure {
  if (isOAuthTokenError(error) && typeof error.error === 'string' && REAUTH_OAUTH_ERRORS.has(error.error)) {
    return 'reauth';
  }
  return 'transient';
}

function cleanText(value: unknown, max = 256): string | undefined {
  if (typeof value !== 'string' && typeof value !== 'number') return undefined;
  const s = String(value);
  if (s === '' || s.length > max || hasControlCharacter(s)) return undefined;
  return s;
}

function requireText(value: unknown, what: string): string {
  const s = cleanText(value);
  if (!s) throw new LinkProviderError('provider_error', `provider identity is missing ${what}`);
  return s;
}

function expiresAtFrom(expiresIn: number | undefined, nowMs: number): string | undefined {
  if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn) || expiresIn <= 0) return undefined;
  return new Date(nowMs + expiresIn * 1000).toISOString();
}

async function fetchJson(url: string, init: RequestInit): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(IDENTITY_TIMEOUT_MS) });
  } catch {
    throw new LinkProviderError('temporarily_unavailable', 'provider identity request failed');
  }
  if (!response.ok) {
    throw new LinkProviderError(response.status >= 500 ? 'temporarily_unavailable' : 'provider_error', 'provider identity request was rejected');
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new LinkProviderError('provider_error', 'provider identity response is not JSON');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new LinkProviderError('provider_error', 'provider identity response is not an object');
  }
  return data as Record<string, unknown>;
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

const SALESFORCE_ID_SEGMENT = /^[A-Za-z0-9]{15,18}$/;

/** Parse `.../id/<org>/<user>` from the Salesforce identity URL without fetching it. */
function salesforceAccountId(idUrl: unknown): string {
  if (typeof idUrl !== 'string' || idUrl.length > 512) throw new LinkProviderError('provider_error', 'salesforce id is missing');
  let parsed: URL;
  try {
    parsed = new URL(idUrl);
  } catch {
    throw new LinkProviderError('provider_error', 'salesforce id is malformed');
  }
  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts.length !== 3 || parts[0] !== 'id' || !SALESFORCE_ID_SEGMENT.test(parts[1]) || !SALESFORCE_ID_SEGMENT.test(parts[2])) {
    throw new LinkProviderError('provider_error', 'salesforce id is malformed');
  }
  return `${parts[1]}/${parts[2]}`;
}

export interface LinkProviderRuntimeOptions {
  providers: ProviderConfig[];
  /** Public Link base URL (no trailing slash); the callback is `<base>/link/v1/callback/<provider>`. */
  baseUrl: string;
}

/** Provider operations for Link, bound to the server's provider configuration. */
export class LinkProviderRuntime {
  private readonly configs = new Map<string, ProviderConfig>();
  private readonly baseUrl: string;
  /** Timeout for refresh and revocation calls (LINK_PROVIDER_CALL_TIMEOUT_MS; lowered in tests). */
  callTimeoutMs = LINK_PROVIDER_CALL_TIMEOUT_MS;

  constructor(options: LinkProviderRuntimeOptions) {
    for (const p of options.providers) this.configs.set(p.slug, p);
    this.baseUrl = options.baseUrl;
  }

  isConfigured(provider: LinkProviderSlug): boolean {
    return this.configs.has(provider);
  }

  redirectUri(provider: LinkProviderSlug): string {
    return `${this.baseUrl}/link/v1/callback/${provider}`;
  }

  adapter(provider: LinkProviderSlug): ServiceAdapter {
    return createAdapter(provider);
  }

  private client(provider: LinkProviderSlug): OAuthClient {
    const config = this.configs.get(provider);
    if (!config) throw new LinkProviderError('provider_error', 'provider is not configured');
    return new OAuthClient({
      adapter: this.adapter(provider),
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: this.redirectUri(provider),
    });
  }

  /** A fresh PKCE verifier when the adapter supports PKCE, else null. */
  newPkceVerifier(provider: LinkProviderSlug): string | null {
    return this.adapter(provider).supportsPkce ? generateVerifier(64) : null;
  }

  /** Provider authorization URL for the given scopes, state and (optional) PKCE verifier. */
  authorizationUrl(provider: LinkProviderSlug, input: { scopes: string[]; state: string; pkceVerifier?: string | null }): string {
    const config = this.configs.get(provider);
    if (!config) throw new LinkProviderError('provider_error', 'provider is not configured');
    const adapter = this.adapter(provider);
    const url = adapter.buildAuthorizationUrl({
      clientId: config.clientId,
      redirectUri: this.redirectUri(provider),
      scopes: input.scopes,
      state: input.state,
      ...(input.pkceVerifier && adapter.supportsPkce ? { codeChallenge: computeChallenge(input.pkceVerifier) } : {}),
    });
    if (provider === 'notion') {
      // Notion's authorize endpoint requires owner=user.
      const parsed = new URL(url);
      parsed.searchParams.set('owner', 'user');
      return parsed.toString();
    }
    return url;
  }

  /** Origin of the provider's authorization endpoint (for CSP form-action). */
  authorizationOrigin(provider: LinkProviderSlug): string | null {
    try {
      const adapter = this.adapter(provider) as ServiceAdapter & { authorizationUrl?: string };
      return typeof adapter.authorizationUrl === 'string' ? new URL(adapter.authorizationUrl).origin : null;
    } catch {
      return null;
    }
  }

  /**
   * Exchange the code, then establish the provider identity. On an identity
   * failure the fresh tokens are revoked (best effort, only when
   * `revokeOnIdentityFailure`) before throwing: the caller decides, because
   * without an identity it cannot tell whether the tokens back a live
   * connection that a grant-wide revocation would break.
   */
  async exchange(
    provider: LinkProviderSlug,
    code: string,
    pkceVerifier: string | null | undefined,
    options: { revokeOnIdentityFailure: boolean },
    nowMs = Date.now(),
  ): Promise<LinkExchangeResult> {
    let response: TokenResponse;
    try {
      response = await this.client(provider).exchangeCode({ code, ...(pkceVerifier ? { codeVerifier: pkceVerifier } : {}) });
    } catch (error) {
      if (isOAuthTokenError(error)) {
        throw new LinkProviderError(error.status >= 500 ? 'temporarily_unavailable' : 'provider_error', 'code exchange was rejected');
      }
      if (error instanceof LinkProviderError) throw error;
      throw new LinkProviderError('temporarily_unavailable', 'code exchange failed');
    }
    if (typeof response.access_token !== 'string' || response.access_token === '') {
      throw new LinkProviderError('provider_error', 'code exchange returned no access token');
    }
    const tokens: LinkTokenSet = { access_token: response.access_token };
    if (response.refresh_token) tokens.refresh_token = response.refresh_token;
    const expiresAt = expiresAtFrom(response.expires_in, nowMs);
    if (expiresAt) tokens.expires_at = expiresAt;
    if (response.token_type) tokens.token_type = response.token_type;

    try {
      const { identity, granted } = await this.identify(provider, response, tokens);
      return {
        tokens,
        granted_scopes: granted ?? parseGrantedScopeString(response.scope),
        identity,
      };
    } catch (error) {
      if (options.revokeOnIdentityFailure) await this.revoke(provider, tokens);
      if (error instanceof LinkProviderError) throw error;
      throw new LinkProviderError('provider_error', 'provider identity lookup failed');
    }
  }

  private async identify(
    provider: LinkProviderSlug,
    response: TokenResponse,
    tokens: LinkTokenSet,
  ): Promise<{ identity: LinkProviderIdentity; granted?: string[] | null }> {
    const bearer = { Authorization: `Bearer ${tokens.access_token}`, Accept: 'application/json' };
    switch (provider) {
      case 'google': {
        const info = await fetchJson(GOOGLE_USERINFO_URL, { method: 'GET', headers: bearer });
        return { identity: { provider_account_id: requireText(info.sub, 'sub'), account_label: cleanText(info.email) } };
      }
      case 'github': {
        const user = await fetchJson(GITHUB_USER_URL, {
          method: 'GET',
          headers: { ...bearer, Accept: 'application/vnd.github+json', 'User-Agent': 'Cred-Server/1.0' },
        });
        if (typeof user.id !== 'number' || !Number.isSafeInteger(user.id)) {
          throw new LinkProviderError('provider_error', 'github user id is missing');
        }
        return { identity: { provider_account_id: String(user.id), account_label: cleanText(user.login) } };
      }
      case 'slack': {
        const raw = getRawTokenResponse(response) ?? {};
        const team = asObject(raw.team);
        const teamId = requireText(team?.id, 'team id');
        const botUserId = requireText(raw.bot_user_id, 'bot user id');
        return { identity: { provider_account_id: `${teamId}/${botUserId}`, account_label: cleanText(team?.name) } };
      }
      case 'notion': {
        const raw = getRawTokenResponse(response) ?? {};
        const workspaceId = requireText(raw.workspace_id, 'workspace id');
        const botId = requireText(raw.bot_id, 'bot id');
        return { identity: { provider_account_id: `${workspaceId}/${botId}`, account_label: cleanText(raw.workspace_name) } };
      }
      case 'salesforce': {
        const raw = getRawTokenResponse(response) ?? {};
        const instanceUrl = linkAudienceFor('salesforce', typeof raw.instance_url === 'string' ? raw.instance_url : null);
        if (!instanceUrl) throw new LinkProviderError('provider_error', 'salesforce instance_url is not acceptable');
        return {
          identity: {
            provider_account_id: salesforceAccountId(raw.id),
            account_label: new URL(instanceUrl).host,
            instance_url: instanceUrl,
          },
        };
      }
      case 'linear': {
        const result = await fetchJson(LINEAR_GRAPHQL_URL, {
          method: 'POST',
          headers: { ...bearer, 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: '{ viewer { id email } }' }),
        });
        const viewer = asObject(asObject(result.data)?.viewer);
        return { identity: { provider_account_id: requireText(viewer?.id, 'viewer id'), account_label: cleanText(viewer?.email) } };
      }
      case 'hubspot': {
        const info = await fetchJson(`${HUBSPOT_TOKEN_INFO_URL}${encodeURIComponent(tokens.access_token)}`, {
          method: 'GET',
          headers: { Accept: 'application/json' },
        });
        const hubId = requireText(info.hub_id, 'hub id');
        const userId = cleanText(info.user_id);
        const granted = Array.isArray(info.scopes) ? parseGrantedScopeString(info.scopes) : null;
        return {
          identity: {
            provider_account_id: userId ? `${hubId}/${userId}` : hubId,
            account_label: cleanText(info.hub_domain) ?? cleanText(info.user),
          },
          granted,
        };
      }
    }
  }

  /**
   * Refresh through the adapter, bounded by callTimeoutMs. Throws the
   * adapter's error (see classifyRefreshError) or LinkProviderTimeoutError
   * (transient).
   */
  async refresh(provider: LinkProviderSlug, refreshToken: string): Promise<RefreshResponse> {
    return withTimeout(this.client(provider).refreshToken(refreshToken), this.callTimeoutMs);
  }

  /** Whether the provider's adapter supports refresh. */
  supportsRefresh(provider: LinkProviderSlug): boolean {
    return this.adapter(provider).supportsRefresh;
  }

  /**
   * Revoke at the provider, best effort (never throws). The refresh token
   * is revoked where that ends the whole authorization (Google, Salesforce,
   * HubSpot needs it); otherwise the access token.
   */
  async revoke(provider: LinkProviderSlug, tokens: LinkTokenSet): Promise<boolean> {
    if (!this.configs.has(provider)) return false;
    const token = provider === 'hubspot'
      ? tokens.refresh_token
      : (provider === 'google' || provider === 'salesforce')
        ? tokens.refresh_token ?? tokens.access_token
        : tokens.access_token;
    if (!token) return false;
    try {
      await withTimeout(this.client(provider).revokeToken(token), this.callTimeoutMs);
      return true;
    } catch (error) {
      console.warn('[link] provider revocation failed', { provider, kind: error instanceof Error ? error.name : 'unknown' });
      return false;
    }
  }
}

/** expires_at for a refresh response. */
export function refreshedTokenSet(previous: LinkTokenSet, refreshed: RefreshResponse, nowMs = Date.now()): LinkTokenSet {
  const next: LinkTokenSet = { access_token: refreshed.access_token };
  const refreshToken = refreshed.refresh_token ?? previous.refresh_token;
  if (refreshToken) next.refresh_token = refreshToken;
  const expiresAt = expiresAtFrom(refreshed.expires_in, nowMs);
  if (expiresAt) next.expires_at = expiresAt;
  if (previous.token_type) next.token_type = previous.token_type;
  return next;
}

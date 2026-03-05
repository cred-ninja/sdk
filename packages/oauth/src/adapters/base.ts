/**
 * BaseServiceAdapter — Abstract base class for OAuth provider adapters.
 *
 * Implements common OAuth 2.0 flows using fetch (Node 18+).
 * No axios, no global registry, no side effects on import.
 */

import type {
  ServiceAdapter,
  TokenResponse,
  RefreshResponse,
  BuildAuthUrlParams,
  ExchangeCodeParams,
  RefreshTokenParams,
  RevokeTokenParams,
} from '../types.js';

export type { ServiceAdapter };

export abstract class BaseServiceAdapter implements ServiceAdapter {
  abstract readonly slug: string;
  abstract readonly authorizationUrl: string;
  abstract readonly tokenUrl: string;
  abstract readonly revocationUrl: string | null;

  /** Scope separator character (space for most, comma for Slack/GitHub) */
  readonly scopeSeparator: string = ' ';
  readonly supportsPkce: boolean = true;
  readonly supportsRefresh: boolean = true;

  buildAuthorizationUrl(params: BuildAuthUrlParams): string {
    const url = new URL(this.authorizationUrl);
    url.searchParams.set('client_id', params.clientId);
    url.searchParams.set('redirect_uri', params.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('state', params.state);

    if (params.scopes.length > 0) {
      url.searchParams.set('scope', params.scopes.join(this.scopeSeparator));
    }

    if (params.codeChallenge && this.supportsPkce) {
      url.searchParams.set('code_challenge', params.codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
    }

    return url.toString();
  }

  async exchangeCodeForTokens(params: ExchangeCodeParams): Promise<TokenResponse> {
    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: params.redirectUri,
      client_id: params.clientId,
      client_secret: params.clientSecret,
    };

    if (params.codeVerifier && this.supportsPkce) {
      body.code_verifier = params.codeVerifier;
    }

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: new URLSearchParams(body),
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as Record<string, unknown>;
    return this.normalizeTokenResponse(data);
  }

  async refreshAccessToken(params: RefreshTokenParams): Promise<RefreshResponse> {
    if (!this.supportsRefresh) {
      throw new Error(`${this.slug} does not support token refresh`);
    }

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: params.refreshToken,
        client_id: params.clientId,
        client_secret: params.clientSecret,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as Record<string, unknown>;
    return this.normalizeRefreshResponse(data);
  }

  async revokeToken(params: RevokeTokenParams): Promise<void> {
    if (!this.revocationUrl) {
      // No-op for providers without a revocation endpoint
      return;
    }

    const response = await fetch(this.revocationUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: params.token,
        client_id: params.clientId,
        client_secret: params.clientSecret,
      }),
    });

    if (!response.ok) {
      throw new Error(`Token revocation failed: ${response.status} ${response.statusText}`);
    }
  }

  /** Normalize provider response to standard TokenResponse shape */
  protected normalizeTokenResponse(data: Record<string, unknown>): TokenResponse {
    return {
      access_token: String(data.access_token ?? ''),
      refresh_token: data.refresh_token ? String(data.refresh_token) : undefined,
      expires_in: typeof data.expires_in === 'number' ? data.expires_in : undefined,
      scope: data.scope ? String(data.scope) : undefined,
      token_type: String(data.token_type ?? 'Bearer'),
    };
  }

  /** Normalize provider response to standard RefreshResponse shape */
  protected normalizeRefreshResponse(data: Record<string, unknown>): RefreshResponse {
    return {
      access_token: String(data.access_token ?? ''),
      expires_in: typeof data.expires_in === 'number' ? data.expires_in : undefined,
      refresh_token: data.refresh_token ? String(data.refresh_token) : undefined,
    };
  }
}

/**
 * GitHub OAuth Adapter
 *
 * Quirks handled:
 * - Accept: application/json header required on token exchange
 * - Scopes are comma-separated (not space-separated)
 * - No PKCE support
 * - Token revocation uses DELETE + Basic auth to /applications/{client_id}/token
 * - 404 on revoke = already revoked = success
 */

import { BaseServiceAdapter } from './base.js';
import type {
  TokenResponse,
  RefreshResponse,
  ExchangeCodeParams,
  RefreshTokenParams,
  RevokeTokenParams,
} from '../types.js';

export class GitHubAdapter extends BaseServiceAdapter {
  readonly slug = 'github';
  readonly authorizationUrl = 'https://github.com/login/oauth/authorize';
  readonly tokenUrl = 'https://github.com/login/oauth/access_token';
  readonly revocationUrl = 'https://api.github.com/applications';

  readonly scopeSeparator = ',';
  readonly supportsPkce = false;
  readonly supportsRefresh = true;

  async exchangeCodeForTokens(params: ExchangeCodeParams): Promise<TokenResponse> {
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json', // Required — GitHub returns plain text by default
      },
      body: new URLSearchParams({
        client_id: params.clientId,
        client_secret: params.clientSecret,
        code: params.code,
        redirect_uri: params.redirectUri,
      }),
    });

    if (!response.ok) {
      throw new Error(`GitHub token exchange failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as Record<string, unknown>;
    return this.normalizeTokenResponse(data);
  }

  async refreshAccessToken(params: RefreshTokenParams): Promise<RefreshResponse> {
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        client_id: params.clientId,
        client_secret: params.clientSecret,
        grant_type: 'refresh_token',
        refresh_token: params.refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error(`GitHub token refresh failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as Record<string, unknown>;
    return this.normalizeRefreshResponse(data);
  }

  async revokeToken(params: RevokeTokenParams): Promise<void> {
    const basicAuth = Buffer.from(`${params.clientId}:${params.clientSecret}`).toString('base64');

    const response = await fetch(`${this.revocationUrl}/${params.clientId}/token`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Accept': 'application/vnd.github+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ access_token: params.token }),
    });

    // GitHub returns 404 if token already revoked — treat as success
    if (response.status === 404 || response.status === 204) {
      return;
    }

    if (!response.ok) {
      throw new Error(`GitHub token revocation failed: ${response.status} ${response.statusText}`);
    }
  }
}

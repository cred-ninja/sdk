/**
 * Asana OAuth Adapter
 *
 * Quirks handled:
 * - No PKCE support
 * - Supports refresh tokens (expiry: 1 hour access, refresh never expires)
 * - Revocation endpoint not provided by Asana — null (no-op)
 * - Space-separated scopes (default: 'default')
 * - Token exchange: standard form POST with client credentials
 */

import { BaseServiceAdapter } from './base.js';
import type { RefreshTokenParams, RefreshResponse } from '../types.js';

export class AsanaAdapter extends BaseServiceAdapter {
  readonly slug = 'asana';
  readonly authorizationUrl = 'https://app.asana.com/-/oauth_authorize';
  readonly tokenUrl = 'https://app.asana.com/-/oauth_token';
  // Asana does not provide a token revocation endpoint
  readonly revocationUrl: string | null = null;

  readonly scopeSeparator = ' ';
  readonly supportsPkce = false;
  readonly supportsRefresh = true;

  async refreshAccessToken(params: RefreshTokenParams): Promise<RefreshResponse> {
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: params.clientId,
        client_secret: params.clientSecret,
        refresh_token: params.refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error(`Asana token refresh failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as Record<string, unknown>;
    return this.normalizeRefreshResponse(data);
  }
}

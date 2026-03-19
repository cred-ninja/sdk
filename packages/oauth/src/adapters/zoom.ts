/**
 * Zoom OAuth Adapter
 *
 * Quirks handled:
 * - Token exchange uses HTTP Basic auth (client_id:client_secret in Authorization header)
 * - Supports PKCE (S256)
 * - Supports refresh tokens
 * - Revocation via POST to /oauth/revoke
 * - Space-separated scopes
 */

import { BaseServiceAdapter } from './base.js';
import type {
  TokenResponse,
  RefreshResponse,
  ExchangeCodeParams,
  RefreshTokenParams,
  RevokeTokenParams,
} from '../types.js';

export class ZoomAdapter extends BaseServiceAdapter {
  readonly slug = 'zoom';
  readonly authorizationUrl = 'https://zoom.us/oauth/authorize';
  readonly tokenUrl = 'https://zoom.us/oauth/token';
  readonly revocationUrl = 'https://zoom.us/oauth/revoke';

  readonly scopeSeparator = ' ';
  readonly supportsPkce = true;
  readonly supportsRefresh = true;

  /** Zoom requires Basic auth on token exchange and refresh */
  private basicAuth(clientId: string, clientSecret: string): string {
    return 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  }

  async exchangeCodeForTokens(params: ExchangeCodeParams): Promise<TokenResponse> {
    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: params.redirectUri,
    };

    if (params.codeVerifier && this.supportsPkce) {
      body.code_verifier = params.codeVerifier;
    }

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': this.basicAuth(params.clientId, params.clientSecret),
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: new URLSearchParams(body),
    });

    if (!response.ok) {
      throw new Error(`Zoom token exchange failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as Record<string, unknown>;
    return this.normalizeTokenResponse(data);
  }

  async refreshAccessToken(params: RefreshTokenParams): Promise<RefreshResponse> {
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': this.basicAuth(params.clientId, params.clientSecret),
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: params.refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error(`Zoom token refresh failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as Record<string, unknown>;
    return this.normalizeRefreshResponse(data);
  }

  async revokeToken(params: RevokeTokenParams): Promise<void> {
    const response = await fetch(`${this.revocationUrl}?token=${encodeURIComponent(params.token)}`, {
      method: 'POST',
      headers: {
        'Authorization': this.basicAuth(params.clientId, params.clientSecret),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    if (!response.ok) {
      throw new Error(`Zoom token revocation failed: ${response.status} ${response.statusText}`);
    }
  }
}

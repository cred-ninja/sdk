/**
 * Notion OAuth Adapter
 *
 * Quirks handled:
 * - Token exchange uses Basic auth header (NOT client_secret in body)
 * - Tokens do not expire — refresh not supported (throws)
 * - No revocation endpoint — revokeToken is a no-op
 * - No PKCE support
 * - Response includes owner.user object (preserved as-is)
 */

import { BaseServiceAdapter } from './base.js';
import type {
  TokenResponse,
  RefreshResponse,
  ExchangeCodeParams,
  RefreshTokenParams,
  RevokeTokenParams,
} from '../types.js';

export class NotionAdapter extends BaseServiceAdapter {
  readonly slug = 'notion';
  readonly authorizationUrl = 'https://api.notion.com/v1/oauth/authorize';
  readonly tokenUrl = 'https://api.notion.com/v1/oauth/token';
  readonly revocationUrl = null; // No revocation endpoint

  readonly scopeSeparator = ' ';
  readonly supportsPkce = false;
  readonly supportsRefresh = false; // Notion tokens don't expire

  async exchangeCodeForTokens(params: ExchangeCodeParams): Promise<TokenResponse> {
    // Notion requires Basic auth — NOT client_secret in the request body
    const basicAuth = Buffer.from(`${params.clientId}:${params.clientSecret}`).toString('base64');

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/json',
        'Notion-Version': '2022-06-28',
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: params.code,
        redirect_uri: params.redirectUri,
      }),
    });

    if (!response.ok) {
      throw new Error(`Notion token exchange failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as Record<string, unknown>;
    return this.normalizeTokenResponse(data);
  }

  protected normalizeTokenResponse(data: Record<string, unknown>): TokenResponse {
    return {
      access_token: String(data.access_token ?? ''),
      refresh_token: undefined, // Notion doesn't issue refresh tokens
      expires_in: undefined, // Notion tokens don't expire
      scope: undefined, // Notion doesn't return scope in token response
      token_type: 'Bearer',
    };
  }

  async refreshAccessToken(_params: RefreshTokenParams): Promise<RefreshResponse> {
    throw new Error('Notion tokens do not expire and cannot be refreshed');
  }

  async revokeToken(_params: RevokeTokenParams): Promise<void> {
    // Notion has no revocation endpoint — no-op
    // Users must disconnect via Notion's settings UI
    return;
  }
}

/**
 * Slack OAuth Adapter
 *
 * Quirks handled:
 * - Scopes are comma-separated
 * - Tokens do NOT expire — refresh not supported (throws)
 * - Revocation uses Bearer token auth (not client credentials)
 * - Token exchange returns nested authed_user.access_token for user tokens
 * - No PKCE support
 */

import { BaseServiceAdapter } from './base.js';
import type {
  TokenResponse,
  RefreshResponse,
  RefreshTokenParams,
  RevokeTokenParams,
} from '../types.js';

export class SlackAdapter extends BaseServiceAdapter {
  readonly slug = 'slack';
  readonly authorizationUrl = 'https://slack.com/oauth/v2/authorize';
  readonly tokenUrl = 'https://slack.com/api/oauth.v2.access';
  readonly revocationUrl = 'https://slack.com/api/auth.revoke';

  readonly scopeSeparator = ',';
  readonly supportsPkce = false;
  readonly supportsRefresh = false; // Slack tokens don't expire

  protected normalizeTokenResponse(data: Record<string, unknown>): TokenResponse {
    // User token response: { authed_user: { access_token, scope, ... } }
    const authedUser = data.authed_user as Record<string, unknown> | undefined;

    if (authedUser?.access_token) {
      return {
        access_token: String(authedUser.access_token),
        refresh_token: undefined,
        expires_in: undefined,
        scope: authedUser.scope ? String(authedUser.scope) : undefined,
        token_type: 'Bearer',
      };
    }

    // Bot token response: { access_token, scope, ... }
    return {
      access_token: String(data.access_token ?? ''),
      refresh_token: undefined,
      expires_in: undefined,
      scope: data.scope ? String(data.scope) : undefined,
      token_type: 'Bearer',
    };
  }

  async refreshAccessToken(_params: RefreshTokenParams): Promise<RefreshResponse> {
    throw new Error('Slack tokens do not expire and cannot be refreshed');
  }

  async revokeToken(params: RevokeTokenParams): Promise<void> {
    // Slack revocation uses Bearer auth with the token itself
    const response = await fetch(this.revocationUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${params.token}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    if (!response.ok) {
      throw new Error(`Slack revocation request failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as Record<string, unknown>;

    if (!data.ok) {
      // Already-revoked tokens are treated as success
      if (data.error !== 'token_revoked') {
        throw new Error(`Slack revocation failed: ${String(data.error ?? 'unknown')}`);
      }
    }
  }
}

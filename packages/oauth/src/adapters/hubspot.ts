/**
 * HubSpot OAuth Adapter
 *
 * Quirks handled:
 * - Scopes are space-separated
 * - No PKCE support
 * - Refresh tokens supported (access tokens expire in 30 minutes)
 * - Token exchange uses application/x-www-form-urlencoded
 * - Revocation via DELETE to /oauth/v1/refresh-tokens/:token (revokes the refresh token)
 * - Optional accountId scopes auth to a specific HubSpot portal
 * - Supports optional_scope parameter for nice-to-have scopes
 */

import { BaseServiceAdapter } from './base.js';
import type {
  BuildAuthUrlParams,
  RevokeTokenParams,
} from '../types.js';

export class HubSpotAdapter extends BaseServiceAdapter {
  readonly slug = 'hubspot';
  readonly authorizationUrl = 'https://app.hubspot.com/oauth/authorize';
  readonly tokenUrl = 'https://api.hubapi.com/oauth/v1/token';
  readonly revocationUrl = 'https://api.hubapi.com/oauth/v1/refresh-tokens';

  readonly scopeSeparator = ' ';
  readonly supportsPkce = false;
  readonly supportsRefresh = true;

  /** Optional HubSpot portal/account ID to scope the OAuth flow to a specific account */
  private readonly accountId: string | undefined;

  constructor(accountId?: string) {
    super();
    this.accountId = accountId;
  }

  buildAuthorizationUrl(params: BuildAuthUrlParams & { optionalScope?: string[] }): string {
    // Use account-specific URL if accountId is set
    const baseUrl = this.accountId
      ? `https://app.hubspot.com/oauth/${this.accountId}/authorize`
      : this.authorizationUrl;

    const url = new URL(baseUrl);
    url.searchParams.set('client_id', params.clientId);
    url.searchParams.set('redirect_uri', params.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('state', params.state);

    if (params.scopes.length > 0) {
      url.searchParams.set('scope', params.scopes.join(this.scopeSeparator));
    }

    // HubSpot supports optional_scope for nice-to-have permissions
    if (params.optionalScope && params.optionalScope.length > 0) {
      url.searchParams.set('optional_scope', params.optionalScope.join(this.scopeSeparator));
    }

    // PKCE not supported by HubSpot; ignore codeChallenge even if provided

    return url.toString();
  }

  async revokeToken(params: RevokeTokenParams): Promise<void> {
    // HubSpot revocation: DELETE /oauth/v1/refresh-tokens/:token
    // Revokes the refresh token (which also invalidates associated access tokens)
    const url = `${this.revocationUrl}/${encodeURIComponent(params.token)}`;

    const response = await fetch(url, {
      method: 'DELETE',
    });

    if (!response.ok) {
      throw new Error(`HubSpot token revocation failed: ${response.status} ${response.statusText}`);
    }
  }
}

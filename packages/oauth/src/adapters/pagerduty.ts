/**
 * PagerDuty OAuth Adapter
 *
 * Quirks handled:
 * - No PKCE support
 * - No refresh tokens — PagerDuty issues long-lived access tokens
 * - Revocation via DELETE to /oauth/token/{token}
 * - Space-separated scopes
 * - Authorization URL uses app.pagerduty.com
 */

import { BaseServiceAdapter } from './base.js';
import type { RefreshTokenParams, RefreshResponse, RevokeTokenParams } from '../types.js';

export class PagerDutyAdapter extends BaseServiceAdapter {
  readonly slug = 'pagerduty';
  readonly authorizationUrl = 'https://app.pagerduty.com/oauth/authorize';
  readonly tokenUrl = 'https://app.pagerduty.com/oauth/token';
  readonly revocationUrl = 'https://app.pagerduty.com/oauth/token';

  readonly scopeSeparator = ' ';
  readonly supportsPkce = false;
  readonly supportsRefresh = false;

  async refreshAccessToken(_params: RefreshTokenParams): Promise<RefreshResponse> {
    throw new Error('PagerDuty OAuth does not support token refresh — tokens are long-lived');
  }

  async revokeToken(params: RevokeTokenParams): Promise<void> {
    const basicAuth = Buffer.from(`${params.clientId}:${params.clientSecret}`).toString('base64');

    const response = await fetch(`${this.revocationUrl}/${encodeURIComponent(params.token)}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Accept': 'application/json',
      },
    });

    // 204 = success, 404 = already revoked
    if (response.status === 204 || response.status === 404) {
      return;
    }

    if (!response.ok) {
      throw new Error(`PagerDuty token revocation failed: ${response.status} ${response.statusText}`);
    }
  }
}

/**
 * Stripe Connect OAuth Adapter
 *
 * Quirks handled:
 * - Authorization URL is https://connect.stripe.com/oauth/authorize
 * - No PKCE support
 * - No refresh tokens — Stripe issues long-lived access tokens
 * - Revocation via POST to /oauth/deauthorize (requires stripe_user_id)
 * - scope is 'read_write' or 'read_only'
 */

import { BaseServiceAdapter } from './base.js';
import type { RefreshTokenParams, RefreshResponse } from '../types.js';

export class StripeAdapter extends BaseServiceAdapter {
  readonly slug = 'stripe';
  readonly authorizationUrl = 'https://connect.stripe.com/oauth/authorize';
  readonly tokenUrl = 'https://connect.stripe.com/oauth/token';
  readonly revocationUrl = 'https://connect.stripe.com/oauth/deauthorize';

  readonly supportsPkce = false;
  readonly supportsRefresh = false; // Stripe issues long-lived access tokens

  async refreshAccessToken(_params: RefreshTokenParams): Promise<RefreshResponse> {
    throw new Error('Stripe Connect OAuth does not support token refresh — tokens are long-lived');
  }
}

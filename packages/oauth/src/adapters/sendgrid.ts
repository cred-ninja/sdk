/**
 * SendGrid API Key Adapter
 *
 * SendGrid does not provide an OAuth 2.0 flow. This adapter implements the
 * ServiceAdapter interface for API key-based credential management.
 *
 * Quirks:
 * - No OAuth flow — all OAuth methods throw with clear error messages
 * - supportsOAuth: false — use this flag to detect API key adapters
 * - supportsRefresh: false — API keys don't expire
 * - supportsPkce: false
 * - Revocation: API keys are managed via the SendGrid dashboard or API
 */

import { BaseServiceAdapter } from './base.js';
import type {
  BuildAuthUrlParams,
  TokenResponse,
  RefreshResponse,
  ExchangeCodeParams,
  RefreshTokenParams,
  RevokeTokenParams,
} from '../types.js';

export class SendGridAdapter extends BaseServiceAdapter {
  readonly slug = 'sendgrid';
  readonly authorizationUrl = 'https://app.sendgrid.com/settings/api_keys';
  readonly tokenUrl = 'https://api.sendgrid.com/v3';
  readonly revocationUrl: string | null = null;

  readonly scopeSeparator = ' ';
  readonly supportsPkce = false;
  readonly supportsRefresh = false;
  /** SendGrid is an API key provider — no OAuth flow */
  readonly supportsOAuth = false;

  buildAuthorizationUrl(_params: BuildAuthUrlParams): string {
    throw new Error(
      'SendGrid does not support OAuth. Generate API keys at https://app.sendgrid.com/settings/api_keys'
    );
  }

  async exchangeCodeForTokens(_params: ExchangeCodeParams): Promise<TokenResponse> {
    throw new Error(
      'SendGrid does not support OAuth code exchange. Use an API key directly.'
    );
  }

  async refreshAccessToken(_params: RefreshTokenParams): Promise<RefreshResponse> {
    throw new Error('SendGrid API keys do not expire and cannot be refreshed');
  }

  async revokeToken(_params: RevokeTokenParams): Promise<void> {
    throw new Error(
      'SendGrid API keys must be revoked via the dashboard or DELETE /v3/api_keys/{api_key_id}'
    );
  }
}

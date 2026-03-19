/**
 * OpenAI API Key Adapter
 *
 * OpenAI does not provide an OAuth 2.0 flow. This adapter implements the
 * ServiceAdapter interface for API key-based credential management.
 *
 * Quirks:
 * - No OAuth flow — all OAuth methods throw with clear error messages
 * - supportsOAuth: false — use this flag to detect API key adapters
 * - supportsRefresh: false — API keys don't expire
 * - supportsPkce: false
 * - Revocation: API keys are managed via the OpenAI dashboard
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

export class OpenAIAdapter extends BaseServiceAdapter {
  readonly slug = 'openai';
  readonly authorizationUrl = 'https://platform.openai.com/api-keys';
  readonly tokenUrl = 'https://api.openai.com/v1';
  readonly revocationUrl: string | null = null;

  readonly scopeSeparator = ' ';
  readonly supportsPkce = false;
  readonly supportsRefresh = false;
  /** OpenAI is an API key provider — no OAuth flow */
  readonly supportsOAuth = false;

  buildAuthorizationUrl(_params: BuildAuthUrlParams): string {
    throw new Error(
      'OpenAI does not support OAuth. Generate API keys at https://platform.openai.com/api-keys'
    );
  }

  async exchangeCodeForTokens(_params: ExchangeCodeParams): Promise<TokenResponse> {
    throw new Error(
      'OpenAI does not support OAuth code exchange. Use an API key directly.'
    );
  }

  async refreshAccessToken(_params: RefreshTokenParams): Promise<RefreshResponse> {
    throw new Error('OpenAI API keys do not expire and cannot be refreshed');
  }

  async revokeToken(_params: RevokeTokenParams): Promise<void> {
    throw new Error(
      'OpenAI API keys must be revoked manually at https://platform.openai.com/api-keys'
    );
  }
}

/**
 * Salesforce OAuth Adapter
 *
 * Quirks handled:
 * - Full PKCE support (S256)
 * - Returns instance_url in token response (needed for API calls)
 * - Supports both production (login.salesforce.com) and sandbox (test.salesforce.com)
 * - Standard OAuth 2.0 otherwise
 */

import { BaseServiceAdapter } from './base.js';
import type { TokenResponse } from '../types.js';

export interface SalesforceTokenResponse extends TokenResponse {
  instance_url?: string;
  id?: string; // User ID URL from Salesforce
}

interface SalesforceConfig {
  slug: string;
  authorizationUrl: string;
  tokenUrl: string;
  revocationUrl: string;
}

export const SALESFORCE_PRODUCTION: SalesforceConfig = {
  slug: 'salesforce',
  authorizationUrl: 'https://login.salesforce.com/services/oauth2/authorize',
  tokenUrl: 'https://login.salesforce.com/services/oauth2/token',
  revocationUrl: 'https://login.salesforce.com/services/oauth2/revoke',
};

export const SALESFORCE_SANDBOX: SalesforceConfig = {
  slug: 'salesforce-sandbox',
  authorizationUrl: 'https://test.salesforce.com/services/oauth2/authorize',
  tokenUrl: 'https://test.salesforce.com/services/oauth2/token',
  revocationUrl: 'https://test.salesforce.com/services/oauth2/revoke',
};

export class SalesforceAdapter extends BaseServiceAdapter {
  readonly slug: string;
  readonly authorizationUrl: string;
  readonly tokenUrl: string;
  readonly revocationUrl: string;

  readonly scopeSeparator = ' ';
  readonly supportsPkce = true;
  readonly supportsRefresh = true;

  constructor(config: SalesforceConfig = SALESFORCE_PRODUCTION) {
    super();
    this.slug = config.slug;
    this.authorizationUrl = config.authorizationUrl;
    this.tokenUrl = config.tokenUrl;
    this.revocationUrl = config.revocationUrl;
  }

  protected normalizeTokenResponse(data: Record<string, unknown>): SalesforceTokenResponse {
    return {
      access_token: String(data.access_token ?? ''),
      refresh_token: data.refresh_token ? String(data.refresh_token) : undefined,
      expires_in: typeof data.expires_in === 'number' ? data.expires_in : undefined,
      scope: data.scope ? String(data.scope) : undefined,
      token_type: String(data.token_type ?? 'Bearer'),
      // Salesforce-specific: required for making API calls
      instance_url: data.instance_url ? String(data.instance_url) : undefined,
      id: data.id ? String(data.id) : undefined,
    };
  }
}

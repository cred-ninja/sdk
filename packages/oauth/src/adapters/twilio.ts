/**
 * Twilio OAuth Adapter
 *
 * Quirks handled:
 * - Authorization via Twilio's user auth portal
 * - Supports PKCE (S256)
 * - Supports refresh tokens
 * - Revocation endpoint not publicly documented — null (no-op)
 * - Scopes: offline_access required for refresh tokens
 */

import { BaseServiceAdapter } from './base.js';

export class TwilioAdapter extends BaseServiceAdapter {
  readonly slug = 'twilio';
  readonly authorizationUrl = 'https://login.twilio.com/oauth2/authorize';
  readonly tokenUrl = 'https://login.twilio.com/oauth2/token';
  // Twilio does not publish a token revocation endpoint
  readonly revocationUrl: string | null = null;

  readonly scopeSeparator = ' ';
  readonly supportsPkce = true;
  readonly supportsRefresh = true;
}

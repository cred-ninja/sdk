/**
 * Discord OAuth Adapter
 *
 * Quirks handled:
 * - Full PKCE support (S256)
 * - Supports refresh tokens
 * - Revocation via POST to /oauth2/token/revoke
 * - Bot scope requires separate bot authorization URL path
 * - scope includes 'identify', 'email', 'guilds', 'bot', etc.
 */

import { BaseServiceAdapter } from './base.js';

export class DiscordAdapter extends BaseServiceAdapter {
  readonly slug = 'discord';
  readonly authorizationUrl = 'https://discord.com/oauth2/authorize';
  readonly tokenUrl = 'https://discord.com/api/oauth2/token';
  readonly revocationUrl = 'https://discord.com/api/oauth2/token/revoke';

  readonly scopeSeparator = ' ';
  readonly supportsPkce = true;
  readonly supportsRefresh = true;
}

/**
 * Linear OAuth Adapter
 *
 * Quirks handled:
 * - Scopes are comma-separated (read, write, issues:create, comments:create, etc.)
 * - PKCE supported (S256)
 * - Refresh tokens enabled by default (since Oct 2025)
 * - Access tokens expire in 24 hours
 * - Token exchange uses application/x-www-form-urlencoded
 * - Refresh can use Basic auth or client_id/client_secret params (we use params)
 * - Supports actor param (user or app) for agent-specific auth
 * - Revocation via POST to /oauth/revoke
 */

import { BaseServiceAdapter } from './base.js';
import type {
  BuildAuthUrlParams,
} from '../types.js';

export class LinearAdapter extends BaseServiceAdapter {
  readonly slug = 'linear';
  readonly authorizationUrl = 'https://linear.app/oauth/authorize';
  readonly tokenUrl = 'https://api.linear.app/oauth/token';
  readonly revocationUrl = 'https://api.linear.app/oauth/revoke';

  readonly scopeSeparator = ',';
  readonly supportsPkce = true;
  readonly supportsRefresh = true;

  /** Actor mode: 'user' (default) or 'app' (for agent/service accounts) */
  private readonly actor: 'user' | 'app';

  constructor(actor: 'user' | 'app' = 'user') {
    super();
    this.actor = actor;
  }

  buildAuthorizationUrl(params: BuildAuthUrlParams): string {
    const url = super.buildAuthorizationUrl(params);
    const parsed = new URL(url);

    // Linear uses actor param for agent-specific auth
    if (this.actor === 'app') {
      parsed.searchParams.set('actor', 'app');
    }

    return parsed.toString();
  }
}

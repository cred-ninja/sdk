/**
 * Google OAuth Adapter
 *
 * Quirks handled:
 * - access_type=offline required for refresh tokens
 * - prompt=consent required to get refresh token on re-authorization
 * - Short scope names auto-prefixed with https://www.googleapis.com/auth/
 * - Full PKCE support (S256)
 */

import { BaseServiceAdapter } from './base.js';
import type { BuildAuthUrlParams } from '../types.js';

export class GoogleAdapter extends BaseServiceAdapter {
  readonly slug: string;
  readonly authorizationUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  readonly tokenUrl = 'https://oauth2.googleapis.com/token';
  readonly revocationUrl = 'https://oauth2.googleapis.com/revoke';

  readonly scopeSeparator = ' ';
  readonly supportsPkce = true;
  readonly supportsRefresh = true;

  constructor(slug: string = 'google') {
    super();
    this.slug = slug;
  }

  buildAuthorizationUrl(params: BuildAuthUrlParams): string {
    const url = new URL(this.authorizationUrl);
    url.searchParams.set('client_id', params.clientId);
    url.searchParams.set('redirect_uri', params.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('state', params.state);

    // Required for refresh token issuance
    url.searchParams.set('access_type', 'offline');
    // Force consent screen to get refresh token on re-auth
    url.searchParams.set('prompt', 'consent');

    if (params.scopes.length > 0) {
      const normalizedScopes = params.scopes.map(scope => {
        if (scope.startsWith('https://') || scope.startsWith('openid') || scope === 'email' || scope === 'profile') {
          return scope;
        }
        return `https://www.googleapis.com/auth/${scope}`;
      });
      url.searchParams.set('scope', normalizedScopes.join(this.scopeSeparator));
    }

    if (params.codeChallenge) {
      url.searchParams.set('code_challenge', params.codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
    }

    return url.toString();
  }
}

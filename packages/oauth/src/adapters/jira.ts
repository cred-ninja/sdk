/**
 * Jira (Atlassian) OAuth 2.0 (3LO) Adapter
 *
 * Quirks handled:
 * - Uses Atlassian Identity platform (id.atlassian.com)
 * - audience param required in auth URL: 'api.atlassian.com'
 * - Full PKCE support (S256)
 * - Supports refresh tokens (offline_access scope required)
 * - Revocation endpoint not provided by Atlassian — null (no-op)
 * - Space-separated scopes
 * - prompt=consent required to get refresh token
 */

import { BaseServiceAdapter } from './base.js';
import type { BuildAuthUrlParams } from '../types.js';

export class JiraAdapter extends BaseServiceAdapter {
  readonly slug = 'jira';
  readonly authorizationUrl = 'https://auth.atlassian.com/authorize';
  readonly tokenUrl = 'https://auth.atlassian.com/oauth/token';
  // Atlassian does not provide a standard OAuth revocation endpoint
  readonly revocationUrl: string | null = null;

  readonly scopeSeparator = ' ';
  readonly supportsPkce = true;
  readonly supportsRefresh = true;

  buildAuthorizationUrl(params: BuildAuthUrlParams): string {
    const url = new URL(this.authorizationUrl);
    url.searchParams.set('client_id', params.clientId);
    url.searchParams.set('redirect_uri', params.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('state', params.state);
    // Atlassian requires audience and prompt params
    url.searchParams.set('audience', 'api.atlassian.com');
    url.searchParams.set('prompt', 'consent');

    if (params.scopes.length > 0) {
      url.searchParams.set('scope', params.scopes.join(this.scopeSeparator));
    }

    if (params.codeChallenge && this.supportsPkce) {
      url.searchParams.set('code_challenge', params.codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
    }

    return url.toString();
  }
}

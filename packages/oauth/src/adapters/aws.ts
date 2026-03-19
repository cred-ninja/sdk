/**
 * AWS IAM Identity Center (SSO) OIDC Adapter
 *
 * Quirks handled:
 * - Uses IAM Identity Center OIDC endpoints (region-specific)
 * - PKCE required (S256)
 * - Supports refresh tokens
 * - Revocation endpoint: not standardized — null (no-op)
 * - Token URL and auth URL are region-dependent; defaults to us-east-1
 * - Client registration is done separately (device authorization or console)
 */

import { BaseServiceAdapter } from './base.js';

const AWS_OIDC_REGION = 'us-east-1';

export class AwsAdapter extends BaseServiceAdapter {
  readonly slug: string;
  readonly authorizationUrl: string;
  readonly tokenUrl: string;
  // AWS IAM Identity Center doesn't expose a standard revocation endpoint
  readonly revocationUrl: string | null = null;

  readonly scopeSeparator = ' ';
  readonly supportsPkce = true;
  readonly supportsRefresh = true;

  constructor(region: string = AWS_OIDC_REGION, slug: string = 'aws') {
    super();
    this.slug = slug;
    this.authorizationUrl = `https://oidc.${region}.amazonaws.com/authorize`;
    this.tokenUrl = `https://oidc.${region}.amazonaws.com/token`;
  }
}

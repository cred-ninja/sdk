/**
 * @credninja/oauth — Type Definitions
 */

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type: string;
  /** Salesforce-specific: base URL for API calls */
  instance_url?: string;
}

export interface RefreshResponse {
  access_token: string;
  expires_in?: number;
  /** Some providers rotate refresh tokens on refresh */
  refresh_token?: string;
}

export interface BuildAuthUrlParams {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
  codeChallenge?: string;
}

export interface ExchangeCodeParams {
  code: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  codeVerifier?: string;
}

export interface RefreshTokenParams {
  refreshToken: string;
  clientId: string;
  clientSecret: string;
}

export interface RevokeTokenParams {
  token: string;
  clientId: string;
  clientSecret: string;
}

export interface OAuthClientOptions {
  adapter: ServiceAdapter;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface GetAuthorizationUrlOptions {
  scopes: string[];
}

export interface GetAuthorizationUrlResult {
  url: string;
  state: string;
  codeVerifier?: string;
}

export interface ExchangeCodeOptions {
  code: string;
  codeVerifier?: string;
}

export interface PKCEPair {
  verifier: string;
  challenge: string;
}

/**
 * ServiceAdapter interface — exactly 4 methods.
 * Each provider adapter handles provider-specific OAuth quirks.
 */
export interface ServiceAdapter {
  readonly slug: string;
  readonly supportsPkce: boolean;
  readonly supportsRefresh: boolean;

  /** Build the authorization URL for redirecting the user to the provider. */
  buildAuthorizationUrl(params: BuildAuthUrlParams): string;

  /** Exchange an authorization code for tokens. */
  exchangeCodeForTokens(params: ExchangeCodeParams): Promise<TokenResponse>;

  /**
   * Refresh an access token using a refresh token.
   * Throws if the provider doesn't support refresh tokens.
   */
  refreshAccessToken(params: RefreshTokenParams): Promise<RefreshResponse>;

  /**
   * Revoke a token at the provider.
   * No-op if the provider doesn't support revocation.
   */
  revokeToken(params: RevokeTokenParams): Promise<void>;
}

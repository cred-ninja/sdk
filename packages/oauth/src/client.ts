/**
 * OAuthClient — Main entry point for OAuth flows.
 *
 * Wraps a ServiceAdapter to provide a clean, high-level API.
 * Handles state generation (cryptographically random) and PKCE automatically.
 */

import { randomBytes } from 'crypto';
import { generatePKCE } from './pkce.js';
import type {
  OAuthClientOptions,
  GetAuthorizationUrlOptions,
  GetAuthorizationUrlResult,
  ExchangeCodeOptions,
  TokenResponse,
  RefreshResponse,
  ServiceAdapter,
} from './types.js';

export class OAuthClient {
  private readonly adapter: ServiceAdapter;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly redirectUri: string;

  constructor(options: OAuthClientOptions) {
    this.adapter = options.adapter;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.redirectUri = options.redirectUri;
  }

  /**
   * Build an authorization URL to redirect the user to.
   *
   * Automatically:
   * - Generates a cryptographically random `state` parameter (CSRF protection)
   * - Generates PKCE verifier + challenge when the adapter supports it
   *
   * Store `state` and `codeVerifier` (if present) in session for use in the callback.
   */
  async getAuthorizationUrl(options: GetAuthorizationUrlOptions): Promise<GetAuthorizationUrlResult> {
    // Cryptographically random state — never Math.random
    const state = randomBytes(32).toString('hex');

    let codeVerifier: string | undefined;
    let codeChallenge: string | undefined;

    if (this.adapter.supportsPkce) {
      const pkce = generatePKCE();
      codeVerifier = pkce.verifier;
      codeChallenge = pkce.challenge;
    }

    const url = this.adapter.buildAuthorizationUrl({
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      scopes: options.scopes,
      state,
      codeChallenge,
    });

    return {
      url,
      state,
      ...(codeVerifier !== undefined ? { codeVerifier } : {}),
    };
  }

  /**
   * Exchange an authorization code for tokens.
   * Pass the `codeVerifier` from `getAuthorizationUrl` if PKCE was used.
   */
  async exchangeCode(options: ExchangeCodeOptions): Promise<TokenResponse> {
    return this.adapter.exchangeCodeForTokens({
      code: options.code,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      redirectUri: this.redirectUri,
      codeVerifier: options.codeVerifier,
    });
  }

  /**
   * Refresh an access token using a refresh token.
   * Throws if the adapter's provider doesn't support token refresh.
   */
  async refreshToken(refreshToken: string): Promise<RefreshResponse> {
    return this.adapter.refreshAccessToken({
      refreshToken,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
    });
  }

  /**
   * Revoke a token.
   * No-op for providers that don't support revocation (e.g. Notion).
   */
  async revokeToken(token: string): Promise<void> {
    return this.adapter.revokeToken({
      token,
      clientId: this.clientId,
      clientSecret: this.clientSecret,
    });
  }

  /** The underlying adapter (useful for accessing adapter-specific properties) */
  get adapterSlug(): string {
    return this.adapter.slug;
  }
}

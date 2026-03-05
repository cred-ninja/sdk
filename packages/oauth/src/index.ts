/**
 * @credninja/oauth — Standalone OAuth2 middleware toolkit
 *
 * Zero runtime dependencies. Works with any Node 18+ project.
 *
 * @example
 * ```ts
 * import { OAuthClient, GoogleAdapter } from '@credninja/oauth';
 *
 * const client = new OAuthClient({
 *   adapter: new GoogleAdapter(),
 *   clientId: process.env.GOOGLE_CLIENT_ID!,
 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
 *   redirectUri: 'http://localhost:3000/callback',
 * });
 *
 * const { url, state, codeVerifier } = await client.getAuthorizationUrl({
 *   scopes: ['calendar.readonly', 'gmail.readonly'],
 * });
 * ```
 */

// Core client
export { OAuthClient } from './client.js';

// PKCE helpers
export { generatePKCE, generateVerifier, computeChallenge } from './pkce.js';

// Adapters
export { BaseServiceAdapter } from './adapters/base.js';
export { GoogleAdapter } from './adapters/google.js';
export { GitHubAdapter } from './adapters/github.js';
export { SlackAdapter } from './adapters/slack.js';
export { NotionAdapter } from './adapters/notion.js';
export {
  SalesforceAdapter,
  SALESFORCE_PRODUCTION,
  SALESFORCE_SANDBOX,
} from './adapters/salesforce.js';
export { LinearAdapter } from './adapters/linear.js';
export { HubSpotAdapter } from './adapters/hubspot.js';

// Factory
export { createAdapter } from './adapters/index.js';

// Types
export type {
  ServiceAdapter,
  TokenResponse,
  RefreshResponse,
  BuildAuthUrlParams,
  ExchangeCodeParams,
  RefreshTokenParams,
  RevokeTokenParams,
  OAuthClientOptions,
  GetAuthorizationUrlOptions,
  GetAuthorizationUrlResult,
  ExchangeCodeOptions,
  PKCEPair,
} from './types.js';

export type {
  SalesforceTokenResponse,
  BuiltinAdapterSlug,
} from './adapters/index.js';

/**
 * Cred SDK — Type definitions
 */

export interface CredConfig {
  /** Agent token issued by Cred (starts with cred_at_) */
  agentToken: string;
  /** Override the API base URL. Defaults to https://api.cred.ninja */
  baseUrl?: string;
}

export interface DelegationResult {
  accessToken: string;
  tokenType: string;
  expiresIn?: number;
  service: string;
  scopes: string[];
  delegationId: string;
  /** JWS-signed delegation receipt from Cred (if agent provided agentDid) */
  receipt?: string;
}

export interface Connection {
  slug: string;
  scopesGranted: string[];
  consentedAt: string | null;
  appClientId: string | null;
}

export interface DelegateParams {
  service: string;
  userId: string;
  /**
   * Your Cred app's client ID. Agents always know this — it's baked into the
   * agent's deployment config alongside the agent token. User-facing consent
   * flows without a specific app context are a portal concern, not SDK concern.
   */
  appClientId: string;
  scopes?: string[];
  /** Agent's DID (did:key:...). If provided, Cred returns a signed receipt. */
  agentDid?: string;
}

export interface GetConsentUrlParams {
  service: string;
  userId: string;
  appClientId: string;
  scopes: string[];
  redirectUri: string;
}

export interface RevokeParams {
  service: string;
  userId: string;
  appClientId?: string;
}

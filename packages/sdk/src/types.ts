/**
 * Cred SDK — Type definitions
 */

// ── Cloud mode config (existing) ─────────────────────────────────────────────

export interface CredCloudConfig {
  /** Agent token issued by Cred (starts with cred_at_) */
  agentToken: string;
  /** Override the API base URL. Defaults to https://api.cred.ninja */
  baseUrl?: string;
  mode?: never;
}

// ── Local mode config (new) ──────────────────────────────────────────────────

export interface CredLocalVaultConfig {
  /** Passphrase for AES-256-GCM vault encryption */
  passphrase: string;
  /** Path to the vault file (e.g. './cred-vault.db') */
  path: string;
  /** Storage backend: 'sqlite' or 'file'. Defaults to 'file'. */
  storage?: 'sqlite' | 'file';
}

export interface CredProviderConfig {
  clientId: string;
  clientSecret: string;
}

export interface CredLocalConfig {
  mode: 'local';
  vault: CredLocalVaultConfig;
  providers: Record<string, CredProviderConfig>;
}

// ── Union config ─────────────────────────────────────────────────────────────

/**
 * Backwards-compatible: existing `{ agentToken }` usage still works.
 * New local mode: `{ mode: 'local', vault: {...}, providers: {...} }`.
 */
export type CredConfig = CredCloudConfig | CredLocalConfig;

// ── Shared types (unchanged) ─────────────────────────────────────────────────

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
   * Your Cred app's client ID. Required for cloud mode.
   * Ignored in local mode (provider credentials are set in the constructor).
   */
  appClientId?: string;
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

// ── TOFU Agent Identity ─────────────────────────────────────────────────────

/**
 * Parameters for TOFU (Trust-On-First-Use) delegation.
 */
export interface TofuDelegateParams {
  /** Agent fingerprint (SHA-256 of hex-encoded Ed25519 public key) */
  fingerprint: string;
  /** The request payload that was signed */
  payload: Buffer | Uint8Array;
  /** Ed25519 signature over payload */
  signature: Buffer | Uint8Array;
  /** Scopes the agent is requesting */
  requestedScopes?: string[];
}

/**
 * Result of a TOFU delegation request.
 */
export interface TofuDelegationResult {
  agentId: string;
  fingerprint: string;
  status: 'unclaimed' | 'claimed';
  ownerUserId: string | null;
  /** Short-lived signed token for unclaimed agents (30 min) */
  token: string;
  /** ISO string */
  tokenExpiresAt: string;
  grantedScopes: string[];
}

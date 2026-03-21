/**
 * Cred SDK — Type definitions
 */

// ── Cloud mode config (existing) ─────────────────────────────────────────────

export interface CredCloudConfig {
  /** Agent token issued by Cred (starts with cred_at_) */
  agentToken: string;
  /** Your Cred server URL (e.g. https://cred.example.com or http://localhost:3456) */
  baseUrl: string;
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
  /** Require the configured local vault backend to persist audit events. */
  requireAudit?: boolean;
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
  /** Seconds until token expires. Always set — defaults to 900 (15 min). */
  expiresIn: number;
  /** Absolute expiry timestamp. Always set. */
  expiresAt: Date;
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

export interface AuditEntry {
  id: string;
  action: string;
  service: string;
  userId: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface AuditParams {
  userId: string;
  appClientId?: string;
  service?: string;
  limit?: number;
}

// ── Agent scope ceiling & revocation types ──────────────────────────────────

export interface RegisterAgentParams {
  name: string;
  fingerprint: string;
  scopeCeiling?: string[];
  createdBy: string;
}

export interface RevokeAgentParams {
  agentId: string;
}

// ── Rotation types ────────────────────────────────────────────────────────────

export type RotationStrategy = 'dual_active' | 'single_swap' | 'ephemeral' | 'oauth_refresh';

export interface RotateParams {
  /** The connection to rotate (provider/userId format or logical connection ID) */
  connectionId: string;
  /** Rotation strategy. Defaults to 'dual_active'. */
  strategy?: RotationStrategy;
  /** How often to auto-rotate in seconds. Defaults to 86400 (24h). */
  intervalSeconds?: number;
}

export interface ScheduleRotationParams {
  connectionId: string;
  strategy?: RotationStrategy;
  intervalSeconds?: number;
}

export interface RotationStatus {
  id: string;
  connectionId: string;
  strategy: RotationStrategy;
  state: string;
  currentVersionId: string | null;
  pendingVersionId: string | null;
  previousVersionId: string | null;
  lastRotatedAt: Date | null;
  nextRotationAt: Date | null;
  failureCount: number;
  failureAction: string;
}

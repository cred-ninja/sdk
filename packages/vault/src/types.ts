/**
 * Stored credential entry for a provider + user combination.
 */
export interface VaultEntry {
  provider: string;
  userId: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: Date;
  scopes?: string[];
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Input for storing credentials.
 */
export interface StoreInput {
  provider: string;
  userId: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: Date;
  scopes?: string[];
}

export interface PermissionRateLimit {
  maxRequests: number;
  windowMs: number;
}

/**
 * Permission granted to an agent for a given connection.
 */
export interface Permission {
  id: string;
  agentId: string;
  connectionId: string;
  allowedScopes: string[];
  rateLimit?: PermissionRateLimit;
  ttlOverride?: number;
  requiresApproval: boolean;
  delegatable: boolean;
  maxDelegationDepth: number;
  createdAt: Date;
  expiresAt?: Date;
  createdBy: string;
}

/**
 * Minimal OAuth adapter interface that vault uses for auto-refresh.
 * Compatible with @credninja/oauth ServiceAdapter.
 */
export interface RefreshAdapter {
  refreshAccessToken(
    refreshToken: string,
    clientId: string,
    clientSecret: string
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresIn?: number;
    scopes?: string[];
  }>;
}

/**
 * Input for retrieving credentials.
 */
export interface GetInput {
  provider: string;
  userId: string;
  /** Optional: provide to enable auto-refresh of expired tokens */
  adapter?: RefreshAdapter;
  /** Required when adapter is provided */
  clientId?: string;
  /** Required when adapter is provided */
  clientSecret?: string;
}

/**
 * Input for deleting credentials.
 */
export interface DeleteInput {
  provider: string;
  userId: string;
}

/**
 * Input for listing all credentials for a user.
 */
export interface ListInput {
  userId: string;
}

/**
 * CredVault constructor options.
 */
export interface VaultOptions {
  passphrase: string;
  storage: 'sqlite' | 'file';
  path: string;
}

/**
 * Raw row stored in the backend (all token fields are ciphertext).
 */
export interface StoredRow {
  provider: string;
  userId: string;
  /** Ciphertext of accessToken */
  accessTokenEnc: string;
  /** IV for accessToken (hex) */
  accessTokenIv: string;
  /** Auth tag for accessToken (hex) */
  accessTokenTag: string;
  /** Ciphertext of refreshToken (optional) */
  refreshTokenEnc?: string;
  refreshTokenIv?: string;
  refreshTokenTag?: string;
  expiresAt?: string; // ISO string
  scopes?: string; // JSON array string
  createdAt: string; // ISO string
  updatedAt: string; // ISO string
}

/**
 * Raw DB row for vault_permissions.
 */
export interface PermissionRow {
  id: string;
  agent_id: string;
  connection_id: string;
  allowed_scopes: string;
  rate_limit_max: number | null;
  rate_limit_window_ms: number | null;
  ttl_override: number | null;
  requires_approval: number;
  delegatable: number;
  max_delegation_depth: number;
  expires_at: string | null;
  created_at: string;
  created_by: string;
}

/**
 * Encrypted payload returned by encrypt().
 */
export interface EncryptedPayload {
  encrypted: string;
  iv: string;
  tag: string;
}

// ── Agent records ───────────────────────────────────────────────────────────

export type AgentStatus = 'active' | 'suspended' | 'revoked';

export interface AgentRecord {
  id: string;
  did?: string;
  fingerprint: string;
  name: string;
  scopeCeiling: string[];
  status: AgentStatus;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  lastSeenAt?: string;
  revokedAt?: string;
}

export interface AgentRow {
  id: string;
  did: string | null;
  fingerprint: string;
  name: string;
  scopeCeiling: string;
  status: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  lastSeenAt: string | null;
  revokedAt: string | null;
}

// ── Rotation records ─────────────────────────────────────────────────────────

export type RotationStrategy = 'dual_active' | 'single_swap' | 'ephemeral' | 'oauth_refresh';
export type RotationState = 'idle' | 'pending' | 'testing' | 'promoting' | 'failed' | 'rolling_back';
export type RotationFailureAction = 'retry_backoff' | 'disable_integration' | 'notify_human';

export interface Rotation {
  /** rot_ prefixed unique ID */
  id: string;
  /** FK to vault_credentials or a logical connection ID */
  connectionId: string;
  strategy: RotationStrategy;
  /** How often to auto-rotate (seconds) */
  intervalSeconds: number;
  state: RotationState;
  /** Access token enc reference for the currently-active token */
  currentVersionId: string | null;
  /** Access token enc reference for the pending (new) token — dual_active window */
  pendingVersionId: string | null;
  /** Access token enc reference for the previous (retiring) token */
  previousVersionId: string | null;
  lastRotatedAt: Date | null;
  nextRotationAt: Date | null;
  failureCount: number;
  failureAction: RotationFailureAction;
  createdAt: Date;
  updatedAt: Date;
}

/** Raw DB row for vault_rotations */
export interface RotationRow {
  id: string;
  connection_id: string;
  strategy: string;
  interval_seconds: number;
  state: string;
  current_version_id: string | null;
  pending_version_id: string | null;
  previous_version_id: string | null;
  last_rotated_at: string | null;
  next_rotation_at: string | null;
  failure_count: number;
  failure_action: string;
  created_at: string;
  updated_at: string;
}

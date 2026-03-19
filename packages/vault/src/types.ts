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

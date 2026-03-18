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

// ── Agent Identity (TOFU) ───────────────────────────────────────────────────

/**
 * Agent identity row as returned from the vault (deserialized).
 */
export interface AgentIdentityRow {
  agentId: string;
  /** Hex-encoded 32-byte Ed25519 public key (NOT encrypted — public keys are not secret) */
  publicKey: string;
  /** SHA-256 of publicKey hex, hex-encoded (used as lookup key) */
  fingerprint: string;
  status: 'unclaimed' | 'claimed';
  ownerUserId: string | null;
  initialScopes: string[];
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Input for registering a new agent identity.
 */
export interface RegisterAgentInput {
  /** Raw 32-byte Ed25519 public key */
  publicKey: Uint8Array;
  initialScopes?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Input for claiming an agent identity.
 */
export interface ClaimAgentInput {
  fingerprint: string;
  ownerUserId: string;
}

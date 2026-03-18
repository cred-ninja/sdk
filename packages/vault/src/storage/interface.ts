import type { StoredRow } from '../types.js';

/**
 * Raw agent identity row as stored in backends (all fields are primitives/strings).
 */
export interface AgentIdentityStoredRow {
  agentId: string;
  /** Hex-encoded Ed25519 public key */
  publicKey: string;
  /** Hex-encoded SHA-256 fingerprint */
  fingerprint: string;
  /** "unclaimed" | "claimed" */
  status: string;
  ownerUserId: string | null;
  /** JSON string */
  initialScopes: string;
  /** JSON string */
  metadata: string;
  /** ISO string */
  createdAt: string;
  /** ISO string */
  updatedAt: string;
}

/**
 * StorageBackend — the interface that all vault storage backends must implement.
 *
 * All token fields in StoredRow are ciphertext — the backend never sees plaintext tokens.
 * Implementors can target SQLite, files, Redis, PostgreSQL, etc.
 */
export interface StorageBackend {
  /**
   * Initialize the backend (create tables, directories, etc.).
   * Must be idempotent — safe to call multiple times.
   */
  init(): void | Promise<void>;

  /**
   * Store (insert or update) a credential row keyed by provider + userId.
   */
  store(row: StoredRow): void | Promise<void>;

  /**
   * Retrieve a credential row by provider + userId.
   * Returns null if not found — never throws for missing entries.
   */
  get(provider: string, userId: string): StoredRow | null | Promise<StoredRow | null>;

  /**
   * Delete a credential row by provider + userId.
   * Must be idempotent — safe to call even if entry doesn't exist.
   */
  delete(provider: string, userId: string): void | Promise<void>;

  /**
   * List all credential rows for a given userId across all providers.
   */
  list(userId: string): StoredRow[] | Promise<StoredRow[]>;

  // ── Agent Identity (TOFU) ──────────────────────────────────────────────────

  /**
   * Register a new agent identity.
   */
  registerAgent(row: AgentIdentityStoredRow): void | Promise<void>;

  /**
   * Retrieve an agent identity by fingerprint.
   * Returns null if not found.
   */
  getAgent(fingerprint: string): AgentIdentityStoredRow | null | Promise<AgentIdentityStoredRow | null>;

  /**
   * Claim an agent identity — sets ownerUserId and updatedAt.
   */
  claimAgent(fingerprint: string, ownerUserId: string, updatedAt: string): void | Promise<void>;

  /**
   * List all agent identities owned by a user.
   */
  listAgents(ownerUserId: string): AgentIdentityStoredRow[] | Promise<AgentIdentityStoredRow[]>;
}

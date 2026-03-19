import type { StoredRow, AgentRow } from '../types.js';

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

  // ── Agent record methods (optional — not all backends need these) ─────────

  storeAgent?(row: AgentRow): void | Promise<void>;
  getAgent?(id: string): AgentRow | null | Promise<AgentRow | null>;
  getAgentByFingerprint?(fingerprint: string): AgentRow | null | Promise<AgentRow | null>;
  updateAgentStatus?(id: string, status: string, revokedAt?: string): void | Promise<void>;
}

import type { StoredRow, AgentRow, PermissionRow, Rotation, RotationRow } from '../types.js';
import type { AuditEvent, AuditFilter } from '../audit.js';

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
   * Retrieve a credential row for vault-managed refresh flows.
   * Unlike get(), this may return expired rows so higher layers can refresh them.
   */
  getForRefresh?(provider: string, userId: string): StoredRow | null | Promise<StoredRow | null>;

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
  getAgentByDid?(did: string): AgentRow | null | Promise<AgentRow | null>;
  getAgentByFingerprint?(fingerprint: string): AgentRow | null | Promise<AgentRow | null>;
  updateAgentStatus?(id: string, status: string, revokedAt?: string): void | Promise<void>;

  // ── Permission methods (optional — not all backends need these) ───────────

  storePermission?(row: PermissionRow): void | Promise<void>;
  getPermission?(agentId: string, connectionId: string): PermissionRow | null | Promise<PermissionRow | null>;
  listPermissions?(agentId: string): PermissionRow[] | Promise<PermissionRow[]>;
  revokePermission?(permissionId: string): void | Promise<void>;
  checkPermissionRateLimit?(
    permissionId: string,
    maxRequests: number,
    windowMs: number,
    now?: Date,
  ): boolean | Promise<boolean>;

  // ── Audit methods (optional — not all backends need these) ─────────────────

  writeAuditEvent?(event: AuditEvent): void | Promise<void>;
  queryAuditEvents?(filter: AuditFilter): AuditEvent[] | Promise<AuditEvent[]>;

  // ── Rotation methods (optional — not all backends need these) ───────────────

  storeRotation?(row: RotationRow): void | Promise<void>;
  getRotation?(id: string): Rotation | null | Promise<Rotation | null>;
  getRotationByConnectionId?(connectionId: string): Rotation | null | Promise<Rotation | null>;
  updateRotation?(id: string, updates: Partial<RotationRow>): void | Promise<void>;
  claimDueRotation?(id: string, now: Date, updates: Partial<RotationRow>): Rotation | null | Promise<Rotation | null>;
  listDueRotations?(now: Date): Rotation[] | Promise<Rotation[]>;
  listRotations?(): Rotation[] | Promise<Rotation[]>;
}

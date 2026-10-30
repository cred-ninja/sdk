import type { StoredRow, AgentRow, PermissionRow, PermissionRowUpdate, Rotation, RotationRow } from '../types.js';
import type { AuditEvent, AuditFilter, AuditChainVerification, AuditChainHead } from '../audit.js';
import type { ConsentRecord, RecordConsentInput } from '../consent.js';
import type {
  DelegationRecord,
  DelegationRevocationOptions,
  DelegationRevocationSeed,
  RecordDelegationInput,
  RevokedDelegation,
} from '../delegation-revocation.js';

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
  /**
   * Atomically apply a partial update to a single permission row, keyed
   * strictly by `id` (never by agent_id/connection_id). Must be a single
   * UPDATE statement, not a read-merge-write, so two concurrent partial
   * updates to distinct fields don't lose one write to the other. Throws
   * (does not silently create) when `id` doesn't exist.
   */
  updatePermission?(id: string, updates: PermissionRowUpdate): PermissionRow | Promise<PermissionRow>;
  /**
   * All permission rows on one connection, any agent (Cred Link). Returns
   * an empty list when there are none; never throws for a missing row.
   */
  listPermissionsForConnection?(connectionId: string): PermissionRow[] | Promise<PermissionRow[]>;
  /**
   * Cred Link narrowing: set every permission row on `connectionId` to
   * allowed_scopes ∩ `scopes`, comparing in canonical scope form
   * (`intersectScopes` from @credninja/protocol), atomically in one
   * transaction. Rows whose scope set changes are rewritten in canonical
   * form with updated_at bumped; the others are left untouched. Returns the
   * rows that changed, as stored after the write. Can only narrow, never
   * widen. A row whose allowed_scopes cannot be parsed is narrowed to [].
   */
  intersectPermissionsForConnection?(connectionId: string, scopes: readonly string[]): PermissionRow[] | Promise<PermissionRow[]>;
  checkPermissionRateLimit?(
    permissionId: string,
    maxRequests: number,
    windowMs: number,
    now?: Date,
  ): boolean | Promise<boolean>;

  // ── Audit methods (optional — not all backends need these) ─────────────────

  writeAuditEvent?(event: AuditEvent): void | Promise<void>;
  /** Write several events at once, in one transaction where the backend can. */
  writeAuditEvents?(events: readonly AuditEvent[]): void | Promise<void>;
  queryAuditEvents?(filter: AuditFilter): AuditEvent[] | Promise<AuditEvent[]>;
  /** Key for the tamper-evident audit chain (set by CredVault.init()). */
  setAuditChainKey?(key: Buffer): void;
  verifyAuditChain?(): AuditChainVerification;
  auditChainHead?(): AuditChainHead | null;

  // ── Delegation methods (optional; CredVault falls back to process memory) ─

  /**
   * Record an issued delegation. Must refuse, with DelegationRevokedError,
   * a record whose parent is revoked, atomically with the insert. An id that
   * already exists is kept as first written.
   */
  storeDelegation?(input: RecordDelegationInput, now: string): DelegationRecord | Promise<DelegationRecord>;
  /** Store a consent record once; an id that already exists is left as first written. */
  storeConsent?(input: RecordConsentInput, now: string): ConsentRecord | Promise<ConsentRecord>;
  getConsent?(id: string): ConsentRecord | null | Promise<ConsentRecord | null>;
  getDelegation?(id: string): DelegationRecord | null | Promise<DelegationRecord | null>;
  /**
   * Revoke the seeds and all their descendants, atomically where the
   * backend can. Returns only the delegations this call revoked.
   */
  revokeDelegationTree?(
    seed: DelegationRevocationSeed,
    revokedAt: string,
    options?: DelegationRevocationOptions,
  ): { revoked: RevokedDelegation[]; truncated: boolean } | Promise<{ revoked: RevokedDelegation[]; truncated: boolean }>;

  // ── Rotation methods (optional — not all backends need these) ───────────────

  storeRotation?(row: RotationRow): void | Promise<void>;
  getRotation?(id: string): Rotation | null | Promise<Rotation | null>;
  getRotationByConnectionId?(connectionId: string): Rotation | null | Promise<Rotation | null>;
  updateRotation?(id: string, updates: Partial<RotationRow>): void | Promise<void>;
  claimDueRotation?(id: string, now: Date, updates: Partial<RotationRow>): Rotation | null | Promise<Rotation | null>;
  listDueRotations?(now: Date): Rotation[] | Promise<Rotation[]>;
  listRotations?(): Rotation[] | Promise<Rotation[]>;
}

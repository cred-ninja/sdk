import fs from 'fs';
import crypto from 'crypto';
import { performance } from 'perf_hooks';
import { generateSalt, encryptWithKey, decryptWithKey, deriveKey } from './crypto.js';
import { SQLiteBackend } from './storage/sqlite.js';
import { FileBackend } from './storage/file.js';
import type { StorageBackend } from './storage/interface.js';
import type {
  VaultOptions,
  StoreInput,
  GetInput,
  DeleteInput,
  ListInput,
  VaultEntry,
  StoredRow,
  EncryptedPayload,
  AgentRecord,
  AgentRow,
  Permission,
  UpdatePermissionInput,
  Rotation,
  RotationStrategy,
} from './types.js';
import type { AuditEvent, AuditFilter, AuditChainHead, AuditChainVerification } from './audit.js';
import { RotationEngine } from './rotation.js';
import {
  MemoryDelegationStore,
  type DelegationRecord,
  type DelegationRevocationOptions,
  type DelegationRevocationResult,
  type DelegationRevocationSeed,
  type RecordDelegationInput,
} from './delegation-revocation.js';
import { MemoryConsentStore } from './consent.js';
import type { ConsentRecord, RecordConsentInput } from './consent.js';
import { PermissionStore, type CreatePermissionInput } from './permissions.js';
import { isReservedLinkVaultUserId, ReservedVaultUserIdError } from './link/vault-ids.js';
import { LINK_VAULT_ACCESS, type LinkVaultAccess } from './link/vault-access.js';
import type { LinkPermissionPort } from '@credninja/protocol';

/**
 * CredVault — local-first encrypted token vault.
 *
 * Tokens are encrypted with AES-256-GCM using a key derived from your passphrase
 * via PBKDF2-SHA256 (100,000 iterations). The passphrase is never stored.
 *
 * Storage backends:
 *   - 'sqlite': uses better-sqlite3 for production use
 *   - 'file':   encrypted JSON file, zero additional deps (ideal for CLI tools)
 *
 * User ids starting with `link:` or `link-staged:` are reserved for Cred
 * Link. Every public method that takes a userId (store, get, getStored,
 * delete, list, getRotationByConnection) throws ReservedVaultUserIdError
 * for them; only this package's VaultLinkSecretStore holds the capability
 * to reach those entries.
 */
/**
 * Every CredVault the constructor has built. Lets package-internal code tell
 * a genuine instance from a Proxy or look-alike (a Proxy around a real vault
 * still passes instanceof, but it is a different object and is not in here).
 * Not exported from the package entry point.
 */
const genuineVaults = new WeakSet<object>();

/** True only for objects built by the CredVault constructor (subclasses included), never a Proxy. */
export function isGenuineCredVault(value: unknown): value is CredVault {
  return typeof value === 'object' && value !== null && value instanceof CredVault && genuineVaults.has(value);
}

export class CredVault {
  private readonly backend: StorageBackend;
  // Passphrase held only in this field — never serialized or logged
  private readonly passphrase: string;
  private readonly saltPath: string;
  private readonly checkPath: string;
  private derivedKey: Buffer | null = null;
  private initPromise: Promise<void> | null = null;
  private rotationEngine: RotationEngine | null = null;
  private permissionStore: PermissionStore | null = null;
  private memoryDelegations: MemoryDelegationStore | null = null;
  private memoryConsents: MemoryConsentStore | null = null;

  constructor(options: VaultOptions) {
    genuineVaults.add(this);
    this.passphrase = options.passphrase;
    // Salt stored adjacent to the vault data file
    this.saltPath = options.path + '.salt';
    this.checkPath = options.path + '.check';

    if (options.storage === 'sqlite') {
      this.backend = new SQLiteBackend(options.path);
    } else if (options.storage === 'file') {
      this.backend = new FileBackend(options.path);
    } else {
      throw new Error(`Unknown storage backend: ${String(options.storage)}`);
    }
  }

  /**
   * Initialize the vault. Can be called explicitly, or will be called
   * automatically on first operation (lazy init).
   * Generates or loads the vault salt, then derives the encryption key.
   *
   * The salt is stored in an adjacent `.salt` file. It is NOT secret —
   * only the passphrase needs to be kept private.
   */
  async init(): Promise<void> {
    await this.backend.init();
    const { salt, created } = this.loadOrCreateSalt();
    const derivedKey = deriveKey(this.passphrase, salt);
    this.checkPassphrase(derivedKey, created);
    this.derivedKey = derivedKey;
    // The audit chain key is derived from the passphrase-derived key and is
    // never stored, so a copy of the database alone cannot forge the chain.
    this.backend.setAuditChainKey?.(crypto.createHmac('sha256', this.derivedKey).update('cred:audit-chain:v1').digest());
  }

  /**
   * Lazy initialization — ensures init() has been called exactly once.
   */
  private async ensureInit(): Promise<void> {
    if (this.derivedKey) return;
    if (!this.initPromise) {
      this.initPromise = this.init();
    }
    await this.initPromise;
  }

  /**
   * Load the salt, or create it. Two processes creating the same vault at
   * once converge on one salt: only the first write lands, and the other
   * reads it.
   */
  private loadOrCreateSalt(): { salt: Buffer; created: boolean } {
    if (!fs.existsSync(this.saltPath)) {
      const salt = generateSalt();
      if (writeFileIfAbsent(this.saltPath, salt.toString('hex'))) return { salt, created: true };
    }
    const hex = fs.readFileSync(this.saltPath, 'utf8').trim();
    return { salt: Buffer.from(hex, 'hex'), created: false };
  }

  /**
   * Refuse a passphrase other than the one this vault was created with,
   * before anything is read or written: a wrong one would decrypt nothing
   * and extend the audit chain under the wrong key. A new vault (its salt was
   * just created) or one created before the check existed gets one now.
   */
  private checkPassphrase(derivedKey: Buffer, saltCreated: boolean): void {
    const expected = crypto.createHmac('sha256', derivedKey).update('cred:passphrase-check:v1').digest();
    if (saltCreated) {
      // A new salt is a new vault: any check value left beside it is stale.
      replaceFile(this.checkPath, expected.toString('hex'));
      return;
    }
    if (writeFileIfAbsent(this.checkPath, expected.toString('hex'))) return;
    const stored = fs.readFileSync(this.checkPath, 'utf8').trim();
    if (!/^[0-9a-f]{64}$/.test(stored)) {
      throw new Error(`Vault passphrase check value at ${this.checkPath} is malformed`);
    }
    if (!crypto.timingSafeEqual(Buffer.from(stored, 'hex'), expected)) {
      throw new Error(
        `Vault passphrase does not match the passphrase this vault was created with (check value in ${this.checkPath}). `
        + 'If that file was written by a start with a mistaken passphrase, remove it and start again with the correct one.',
      );
    }
  }

  private ensureKey(): Buffer {
    if (!this.derivedKey) {
      throw new Error('CredVault not initialized — call await vault.init() first');
    }
    return this.derivedKey;
  }

  private async ensureReady(): Promise<Buffer> {
    await this.ensureInit();
    return this.ensureKey();
  }

  /**
   * Store credentials for a provider + user combination.
   * Access tokens and refresh tokens are AES-256-GCM encrypted before storage.
   * Neither the passphrase nor any plaintext token is ever written to disk.
   */
  async store(input: StoreInput, access?: LinkVaultAccess): Promise<void> {
    this.assertUserIdAllowed('store', input.userId, access);
    await this.writeEntry(input);
  }

  /**
   * Refuses reserved Cred Link user ids (`link:`, `link-staged:`) unless the
   * caller holds the package-internal Link capability. Every public method
   * that takes a userId calls this first.
   */
  private assertUserIdAllowed(method: string, userId: string, access: LinkVaultAccess | undefined): void {
    if (isReservedLinkVaultUserId(userId) && access !== LINK_VAULT_ACCESS) {
      throw new ReservedVaultUserIdError(method);
    }
  }

  private async writeEntry(input: StoreInput): Promise<void> {
    const key = await this.ensureReady();
    const now = new Date().toISOString();

    const accessEnc = encryptWithKey(input.accessToken, key);

    const row: StoredRow = {
      provider: input.provider,
      userId: input.userId,
      accessTokenEnc: accessEnc.encrypted,
      accessTokenIv: accessEnc.iv,
      accessTokenTag: accessEnc.tag,
      expiresAt: input.expiresAt?.toISOString(),
      scopes: input.scopes ? JSON.stringify(input.scopes) : undefined,
      createdAt: now,
      updatedAt: now,
    };

    if (input.refreshToken) {
      const refreshEnc = encryptWithKey(input.refreshToken, key);
      row.refreshTokenEnc = refreshEnc.encrypted;
      row.refreshTokenIv = refreshEnc.iv;
      row.refreshTokenTag = refreshEnc.tag;
    }

    await this.backend.store(row);
  }

  /**
   * Retrieve credentials for a provider + user.
   *
   * If the stored token is expired and an adapter + client credentials are provided,
   * automatically refreshes the token and persists the new one before returning.
   *
   * Returns null if no entry is found for this provider + userId combination.
   */
  async get(input: GetInput, access?: LinkVaultAccess): Promise<VaultEntry | null> {
    this.assertUserIdAllowed('get', input.userId, access);
    await this.ensureInit();
    let row = await this.backend.get(input.provider, input.userId);
    if (!row && input.adapter && input.clientId && input.clientSecret && this.backend.getForRefresh) {
      row = await this.backend.getForRefresh(input.provider, input.userId);
    }
    if (!row) return null;

    const key = this.ensureKey();

    const accessToken = this.decryptField(
      { encrypted: row.accessTokenEnc, iv: row.accessTokenIv, tag: row.accessTokenTag },
      key
    );

    let refreshToken: string | undefined;
    if (row.refreshTokenEnc && row.refreshTokenIv && row.refreshTokenTag) {
      refreshToken = this.decryptField(
        { encrypted: row.refreshTokenEnc, iv: row.refreshTokenIv, tag: row.refreshTokenTag },
        key
      );
    }

    const expiresAt = row.expiresAt ? new Date(row.expiresAt) : undefined;
    const scopes: string[] | undefined = row.scopes
      ? (JSON.parse(row.scopes) as string[])
      : undefined;

    // Auto-refresh if expired and adapter + credentials provided
    const isExpired = expiresAt !== undefined && expiresAt <= new Date();
    if (isExpired && input.adapter && input.clientId && input.clientSecret && refreshToken) {
      try {
        const refreshed = await input.adapter.refreshAccessToken(
          refreshToken,
          input.clientId,
          input.clientSecret
        );

        const newExpiresAt = refreshed.expiresIn
          ? new Date(Date.now() + refreshed.expiresIn * 1000)
          : undefined;

        const newRefreshToken = refreshed.refreshToken ?? refreshToken;
        const newScopes = refreshed.scopes ?? scopes;

        // Persist refreshed tokens (encrypted)
        await this.writeEntry({
          provider: input.provider,
          userId: input.userId,
          accessToken: refreshed.accessToken,
          refreshToken: newRefreshToken,
          expiresAt: newExpiresAt,
          scopes: newScopes,
        });

        return {
          provider: input.provider,
          userId: input.userId,
          accessToken: refreshed.accessToken,
          refreshToken: newRefreshToken,
          expiresAt: newExpiresAt,
          scopes: newScopes,
          createdAt: new Date(row.createdAt),
          updatedAt: new Date(),
        };
      } catch {
        // Refresh failed — token is expired and unrecoverable
        return null;
      }
    }

    // If token is expired and no refresh was attempted, return null
    if (isExpired) {
      return null;
    }

    return {
      provider: input.provider,
      userId: input.userId,
      accessToken,
      refreshToken,
      expiresAt,
      scopes,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    };
  }

  /**
   * Retrieve the stored, decrypted entry for a provider + user exactly as
   * it is at rest: expired entries are returned too, and no refresh is ever
   * attempted. Returns null when no entry exists.
   *
   * Use this when the caller manages refresh itself (Cred Link's token
   * holder) or needs an expired entry's refresh token, for example to revoke
   * it at the provider. get() keeps its existing behavior.
   *
   * Reads through the backend's getForRefresh() (both built-in backends have
   * it). A custom backend without getForRefresh() falls back to get(), which
   * may hide expired rows.
   */
  async getStored(input: Pick<GetInput, 'provider' | 'userId'>, access?: LinkVaultAccess): Promise<VaultEntry | null> {
    this.assertUserIdAllowed('getStored', input.userId, access);
    await this.ensureInit();
    const row = this.backend.getForRefresh
      ? await this.backend.getForRefresh(input.provider, input.userId)
      : await this.backend.get(input.provider, input.userId);
    if (!row) return null;
    const key = this.ensureKey();

    let refreshToken: string | undefined;
    if (row.refreshTokenEnc && row.refreshTokenIv && row.refreshTokenTag) {
      refreshToken = this.decryptField(
        { encrypted: row.refreshTokenEnc, iv: row.refreshTokenIv, tag: row.refreshTokenTag },
        key
      );
    }

    return {
      provider: row.provider,
      userId: row.userId,
      accessToken: this.decryptField(
        { encrypted: row.accessTokenEnc, iv: row.accessTokenIv, tag: row.accessTokenTag },
        key
      ),
      refreshToken,
      expiresAt: row.expiresAt ? new Date(row.expiresAt) : undefined,
      scopes: row.scopes ? (JSON.parse(row.scopes) as string[]) : undefined,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    };
  }

  /**
   * Delete credentials for a provider + user.
   * Idempotent — safe to call even if no entry exists.
   */
  async delete(input: DeleteInput, access?: LinkVaultAccess): Promise<void> {
    this.assertUserIdAllowed('delete', input.userId, access);
    await this.ensureInit();
    await this.backend.delete(input.provider, input.userId);
  }

  /**
   * List all connections for a userId across all providers.
   * Returns fully decrypted entries.
   */
  async list(input: ListInput, access?: LinkVaultAccess): Promise<VaultEntry[]> {
    this.assertUserIdAllowed('list', input.userId, access);
    await this.ensureInit();
    const rows = await this.backend.list(input.userId);
    const key = this.ensureKey();

    return rows.map((row) => {
      const accessToken = this.decryptField(
        { encrypted: row.accessTokenEnc, iv: row.accessTokenIv, tag: row.accessTokenTag },
        key
      );

      let refreshToken: string | undefined;
      if (row.refreshTokenEnc && row.refreshTokenIv && row.refreshTokenTag) {
        refreshToken = this.decryptField(
          { encrypted: row.refreshTokenEnc, iv: row.refreshTokenIv, tag: row.refreshTokenTag },
          key
        );
      }

      return {
        provider: row.provider,
        userId: row.userId,
        accessToken,
        refreshToken,
        expiresAt: row.expiresAt ? new Date(row.expiresAt) : undefined,
        scopes: row.scopes ? (JSON.parse(row.scopes) as string[]) : undefined,
        createdAt: new Date(row.createdAt),
        updatedAt: new Date(row.updatedAt),
      };
    });
  }

  // ── Agent record methods ──────────────────────────────────────────────────

  async registerAgent(record: AgentRecord): Promise<void> {
    await this.ensureInit();
    if (!this.backend.storeAgent) {
      throw new Error('Agent storage not supported by this backend');
    }
    const row: AgentRow = {
      id: record.id,
      did: record.did ?? null,
      fingerprint: record.fingerprint,
      name: record.name,
      scopeCeiling: JSON.stringify(record.scopeCeiling),
      status: record.status,
      createdBy: record.createdBy,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      lastSeenAt: record.lastSeenAt ?? null,
      revokedAt: record.revokedAt ?? null,
    };
    await this.backend.storeAgent(row);
  }

  async getAgentByDid(did: string): Promise<AgentRecord | null> {
    await this.ensureInit();
    if (!this.backend.getAgentByDid) {
      return null;
    }
    const row = await this.backend.getAgentByDid(did);
    if (!row) return null;
    return this.agentRowToRecord(row);
  }

  async getAgentByFingerprint(fingerprint: string): Promise<AgentRecord | null> {
    await this.ensureInit();
    if (!this.backend.getAgentByFingerprint) {
      return null;
    }
    const row = await this.backend.getAgentByFingerprint(fingerprint);
    if (!row) return null;
    return this.agentRowToRecord(row);
  }

  async getAgent(id: string): Promise<AgentRecord | null> {
    await this.ensureInit();
    if (!this.backend.getAgent) {
      return null;
    }
    const row = await this.backend.getAgent(id);
    if (!row) return null;
    return this.agentRowToRecord(row);
  }

  async revokeAgent(agentId: string): Promise<void> {
    await this.ensureInit();
    if (!this.backend.updateAgentStatus) {
      throw new Error('Agent storage not supported by this backend');
    }
    const now = new Date().toISOString();
    await this.backend.updateAgentStatus(agentId, 'revoked', now);
  }

  /**
   * Revoke an agent and cascade: every delegation issued to the agent's DID
   * and every delegation derived from those is revoked too. The agent is
   * marked revoked first, so a delegation recorded for it after this point
   * is refused (see recordDelegation()). An agent without a DID has no
   * delegations to reach and returns an empty result.
   */
  async revokeAgentCascade(agentId: string, options: DelegationRevocationOptions = {}): Promise<DelegationRevocationResult> {
    const started = performance.now();
    await this.ensureInit();
    const agent = await this.getAgent(agentId);
    await this.revokeAgent(agentId);
    if (!agent?.did) {
      return { revoked: [], revokedIds: [], count: 0, elapsedMs: performance.now() - started, truncated: false };
    }
    return this.revokeDelegationsSince(started, { agentDid: agent.did }, options);
  }

  // ── Delegation records ───────────────────────────────────────────────────

  /**
   * Backends with a delegation table persist records; the others (the file
   * backend) keep them in process memory, alongside the in-memory brokered
   * handles they describe.
   */
  private delegationStore(): Required<Pick<StorageBackend, 'storeDelegation' | 'getDelegation' | 'revokeDelegationTree'>> {
    const backend = this.backend;
    if (backend.storeDelegation && backend.getDelegation && backend.revokeDelegationTree) {
      return {
        storeDelegation: backend.storeDelegation.bind(backend),
        getDelegation: backend.getDelegation.bind(backend),
        revokeDelegationTree: backend.revokeDelegationTree.bind(backend),
      };
    }
    this.memoryDelegations ??= new MemoryDelegationStore();
    const memory = this.memoryDelegations;
    return {
      storeDelegation: memory.storeDelegation.bind(memory),
      getDelegation: memory.getDelegation.bind(memory),
      revokeDelegationTree: memory.revokeDelegationTree.bind(memory),
    };
  }

  /**
   * Record an issued delegation and its parent linkage. Throws
   * DelegationRevokedError when the parent delegation (or, on SQLite, the
   * agent) is already revoked; the caller must not hand the delegation out.
   */
  async recordDelegation(input: RecordDelegationInput): Promise<DelegationRecord> {
    await this.ensureInit();
    return this.delegationStore().storeDelegation(input, new Date().toISOString());
  }

  /** Record a consent event once (draft Section 8.2); a replayed id keeps the first record. */
  async recordConsent(input: RecordConsentInput): Promise<ConsentRecord> {
    await this.ensureInit();
    const now = new Date().toISOString();
    if (this.backend.storeConsent) return this.backend.storeConsent(input, now);
    this.memoryConsents ??= new MemoryConsentStore();
    return this.memoryConsents.storeConsent(input, now);
  }

  async getConsent(id: string): Promise<ConsentRecord | null> {
    await this.ensureInit();
    if (this.backend.getConsent) return this.backend.getConsent(id);
    return this.memoryConsents?.getConsent(id) ?? null;
  }

  async getDelegation(id: string): Promise<DelegationRecord | null> {
    await this.ensureInit();
    return this.delegationStore().getDelegation(id);
  }

  /**
   * Revoke delegations and, transitively, every delegation derived from
   * them. Idempotent: delegations already revoked are not counted again.
   */
  async revokeDelegations(seed: DelegationRevocationSeed, options: DelegationRevocationOptions = {}): Promise<DelegationRevocationResult> {
    const started = performance.now();
    await this.ensureInit();
    return this.revokeDelegationsSince(started, seed, options);
  }

  private async revokeDelegationsSince(
    started: number,
    seed: DelegationRevocationSeed,
    options: DelegationRevocationOptions,
  ): Promise<DelegationRevocationResult> {
    const { revoked, truncated } = await this.delegationStore().revokeDelegationTree(seed, new Date().toISOString(), options);
    return {
      revoked,
      revokedIds: revoked.map((r) => r.id),
      count: revoked.length,
      elapsedMs: performance.now() - started,
      truncated,
    };
  }

  // ── Permission methods ───────────────────────────────────────────────────

  async createPermission(permission: CreatePermissionInput): Promise<Permission> {
    await this.ensureInit();
    return this.getPermissionStore().create(permission);
  }

  async getPermission(agentId: string, connectionId: string): Promise<Permission | null> {
    await this.ensureInit();
    return this.getPermissionStore().get(agentId, connectionId);
  }

  async listPermissions(agentId: string): Promise<Permission[]> {
    await this.ensureInit();
    return this.getPermissionStore().list(agentId);
  }

  async revokePermission(permissionId: string): Promise<void> {
    await this.ensureInit();
    await this.getPermissionStore().revoke(permissionId);
  }

  /**
   * Atomically update a subset of an existing permission's fields (scope
   * ceiling, rate limit, TTL override, etc). Cannot move the permission to a
   * different (agentId, connectionId) pair. Prospective-only: narrowing
   * `allowedScopes` constrains future delegate()/subdelegate() calls but has
   * no effect on a delegation handle already brokered through
   * `POST /api/v1/use` — that route resolves scopes from an in-memory
   * snapshot taken at delegation time and never re-reads the Permission row.
   */
  async updatePermission(id: string, input: UpdatePermissionInput): Promise<Permission> {
    await this.ensureInit();
    return this.getPermissionStore().update(id, input);
  }

  async checkPermissionRateLimit(
    permissionId: string,
    maxRequests: number,
    windowMs: number,
    now?: Date,
  ): Promise<boolean> {
    await this.ensureInit();
    return this.getPermissionStore().checkRateLimit(permissionId, maxRequests, windowMs, now);
  }

  /** Cred Link: all permissions on one connection, any agent. */
  async listPermissionsForConnection(connectionId: string): Promise<Permission[]> {
    await this.ensureInit();
    return this.getPermissionStore().listForConnection(connectionId);
  }

  /**
   * Cred Link: atomically set every permission on the connection to
   * allowedScopes ∩ scopes (canonical comparison). Returns the permissions
   * that changed. Never widens.
   */
  async intersectPermissionsForConnection(connectionId: string, scopes: readonly string[]): Promise<Permission[]> {
    await this.ensureInit();
    return this.getPermissionStore().intersectForConnection(connectionId, scopes);
  }

  /**
   * The vault's permission storage as Cred Link's `LinkPermissionPort`
   * (from @credninja/protocol), for `createLinkHooks` in @credninja/guard.
   * Every call ensures the vault is initialized first.
   *
   * Throws synchronously when the storage backend has no permission
   * support (the file backend), so a server that enables Link on such a
   * vault fails at startup instead of denying every Link call at runtime.
   */
  getLinkPermissionPort(): LinkPermissionPort {
    const store = this.getPermissionStore();
    if (!store.supportsLinkPermissions()) {
      throw new Error('Link permission storage not supported by this backend');
    }
    return {
      get: async (agentId, connectionId) => {
        await this.ensureInit();
        return store.get(agentId, connectionId);
      },
      list: async (agentId) => {
        await this.ensureInit();
        return store.list(agentId);
      },
      create: async (input) => {
        await this.ensureInit();
        return store.create(input);
      },
      update: async (id, input) => {
        await this.ensureInit();
        return store.update(id, input);
      },
      revoke: async (permissionId) => {
        await this.ensureInit();
        await store.revoke(permissionId);
      },
      listForConnection: async (connectionId) => {
        await this.ensureInit();
        return store.listForConnection(connectionId);
      },
      intersectForConnection: async (connectionId, scopes) => {
        await this.ensureInit();
        return store.intersectForConnection(connectionId, scopes);
      },
    };
  }

  // ── Audit event methods ──────────────────────────────────────────────────

  /**
   * Write an audit event. Fail-closed: throws if backend does not support audit
   * or if the write fails. This ensures no delegation succeeds without an audit record.
   */
  writeAuditEvent(event: AuditEvent): void {
    if (!this.backend.writeAuditEvent) {
      throw new Error('Audit logging not supported by this storage backend');
    }
    this.backend.writeAuditEvent(event);
  }

  /**
   * Write several audit events, in one transaction where the backend
   * supports it (a cascading revocation writes one per revoked delegation).
   */
  writeAuditEvents(events: readonly AuditEvent[]): void {
    if (this.backend.writeAuditEvents) {
      this.backend.writeAuditEvents(events);
      return;
    }
    for (const event of events) this.writeAuditEvent(event);
  }

  queryAuditEvents(filter: AuditFilter): AuditEvent[] {
    if (!this.backend.queryAuditEvents) {
      return [];
    }
    return this.backend.queryAuditEvents(filter) as AuditEvent[];
  }

  /**
   * Recompute the tamper-evident audit chain (SQLite storage). Reports the
   * first entry that is missing or does not match its hash.
   */
  verifyAuditChain(): AuditChainVerification {
    if (!this.backend.verifyAuditChain) {
      throw new Error('The audit chain is not supported by this storage backend');
    }
    return this.backend.verifyAuditChain();
  }

  /** The newest chained audit entry, to record outside the vault host. */
  auditChainHead(): AuditChainHead | null {
    return this.backend.auditChainHead ? this.backend.auditChainHead() : null;
  }

  // ── Rotation methods ────────────────────────────────────────────────────

  /**
   * Start a rotation schedule for a connection.
   * Creates a rotation record in 'pending' state via the RotationEngine.
   *
   * @param connectionId - Logical connection ID (e.g. "github_user123")
   * @param strategy - Rotation strategy (dual_active, single_swap, etc.)
   * @param intervalSeconds - How often to auto-rotate (default 86400 = 24h)
   */
  async startRotation(
    connectionId: string,
    strategy: RotationStrategy,
    intervalSeconds?: number,
  ): Promise<Rotation> {
    await this.ensureInit();
    return this.getRotationEngine().startRotation(connectionId, strategy, intervalSeconds);
  }

  /**
   * Promote the pending rotation to current.
   * Dual-active: old current → previous, pending → current.
   */
  async promoteRotation(rotationId: string): Promise<Rotation> {
    await this.ensureInit();
    return this.getRotationEngine().promoteRotation(rotationId);
  }

  /**
   * Roll back a rotation — restore previous version as current.
   */
  async rollbackRotation(rotationId: string): Promise<Rotation> {
    await this.ensureInit();
    return this.getRotationEngine().rollbackRotation(rotationId);
  }

  /**
   * Get current rotation state for a connection by provider + userId.
   */
  async getRotationByConnection(provider: string, userId: string, access?: LinkVaultAccess): Promise<Rotation | null> {
    this.assertUserIdAllowed('getRotationByConnection', userId, access);
    await this.ensureInit();
    if (!this.backend.getRotationByConnectionId) return null;
    const connectionId = `${provider}_${userId}`;
    return this.backend.getRotationByConnectionId(connectionId);
  }

  /**
   * Get a rotation by its ID.
   */
  async getRotationById(rotationId: string): Promise<Rotation | null> {
    await this.ensureInit();
    if (!this.backend.getRotation) return null;
    return this.backend.getRotation(rotationId);
  }

  private agentRowToRecord(row: AgentRow): AgentRecord {
    return {
      id: row.id,
      did: row.did ?? undefined,
      fingerprint: row.fingerprint,
      name: row.name,
      scopeCeiling: JSON.parse(row.scopeCeiling) as string[],
      status: row.status as AgentRecord['status'],
      createdBy: row.createdBy,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      lastSeenAt: row.lastSeenAt ?? undefined,
      revokedAt: row.revokedAt ?? undefined,
    };
  }

  private getRotationEngine(): RotationEngine {
    if (!this.rotationEngine) {
      this.rotationEngine = new RotationEngine(this.backend);
    }
    return this.rotationEngine;
  }

  private getPermissionStore(): PermissionStore {
    if (!this.permissionStore) {
      this.permissionStore = new PermissionStore(this.backend);
    }
    return this.permissionStore;
  }

  private decryptField(payload: EncryptedPayload, key: Buffer): string {
    return decryptWithKey(payload, key);
  }
}

/**
 * Factory: create and initialize a CredVault in one async call.
 *
 * @example
 * const vault = await createVault({
 *   passphrase: process.env.VAULT_PASSPHRASE!,
 *   storage: 'sqlite',
 *   path: './cred-vault.db',
 * });
 */
export async function createVault(options: VaultOptions): Promise<CredVault> {
  const vault = new CredVault(options);
  await vault.init();
  return vault;
}

/**
 * Write a small file, mode 0600, only if nothing is at `path` yet: the
 * content is written to a temporary file and linked into place, so the
 * file appears complete or not at all. Returns false when it already exists.
 */
function writeFileIfAbsent(path: string, content: string): boolean {
  const tmp = `${path}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, content, { encoding: 'utf8', mode: 0o600 });
  try {
    fs.linkSync(tmp, path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false;
    // Filesystems without hard links: an exclusive create instead.
    try {
      fs.writeFileSync(path, content, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      return true;
    } catch (fallback) {
      if ((fallback as NodeJS.ErrnoException).code === 'EEXIST') return false;
      throw fallback;
    }
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

/** Replace a small file atomically, mode 0600. */
function replaceFile(path: string, content: string): void {
  const tmp = `${path}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, content, { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmp, path);
}

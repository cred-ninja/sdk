import fs from 'fs';
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
  Rotation,
  RotationStrategy,
  RotationFailureAction,
} from './types.js';
import type { AuditEvent, AuditFilter } from './audit.js';
import { RotationEngine } from './rotation.js';

/**
 * CredVault — local-first encrypted token vault.
 *
 * Tokens are encrypted with AES-256-GCM using a key derived from your passphrase
 * via PBKDF2-SHA256 (100,000 iterations). The passphrase is never stored.
 *
 * Storage backends:
 *   - 'sqlite': uses better-sqlite3 for production use
 *   - 'file':   encrypted JSON file, zero additional deps (ideal for CLI tools)
 */
export class CredVault {
  private readonly backend: StorageBackend;
  // Passphrase held only in this field — never serialized or logged
  private readonly passphrase: string;
  private readonly saltPath: string;
  private derivedKey: Buffer | null = null;
  private initPromise: Promise<void> | null = null;
  private rotationEngine: RotationEngine | null = null;

  constructor(options: VaultOptions) {
    this.passphrase = options.passphrase;
    // Salt stored adjacent to the vault data file
    this.saltPath = options.path + '.salt';

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
    const salt = this.loadOrCreateSalt();
    this.derivedKey = deriveKey(this.passphrase, salt);
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

  private loadOrCreateSalt(): Buffer {
    if (fs.existsSync(this.saltPath)) {
      const hex = fs.readFileSync(this.saltPath, 'utf8').trim();
      return Buffer.from(hex, 'hex');
    }

    const salt = generateSalt();
    fs.writeFileSync(this.saltPath, salt.toString('hex'), { encoding: 'utf8', mode: 0o600 });
    return salt;
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
  async store(input: StoreInput): Promise<void> {
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
  async get(input: GetInput): Promise<VaultEntry | null> {
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
        await this.store({
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
   * Delete credentials for a provider + user.
   * Idempotent — safe to call even if no entry exists.
   */
  async delete(input: DeleteInput): Promise<void> {
    await this.ensureInit();
    await this.backend.delete(input.provider, input.userId);
  }

  /**
   * List all connections for a userId across all providers.
   * Returns fully decrypted entries.
   */
  async list(input: ListInput): Promise<VaultEntry[]> {
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

  queryAuditEvents(filter: AuditFilter): AuditEvent[] {
    if (!this.backend.queryAuditEvents) {
      return [];
    }
    return this.backend.queryAuditEvents(filter) as AuditEvent[];
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
  async getRotationByConnection(provider: string, userId: string): Promise<Rotation | null> {
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

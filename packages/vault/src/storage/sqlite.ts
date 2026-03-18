import type { StorageBackend, AgentIdentityStoredRow } from './interface.js';
import type { StoredRow } from '../types.js';

/**
 * SQLite storage backend using better-sqlite3 (synchronous API).
 *
 * All token columns store ciphertext — never plaintext.
 * Table is created automatically on init().
 */
export class SQLiteBackend implements StorageBackend {
  private db: import('better-sqlite3').Database | null = null;
  private readonly dbPath: string;

  constructor(path: string) {
    this.dbPath = path;
  }

  init(): void {
    // Lazy require so the package works without better-sqlite3 when using file backend
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const Database = require('better-sqlite3') as typeof import('better-sqlite3');
    this.db = new Database(this.dbPath);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_credentials (
        provider           TEXT NOT NULL,
        user_id            TEXT NOT NULL,
        access_token_enc   TEXT NOT NULL,
        access_token_iv    TEXT NOT NULL,
        access_token_tag   TEXT NOT NULL,
        refresh_token_enc  TEXT,
        refresh_token_iv   TEXT,
        refresh_token_tag  TEXT,
        expires_at         TEXT,
        scopes             TEXT,
        created_at         TEXT NOT NULL,
        updated_at         TEXT NOT NULL,
        PRIMARY KEY (provider, user_id)
      )
    `);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_agent_identities (
        agent_id       TEXT NOT NULL PRIMARY KEY,
        public_key     TEXT NOT NULL,
        fingerprint    TEXT NOT NULL UNIQUE,
        status         TEXT NOT NULL DEFAULT 'unclaimed',
        owner_user_id  TEXT,
        initial_scopes TEXT NOT NULL DEFAULT '[]',
        metadata       TEXT NOT NULL DEFAULT '{}',
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL
      )
    `);
  }

  private ensureDb(): import('better-sqlite3').Database {
    if (!this.db) {
      throw new Error('SQLiteBackend not initialized — call init() first');
    }
    return this.db;
  }

  store(row: StoredRow): void {
    const db = this.ensureDb();

    const stmt = db.prepare(`
      INSERT INTO vault_credentials (
        provider, user_id,
        access_token_enc, access_token_iv, access_token_tag,
        refresh_token_enc, refresh_token_iv, refresh_token_tag,
        expires_at, scopes, created_at, updated_at
      ) VALUES (
        @provider, @userId,
        @accessTokenEnc, @accessTokenIv, @accessTokenTag,
        @refreshTokenEnc, @refreshTokenIv, @refreshTokenTag,
        @expiresAt, @scopes, @createdAt, @updatedAt
      )
      ON CONFLICT (provider, user_id) DO UPDATE SET
        access_token_enc  = excluded.access_token_enc,
        access_token_iv   = excluded.access_token_iv,
        access_token_tag  = excluded.access_token_tag,
        refresh_token_enc = excluded.refresh_token_enc,
        refresh_token_iv  = excluded.refresh_token_iv,
        refresh_token_tag = excluded.refresh_token_tag,
        expires_at        = excluded.expires_at,
        scopes            = excluded.scopes,
        updated_at        = excluded.updated_at
    `);

    stmt.run({
      provider: row.provider,
      userId: row.userId,
      accessTokenEnc: row.accessTokenEnc,
      accessTokenIv: row.accessTokenIv,
      accessTokenTag: row.accessTokenTag,
      refreshTokenEnc: row.refreshTokenEnc ?? null,
      refreshTokenIv: row.refreshTokenIv ?? null,
      refreshTokenTag: row.refreshTokenTag ?? null,
      expiresAt: row.expiresAt ?? null,
      scopes: row.scopes ?? null,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }

  get(provider: string, userId: string): StoredRow | null {
    const db = this.ensureDb();

    const stmt = db.prepare(`
      SELECT
        provider,
        user_id            AS userId,
        access_token_enc   AS accessTokenEnc,
        access_token_iv    AS accessTokenIv,
        access_token_tag   AS accessTokenTag,
        refresh_token_enc  AS refreshTokenEnc,
        refresh_token_iv   AS refreshTokenIv,
        refresh_token_tag  AS refreshTokenTag,
        expires_at         AS expiresAt,
        scopes,
        created_at         AS createdAt,
        updated_at         AS updatedAt
      FROM vault_credentials
      WHERE provider = ? AND user_id = ?
    `);

    const row = stmt.get(provider, userId) as StoredRow | undefined;
    return row ?? null;
  }

  delete(provider: string, userId: string): void {
    const db = this.ensureDb();
    db.prepare('DELETE FROM vault_credentials WHERE provider = ? AND user_id = ?')
      .run(provider, userId);
  }

  list(userId: string): StoredRow[] {
    const db = this.ensureDb();

    const rows = db.prepare(`
      SELECT
        provider,
        user_id            AS userId,
        access_token_enc   AS accessTokenEnc,
        access_token_iv    AS accessTokenIv,
        access_token_tag   AS accessTokenTag,
        refresh_token_enc  AS refreshTokenEnc,
        refresh_token_iv   AS refreshTokenIv,
        refresh_token_tag  AS refreshTokenTag,
        expires_at         AS expiresAt,
        scopes,
        created_at         AS createdAt,
        updated_at         AS updatedAt
      FROM vault_credentials
      WHERE user_id = ?
      ORDER BY provider ASC
    `).all(userId) as StoredRow[];

    return rows;
  }

  // ── Agent Identity (TOFU) ──────────────────────────────────────────────────

  registerAgent(row: AgentIdentityStoredRow): void {
    const db = this.ensureDb();

    db.prepare(`
      INSERT INTO vault_agent_identities (
        agent_id, public_key, fingerprint, status,
        owner_user_id, initial_scopes, metadata,
        created_at, updated_at
      ) VALUES (
        @agentId, @publicKey, @fingerprint, @status,
        @ownerUserId, @initialScopes, @metadata,
        @createdAt, @updatedAt
      )
    `).run({
      agentId: row.agentId,
      publicKey: row.publicKey,
      fingerprint: row.fingerprint,
      status: row.status,
      ownerUserId: row.ownerUserId,
      initialScopes: row.initialScopes,
      metadata: row.metadata,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    });
  }

  getAgent(fingerprint: string): AgentIdentityStoredRow | null {
    const db = this.ensureDb();

    const row = db.prepare(`
      SELECT
        agent_id       AS agentId,
        public_key     AS publicKey,
        fingerprint,
        status,
        owner_user_id  AS ownerUserId,
        initial_scopes AS initialScopes,
        metadata,
        created_at     AS createdAt,
        updated_at     AS updatedAt
      FROM vault_agent_identities
      WHERE fingerprint = ?
    `).get(fingerprint) as AgentIdentityStoredRow | undefined;

    return row ?? null;
  }

  claimAgent(fingerprint: string, ownerUserId: string, updatedAt: string): void {
    const db = this.ensureDb();

    db.prepare(`
      UPDATE vault_agent_identities
      SET status = 'claimed', owner_user_id = ?, updated_at = ?
      WHERE fingerprint = ?
    `).run(ownerUserId, updatedAt, fingerprint);
  }

  listAgents(ownerUserId: string): AgentIdentityStoredRow[] {
    const db = this.ensureDb();

    return db.prepare(`
      SELECT
        agent_id       AS agentId,
        public_key     AS publicKey,
        fingerprint,
        status,
        owner_user_id  AS ownerUserId,
        initial_scopes AS initialScopes,
        metadata,
        created_at     AS createdAt,
        updated_at     AS updatedAt
      FROM vault_agent_identities
      WHERE owner_user_id = ?
      ORDER BY created_at ASC
    `).all(ownerUserId) as AgentIdentityStoredRow[];
  }
}

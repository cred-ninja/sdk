import type { StorageBackend } from './interface.js';
import type { StoredRow, AgentRow } from '../types.js';

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
      CREATE TABLE IF NOT EXISTS vault_agents (
        id               TEXT PRIMARY KEY,
        fingerprint      TEXT NOT NULL UNIQUE,
        name             TEXT NOT NULL,
        scope_ceiling    TEXT NOT NULL DEFAULT '[]',
        status           TEXT NOT NULL DEFAULT 'active',
        created_by       TEXT NOT NULL,
        created_at       TEXT NOT NULL,
        updated_at       TEXT NOT NULL,
        last_seen_at     TEXT,
        revoked_at       TEXT
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
      AND (
          expires_at IS NULL
          OR datetime(expires_at) > datetime('now')
          OR refresh_token_enc IS NOT NULL
        )
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

  // ── Agent record methods ──────────────────────────────────────────────────

  storeAgent(row: AgentRow): void {
    const db = this.ensureDb();

    const stmt = db.prepare(`
      INSERT INTO vault_agents (
        id, fingerprint, name, scope_ceiling, status,
        created_by, created_at, updated_at, last_seen_at, revoked_at
      ) VALUES (
        @id, @fingerprint, @name, @scopeCeiling, @status,
        @createdBy, @createdAt, @updatedAt, @lastSeenAt, @revokedAt
      )
      ON CONFLICT (id) DO UPDATE SET
        name          = excluded.name,
        scope_ceiling = excluded.scope_ceiling,
        status        = excluded.status,
        updated_at    = excluded.updated_at,
        last_seen_at  = excluded.last_seen_at,
        revoked_at    = excluded.revoked_at
    `);

    stmt.run({
      id: row.id,
      fingerprint: row.fingerprint,
      name: row.name,
      scopeCeiling: row.scopeCeiling,
      status: row.status,
      createdBy: row.createdBy,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      lastSeenAt: row.lastSeenAt ?? null,
      revokedAt: row.revokedAt ?? null,
    });
  }

  getAgent(id: string): AgentRow | null {
    const db = this.ensureDb();

    const row = db.prepare(`
      SELECT
        id,
        fingerprint,
        name,
        scope_ceiling  AS scopeCeiling,
        status,
        created_by     AS createdBy,
        created_at     AS createdAt,
        updated_at     AS updatedAt,
        last_seen_at   AS lastSeenAt,
        revoked_at     AS revokedAt
      FROM vault_agents
      WHERE id = ?
    `).get(id) as AgentRow | undefined;

    return row ?? null;
  }

  getAgentByFingerprint(fingerprint: string): AgentRow | null {
    const db = this.ensureDb();

    const row = db.prepare(`
      SELECT
        id,
        fingerprint,
        name,
        scope_ceiling  AS scopeCeiling,
        status,
        created_by     AS createdBy,
        created_at     AS createdAt,
        updated_at     AS updatedAt,
        last_seen_at   AS lastSeenAt,
        revoked_at     AS revokedAt
      FROM vault_agents
      WHERE fingerprint = ?
    `).get(fingerprint) as AgentRow | undefined;

    return row ?? null;
  }

  updateAgentStatus(id: string, status: string, revokedAt?: string): void {
    const db = this.ensureDb();
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE vault_agents
      SET status = ?, updated_at = ?, revoked_at = ?
      WHERE id = ?
    `).run(status, now, revokedAt ?? null, id);
  }
}

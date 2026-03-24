import type { AgentIdentityBackend } from './interface.js';
import type { AgentIdentityStoredRow } from '../types.js';

export class SQLiteBackend implements AgentIdentityBackend {
  private db: import('better-sqlite3').Database | null = null;
  private readonly dbPath: string;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
  }

  init(): void {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const Database = require('better-sqlite3') as typeof import('better-sqlite3');
    this.db = new Database(this.dbPath);
    const db = this.ensureDb();

    db.exec(`
      CREATE TABLE IF NOT EXISTS tofu_agents (
        agent_id                   TEXT PRIMARY KEY,
        public_key                 TEXT NOT NULL,
        fingerprint                TEXT NOT NULL UNIQUE,
        key_id                     TEXT NOT NULL,
        status                     TEXT NOT NULL,
        owner_user_id              TEXT,
        initial_scopes             TEXT NOT NULL DEFAULT '[]',
        metadata                   TEXT NOT NULL DEFAULT '{}',
        created_at                 TEXT NOT NULL,
        updated_at                 TEXT NOT NULL,
        claimed_at                 TEXT,
        revoked_at                 TEXT,
        previous_public_key        TEXT,
        previous_fingerprint       TEXT,
        rotation_grace_expires_at  TEXT
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_tofu_agents_previous_fingerprint
        ON tofu_agents(previous_fingerprint)
        WHERE previous_fingerprint IS NOT NULL;
    `);

    const columns = db.prepare(`PRAGMA table_info(tofu_agents)`).all() as Array<{ name: string }>;
    const hasKeyId = columns.some((column) => column.name === 'key_id');
    if (!hasKeyId) {
      db.exec(`ALTER TABLE tofu_agents ADD COLUMN key_id TEXT`);
      db.exec(`UPDATE tofu_agents SET key_id = fingerprint WHERE key_id IS NULL`);
      db.exec(`CREATE INDEX IF NOT EXISTS idx_tofu_agents_key_id ON tofu_agents(key_id)`);
    } else {
      db.exec(`CREATE INDEX IF NOT EXISTS idx_tofu_agents_key_id ON tofu_agents(key_id)`);
    }
  }

  insertAgent(row: AgentIdentityStoredRow): void {
    const db = this.ensureDb();
    db.prepare(`
      INSERT INTO tofu_agents (
        agent_id, public_key, fingerprint, key_id, status, owner_user_id,
        initial_scopes, metadata, created_at, updated_at, claimed_at, revoked_at,
        previous_public_key, previous_fingerprint, rotation_grace_expires_at
      ) VALUES (
        @agentId, @publicKey, @fingerprint, @keyId, @status, @ownerUserId,
        @initialScopes, @metadata, @createdAt, @updatedAt, @claimedAt, @revokedAt,
        @previousPublicKey, @previousFingerprint, @rotationGraceExpiresAt
      )
    `).run(row);
  }

  getAgentByFingerprint(fingerprint: string, nowIso: string): AgentIdentityStoredRow | null {
    const db = this.ensureDb();
    const row = db.prepare(`
      SELECT
        agent_id                  AS agentId,
        public_key                AS publicKey,
        fingerprint,
        COALESCE(key_id, fingerprint) AS keyId,
        status,
        owner_user_id             AS ownerUserId,
        initial_scopes            AS initialScopes,
        metadata,
        created_at                AS createdAt,
        updated_at                AS updatedAt,
        claimed_at                AS claimedAt,
        revoked_at                AS revokedAt,
        previous_public_key       AS previousPublicKey,
        previous_fingerprint      AS previousFingerprint,
        rotation_grace_expires_at AS rotationGraceExpiresAt
      FROM tofu_agents
      WHERE fingerprint = @fingerprint
         OR (
           previous_fingerprint = @fingerprint
           AND rotation_grace_expires_at IS NOT NULL
           AND rotation_grace_expires_at > @nowIso
         )
      LIMIT 1
    `).get({ fingerprint, nowIso }) as AgentIdentityStoredRow | undefined;

    return row ?? null;
  }

  listAgents(_nowIso: string): AgentIdentityStoredRow[] {
    const db = this.ensureDb();
    return db.prepare(`
      SELECT
        agent_id                  AS agentId,
        public_key                AS publicKey,
        fingerprint,
        COALESCE(key_id, fingerprint) AS keyId,
        status,
        owner_user_id             AS ownerUserId,
        initial_scopes            AS initialScopes,
        metadata,
        created_at                AS createdAt,
        updated_at                AS updatedAt,
        claimed_at                AS claimedAt,
        revoked_at                AS revokedAt,
        previous_public_key       AS previousPublicKey,
        previous_fingerprint      AS previousFingerprint,
        rotation_grace_expires_at AS rotationGraceExpiresAt
      FROM tofu_agents
      ORDER BY created_at ASC
    `).all() as AgentIdentityStoredRow[];
  }

  updateAgent(row: AgentIdentityStoredRow): void {
    const db = this.ensureDb();
    db.prepare(`
      UPDATE tofu_agents
      SET public_key = @publicKey,
          fingerprint = @fingerprint,
          key_id = @keyId,
          status = @status,
          owner_user_id = @ownerUserId,
          initial_scopes = @initialScopes,
          metadata = @metadata,
          updated_at = @updatedAt,
          claimed_at = @claimedAt,
          revoked_at = @revokedAt,
          previous_public_key = @previousPublicKey,
          previous_fingerprint = @previousFingerprint,
          rotation_grace_expires_at = @rotationGraceExpiresAt
      WHERE agent_id = @agentId
    `).run(row);
  }

  private ensureDb(): import('better-sqlite3').Database {
    if (!this.db) {
      throw new Error('SQLiteBackend not initialized — call init() first');
    }
    return this.db;
  }
}

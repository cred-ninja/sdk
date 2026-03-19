import type { StorageBackend } from './interface.js';
import type { StoredRow, AgentRow } from '../types.js';
import type { AuditEvent, AuditFilter, AuditActor, AuditResource } from '../audit.js';

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
      CREATE TABLE IF NOT EXISTS vault_audit_events (
        id                TEXT PRIMARY KEY,
        timestamp         TEXT NOT NULL,
        actor_type        TEXT NOT NULL,
        actor_id          TEXT NOT NULL,
        actor_fingerprint TEXT,
        action            TEXT NOT NULL,
        resource_type     TEXT NOT NULL,
        resource_id       TEXT NOT NULL,
        outcome           TEXT NOT NULL,
        delegation_chain  TEXT,
        scopes_requested  TEXT,
        scopes_granted    TEXT,
        correlation_id    TEXT NOT NULL,
        sensitive_hmac    TEXT,
        error_message     TEXT,
        created_at        TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_actor     ON vault_audit_events(actor_id, timestamp);
      CREATE INDEX IF NOT EXISTS idx_audit_resource  ON vault_audit_events(resource_id, timestamp);
      CREATE INDEX IF NOT EXISTS idx_audit_action    ON vault_audit_events(action, timestamp);
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

  // ── Audit event methods ─────────────────────────────────────────────────────

  writeAuditEvent(event: AuditEvent): void {
    const db = this.ensureDb();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO vault_audit_events (
        id, timestamp, actor_type, actor_id, actor_fingerprint,
        action, resource_type, resource_id, outcome,
        delegation_chain, scopes_requested, scopes_granted,
        correlation_id, sensitive_hmac, error_message, created_at
      ) VALUES (
        @id, @timestamp, @actorType, @actorId, @actorFingerprint,
        @action, @resourceType, @resourceId, @outcome,
        @delegationChain, @scopesRequested, @scopesGranted,
        @correlationId, @sensitiveHmac, @errorMessage, @createdAt
      )
    `).run({
      id: event.id,
      timestamp: event.timestamp.toISOString(),
      actorType: event.actor.type,
      actorId: event.actor.id,
      actorFingerprint: event.actor.fingerprint ?? null,
      action: event.action,
      resourceType: event.resource.type,
      resourceId: event.resource.id,
      outcome: event.outcome,
      delegationChain: event.delegationChain ? JSON.stringify(event.delegationChain) : null,
      scopesRequested: event.scopesRequested ? JSON.stringify(event.scopesRequested) : null,
      scopesGranted: event.scopesGranted ? JSON.stringify(event.scopesGranted) : null,
      correlationId: event.correlationId,
      sensitiveHmac: event.sensitiveFieldsHmac ? JSON.stringify(event.sensitiveFieldsHmac) : null,
      errorMessage: event.errorMessage ?? null,
      createdAt: now,
    });
  }

  queryAuditEvents(filter: AuditFilter): AuditEvent[] {
    const db = this.ensureDb();

    const conditions: string[] = [];
    const params: Record<string, unknown> = {};

    if (filter.actorId) {
      conditions.push('actor_id = @actorId');
      params.actorId = filter.actorId;
    }
    if (filter.resourceId) {
      conditions.push('resource_id = @resourceId');
      params.resourceId = filter.resourceId;
    }
    if (filter.action) {
      conditions.push('action = @action');
      params.action = filter.action;
    }
    if (filter.outcome) {
      conditions.push('outcome = @outcome');
      params.outcome = filter.outcome;
    }
    if (filter.after) {
      conditions.push('timestamp >= @after');
      params.after = filter.after.toISOString();
    }
    if (filter.before) {
      conditions.push('timestamp <= @before');
      params.before = filter.before.toISOString();
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limitClause = filter.limit ? `LIMIT ${filter.limit}` : '';

    interface AuditDbRow {
      id: string;
      timestamp: string;
      actor_type: string;
      actor_id: string;
      actor_fingerprint: string | null;
      action: string;
      resource_type: string;
      resource_id: string;
      outcome: string;
      delegation_chain: string | null;
      scopes_requested: string | null;
      scopes_granted: string | null;
      correlation_id: string;
      sensitive_hmac: string | null;
      error_message: string | null;
    }

    const rows = db.prepare(`
      SELECT * FROM vault_audit_events
      ${whereClause}
      ORDER BY timestamp DESC
      ${limitClause}
    `).all(params) as AuditDbRow[];

    return rows.map((row): AuditEvent => ({
      id: row.id,
      timestamp: new Date(row.timestamp),
      actor: {
        type: row.actor_type as AuditActor['type'],
        id: row.actor_id,
        fingerprint: row.actor_fingerprint ?? undefined,
      },
      action: row.action as AuditEvent['action'],
      resource: {
        type: row.resource_type as AuditResource['type'],
        id: row.resource_id,
      },
      outcome: row.outcome as AuditEvent['outcome'],
      delegationChain: row.delegation_chain
        ? (JSON.parse(row.delegation_chain) as AuditEvent['delegationChain'])
        : undefined,
      scopesRequested: row.scopes_requested
        ? (JSON.parse(row.scopes_requested) as string[])
        : undefined,
      scopesGranted: row.scopes_granted
        ? (JSON.parse(row.scopes_granted) as string[])
        : undefined,
      correlationId: row.correlation_id,
      sensitiveFieldsHmac: row.sensitive_hmac
        ? (JSON.parse(row.sensitive_hmac) as Record<string, string>)
        : undefined,
      errorMessage: row.error_message ?? undefined,
    }));
  }
}

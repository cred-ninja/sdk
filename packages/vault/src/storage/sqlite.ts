import type { StorageBackend } from './interface.js';
import type { StoredRow, AgentRow, PermissionRow, Rotation, RotationRow, RotationStrategy, RotationState, RotationFailureAction } from '../types.js';
import type { AuditEvent, AuditFilter, AuditActor, AuditResource, AuditRow } from '../audit.js';

const IN_PROGRESS_ROTATION_STATES: RotationState[] = ['pending', 'testing', 'promoting'];


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
        did              TEXT,
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

    const agentColumns = this.db.prepare('PRAGMA table_info(vault_agents)')
      .all() as Array<{ name: string }>;
    if (!agentColumns.some((column) => column.name === 'did')) {
      this.db.exec('ALTER TABLE vault_agents ADD COLUMN did TEXT');
    }
    this.db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_did ON vault_agents(did) WHERE did IS NOT NULL');

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_permissions (
        id                   TEXT PRIMARY KEY,
        agent_id             TEXT NOT NULL,
        connection_id        TEXT NOT NULL,
        allowed_scopes       TEXT NOT NULL,
        rate_limit_max       INTEGER,
        rate_limit_window_ms INTEGER,
        ttl_override         INTEGER,
        requires_approval    INTEGER NOT NULL DEFAULT 0,
        delegatable          INTEGER NOT NULL DEFAULT 0,
        max_delegation_depth INTEGER NOT NULL DEFAULT 1,
        expires_at           TEXT,
        created_at           TEXT NOT NULL,
        created_by           TEXT NOT NULL,
        UNIQUE(agent_id, connection_id)
      );
      CREATE INDEX IF NOT EXISTS idx_permissions_agent ON vault_permissions(agent_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_permissions_connection ON vault_permissions(connection_id);
    `);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_rate_limit_counters (
        permission_id TEXT NOT NULL,
        window_start  TEXT NOT NULL,
        request_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (permission_id, window_start)
      )
    `);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS vault_rotations (
        id                  TEXT PRIMARY KEY,
        connection_id       TEXT NOT NULL,
        strategy            TEXT NOT NULL,
        interval_seconds    INTEGER NOT NULL,
        state               TEXT NOT NULL DEFAULT 'idle',
        current_version_id  TEXT,
        pending_version_id  TEXT,
        previous_version_id TEXT,
        last_rotated_at     TEXT,
        next_rotation_at    TEXT,
        failure_count       INTEGER NOT NULL DEFAULT 0,
        failure_action      TEXT NOT NULL DEFAULT 'retry_backoff',
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_rotations_connection_unique ON vault_rotations(connection_id);
      CREATE INDEX IF NOT EXISTS idx_rotations_due ON vault_rotations(next_rotation_at, state);
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
        )
    `);

    const row = stmt.get(provider, userId) as StoredRow | undefined;
    return row ?? null;
  }

  getForRefresh(provider: string, userId: string): StoredRow | null {
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
        AND (
          expires_at IS NULL
          OR datetime(expires_at) > datetime('now')
        )
      ORDER BY provider ASC
    `).all(userId) as StoredRow[];

    return rows;
  }

  // ── Agent record methods ──────────────────────────────────────────────────

  storeAgent(row: AgentRow): void {
    const db = this.ensureDb();

    const stmt = db.prepare(`
      INSERT INTO vault_agents (
        id, did, fingerprint, name, scope_ceiling, status,
        created_by, created_at, updated_at, last_seen_at, revoked_at
      ) VALUES (
        @id, @did, @fingerprint, @name, @scopeCeiling, @status,
        @createdBy, @createdAt, @updatedAt, @lastSeenAt, @revokedAt
      )
      ON CONFLICT (id) DO UPDATE SET
        did           = excluded.did,
        name          = excluded.name,
        scope_ceiling = excluded.scope_ceiling,
        status        = excluded.status,
        updated_at    = excluded.updated_at,
        last_seen_at  = excluded.last_seen_at,
        revoked_at    = excluded.revoked_at
    `);

    stmt.run({
      id: row.id,
      did: row.did ?? null,
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
        did,
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

  getAgentByDid(did: string): AgentRow | null {
    const db = this.ensureDb();

    const row = db.prepare(`
      SELECT
        id,
        did,
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
      WHERE did = ?
    `).get(did) as AgentRow | undefined;

    return row ?? null;
  }

  getAgentByFingerprint(fingerprint: string): AgentRow | null {
    const db = this.ensureDb();

    const row = db.prepare(`
      SELECT
        id,
        did,
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

  // ── Permission methods ──────────────────────────────────────────────────

  storePermission(row: PermissionRow): void {
    const db = this.ensureDb();

    db.prepare(`
      INSERT INTO vault_permissions (
        id, agent_id, connection_id, allowed_scopes,
        rate_limit_max, rate_limit_window_ms, ttl_override,
        requires_approval, delegatable, max_delegation_depth,
        expires_at, created_at, created_by
      ) VALUES (
        @id, @agent_id, @connection_id, @allowed_scopes,
        @rate_limit_max, @rate_limit_window_ms, @ttl_override,
        @requires_approval, @delegatable, @max_delegation_depth,
        @expires_at, @created_at, @created_by
      )
      ON CONFLICT(agent_id, connection_id) DO UPDATE SET
        id                   = excluded.id,
        allowed_scopes       = excluded.allowed_scopes,
        rate_limit_max       = excluded.rate_limit_max,
        rate_limit_window_ms = excluded.rate_limit_window_ms,
        ttl_override         = excluded.ttl_override,
        requires_approval    = excluded.requires_approval,
        delegatable          = excluded.delegatable,
        max_delegation_depth = excluded.max_delegation_depth,
        expires_at           = excluded.expires_at,
        created_by           = excluded.created_by
    `).run(row);
  }

  getPermission(agentId: string, connectionId: string): PermissionRow | null {
    const db = this.ensureDb();

    const row = db.prepare(`
      SELECT
        id,
        agent_id,
        connection_id,
        allowed_scopes,
        rate_limit_max,
        rate_limit_window_ms,
        ttl_override,
        requires_approval,
        delegatable,
        max_delegation_depth,
        expires_at,
        created_at,
        created_by
      FROM vault_permissions
      WHERE agent_id = ? AND connection_id = ?
    `).get(agentId, connectionId) as PermissionRow | undefined;

    return row ?? null;
  }

  listPermissions(agentId: string): PermissionRow[] {
    const db = this.ensureDb();

    return db.prepare(`
      SELECT
        id,
        agent_id,
        connection_id,
        allowed_scopes,
        rate_limit_max,
        rate_limit_window_ms,
        ttl_override,
        requires_approval,
        delegatable,
        max_delegation_depth,
        expires_at,
        created_at,
        created_by
      FROM vault_permissions
      WHERE agent_id = ?
      ORDER BY created_at DESC
    `).all(agentId) as PermissionRow[];
  }

  revokePermission(permissionId: string): void {
    const db = this.ensureDb();

    const revoke = db.transaction((id: string) => {
      db.prepare('DELETE FROM vault_rate_limit_counters WHERE permission_id = ?').run(id);
      db.prepare('DELETE FROM vault_permissions WHERE id = ?').run(id);
    });

    revoke(permissionId);
  }

  checkPermissionRateLimit(
    permissionId: string,
    maxRequests: number,
    windowMs: number,
    now = new Date(),
  ): boolean {
    const db = this.ensureDb();
    const windowStart = new Date(
      Math.floor(now.getTime() / windowMs) * windowMs,
    ).toISOString();

    const check = db.transaction((id: string, start: string) => {
      const current = db.prepare(`
        SELECT request_count AS requestCount
        FROM vault_rate_limit_counters
        WHERE permission_id = ? AND window_start = ?
      `).get(id, start) as { requestCount: number } | undefined;

      if (!current) {
        db.prepare(`
          INSERT INTO vault_rate_limit_counters (permission_id, window_start, request_count)
          VALUES (?, ?, 1)
        `).run(id, start);
        return true;
      }

      if (current.requestCount >= maxRequests) {
        return false;
      }

      db.prepare(`
        UPDATE vault_rate_limit_counters
        SET request_count = request_count + 1
        WHERE permission_id = ? AND window_start = ?
      `).run(id, start);

      return true;
    });

    return check(permissionId, windowStart);
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

    const rows = db.prepare(`
      SELECT * FROM vault_audit_events
      ${whereClause}
      ORDER BY timestamp DESC
      ${limitClause}
    `).all(params) as AuditRow[];

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

  // ── Rotation methods ──────────────────────────────────────────────────────

  storeRotation(row: RotationRow): void {
    const db = this.ensureDb();

    db.prepare(`
      INSERT INTO vault_rotations (
        id, connection_id, strategy, interval_seconds, state,
        current_version_id, pending_version_id, previous_version_id,
        last_rotated_at, next_rotation_at, failure_count, failure_action,
        created_at, updated_at
      ) VALUES (
        @id, @connectionId, @strategy, @intervalSeconds, @state,
        @currentVersionId, @pendingVersionId, @previousVersionId,
        @lastRotatedAt, @nextRotationAt, @failureCount, @failureAction,
        @createdAt, @updatedAt
      )
      ON CONFLICT (id) DO UPDATE SET
        strategy            = excluded.strategy,
        interval_seconds    = excluded.interval_seconds,
        state               = excluded.state,
        current_version_id  = excluded.current_version_id,
        pending_version_id  = excluded.pending_version_id,
        previous_version_id = excluded.previous_version_id,
        last_rotated_at     = excluded.last_rotated_at,
        next_rotation_at    = excluded.next_rotation_at,
        failure_count       = excluded.failure_count,
        failure_action      = excluded.failure_action,
        updated_at          = excluded.updated_at
    `).run({
      id: row.id,
      connectionId: row.connection_id,
      strategy: row.strategy,
      intervalSeconds: row.interval_seconds,
      state: row.state,
      currentVersionId: row.current_version_id ?? null,
      pendingVersionId: row.pending_version_id ?? null,
      previousVersionId: row.previous_version_id ?? null,
      lastRotatedAt: row.last_rotated_at ?? null,
      nextRotationAt: row.next_rotation_at ?? null,
      failureCount: row.failure_count,
      failureAction: row.failure_action,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    });
  }

  getRotation(id: string): Rotation | null {
    const db = this.ensureDb();
    const row = db.prepare('SELECT * FROM vault_rotations WHERE id = ?').get(id) as RotationRow | undefined;
    return row ? this.mapRotationRow(row) : null;
  }

  getRotationByConnectionId(connectionId: string): Rotation | null {
    const db = this.ensureDb();
    const row = db.prepare('SELECT * FROM vault_rotations WHERE connection_id = ? ORDER BY created_at DESC LIMIT 1').get(connectionId) as RotationRow | undefined;
    return row ? this.mapRotationRow(row) : null;
  }

  startRotationTransaction(row: RotationRow): Rotation {
    const db = this.ensureDb();
    const getByConnection = db.prepare(`
      SELECT * FROM vault_rotations
      WHERE connection_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `);
    const getById = db.prepare('SELECT * FROM vault_rotations WHERE id = ?');
    const upsert = db.prepare(`
      INSERT INTO vault_rotations (
        id, connection_id, strategy, interval_seconds, state,
        current_version_id, pending_version_id, previous_version_id,
        last_rotated_at, next_rotation_at, failure_count, failure_action,
        created_at, updated_at
      ) VALUES (
        @id, @connectionId, @strategy, @intervalSeconds, @state,
        @currentVersionId, @pendingVersionId, @previousVersionId,
        @lastRotatedAt, @nextRotationAt, @failureCount, @failureAction,
        @createdAt, @updatedAt
      )
      ON CONFLICT (connection_id) DO UPDATE SET
        id                  = excluded.id,
        strategy            = excluded.strategy,
        interval_seconds    = excluded.interval_seconds,
        state               = excluded.state,
        current_version_id  = excluded.current_version_id,
        pending_version_id  = excluded.pending_version_id,
        previous_version_id = excluded.previous_version_id,
        last_rotated_at     = excluded.last_rotated_at,
        next_rotation_at    = excluded.next_rotation_at,
        failure_count       = excluded.failure_count,
        failure_action      = excluded.failure_action,
        created_at          = excluded.created_at,
        updated_at          = excluded.updated_at
      WHERE vault_rotations.state NOT IN ('pending', 'testing', 'promoting')
    `);

    const transaction = db.transaction((rotationRow: RotationRow): Rotation => {
      const existing = getByConnection.get(rotationRow.connection_id) as RotationRow | undefined;
      if (existing && IN_PROGRESS_ROTATION_STATES.includes(existing.state as RotationState)) {
        throw new Error(
          `Rotation already in progress for connection ${rotationRow.connection_id} (state: ${existing.state})`,
        );
      }

      const result = upsert.run({
        id: rotationRow.id,
        connectionId: rotationRow.connection_id,
        strategy: rotationRow.strategy,
        intervalSeconds: rotationRow.interval_seconds,
        state: rotationRow.state,
        currentVersionId: rotationRow.current_version_id ?? null,
        pendingVersionId: rotationRow.pending_version_id ?? null,
        previousVersionId: rotationRow.previous_version_id ?? null,
        lastRotatedAt: rotationRow.last_rotated_at ?? null,
        nextRotationAt: rotationRow.next_rotation_at ?? null,
        failureCount: rotationRow.failure_count,
        failureAction: rotationRow.failure_action,
        createdAt: rotationRow.created_at,
        updatedAt: rotationRow.updated_at,
      });

      if (result.changes === 0) {
        throw new Error(`Rotation already in progress for connection ${rotationRow.connection_id}`);
      }

      const created = getById.get(rotationRow.id) as RotationRow | undefined;
      if (!created) {
        throw new Error(`Failed to create rotation record ${rotationRow.id}`);
      }

      return this.mapRotationRow(created);
    });

    return transaction(row);
  }

  updateRotation(id: string, updates: Partial<RotationRow>): void {
    const db = this.ensureDb();
    const now = updates.updated_at ?? new Date().toISOString();

    const fields: string[] = ['updated_at = @updatedAt'];
    const params: Record<string, unknown> = { id, updatedAt: now };

    if (updates.state !== undefined) { fields.push('state = @state'); params.state = updates.state; }
    if (updates.current_version_id !== undefined) { fields.push('current_version_id = @currentVersionId'); params.currentVersionId = updates.current_version_id; }
    if (updates.pending_version_id !== undefined) { fields.push('pending_version_id = @pendingVersionId'); params.pendingVersionId = updates.pending_version_id; }
    if (updates.previous_version_id !== undefined) { fields.push('previous_version_id = @previousVersionId'); params.previousVersionId = updates.previous_version_id; }
    if (updates.last_rotated_at !== undefined) { fields.push('last_rotated_at = @lastRotatedAt'); params.lastRotatedAt = updates.last_rotated_at; }
    if (updates.next_rotation_at !== undefined) { fields.push('next_rotation_at = @nextRotationAt'); params.nextRotationAt = updates.next_rotation_at; }
    if (updates.failure_count !== undefined) { fields.push('failure_count = @failureCount'); params.failureCount = updates.failure_count; }
    if (updates.interval_seconds !== undefined) { fields.push('interval_seconds = @intervalSeconds'); params.intervalSeconds = updates.interval_seconds; }

    db.prepare(`UPDATE vault_rotations SET ${fields.join(', ')} WHERE id = @id`).run(params);
  }

  claimDueRotation(id: string, now: Date, updates: Partial<RotationRow>): Rotation | null {
    const db = this.ensureDb();
    const updatedAt = updates.updated_at ?? new Date().toISOString();
    const fields: string[] = ['updated_at = @updatedAt'];
    const params: Record<string, unknown> = {
      id,
      now: now.toISOString(),
      updatedAt,
    };

    if (updates.state !== undefined) { fields.push('state = @state'); params.state = updates.state; }
    if (updates.current_version_id !== undefined) { fields.push('current_version_id = @currentVersionId'); params.currentVersionId = updates.current_version_id; }
    if (updates.pending_version_id !== undefined) { fields.push('pending_version_id = @pendingVersionId'); params.pendingVersionId = updates.pending_version_id; }
    if (updates.previous_version_id !== undefined) { fields.push('previous_version_id = @previousVersionId'); params.previousVersionId = updates.previous_version_id; }
    if (updates.last_rotated_at !== undefined) { fields.push('last_rotated_at = @lastRotatedAt'); params.lastRotatedAt = updates.last_rotated_at; }
    if (updates.next_rotation_at !== undefined) { fields.push('next_rotation_at = @nextRotationAt'); params.nextRotationAt = updates.next_rotation_at; }
    if (updates.failure_count !== undefined) { fields.push('failure_count = @failureCount'); params.failureCount = updates.failure_count; }
    if (updates.interval_seconds !== undefined) { fields.push('interval_seconds = @intervalSeconds'); params.intervalSeconds = updates.interval_seconds; }

    const result = db.prepare(`
      UPDATE vault_rotations
      SET ${fields.join(', ')}
      WHERE id = @id
        AND state = 'idle'
        AND next_rotation_at IS NOT NULL
        AND datetime(next_rotation_at) <= datetime(@now)
    `).run(params);

    if (result.changes === 0) {
      return null;
    }

    return this.getRotation(id);
  }

  listDueRotations(now: Date): Rotation[] {
    const db = this.ensureDb();
    const rows = db.prepare(`
      SELECT * FROM vault_rotations
      WHERE state = 'idle'
        AND next_rotation_at IS NOT NULL
        AND datetime(next_rotation_at) <= datetime(?)
    `).all(now.toISOString()) as RotationRow[];
    return rows.map((row) => this.mapRotationRow(row));
  }

  listRotations(): Rotation[] {
    const db = this.ensureDb();
    const rows = db.prepare('SELECT * FROM vault_rotations ORDER BY created_at DESC').all() as RotationRow[];
    return rows.map((row) => this.mapRotationRow(row));
  }

  private mapRotationRow(row: RotationRow): Rotation {
    return {
      id: row.id,
      connectionId: row.connection_id,
      strategy: row.strategy as RotationStrategy,
      intervalSeconds: row.interval_seconds,
      state: row.state as RotationState,
      currentVersionId: row.current_version_id,
      pendingVersionId: row.pending_version_id,
      previousVersionId: row.previous_version_id,
      lastRotatedAt: row.last_rotated_at ? new Date(row.last_rotated_at) : null,
      nextRotationAt: row.next_rotation_at ? new Date(row.next_rotation_at) : null,
      failureCount: row.failure_count,
      failureAction: row.failure_action as RotationFailureAction,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }
}

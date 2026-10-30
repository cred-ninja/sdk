/**
 * @credninja/vault — Structured Audit Logging
 *
 * Fail-closed: if the audit backend cannot write, the operation must fail.
 * This ensures no delegation can succeed without a corresponding audit record.
 *
 * HMAC-SHA256 is used for sensitive field references — raw tokens are never logged.
 */

import crypto from 'crypto';
import Database from 'better-sqlite3';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AuditActor {
  type: 'agent' | 'user' | 'system';
  id: string;
  fingerprint?: string;
}

export interface AuditResource {
  /** 'grant' is a Cred Link client grant (protocol LINK_AUDIT_RESOURCE_TYPE_GRANT). */
  type: 'connection' | 'token' | 'agent' | 'permission' | 'rotation' | 'grant';
  id: string;
}

export interface AuditEvent {
  /** evt_ prefixed unique ID */
  id: string;
  /** UTC timestamp with sub-second precision */
  timestamp: Date;
  actor: AuditActor;
  action: 'delegate' | 'access' | 'rotate' | 'revoke' | 'create' | 'update' | 'delete' | 'deny';
  resource: AuditResource;
  outcome: 'pending' | 'success' | 'denied' | 'error';
  delegationChain?: Array<{ delegatorId: string; delegateeId: string; scopes: string[] }>;
  scopesRequested?: string[];
  scopesGranted?: string[];
  sourceIp?: string;
  userAgent?: string;
  /** Unique per delegation flow — correlates all events from one request */
  correlationId: string;
  /** HMAC-SHA256 of sensitive references (raw values never stored) */
  sensitiveFieldsHmac?: Record<string, string>;
  /** Structured metadata for audit analysis */
  metadata?: Record<string, unknown>;
  errorMessage?: string;
}

export interface AuditFilter {
  actorId?: string;
  resourceId?: string;
  action?: AuditEvent['action'];
  outcome?: AuditEvent['outcome'];
  after?: Date;
  before?: Date;
  /**
   * Cursor for incremental polling: return only events with a timestamp
   * strictly after this value (`>`, not `>=` like `after`). Callers that
   * re-poll with the timestamp of the last event they already saw as the
   * next `since` will not see that event again. Distinct from `after`
   * (inclusive range filtering) to give pollers an unambiguous, dedup-safe
   * cursor semantic.
   */
  since?: Date;
  limit?: number;
}

// ── Backend interface ─────────────────────────────────────────────────────────

export interface AuditBackend {
  /**
   * Write an audit event. Synchronous — must throw on failure (fail-closed).
   * Never silently swallow errors.
   */
  write(event: AuditEvent): void;
  query(filter: AuditFilter): AuditEvent[];
}

// ── HMAC helper ───────────────────────────────────────────────────────────────

/**
 * HMAC-SHA256 a sensitive value. Used to record a verifiable reference
 * to a token without storing the raw value.
 */
export function hmacAuditField(value: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(value).digest('hex');
}

// ── Tamper-evident chain ──────────────────────────────────────────────────────

/**
 * Result of checking the audit chain. Each chained entry carries an
 * HMAC-SHA256, under a key derived from the vault passphrase, over the
 * previous entry's hash and its own stored fields, so editing, deleting or
 * reordering a chained entry breaks every later one. Rows written before
 * the chain existed are counted as `unchained`.
 */
export type AuditChainVerification =
  | { ok: true; entries: number; unchained: number; head: AuditChainHead | null }
  | { ok: false; entries: number; unchained: number; brokenAt: number; reason: string };

/**
 * The newest chained entry. Record it somewhere the vault's host cannot
 * rewrite (an external log, a ticket, a time-stamp service): the chain
 * proves nothing against an attacker who also holds the vault passphrase,
 * except relative to a head recorded earlier.
 */
export interface AuditChainHead {
  seq: number;
  hash: string;
}

/** The value the first chained entry links to. */
export const AUDIT_CHAIN_GENESIS = 'cred-audit-chain-v1';

/**
 * What the first chained entry links to: the genesis value and the number
 * of unchained rows (written before the chain existed) at that moment. The
 * count is bound into every hash after it, so an unchained row added later,
 * or a chained row stripped of its chain columns, breaks the chain at
 * entry 1 instead of passing as a pre-upgrade row.
 */
export function auditChainGenesis(unchainedBefore: number): string {
  return `${AUDIT_CHAIN_GENESIS}:${unchainedBefore}`;
}

/**
 * The stored audit columns the chain hash covers, in hash order. Every
 * AuditRow field must be listed (checked below at compile time); a new
 * column goes at the end so existing chains keep verifying.
 */
export const AUDIT_CHAIN_FIELDS = [
  'id', 'timestamp', 'actor_type', 'actor_id', 'actor_fingerprint',
  'action', 'resource_type', 'resource_id', 'outcome',
  'delegation_chain', 'scopes_requested', 'scopes_granted',
  'correlation_id', 'sensitive_hmac', 'metadata_json', 'error_message', 'created_at',
] as const satisfies readonly (keyof AuditRow)[];

// Fails to compile when AuditRow gains a field the chain does not hash.
const auditChainCoversAuditRow: Exclude<keyof AuditRow, (typeof AUDIT_CHAIN_FIELDS)[number]> extends never ? true : never = true;
void auditChainCoversAuditRow;

/**
 * Chain hash of one stored row: HMAC-SHA256(key, previousHash "\n" JSON of
 * the sequence number and AUDIT_CHAIN_FIELDS, in order). Exported for
 * verifiers.
 */
export function auditChainHash(key: Buffer, previousHash: string, seq: number, row: AuditRow): string {
  const fields = [seq, ...AUDIT_CHAIN_FIELDS.map((field) => row[field])];
  return crypto.createHmac('sha256', key).update(`${previousHash}\n${JSON.stringify(fields)}`, 'utf8').digest('base64url');
}

// ── Raw DB row type ───────────────────────────────────────────────────────────

/** Raw audit_events DB row — used by SQLite backends. */
export interface AuditRow {
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
  metadata_json: string | null;
  error_message: string | null;
  created_at: string;
}

// ── SQLite audit backend ──────────────────────────────────────────────────────

/**
 * Standalone audit log in its own SQLite file. Its rows are not chained:
 * do not point it at a vault database, whose chain verification would
 * report them as tampering.
 */
export class SQLiteAuditBackend implements AuditBackend {
  private db: import('better-sqlite3').Database | null = null;

  constructor(private readonly dbPath: string) {}

  init(): void {
    this.db = new Database(this.dbPath);

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
        metadata_json     TEXT,
        error_message     TEXT,
        created_at        TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_actor     ON vault_audit_events(actor_id, timestamp);
      CREATE INDEX IF NOT EXISTS idx_audit_resource  ON vault_audit_events(resource_id, timestamp);
      CREATE INDEX IF NOT EXISTS idx_audit_action    ON vault_audit_events(action, timestamp);
    `);

    const columns = this.db.prepare('PRAGMA table_info(vault_audit_events)')
      .all() as Array<{ name: string }>;
    if (!columns.some((column) => column.name === 'metadata_json')) {
      this.db.exec('ALTER TABLE vault_audit_events ADD COLUMN metadata_json TEXT');
    }
  }

  private ensureDb(): import('better-sqlite3').Database {
    if (!this.db) {
      throw new Error('SQLiteAuditBackend not initialized — call init() first');
    }
    return this.db;
  }

  /**
   * Write an audit event. Throws if the DB is unavailable — fail-closed.
   */
  write(event: AuditEvent): void {
    const db = this.ensureDb();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO vault_audit_events (
        id, timestamp, actor_type, actor_id, actor_fingerprint,
        action, resource_type, resource_id, outcome,
        delegation_chain, scopes_requested, scopes_granted,
        correlation_id, sensitive_hmac, metadata_json, error_message, created_at
      ) VALUES (
        @id, @timestamp, @actorType, @actorId, @actorFingerprint,
        @action, @resourceType, @resourceId, @outcome,
        @delegationChain, @scopesRequested, @scopesGranted,
        @correlationId, @sensitiveHmac, @metadataJson, @errorMessage, @createdAt
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
      metadataJson: event.metadata ? JSON.stringify(event.metadata) : null,
      errorMessage: event.errorMessage ?? null,
      createdAt: now,
    });
  }

  query(filter: AuditFilter): AuditEvent[] {
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
    if (filter.since) {
      conditions.push('timestamp > @since');
      params.since = filter.since.toISOString();
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

    return rows.map((row) => this.mapRow(row));
  }

  private mapRow(row: AuditRow): AuditEvent {
    return {
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
      metadata: row.metadata_json
        ? (JSON.parse(row.metadata_json) as Record<string, unknown>)
        : undefined,
      errorMessage: row.error_message ?? undefined,
    };
  }
}

// ── No-op audit backend (for file backend or when audit is not needed) ───────

export class NoopAuditBackend implements AuditBackend {
  write(_event: AuditEvent): void {
    // intentionally empty — no audit persistence
  }
  query(_filter: AuditFilter): AuditEvent[] {
    return [];
  }
}

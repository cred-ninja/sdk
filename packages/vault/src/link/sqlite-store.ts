import Database from 'better-sqlite3';
import {
  LINK_GRANT_STATUS_FOR_CONNECTION_STATUS,
  LINK_PROVIDERS,
  LINK_SCOPE_CATALOG,
  canonicalScopeSet,
  intersectScopes,
  isConnectionId,
  isGrantId,
  isLinkClientId,
  isLinkConnectionStatus,
  isLinkIntent,
  isLinkMachineErrorCode,
  isLinkProviderSlug,
  isLinkStepTransitionAllowed,
  isLinkSubjectType,
  isLinkWidgetMode,
  isOrgId,
  isScopeSubset,
  isTransactionId,
  scopeSetsEqual,
  unionScopes,
} from '@credninja/protocol';
import type {
  ClientGrant,
  Connection,
  LinkActivationClaim,
  LinkClient,
  LinkConfirmCommit,
  LinkConnectionStatus,
  LinkErrorCode,
  LinkGrantStatus,
  LinkMachineErrorCode,
  LinkProviderSlug,
  LinkScopeMap,
  LinkStep,
  LinkStore,
  LinkTheme,
  LinkTransaction,
  LinkTransactionEntry,
  LinkTransactionOutcome,
  LinkTransactionPatch,
  LinkWidgetMode,
  NewLinkTransaction,
  TransactionId,
} from '@credninja/protocol';
import {
  LINK_SCHEMA_SQL,
  LINK_SCHEMA_VERSION,
  rowToClient,
  rowToConnection,
  rowToGrant,
  rowToTransaction,
} from './schema.js';
import type { ClientRow, ConnectionRow, GrantRow, TransactionRow } from './schema.js';

type Db = import('better-sqlite3').Database;

/**
 * Typed failure for calls that cannot proceed and whose LinkStore result
 * type has no variant for it (programmer errors and lost races). The server
 * maps these to server_error, or to the local error page on hosted hops.
 */
export type LinkStoreErrorCode =
  | 'not_found'
  | 'terminal'
  | 'expired'
  | 'wrong_step'
  | 'not_claimed'
  | 'connection_unavailable'
  | 'activation_superseded'
  | 'invalid_transition'
  | 'invalid_scopes'
  | 'invalid_input';

export class LinkStoreError extends Error {
  readonly code: LinkStoreErrorCode;

  constructor(code: LinkStoreErrorCode, message: string) {
    super(message);
    this.name = 'LinkStoreError';
    this.code = code;
  }
}

export interface SqliteLinkStoreOptions {
  /**
   * Seconds after activation_claimed_at during which the expiry sweep leaves
   * a claimed transaction alone, so a sweep cannot revoke a connection
   * between claimActivation and commitActivation. Default 60.
   */
  activationGraceSeconds?: number;
  /** SQLite busy_timeout for concurrent writers on a shared file, in ms. Default 5000. */
  busyTimeoutMs?: number;
}

const ISO_PREFIX = /^\d{4}-\d{2}-\d{2}T/;

/** Normalizes a caller-supplied ISO-8601 timestamp to toISOString() form. Never reads the clock. */
function iso(value: unknown, field: string): string {
  if (typeof value !== 'string' || !ISO_PREFIX.test(value)) {
    throw new LinkStoreError('invalid_input', `${field} must be an ISO-8601 timestamp`);
  }
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    throw new LinkStoreError('invalid_input', `${field} must be an ISO-8601 timestamp`);
  }
  return new Date(ms).toISOString();
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value === '') {
    throw new LinkStoreError('invalid_input', `${field} must be a non-empty string`);
  }
  return value;
}

function optString(value: unknown, field: string): string | null {
  if (value === undefined || value === null) return null;
  return requireString(value, field);
}

function scopesJson(scopes: unknown, field: string): string {
  if (!Array.isArray(scopes)) {
    throw new LinkStoreError('invalid_input', `${field} must be an array of scopes`);
  }
  return JSON.stringify(canonicalScopeSet(scopes as string[]));
}

function canonicalScopeMap(map: unknown, field: string): LinkScopeMap {
  if (map === null || typeof map !== 'object' || Array.isArray(map)) {
    throw new LinkStoreError('invalid_input', `${field} must be an object keyed by provider`);
  }
  const out: LinkScopeMap = {};
  for (const [provider, scopes] of Object.entries(map as Record<string, unknown>)) {
    if (!isLinkProviderSlug(provider)) {
      throw new LinkStoreError('invalid_input', `${field} has an unknown provider key`);
    }
    if (!Array.isArray(scopes)) {
      throw new LinkStoreError('invalid_input', `${field}.${provider} must be an array`);
    }
    out[provider] = canonicalScopeSet(scopes as string[]);
  }
  return out;
}

function providerList(value: unknown, field: string): LinkProviderSlug[] {
  if (!Array.isArray(value) || !value.every(isLinkProviderSlug)) {
    throw new LinkStoreError('invalid_input', `${field} must be a list of Link provider slugs`);
  }
  return LINK_PROVIDERS.filter((p) => (value as string[]).includes(p));
}

/**
 * Scopes a grant may hold for a provider (ClientGrant invariant): catalog
 * scopes for that provider only, never a 'hidden' or 'never_offer' one. Provider-enforced
 * catalog scopes count only when the provider granted them; Cred-enforced
 * ones always count. A provider scope outside the catalog (for example
 * Google's `profile`) can never enter a grant, because PAR only accepts
 * catalog scopes and the user never saw it as a toggle.
 */
function allowedGrantScopes(provider: LinkProviderSlug, providerScopes: readonly string[]): string[] {
  const granted = new Set(canonicalScopeSet(providerScopes));
  const allowed: string[] = [];
  for (const e of LINK_SCOPE_CATALOG) {
    if (e.provider !== provider || e.flags.includes('hidden') || e.flags.includes('never_offer')) continue;
    if (e.enforced_by === 'cred' || granted.has(e.scope)) allowed.push(e.scope);
  }
  return canonicalScopeSet(allowed);
}

const PATCH_KEYS = new Set<keyof LinkTransactionPatch>([
  'provider',
  'selected_scopes',
  'provider_requested_scopes',
  'pkce_verifier',
  'provider_attempt',
  'exchanged_at',
  'provider_granted_scopes',
  'provider_account_id',
  'account_label',
  'instance_url',
]);

/**
 * SQLite implementation of LinkStore (packages/protocol link.ts section 6).
 *
 * Uses its own database file (':memory:' works for tests). Every method
 * that writes runs in one BEGIN IMMEDIATE transaction, so a read followed by
 * a conditional write cannot interleave with another connection's write to
 * the same file. Nothing here stores or returns provider tokens: those live
 * behind LinkSecretStore. Timestamps come only from the caller's `now`.
 */
export class SqliteLinkStore implements LinkStore {
  private readonly db: Db;
  private readonly activationGraceMs: number;

  constructor(path: string, options: SqliteLinkStoreOptions = {}) {
    const grace = options.activationGraceSeconds ?? 60;
    if (!Number.isFinite(grace) || grace < 0) {
      throw new LinkStoreError('invalid_input', 'activationGraceSeconds must be a non-negative number');
    }
    this.activationGraceMs = grace * 1000;
    this.db = new Database(path);
    this.db.pragma(`busy_timeout = ${Math.max(0, Math.floor(options.busyTimeoutMs ?? 5000))}`);
    if (path !== ':memory:' && path !== '') {
      this.db.pragma('journal_mode = WAL');
    }
    this.db.pragma('foreign_keys = ON');
    this.migrate();
  }

  /** Close the underlying database handle. */
  close(): void {
    this.db.close();
  }

  /**
   * Creates or verifies the schema. user_version 0 is a new file; anything
   * above LINK_SCHEMA_VERSION was written by a newer build and is refused.
   * LINK_SCHEMA_SQL is idempotent, so reopening a current file is a no-op.
   *
   * Future migrations go in the marked spot, one guarded step per version,
   * for example `if (current >= 1 && current < 2) { ...alter v1 to v2... }`,
   * all inside this one IMMEDIATE transaction.
   */
  private migrate(): void {
    const current = this.db.pragma('user_version', { simple: true }) as number;
    if (current > LINK_SCHEMA_VERSION) {
      throw new Error(`Link database schema version ${current} is newer than this build supports (${LINK_SCHEMA_VERSION})`);
    }
    this.db.transaction(() => {
      // Migration steps from older versions go here (none yet: version 1 is the first layout).
      this.db.exec(LINK_SCHEMA_SQL);
      if (current < LINK_SCHEMA_VERSION) {
        this.db.pragma(`user_version = ${LINK_SCHEMA_VERSION}`);
      }
    }).immediate();
  }

  /** Runs `fn` in one BEGIN IMMEDIATE transaction. */
  private write<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate();
  }

  // ── Row access (call inside write() when the result feeds a write) ────────

  private txRow(tid: string): TransactionRow | null {
    return (this.db.prepare('SELECT * FROM link_transactions WHERE tid = ?').get(tid) as TransactionRow | undefined) ?? null;
  }

  private connRow(id: string): ConnectionRow | null {
    return (this.db.prepare('SELECT * FROM link_connections WHERE id = ?').get(id) as ConnectionRow | undefined) ?? null;
  }

  private grantRowById(id: string): GrantRow | null {
    return (this.db.prepare('SELECT * FROM link_grants WHERE id = ?').get(id) as GrantRow | undefined) ?? null;
  }

  private grantRowForConnection(connection_id: string): GrantRow | null {
    return (this.db.prepare('SELECT * FROM link_grants WHERE connection_id = ?').get(connection_id) as GrantRow | undefined) ?? null;
  }

  /**
   * The live connection (status other than pending or revoked) for a
   * (client_id, audience, subject, provider_account_id) key, if any. The
   * unique index guarantees at most one.
   */
  private liveConnectionRow(client_id: string, audience: string, subject: string, provider_account_id: string): ConnectionRow | null {
    return (this.db.prepare(`
      SELECT * FROM link_connections
      WHERE client_id = ? AND audience = ? AND subject = ? AND provider_account_id = ?
        AND status NOT IN ('pending', 'revoked')
    `).get(client_id, audience, subject, provider_account_id) as ConnectionRow | undefined) ?? null;
  }

  /** UPDATE one row by primary key. Column names come from this file only, never from input. */
  private update(table: string, keyColumn: string, key: string, fields: Record<string, unknown>): void {
    const cols = Object.keys(fields);
    if (cols.length === 0) return;
    const set = cols.map((c) => `${c} = @${c}`).join(', ');
    this.db.prepare(`UPDATE ${table} SET ${set} WHERE ${keyColumn} = @__key`).run({ ...fields, __key: key });
  }

  private updateTx(tid: string, fields: Partial<Record<keyof TransactionRow, unknown>>): TransactionRow {
    this.update('link_transactions', 'tid', tid, fields);
    return this.txRow(tid) as TransactionRow;
  }

  private static isTerminal(row: TransactionRow): boolean {
    return row.consumed_at !== null;
  }

  private static isExpired(row: TransactionRow, now: string): boolean {
    return row.expires_at <= now;
  }

  /**
   * Ends a transaction (terminal). If it created a connection and was not
   * activated, revokes that connection and grant. Connections are never
   * shared between transactions, so these rows belong to this transaction
   * alone; the pending checks only skip rows already revoked elsewhere (for
   * example by DELETE /connections/:id).
   */
  private endTx(row: TransactionRow, outcome: LinkTransactionOutcome, error: LinkErrorCode | null, now: string): TransactionRow {
    if (row.creates_connection === 1 && row.activated_at === null && row.connection_id !== null) {
      const conn = this.connRow(row.connection_id);
      if (conn && conn.status === 'pending') {
        this.update('link_connections', 'id', conn.id, {
          status: 'revoked',
          version: conn.version + 1,
          updated_at: now,
        });
        const grant = this.grantRowForConnection(conn.id);
        const grantStatus: LinkGrantStatus = outcome === 'expired' ? 'expired' : 'revoked';
        if (grant && grant.status === 'pending') {
          this.update('link_grants', 'id', grant.id, {
            status: grantStatus,
            version: grant.version + 1,
            updated_at: now,
          });
        }
      }
    }
    return this.updateTx(row.tid, { consumed_at: now, outcome, error, updated_at: now });
  }

  // ── Clients ───────────────────────────────────────────────────────────────

  async getClient(client_id: string): Promise<LinkClient | null> {
    const row = this.db.prepare('SELECT * FROM link_clients WHERE client_id = ?').get(client_id) as ClientRow | undefined;
    return row ? rowToClient(row) : null;
  }

  async putClient(client: LinkClient): Promise<void> {
    if (!isLinkClientId(client.client_id)) throw new LinkStoreError('invalid_input', 'client_id is malformed');
    if (!isOrgId(client.org_id)) throw new LinkStoreError('invalid_input', 'org_id is malformed');
    if (client.status !== 'active' && client.status !== 'disabled') {
      throw new LinkStoreError('invalid_input', 'client status must be active or disabled');
    }
    let secretHash: string | null = null;
    let jwks: string | null = null;
    if (client.token_endpoint_auth_method === 'client_secret_basic') {
      secretHash = requireString(client.client_secret_hash, 'client_secret_hash');
    } else if (client.token_endpoint_auth_method === 'private_key_jwt') {
      if (!client.jwks || !Array.isArray(client.jwks.keys)) {
        throw new LinkStoreError('invalid_input', 'private_key_jwt clients need jwks.keys');
      }
      jwks = JSON.stringify(client.jwks);
    } else {
      throw new LinkStoreError('invalid_input', 'unknown token_endpoint_auth_method');
    }
    this.db.prepare(`
      INSERT INTO link_clients (
        client_id, org_id, name, token_endpoint_auth_method, client_secret_hash, jwks_json,
        redirect_uris_json, origins_json, theme_json, allow_raw_tokens, status, created_at, updated_at
      ) VALUES (
        @client_id, @org_id, @name, @method, @secret, @jwks,
        @redirect_uris, @origins, @theme, @allow_raw, @status, @created_at, @updated_at
      )
      ON CONFLICT (client_id) DO UPDATE SET
        org_id = excluded.org_id,
        name = excluded.name,
        token_endpoint_auth_method = excluded.token_endpoint_auth_method,
        client_secret_hash = excluded.client_secret_hash,
        jwks_json = excluded.jwks_json,
        redirect_uris_json = excluded.redirect_uris_json,
        origins_json = excluded.origins_json,
        theme_json = excluded.theme_json,
        allow_raw_tokens = excluded.allow_raw_tokens,
        status = excluded.status,
        created_at = excluded.created_at,
        updated_at = excluded.updated_at
    `).run({
      client_id: client.client_id,
      org_id: client.org_id,
      name: client.name,
      method: client.token_endpoint_auth_method,
      secret: secretHash,
      jwks,
      redirect_uris: JSON.stringify(client.redirect_uris ?? []),
      origins: JSON.stringify(client.origins ?? []),
      theme: client.theme === undefined ? null : JSON.stringify(client.theme),
      allow_raw: client.allow_raw_tokens ? 1 : 0,
      status: client.status,
      created_at: iso(client.created_at, 'created_at'),
      updated_at: iso(client.updated_at, 'updated_at'),
    });
  }

  async listClients(): Promise<LinkClient[]> {
    const rows = this.db.prepare('SELECT * FROM link_clients ORDER BY client_id ASC').all() as ClientRow[];
    return rows.map(rowToClient);
  }

  // ── Transactions ──────────────────────────────────────────────────────────

  async createTransaction(tx: NewLinkTransaction): Promise<LinkTransaction> {
    if (!isTransactionId(tx.tid)) throw new LinkStoreError('invalid_input', 'tid is malformed');
    if (!isOrgId(tx.org_id)) throw new LinkStoreError('invalid_input', 'org_id is malformed');
    if (!isLinkClientId(tx.client_id)) throw new LinkStoreError('invalid_input', 'client_id is malformed');
    if (!isLinkIntent(tx.intent)) throw new LinkStoreError('invalid_input', 'intent is invalid');
    if (!isLinkSubjectType(tx.subject_type)) throw new LinkStoreError('invalid_input', 'subject_type is invalid');
    const providers = providerList(tx.providers, 'providers');
    if (tx.connection_id !== undefined && !isConnectionId(tx.connection_id)) {
      throw new LinkStoreError('invalid_input', 'connection_id is malformed');
    }
    if (tx.grant_id !== undefined && !isGrantId(tx.grant_id)) {
      throw new LinkStoreError('invalid_input', 'grant_id is malformed');
    }
    if (tx.intent !== 'connect') {
      if (tx.connection_id === undefined) {
        throw new LinkStoreError('invalid_input', `${tx.intent} needs connection_id`);
      }
      if (providers.length !== 1) {
        throw new LinkStoreError('invalid_input', `${tx.intent} needs exactly one provider`);
      }
    }
    const row = {
      tid: tx.tid,
      org_id: tx.org_id,
      client_id: tx.client_id,
      intent: tx.intent,
      subject: requireString(tx.subject, 'subject'),
      subject_type: tx.subject_type,
      providers_json: JSON.stringify(providers),
      requested_scopes_json: JSON.stringify(canonicalScopeMap(tx.requested_scopes, 'requested_scopes')),
      required_scopes_json: JSON.stringify(canonicalScopeMap(tx.required_scopes, 'required_scopes')),
      authorization_details_json: JSON.stringify(Array.isArray(tx.authorization_details) ? tx.authorization_details : []),
      redirect_uri: requireString(tx.redirect_uri, 'redirect_uri'),
      origin: requireString(tx.origin, 'origin'),
      client_state: tx.client_state ?? null,
      agent_id: optString(tx.agent_id, 'agent_id'),
      connection_id: tx.connection_id ?? null,
      grant_id: tx.grant_id ?? null,
      request_uri_hash: requireString(tx.request_uri_hash, 'request_uri_hash'),
      step: 'picker',
      provider_attempt: 0,
      created_at: iso(tx.created_at, 'created_at'),
      updated_at: iso(tx.created_at, 'created_at'),
      expires_at: iso(tx.expires_at, 'expires_at'),
    };
    const cols = Object.keys(row);
    this.write(() => {
      this.db.prepare(
        `INSERT INTO link_transactions (${cols.join(', ')}) VALUES (${cols.map((c) => `@${c}`).join(', ')})`,
      ).run(row);
    });
    return rowToTransaction(this.txRow(tx.tid) as TransactionRow);
  }

  async getTransaction(tid: TransactionId): Promise<LinkTransaction | null> {
    const row = this.txRow(tid);
    return row ? rowToTransaction(row) : null;
  }

  async enterByRequestUri(input: {
    request_uri_hash: string;
    client_id?: string;
    presented_cookie_hash: string | null;
    new_handle_hash: string;
    new_binding_cookie_hash?: string;
    mode: LinkWidgetMode;
    theme?: LinkTheme;
    narrowed?: { providers: LinkProviderSlug[]; requested_scopes: LinkScopeMap };
    now: string;
  }): Promise<LinkTransactionEntry> {
    const now = iso(input.now, 'now');
    const newHandle = requireString(input.new_handle_hash, 'new_handle_hash');
    if (!isLinkWidgetMode(input.mode)) throw new LinkStoreError('invalid_input', 'mode is invalid');
    const narrowedProviders = input.narrowed ? providerList(input.narrowed.providers, 'narrowed.providers') : null;
    const narrowedScopes = input.narrowed
      ? canonicalScopeMap(input.narrowed.requested_scopes, 'narrowed.requested_scopes')
      : null;

    return this.write((): LinkTransactionEntry => {
      const row = this.db.prepare('SELECT * FROM link_transactions WHERE request_uri_hash = ?')
        .get(input.request_uri_hash) as TransactionRow | undefined;
      if (!row) return { kind: 'rejected', reason: 'unknown' };
      if (input.client_id !== undefined && input.client_id !== row.client_id) {
        return { kind: 'rejected', reason: 'client_mismatch' };
      }
      if (SqliteLinkStore.isTerminal(row)) return { kind: 'rejected', reason: 'finished' };
      if (SqliteLinkStore.isExpired(row, now)) return { kind: 'rejected', reason: 'expired' };

      if (row.request_uri_consumed_at === null) {
        const fields: Partial<Record<keyof TransactionRow, unknown>> = {
          request_uri_consumed_at: now,
          handle_hash: newHandle,
          mode: input.mode,
          updated_at: now,
        };
        if (input.theme !== undefined) fields.theme_json = JSON.stringify(input.theme);
        if (input.new_binding_cookie_hash !== undefined) {
          fields.binding_cookie_hash = requireString(input.new_binding_cookie_hash, 'new_binding_cookie_hash');
        }
        if (narrowedProviders && narrowedScopes) {
          const narrowed = narrow(rowToTransaction(row), narrowedProviders, narrowedScopes);
          fields.providers_json = JSON.stringify(narrowed.providers);
          fields.requested_scopes_json = JSON.stringify(narrowed.requested_scopes);
        }
        return { kind: 'fresh', transaction: rowToTransaction(this.updateTx(row.tid, fields)) };
      }

      if (cookieMatches(row, input.presented_cookie_hash)) {
        return {
          kind: 'reentry',
          transaction: rowToTransaction(this.updateTx(row.tid, { handle_hash: newHandle, updated_at: now })),
        };
      }
      return { kind: 'rejected', reason: 'replayed' };
    });
  }

  async enterByHandle(input: {
    tid: TransactionId;
    client_id: string;
    handle_hash: string;
    presented_cookie_hash: string | null;
    new_handle_hash: string;
    new_binding_cookie_hash?: string;
    now: string;
  }): Promise<LinkTransactionEntry> {
    const now = iso(input.now, 'now');
    const newHandle = requireString(input.new_handle_hash, 'new_handle_hash');

    return this.write((): LinkTransactionEntry => {
      const row = this.txRow(input.tid);
      if (!row) return { kind: 'rejected', reason: 'unknown' };
      if (input.client_id !== row.client_id) return { kind: 'rejected', reason: 'client_mismatch' };
      if (SqliteLinkStore.isTerminal(row)) return { kind: 'rejected', reason: 'finished' };
      if (SqliteLinkStore.isExpired(row, now)) return { kind: 'rejected', reason: 'expired' };

      const handleMatches = row.handle_hash !== null
        && typeof input.handle_hash === 'string'
        && row.handle_hash === input.handle_hash;
      // Spec 5: once the binding cookie is set, the handle is bound to it. A
      // matching handle from another browser falls through to 'replayed'.
      if (handleMatches && (row.binding_cookie_hash === null || cookieMatches(row, input.presented_cookie_hash))) {
        const fields: Partial<Record<keyof TransactionRow, unknown>> = { handle_hash: newHandle, updated_at: now };
        if (row.binding_cookie_hash === null && input.new_binding_cookie_hash !== undefined) {
          fields.binding_cookie_hash = requireString(input.new_binding_cookie_hash, 'new_binding_cookie_hash');
        }
        return { kind: 'fresh', transaction: rowToTransaction(this.updateTx(row.tid, fields)) };
      }

      if (cookieMatches(row, input.presented_cookie_hash)) {
        return {
          kind: 'reentry',
          transaction: rowToTransaction(this.updateTx(row.tid, { handle_hash: newHandle, updated_at: now })),
        };
      }
      return { kind: 'rejected', reason: 'replayed' };
    });
  }

  async advanceTransaction(input: {
    tid: TransactionId;
    from: LinkStep;
    to: LinkStep;
    patch: LinkTransactionPatch;
    now: string;
  }): Promise<LinkTransaction | null> {
    const now = iso(input.now, 'now');
    if (!isLinkStepTransitionAllowed(input.from, input.to) || (input.from === 'confirm' && input.to === 'done')) {
      throw new LinkStoreError('invalid_transition', `step transition ${input.from} -> ${input.to} is not allowed here`);
    }
    const patch = input.patch ?? {};
    for (const key of Object.keys(patch)) {
      if (!PATCH_KEYS.has(key as keyof LinkTransactionPatch)) {
        throw new LinkStoreError('invalid_input', `patch field ${key} cannot be set by advanceTransaction`);
      }
    }
    if (input.from === 'provider' && input.to === 'confirm' && (patch.exchanged_at === undefined || patch.exchanged_at === null)) {
      throw new LinkStoreError('invalid_input', 'provider -> confirm must carry exchanged_at');
    }
    const fields = patchFields(patch);

    return this.write(() => {
      const row = this.txRow(input.tid);
      if (!row) return null;
      if (row.step !== input.from || SqliteLinkStore.isTerminal(row) || SqliteLinkStore.isExpired(row, now)) {
        return null;
      }
      if (typeof patch.provider === 'string') {
        const allowed = JSON.parse(row.providers_json) as string[];
        if (!allowed.includes(patch.provider)) {
          throw new LinkStoreError('invalid_input', 'patch.provider is not one of the transaction providers');
        }
      }
      return rowToTransaction(this.updateTx(row.tid, { ...fields, step: input.to, updated_at: now }));
    });
  }

  async commitConfirm(input: {
    tid: TransactionId;
    confirmed_scopes: string[];
    activation_code_hash: string;
    new_connection: Pick<
      Connection,
      'id' | 'audience' | 'provider_account_id' | 'account_label' | 'provider_scopes' | 'instance_url' | 'custody'
    >;
    new_grant: Pick<ClientGrant, 'id' | 'org_policy' | 'authorization_details_types'>;
    now: string;
  }): Promise<LinkConfirmCommit> {
    const now = iso(input.now, 'now');
    const codeHash = requireString(input.activation_code_hash, 'activation_code_hash');
    const confirmed = JSON.parse(scopesJson(input.confirmed_scopes, 'confirmed_scopes')) as string[];

    return this.write((): LinkConfirmCommit => {
      const row = this.txRow(input.tid);
      if (!row) throw new LinkStoreError('not_found', 'unknown transaction');
      if (row.confirmed_at !== null) return { kind: 'already_committed', transaction: rowToTransaction(row) };
      if (SqliteLinkStore.isTerminal(row)) throw new LinkStoreError('terminal', 'transaction has ended');
      if (row.step !== 'confirm') throw new LinkStoreError('wrong_step', `transaction is at step ${row.step}, not confirm`);
      if (SqliteLinkStore.isExpired(row, now)) throw new LinkStoreError('expired', 'transaction has expired');
      if (row.provider === null || row.exchanged_at === null || row.provider_account_id === null) {
        throw new LinkStoreError('wrong_step', 'transaction has no completed provider exchange');
      }
      const tx = rowToTransaction(row);
      const provider = tx.provider as LinkProviderSlug;
      const granted = canonicalScopeSet(tx.provider_granted_scopes ?? []);

      // Scope bounds, on every branch: the browser can only narrow what the
      // backend pushed (requested_scopes after narrowing), and a grant only
      // holds non-hidden catalog scopes the provider granted (or Cred enforces).
      if (!isScopeSubset(confirmed, tx.requested_scopes[provider] ?? [])) {
        throw new LinkStoreError('invalid_scopes', 'confirmed_scopes include scopes that were not requested');
      }
      if (!isScopeSubset(confirmed, allowedGrantScopes(provider, granted))) {
        throw new LinkStoreError('invalid_scopes', 'confirmed_scopes exceed what the provider granted');
      }

      let connectionId: string;
      let grantId: string;
      let creates: boolean;

      if (tx.intent === 'connect') {
        const nc = input.new_connection;
        const audience = requireString(nc.audience, 'new_connection.audience');
        if (nc.provider_account_id !== tx.provider_account_id) {
          throw new LinkStoreError('invalid_input', 'new_connection.provider_account_id differs from the exchange result');
        }
        // provider_scopes are stored from the exchange result; a caller value that disagrees is refused.
        if (!Array.isArray(nc.provider_scopes) || !scopeSetsEqual(nc.provider_scopes, granted)) {
          throw new LinkStoreError('invalid_input', 'new_connection.provider_scopes differs from the exchange result');
        }
        const live = this.liveConnectionRow(tx.client_id, audience, tx.subject, tx.provider_account_id);

        if (live) {
          if (live.provider !== provider) return { kind: 'account_mismatch', transaction: tx };
          const grant = this.grantRowForConnection(live.id);
          if (!grant || grant.status === 'revoked' || grant.status === 'pending') {
            return { kind: 'connection_unavailable', transaction: tx };
          }
          connectionId = live.id;
          grantId = grant.id;
          creates = false;
        } else {
          // No live connection: this transaction always gets its own pending
          // rows, even when another flow holds a pending one for the same key.
          if (!isConnectionId(nc.id)) throw new LinkStoreError('invalid_input', 'new_connection.id is malformed');
          if (!isGrantId(input.new_grant.id)) throw new LinkStoreError('invalid_input', 'new_grant.id is malformed');
          this.db.prepare(`
            INSERT INTO link_connections (
              id, org_id, client_id, provider, audience, subject, subject_type, provider_account_id,
              account_label, provider_scopes_json, instance_url, status, status_reason, custody,
              version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?, 1, ?, ?)
          `).run(
            nc.id, tx.org_id, tx.client_id, provider, audience, tx.subject, tx.subject_type,
            tx.provider_account_id, nc.account_label ?? null, JSON.stringify(granted),
            nc.instance_url ?? null, nc.custody === 'hosted' ? 'hosted' : 'self', now, now,
          );
          this.db.prepare(`
            INSERT INTO link_grants (
              id, org_id, client_id, audience, subject, subject_type, scopes_json, org_policy_json,
              authorization_details_types_json, connection_id, status, version, granted_at, updated_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 1, ?, ?, NULL)
          `).run(
            input.new_grant.id, tx.org_id, tx.client_id, audience, tx.subject, tx.subject_type,
            JSON.stringify(confirmed), JSON.stringify(input.new_grant.org_policy ?? { usage: 'allow' }),
            JSON.stringify(input.new_grant.authorization_details_types ?? []), nc.id, now, now,
          );
          connectionId = nc.id;
          grantId = input.new_grant.id;
          creates = true;
        }
      } else {
        const conn = tx.connection_id ? this.connRow(tx.connection_id) : null;
        // A pending target belongs to an unfinished connect flow; it is never updated in place.
        if (!conn || conn.status === 'revoked' || conn.status === 'pending'
          || conn.client_id !== tx.client_id || conn.subject !== tx.subject) {
          return { kind: 'connection_unavailable', transaction: tx };
        }
        if (conn.provider !== provider || conn.provider_account_id !== tx.provider_account_id) {
          return { kind: 'account_mismatch', transaction: tx };
        }
        const grant = this.grantRowForConnection(conn.id);
        if (!grant || grant.status === 'revoked' || grant.status === 'pending'
          || (tx.grant_id !== undefined && tx.grant_id !== grant.id)) {
          return { kind: 'connection_unavailable', transaction: tx };
        }
        connectionId = conn.id;
        grantId = grant.id;
        creates = false;
      }

      const updated = this.updateTx(row.tid, {
        confirmed_scopes_json: JSON.stringify(confirmed),
        activation_code_hash: codeHash,
        confirmed_at: now,
        connection_id: connectionId,
        grant_id: grantId,
        creates_connection: creates ? 1 : 0,
        step: 'done',
        updated_at: now,
      });
      return { kind: 'committed', transaction: rowToTransaction(updated) };
    });
  }

  async replaceActivationCode(input: { tid: TransactionId; activation_code_hash: string; now: string }): Promise<boolean> {
    const now = iso(input.now, 'now');
    const codeHash = requireString(input.activation_code_hash, 'activation_code_hash');
    return this.write(() => {
      const row = this.txRow(input.tid);
      if (!row || row.confirmed_at === null || row.activation_claimed_at !== null) return false;
      if (SqliteLinkStore.isTerminal(row) || SqliteLinkStore.isExpired(row, now)) return false;
      this.updateTx(row.tid, { activation_code_hash: codeHash, updated_at: now });
      return true;
    });
  }

  async claimActivation(input: {
    client_id: string;
    connection_id: string;
    activation_code_hash: string;
    subject: string;
    now: string;
  }): Promise<LinkActivationClaim> {
    const now = iso(input.now, 'now');
    return this.write((): LinkActivationClaim => {
      const row = this.db.prepare(`
        SELECT * FROM link_transactions
        WHERE client_id = ? AND connection_id = ? AND activation_code_hash = ?
          AND confirmed_at IS NOT NULL AND activation_claimed_at IS NULL AND consumed_at IS NULL
      `).get(input.client_id, input.connection_id, input.activation_code_hash) as TransactionRow | undefined;
      if (!row) return { ok: false, reason: 'invalid_code' };

      const claimed = this.updateTx(row.tid, { activation_claimed_at: now, updated_at: now });
      if (SqliteLinkStore.isExpired(claimed, now)) {
        return { ok: false, reason: 'expired', transaction: rowToTransaction(this.endTx(claimed, 'expired', null, now)) };
      }
      if (typeof input.subject !== 'string' || input.subject !== claimed.subject) {
        return {
          ok: false,
          reason: 'subject_mismatch',
          transaction: rowToTransaction(this.endTx(claimed, 'failed', 'access_denied', now)),
        };
      }
      return { ok: true, transaction: rowToTransaction(claimed) };
    });
  }

  /**
   * Phase 1 limitation: this database commit and the token move
   * (LinkSecretStore.commitStaged) are two separate stores. If the process
   * stops after this call and before commitStaged, the transaction is
   * already terminal, so the sweep never returns it, and its staged tokens
   * stay under `link-staged:<tid>` while the connection has no tokens of
   * its own. The server handles this at use time: a connection with no
   * tokens is moved to needs_reauth and the user reconnects.
   */
  async commitActivation(input: { tid: TransactionId; now: string }): Promise<{
    connection: Connection;
    grant: ClientGrant;
    previous_grant_scopes: string[] | null;
  }> {
    const now = iso(input.now, 'now');
    type Result =
      | { ok: true; connection: Connection; grant: ClientGrant; previous_grant_scopes: string[] | null }
      | { ok: false; code: LinkStoreErrorCode; message: string };

    const result = this.write((): Result => {
      const row = this.txRow(input.tid);
      if (!row) throw new LinkStoreError('not_found', 'unknown transaction');
      if (SqliteLinkStore.isTerminal(row)) throw new LinkStoreError('terminal', 'transaction has ended');
      if (row.activation_claimed_at === null) throw new LinkStoreError('not_claimed', 'activation has not been claimed');
      if (row.connection_id === null || row.grant_id === null) {
        throw new LinkStoreError('wrong_step', 'transaction has no confirmed connection');
      }

      // A refusal ends the transaction as failed (revoking the pending rows it
      // created) and commits that, then the caller gets a LinkStoreError.
      const refuse = (code: LinkStoreErrorCode, message: string): Result => {
        this.endTx(row, 'failed', 'access_denied', now);
        return { ok: false, code, message };
      };

      const conn = this.connRow(row.connection_id);
      const grant = this.grantRowById(row.grant_id);
      if (!conn || !grant || grant.connection_id !== conn.id) {
        return refuse('connection_unavailable', 'connection or grant is missing');
      }

      let previous: string[] | null;
      if (row.creates_connection === 1) {
        if (conn.status !== 'pending' || grant.status !== 'pending') {
          return refuse('connection_unavailable', `connection is ${conn.status}, grant is ${grant.status}`);
        }
        // First activation wins: another flow for the same account already went live.
        if (this.liveConnectionRow(conn.client_id, conn.audience, conn.subject, conn.provider_account_id)) {
          return refuse('activation_superseded', 'another transaction already activated a connection for this account');
        }
        this.update('link_connections', 'id', conn.id, {
          status: 'active',
          status_reason: null,
          version: conn.version + 1,
          updated_at: now,
        });
        this.update('link_grants', 'id', grant.id, { status: 'active', version: grant.version + 1, updated_at: now });
        previous = null;
      } else {
        // Only the creating transaction may turn a pending connection active.
        if (conn.status === 'revoked' || conn.status === 'pending' || grant.status === 'revoked' || grant.status === 'pending') {
          return refuse('connection_unavailable', `connection is ${conn.status}, grant is ${grant.status}`);
        }
        if (row.provider_granted_scopes_json === null || row.confirmed_scopes_json === null) {
          throw new LinkStoreError('wrong_step', 'transaction has no staged scopes');
        }
        this.update('link_connections', 'id', conn.id, {
          provider_scopes_json: row.provider_granted_scopes_json,
          status: 'active',
          status_reason: null,
          version: conn.version + 1,
          updated_at: now,
        });
        this.update('link_grants', 'id', grant.id, {
          scopes_json: row.confirmed_scopes_json,
          status: 'active',
          version: grant.version + 1,
          updated_at: now,
        });
        previous = JSON.parse(grant.scopes_json) as string[];
      }

      this.updateTx(row.tid, { activated_at: now, consumed_at: now, outcome: 'activated', updated_at: now });
      return {
        ok: true,
        connection: rowToConnection(this.connRow(conn.id) as ConnectionRow),
        grant: rowToGrant(this.grantRowById(grant.id) as GrantRow),
        previous_grant_scopes: previous,
      };
    });

    if (!result.ok) throw new LinkStoreError(result.code, result.message);
    return { connection: result.connection, grant: result.grant, previous_grant_scopes: result.previous_grant_scopes };
  }

  async endTransaction(input: {
    tid: TransactionId;
    outcome: 'failed' | 'cancelled';
    error?: LinkErrorCode;
    now: string;
  }): Promise<LinkTransaction | null> {
    const now = iso(input.now, 'now');
    if (input.outcome !== 'failed' && input.outcome !== 'cancelled') {
      throw new LinkStoreError('invalid_input', 'outcome must be failed or cancelled');
    }
    return this.write(() => {
      const row = this.txRow(input.tid);
      if (!row || SqliteLinkStore.isTerminal(row)) return null;
      return rowToTransaction(this.endTx(row, input.outcome, input.error ?? null, now));
    });
  }

  async sweepExpiredTransactions(input: { now: string; limit: number }): Promise<LinkTransaction[]> {
    const now = iso(input.now, 'now');
    const limit = Math.floor(input.limit);
    if (!Number.isFinite(limit) || limit <= 0) return [];
    const claimCutoff = new Date(Date.parse(now) - this.activationGraceMs).toISOString();
    return this.write(() => {
      const rows = this.db.prepare(`
        SELECT * FROM link_transactions
        WHERE consumed_at IS NULL AND expires_at <= ?
          AND (activation_claimed_at IS NULL OR activation_claimed_at <= ?)
        ORDER BY expires_at ASC, tid ASC
        LIMIT ?
      `).all(now, claimCutoff, limit) as TransactionRow[];
      return rows.map((row) => rowToTransaction(this.endTx(row, 'expired', null, now)));
    });
  }

  // ── Connections ───────────────────────────────────────────────────────────

  async getConnection(connection_id: string): Promise<Connection | null> {
    const row = this.connRow(connection_id);
    return row ? rowToConnection(row) : null;
  }

  async getClientConnection(input: { client_id: string; connection_id: string }): Promise<Connection | null> {
    const row = this.db.prepare('SELECT * FROM link_connections WHERE id = ? AND client_id = ?')
      .get(input.connection_id, input.client_id) as ConnectionRow | undefined;
    return row ? rowToConnection(row) : null;
  }

  async getSubjectConnection(input: { client_id: string; subject: string; connection_id: string }): Promise<Connection | null> {
    const row = this.db.prepare('SELECT * FROM link_connections WHERE id = ? AND client_id = ? AND subject = ?')
      .get(input.connection_id, input.client_id, input.subject) as ConnectionRow | undefined;
    return row ? rowToConnection(row) : null;
  }

  async listConnections(input: { client_id: string; subject: string }): Promise<Connection[]> {
    const rows = this.db.prepare(`
      SELECT * FROM link_connections WHERE client_id = ? AND subject = ?
      ORDER BY created_at DESC, rowid DESC
    `).all(input.client_id, input.subject) as ConnectionRow[];
    return rows.map(rowToConnection);
  }

  async listAccountConnections(input: { provider: LinkProviderSlug; provider_account_id: string }): Promise<Connection[]> {
    const rows = this.db.prepare(`
      SELECT * FROM link_connections
      WHERE provider = ? AND provider_account_id = ? AND status <> 'revoked'
      ORDER BY created_at ASC, id ASC
    `).all(input.provider, input.provider_account_id) as ConnectionRow[];
    return rows.map(rowToConnection);
  }

  /**
   * Non-terminal transactions (consumed_at unset, including expired ones the
   * sweep has not ended yet) whose provider exchange for this account has
   * completed (exchanged_at set), so tokens may be staged under their tid.
   */
  async listOpenAccountTransactions(input: { provider: LinkProviderSlug; provider_account_id: string }): Promise<LinkTransaction[]> {
    const rows = this.db.prepare(`
      SELECT * FROM link_transactions
      WHERE provider = ? AND provider_account_id = ? AND consumed_at IS NULL AND exchanged_at IS NOT NULL
      ORDER BY created_at ASC, tid ASC
    `).all(input.provider, input.provider_account_id) as TransactionRow[];
    return rows.map(rowToTransaction);
  }

  async setConnectionStatus(input: {
    connection_id: string;
    status: Exclude<LinkConnectionStatus, 'pending'>;
    reason?: LinkMachineErrorCode;
    now: string;
  }): Promise<{ connection: Connection; grant: ClientGrant | null } | null> {
    const now = iso(input.now, 'now');
    const status = input.status as LinkConnectionStatus;
    if (!isLinkConnectionStatus(status) || status === 'pending') {
      throw new LinkStoreError('invalid_input', 'status must be active, needs_reauth, frozen or revoked');
    }
    if (input.reason !== undefined && !isLinkMachineErrorCode(input.reason)) {
      throw new LinkStoreError('invalid_input', 'reason must be a Link machine error code');
    }
    return this.write(() => {
      const conn = this.connRow(input.connection_id);
      if (!conn || conn.status === 'revoked') return null;
      // A pending connection only becomes usable through activation; here it can only be revoked.
      if (conn.status === 'pending' && status !== 'revoked') return null;

      const reason = status === 'active' ? null : (input.reason ?? null);
      if (conn.status !== status || conn.status_reason !== reason) {
        this.update('link_connections', 'id', conn.id, {
          status,
          status_reason: reason,
          version: conn.version + 1,
          updated_at: now,
        });
      }
      const grant = this.grantRowForConnection(conn.id);
      if (grant) {
        const target = LINK_GRANT_STATUS_FOR_CONNECTION_STATUS[status];
        if (grant.status !== target && grant.status !== 'revoked') {
          this.update('link_grants', 'id', grant.id, { status: target, version: grant.version + 1, updated_at: now });
        }
      }
      const g = this.grantRowForConnection(conn.id);
      return { connection: rowToConnection(this.connRow(conn.id) as ConnectionRow), grant: g ? rowToGrant(g) : null };
    });
  }

  async applyProviderScopes(input: { connection_id: string; provider_scopes: string[]; now: string }): Promise<{
    connection: Connection;
    grant: ClientGrant | null;
    previous_grant_scopes: string[] | null;
  } | null> {
    const now = iso(input.now, 'now');
    const reported = JSON.parse(scopesJson(input.provider_scopes, 'provider_scopes')) as string[];
    return this.write(() => {
      const conn = this.connRow(input.connection_id);
      if (!conn || conn.status === 'revoked') return null;
      const currentProviderScopes = JSON.parse(conn.provider_scopes_json) as string[];
      if (!scopeSetsEqual(currentProviderScopes, reported)) {
        this.update('link_connections', 'id', conn.id, {
          provider_scopes_json: JSON.stringify(reported),
          version: conn.version + 1,
          updated_at: now,
        });
      }
      const grant = this.grantRowForConnection(conn.id);
      let previous: string[] | null = null;
      if (grant) {
        previous = JSON.parse(grant.scopes_json) as string[];
        const next = intersectScopes(previous, allowedGrantScopes(conn.provider as LinkProviderSlug, reported));
        if (!scopeSetsEqual(previous, next)) {
          this.update('link_grants', 'id', grant.id, {
            scopes_json: JSON.stringify(next),
            version: grant.version + 1,
            updated_at: now,
          });
        }
      }
      const g = this.grantRowForConnection(conn.id);
      return {
        connection: rowToConnection(this.connRow(conn.id) as ConnectionRow),
        grant: g ? rowToGrant(g) : null,
        previous_grant_scopes: previous,
      };
    });
  }

  // ── Grants ────────────────────────────────────────────────────────────────

  async getGrant(grant_id: string): Promise<ClientGrant | null> {
    const row = this.grantRowById(grant_id);
    return row ? rowToGrant(row) : null;
  }

  async getGrantForConnection(connection_id: string): Promise<ClientGrant | null> {
    const row = this.grantRowForConnection(connection_id);
    return row ? rowToGrant(row) : null;
  }

  async listGrants(input: { client_id: string; audience: string; subject: string }): Promise<ClientGrant[]> {
    const rows = this.db.prepare(`
      SELECT * FROM link_grants WHERE client_id = ? AND audience = ? AND subject = ?
      ORDER BY granted_at DESC, rowid DESC
    `).all(input.client_id, input.audience, input.subject) as GrantRow[];
    return rows.map(rowToGrant);
  }

  async narrowGrant(input: { grant_id: string; scopes: string[]; expected_version?: number; now: string }): Promise<{
    grant: ClientGrant;
    previous_scopes: string[];
  } | null> {
    const now = iso(input.now, 'now');
    const wanted = JSON.parse(scopesJson(input.scopes, 'scopes')) as string[];
    return this.write(() => {
      const grant = this.grantRowById(input.grant_id);
      if (!grant || grant.status !== 'active') return null;
      if (input.expected_version !== undefined && input.expected_version !== grant.version) return null;
      const previous = JSON.parse(grant.scopes_json) as string[];
      const next = intersectScopes(previous, wanted);
      if (!scopeSetsEqual(previous, next)) {
        this.update('link_grants', 'id', grant.id, {
          scopes_json: JSON.stringify(next),
          version: grant.version + 1,
          updated_at: now,
        });
      }
      return { grant: rowToGrant(this.grantRowById(grant.id) as GrantRow), previous_scopes: previous };
    });
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function cookieMatches(row: TransactionRow, presented: string | null): boolean {
  return row.binding_cookie_hash !== null
    && typeof presented === 'string'
    && presented !== ''
    && presented === row.binding_cookie_hash;
}

/**
 * Narrowing at authorize can only remove: providers are intersected with the
 * pushed list, scopes with the pushed scopes. A provider absent from the
 * narrowed scope map keeps its pushed scopes. Required scopes are locked
 * (spec 2) and stay in requested_scopes, preserving required ⊆ requested.
 */
function narrow(
  tx: LinkTransaction,
  providers: LinkProviderSlug[],
  scopes: LinkScopeMap,
): { providers: LinkProviderSlug[]; requested_scopes: LinkScopeMap } {
  const keptProviders = tx.providers.filter((p) => providers.includes(p));
  const requested: LinkScopeMap = {};
  for (const p of keptProviders) {
    const pushed = tx.requested_scopes[p];
    if (pushed === undefined) continue;
    const asked = scopes[p];
    const base = asked === undefined ? pushed : intersectScopes(asked, pushed);
    requested[p] = unionScopes(base, intersectScopes(tx.required_scopes[p] ?? [], pushed));
  }
  return { providers: keptProviders, requested_scopes: requested };
}

function patchFields(patch: LinkTransactionPatch): Partial<Record<keyof TransactionRow, unknown>> {
  const out: Partial<Record<keyof TransactionRow, unknown>> = {};
  const has = (k: keyof LinkTransactionPatch): boolean => Object.prototype.hasOwnProperty.call(patch, k) && patch[k] !== undefined;

  if (has('provider')) {
    if (patch.provider !== null && !isLinkProviderSlug(patch.provider)) {
      throw new LinkStoreError('invalid_input', 'patch.provider is not a Link provider');
    }
    out.provider = patch.provider;
  }
  if (has('selected_scopes')) {
    out.selected_scopes_json = patch.selected_scopes === null ? null : scopesJson(patch.selected_scopes, 'selected_scopes');
  }
  if (has('provider_requested_scopes')) {
    out.provider_requested_scopes_json = patch.provider_requested_scopes === null
      ? null
      : scopesJson(patch.provider_requested_scopes, 'provider_requested_scopes');
  }
  if (has('provider_granted_scopes')) {
    out.provider_granted_scopes_json = patch.provider_granted_scopes === null
      ? null
      : scopesJson(patch.provider_granted_scopes, 'provider_granted_scopes');
  }
  if (has('pkce_verifier')) out.pkce_verifier = optString(patch.pkce_verifier, 'pkce_verifier');
  if (has('provider_account_id')) out.provider_account_id = optString(patch.provider_account_id, 'provider_account_id');
  if (has('account_label')) out.account_label = patch.account_label === null ? null : String(patch.account_label);
  if (has('instance_url')) out.instance_url = optString(patch.instance_url, 'instance_url');
  if (has('exchanged_at')) out.exchanged_at = patch.exchanged_at === null ? null : iso(patch.exchanged_at, 'exchanged_at');
  if (has('provider_attempt')) {
    const n = patch.provider_attempt === null ? 0 : patch.provider_attempt;
    if (typeof n !== 'number' || !Number.isInteger(n) || n < 0) {
      throw new LinkStoreError('invalid_input', 'provider_attempt must be a non-negative integer');
    }
    out.provider_attempt = n;
  }
  return out;
}

import Database from 'better-sqlite3';
import { closeSync, lstatSync, openSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { randomUUID } from 'node:crypto';
import { parseConstraints, constraintsSubsume, constraintTypeOf, type DelegationConstraint } from '@credninja/attenuation';
import { closedFields, frozenOperation, operationFingerprint, type PreparedBudgetOperation, type FrozenBudgetOperation } from './budget-operation.js';
export { prepareBudgetOperation } from './budget-operation.js';
export type { PreparedBudgetOperation, FrozenBudgetOperation, BudgetOperationInput } from './budget-operation.js';

export interface BudgetConnectionRegistration {
  issuer: string; tenant: string; subject: string; provider: string; connectionId: string; epoch: number;
}
export interface BudgetGrantRegistration extends BudgetConnectionRegistration {
  grantId: string; policyVersion: string; connectionEpoch: number; maxCalls: number;
}
/** Authenticated and chain/scope-validated by the trusted host, not an HTTP body. */
export interface BudgetAuthenticatedContext {
  issuer: string; tenant: string; grantId: string; tokenId: string; subject: string; holder: string;
  provider: string; connectionId: string; policyVersion: string; grantEpoch: number; connectionEpoch: number;
}
export interface BudgetTokenRegistration extends BudgetAuthenticatedContext {
  parentId: string | null; expiresAt: number; constraints: readonly DelegationConstraint[];
}
export type BudgetRequestState = 'reserved' | 'dispatch_claimed' | 'finalized' | 'indeterminate' | 'cancelled';
export interface BudgetOutcome { reference: string; status?: number }
export interface BudgetRequest {
  requestKey: string; state: BudgetRequestState; outcome?: BudgetOutcome; reason?: string;
}
export interface BudgetDispatchFence { readonly requestKey: string; readonly executor: string; readonly fence: string }
export interface BudgetAccount {
  owner: string; type: string; bound: number; reserved: number; charged: number;
}
type AccountRow = BudgetAccount & { issuer: string; tenant: string; grant_id: string };
type RequestRow = {
  request_key: string; context: string; fingerprint: string; state: BudgetRequestState;
  executor: string | null; fence: string | null; outcome: string | null; reason: string | null;
};

const MAX = Number.MAX_SAFE_INTEGER;
function integer(value: unknown): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new BudgetAdmissionError('invalid_integer');
}
function text(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !value || value.length > 1024 || /[\u0000-\u001f]/u.test(value)) throw new BudgetAdmissionError('invalid_identity');
}
const CONTEXT_FIELDS = ['issuer', 'tenant', 'grantId', 'tokenId', 'subject', 'holder', 'provider', 'connectionId', 'policyVersion', 'grantEpoch', 'connectionEpoch'];
function contextOf(input: BudgetAuthenticatedContext, token = false): BudgetAuthenticatedContext {
  closedFields(input, token ? [...CONTEXT_FIELDS, 'parentId', 'expiresAt', 'constraints'] : CONTEXT_FIELDS);
  const { issuer, tenant, grantId, tokenId, subject, holder, provider, connectionId, policyVersion, grantEpoch, connectionEpoch } = input;
  for (const value of [issuer, tenant, grantId, tokenId, subject, holder, provider, connectionId, policyVersion]) text(value);
  integer(grantEpoch); integer(connectionEpoch);
  return { issuer, tenant, grantId, tokenId, subject, holder, provider, connectionId, policyVersion, grantEpoch, connectionEpoch };
}
function tokenKey(input: BudgetAuthenticatedContext): [string, string, string, string] {
  return [input.issuer, input.tenant, input.grantId, input.tokenId];
}
function dispatchOf(input: BudgetDispatchFence): BudgetDispatchFence {
  closedFields(input, ['requestKey', 'executor', 'fence']);
  const { requestKey, executor, fence } = input;
  text(requestKey); text(executor); text(fence);
  return { requestKey, executor, fence };
}
function safeOutcome(outcome: BudgetOutcome): BudgetOutcome {
  closedFields(outcome, ['reference', 'status']);
  if (typeof outcome.reference !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(outcome.reference)
    || (outcome.status !== undefined && (!Number.isInteger(outcome.status) || outcome.status < 100 || outcome.status > 599))) throw new BudgetAdmissionError('invalid_outcome');
  return { reference: outcome.reference, ...(outcome.status === undefined ? {} : { status: outcome.status }) };
}
function view(row: RequestRow): BudgetRequest {
  return { requestKey: row.request_key, state: row.state,
    ...(row.outcome ? { outcome: JSON.parse(row.outcome) as BudgetOutcome } : {}),
    ...(row.reason ? { reason: row.reason } : {}) };
}

const SCHEMA = [
  `CREATE TABLE admission_connections (
    issuer TEXT NOT NULL, tenant TEXT NOT NULL, provider TEXT NOT NULL, connection_id TEXT NOT NULL,
    metadata TEXT NOT NULL, epoch INTEGER NOT NULL CHECK (epoch BETWEEN 0 AND ${MAX}),
    PRIMARY KEY (issuer, tenant, provider, connection_id)
  )`,
  `CREATE TABLE admission_grants (
    issuer TEXT NOT NULL, tenant TEXT NOT NULL, grant_id TEXT NOT NULL, metadata TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch BETWEEN 0 AND ${MAX}), revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0,1)),
    PRIMARY KEY (issuer, tenant, grant_id)
  )`,
  `CREATE TABLE admission_tokens (
    issuer TEXT NOT NULL, tenant TEXT NOT NULL, grant_id TEXT NOT NULL, token_id TEXT NOT NULL,
    metadata TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0,1)),
    PRIMARY KEY (issuer, tenant, grant_id, token_id),
    FOREIGN KEY (issuer, tenant, grant_id) REFERENCES admission_grants (issuer, tenant, grant_id)
  )`,
  `CREATE TABLE admission_accounts (
    issuer TEXT NOT NULL, tenant TEXT NOT NULL, grant_id TEXT NOT NULL, owner TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('grant','max_lifetime','max_subtree')),
    bound INTEGER NOT NULL CHECK (typeof(bound) = 'integer' AND bound BETWEEN 0 AND ${MAX}),
    reserved INTEGER NOT NULL DEFAULT 0 CHECK (typeof(reserved) = 'integer' AND reserved BETWEEN 0 AND ${MAX}),
    charged INTEGER NOT NULL DEFAULT 0 CHECK (typeof(charged) = 'integer' AND charged BETWEEN 0 AND ${MAX}),
    CHECK (reserved <= bound - charged),
    PRIMARY KEY (issuer, tenant, grant_id, owner, type),
    FOREIGN KEY (issuer, tenant, grant_id) REFERENCES admission_grants (issuer, tenant, grant_id)
  )`,
  `CREATE TABLE admission_requests (
    issuer TEXT NOT NULL, request_key TEXT NOT NULL, context TEXT NOT NULL, fingerprint TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved','dispatch_claimed','finalized','indeterminate','cancelled')),
    executor TEXT, fence TEXT, outcome TEXT, reason TEXT,
    PRIMARY KEY (issuer, request_key)
  )`,
  `CREATE TABLE admission_request_accounts (
    issuer TEXT NOT NULL, request_key TEXT NOT NULL, tenant TEXT NOT NULL, grant_id TEXT NOT NULL, owner TEXT NOT NULL, type TEXT NOT NULL,
    PRIMARY KEY (issuer, request_key, tenant, grant_id, owner, type),
    FOREIGN KEY (issuer, request_key) REFERENCES admission_requests (issuer, request_key),
    FOREIGN KEY (issuer, tenant, grant_id, owner, type) REFERENCES admission_accounts (issuer, tenant, grant_id, owner, type)
  )`,
  `CREATE TABLE admission_transitions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, issuer TEXT NOT NULL, request_key TEXT NOT NULL, event TEXT NOT NULL
  )`,
];

export class BudgetAdmissionError extends Error {
  constructor(public readonly code: string, detail = code) {
    super(`${code}: ${detail}`);
    this.name = 'BudgetAdmissionError';
  }
}

export interface DurableBudgetStoreOptions {
  /** Absolute path to a durable file on a supported single-host local filesystem. */
  path: string;
  issuer: string;
  /** Must be supplied by the trusted deployment, never inferred from the DB. */
  deploymentEpoch: string;
  /** Exclusive creation only. Existing stores are never initialized or repaired. */
  initialize?: 'new';
  busyTimeoutMs?: number;
}

const META_SCHEMA = `CREATE TABLE admission_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  version INTEGER NOT NULL,
  issuer TEXT NOT NULL,
  deployment_epoch TEXT NOT NULL
)`;

/** Separate from the legacy cumulative ledger; no HTTP routes use this store. */
export class DurableBudgetStore {
  private readonly db: Database.Database;
  private readonly path: string;
  private readonly device: number;
  private readonly inode: number;
  readonly issuer: string;

  constructor(options: DurableBudgetStoreOptions) {
    if (!options || typeof options.path !== 'string' || !isAbsolute(options.path)) {
      throw new BudgetAdmissionError('durable_path', 'An absolute durable file path is required');
    }
    closedFields(options, ['path', 'issuer', 'deploymentEpoch', 'initialize', 'busyTimeoutMs']);
    if (options.initialize !== undefined && options.initialize !== 'new') throw new BudgetAdmissionError('invalid_initialize');
    text(options.issuer); text(options.deploymentEpoch);
    const timeout = options.busyTimeoutMs ?? 5000;
    if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > 60000) throw new BudgetAdmissionError('invalid_timeout');
    this.path = options.path;
    this.issuer = options.issuer;
    let db: Database.Database | undefined;
    try {
      if (options.initialize === 'new') closeSync(openSync(options.path, 'wx', 0o600));
      const stat = lstatSync(options.path);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new BudgetAdmissionError('durable_path');
      this.device = stat.dev;
      this.inode = stat.ino;
      db = new Database(options.path, { fileMustExist: true, timeout });
      this.db = db;
      if (options.initialize === 'new') db.pragma('journal_mode = WAL');
      else if (db.pragma('journal_mode', { simple: true }) !== 'wal') throw new BudgetAdmissionError('store_incompatible');
      db.pragma('synchronous = FULL');
      db.pragma(`busy_timeout = ${timeout}`);
      db.pragma('foreign_keys = ON');
      if (options.initialize === 'new') {
        db.transaction(() => {
          db!.exec([META_SCHEMA, ...SCHEMA].join(';'));
          db!.prepare('INSERT INTO admission_meta VALUES (1, 1, ?, ?)').run(options.issuer, options.deploymentEpoch);
          db!.pragma('user_version = 1');
        }).immediate();
      }
      const meta = db.prepare('SELECT * FROM admission_meta').all() as Array<{ version: number; issuer: string; deployment_epoch: string }>;
      if (meta.length !== 1 || meta[0].version !== 1 || meta[0].issuer !== options.issuer
        || meta[0].deployment_epoch !== options.deploymentEpoch || db.pragma('user_version', { simple: true }) !== 1) {
        throw new BudgetAdmissionError('store_incompatible');
      }
      const normalize = (sql: string) => sql.replace(/\s+/g, ' ').trim();
      const schema = db.prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*'").all() as Array<{ sql: string }>;
      if (JSON.stringify(schema.map(row => normalize(row.sql)).sort()) !== JSON.stringify([META_SCHEMA, ...SCHEMA].map(normalize).sort())
        || (db.pragma('foreign_key_check') as unknown[]).length !== 0
        || db.pragma('journal_mode', { simple: true }) !== 'wal'
        || db.pragma('synchronous', { simple: true }) !== 2
        || db.pragma('quick_check', { simple: true }) !== 'ok') throw new BudgetAdmissionError('store_incompatible');
    } catch (error) {
      db?.close();
      if (error instanceof BudgetAdmissionError) throw error;
      throw new BudgetAdmissionError('store_unavailable');
    }
  }

  private transaction<T>(action: () => T): T {
    try {
      const stat = lstatSync(this.path);
      if (!this.db.open || stat.dev !== this.device || stat.ino !== this.inode || !stat.isFile()) {
        throw new BudgetAdmissionError('store_unavailable');
      }
      return this.db.transaction(action).immediate();
    } catch (error) {
      if (error instanceof BudgetAdmissionError) throw error;
      throw new BudgetAdmissionError('store_unavailable');
    }
  }

  /** Trusted administrative authorization; do not expose to clients. */
  registerConnection(input: BudgetConnectionRegistration): void {
    closedFields(input, ['issuer', 'tenant', 'subject', 'provider', 'connectionId', 'epoch']);
    const { issuer, tenant, subject, provider, connectionId, epoch } = input;
    for (const value of [issuer, tenant, subject, provider, connectionId]) text(value);
    integer(epoch);
    this.checkIssuer(issuer);
    const metadata = JSON.stringify({ issuer, tenant, subject, provider, connectionId, epoch });
    this.transaction(() => {
      const old = this.db.prepare('SELECT metadata FROM admission_connections WHERE issuer=? AND tenant=? AND provider=? AND connection_id=?')
        .get(issuer, tenant, provider, connectionId) as { metadata: string } | undefined;
      if (old) { this.sameRegistration(old.metadata, metadata); return; }
      this.db.prepare('INSERT INTO admission_connections VALUES (?, ?, ?, ?, ?, ?)').run(issuer, tenant, provider, connectionId, metadata, epoch);
    });
  }

  /** Explicit new grant authorization, including its required continuity allowance. */
  registerGrant(input: BudgetGrantRegistration): void {
    closedFields(input, ['issuer', 'tenant', 'subject', 'provider', 'connectionId', 'epoch', 'grantId', 'policyVersion', 'connectionEpoch', 'maxCalls']);
    const { issuer, tenant, subject, provider, connectionId, epoch, grantId, policyVersion, connectionEpoch, maxCalls } = input;
    for (const value of [issuer, tenant, subject, provider, connectionId, grantId, policyVersion]) text(value);
    integer(epoch); integer(connectionEpoch); integer(maxCalls);
    this.checkIssuer(issuer);
    const metadata = JSON.stringify({ issuer, tenant, subject, provider, connectionId, epoch, grantId, policyVersion, connectionEpoch, maxCalls });
    this.transaction(() => {
      const old = this.db.prepare('SELECT metadata FROM admission_grants WHERE issuer=? AND tenant=? AND grant_id=?')
        .get(issuer, tenant, grantId) as { metadata: string } | undefined;
      if (old) { this.sameRegistration(old.metadata, metadata); return; }
      this.connectionAuthority({ ...input, connectionEpoch });
      this.db.prepare('INSERT INTO admission_grants (issuer,tenant,grant_id,metadata,epoch) VALUES (?,?,?,?,?)')
        .run(issuer, tenant, grantId, metadata, epoch);
      this.insertAccount({ issuer, tenant, grantId }, grantId, 'grant', maxCalls);
    });
  }

  registerToken(input: BudgetTokenRegistration): void {
    const context = contextOf(input, true);
    this.checkIssuer(context.issuer);
    integer(input.expiresAt);
    if (input.parentId !== null) text(input.parentId);
    const constraints = this.constraints(input.constraints);
    const metadata = JSON.stringify({ ...context, parentId: input.parentId, expiresAt: input.expiresAt, constraints });
    this.transaction(() => {
      const old = this.db.prepare('SELECT metadata FROM admission_tokens WHERE issuer=? AND tenant=? AND grant_id=? AND token_id=?')
        .get(...tokenKey(context)) as { metadata: string } | undefined;
      if (old) { this.sameRegistration(old.metadata, metadata); return; }
      this.grantAuthority(context);
      if (input.parentId !== null) {
        const parents = this.lineage(context, input.parentId, false);
        if (parents.length >= 64 || parents.some(p => p.tokenId === context.tokenId)) throw new BudgetAdmissionError('chain_incomplete');
        this.attenuates(parents[0], { ...context, parentId: input.parentId, expiresAt: input.expiresAt, constraints });
      }
      this.db.prepare('INSERT INTO admission_tokens (issuer,tenant,grant_id,token_id,metadata) VALUES (?,?,?,?,?)')
        .run(...tokenKey(context), metadata);
      for (const c of constraints) this.insertAccount(context, context.tokenId, constraintTypeOf(c), this.bound(c));
    });
  }

  reserve(input: BudgetAuthenticatedContext, requestKey: string, operation: PreparedBudgetOperation): BudgetRequest {
    const context = contextOf(input);
    this.checkIssuer(context.issuer);
    text(requestKey);
    const fingerprint = operationFingerprint(context, operation);
    return this.transaction(() => {
      const old = this.request(requestKey);
      if (old) { this.sameRequest(old, fingerprint, context); return view(old); }
      const accounts = this.authority(context);
      for (const account of accounts) {
        if (account.reserved >= account.bound - account.charged) throw new BudgetAdmissionError('budget_exceeded');
      }
      this.db.prepare('INSERT INTO admission_requests (issuer,request_key,context,fingerprint,state) VALUES (?,?,?,?,?)')
        .run(this.issuer, requestKey, JSON.stringify(context), fingerprint, 'reserved');
      for (const account of accounts) {
        this.db.prepare('UPDATE admission_accounts SET reserved=reserved+1 WHERE issuer=? AND tenant=? AND grant_id=? AND owner=? AND type=?')
          .run(account.issuer, account.tenant, account.grant_id, account.owner, account.type);
        this.db.prepare('INSERT INTO admission_request_accounts VALUES (?,?,?,?,?,?)')
          .run(this.issuer, requestKey, account.tenant, account.grant_id, account.owner, account.type);
      }
      this.event(requestKey, 'reserved');
      return view(this.request(requestKey)!);
    });
  }

  claim(input: BudgetAuthenticatedContext, requestKey: string, operation: PreparedBudgetOperation, executor: string): { request: BudgetRequest; dispatch?: BudgetDispatchFence } {
    const context = contextOf(input);
    this.checkIssuer(context.issuer);
    text(executor);
    const fingerprint = operationFingerprint(context, operation);
    return this.transaction(() => {
      const row = this.request(requestKey);
      if (!row) throw new BudgetAdmissionError('unknown_request');
      this.sameRequest(row, fingerprint, context);
      if (row.state !== 'reserved') return { request: view(row) };
      let accounts: AccountRow[];
      try { accounts = this.authority(context); }
      catch (error) {
        if (!(error instanceof BudgetAdmissionError) || !['revoked', 'expired', 'authority_mismatch'].includes(error.code)) throw error;
        return { request: this.cancelReserved(context, row, error.code) };
      }
      this.checkReservation(row, accounts);
      for (const account of accounts) {
        if (account.reserved < 1) throw new BudgetAdmissionError('account_corrupt');
        this.db.prepare('UPDATE admission_accounts SET reserved=reserved-1,charged=charged+1 WHERE issuer=? AND tenant=? AND grant_id=? AND owner=? AND type=?')
          .run(account.issuer, account.tenant, account.grant_id, account.owner, account.type);
      }
      const fence = randomUUID();
      this.db.prepare("UPDATE admission_requests SET state='dispatch_claimed',executor=?,fence=? WHERE issuer=? AND request_key=?")
        .run(executor, fence, this.issuer, requestKey);
      this.event(requestKey, 'dispatch_claimed');
      return { request: view(this.request(requestKey)!), dispatch: Object.freeze({ requestKey, executor, fence }) };
    });
  }

  finalize(dispatch: BudgetDispatchFence, outcome: BudgetOutcome): BudgetRequest {
    const { requestKey, executor, fence } = dispatchOf(dispatch);
    const serialized = JSON.stringify(safeOutcome(outcome));
    return this.transaction(() => {
      const row = this.request(requestKey);
      if (!row || row.executor !== executor || row.fence !== fence) throw new BudgetAdmissionError('stale_executor');
      if (row.state === 'finalized') {
        if (row.outcome !== serialized) throw new BudgetAdmissionError('outcome_conflict');
        return view(row);
      }
      if (row.state !== 'dispatch_claimed') throw new BudgetAdmissionError('invalid_transition');
      this.db.prepare("UPDATE admission_requests SET state='finalized',outcome=? WHERE issuer=? AND request_key=?")
        .run(serialized, this.issuer, requestKey);
      this.event(requestKey, 'finalized');
      return view(this.request(requestKey)!);
    });
  }

  markIndeterminate(dispatch: BudgetDispatchFence): BudgetRequest {
    const { requestKey, executor, fence } = dispatchOf(dispatch);
    return this.transaction(() => {
      const row = this.request(requestKey);
      if (!row || row.executor !== executor || row.fence !== fence) throw new BudgetAdmissionError('stale_executor');
      // A lost finalization acknowledgement must not overwrite its committed outcome.
      if (row.state === 'finalized' || row.state === 'indeterminate') return view(row);
      if (row.state !== 'dispatch_claimed') throw new BudgetAdmissionError('invalid_transition');
      this.db.prepare("UPDATE admission_requests SET state='indeterminate' WHERE issuer=? AND request_key=?").run(this.issuer, requestKey);
      this.event(requestKey, 'indeterminate');
      return view(this.request(requestKey)!);
    });
  }

  /** Trusted administrative revocation, ordered with reserve and claim. */
  revokeToken(input: Pick<BudgetAuthenticatedContext, 'issuer' | 'tenant' | 'grantId' | 'tokenId'>): void {
    this.checkIssuer(input.issuer);
    const key = [input.issuer, input.tenant, input.grantId, input.tokenId];
    key.forEach(text);
    this.transaction(() => {
      const result = this.db.prepare('UPDATE admission_tokens SET revoked=1 WHERE issuer=? AND tenant=? AND grant_id=? AND token_id=?').run(...key);
      if (!result.changes) throw new BudgetAdmissionError('chain_incomplete');
      this.event(JSON.stringify(key), 'token_revoked');
    });
  }

  /** Trusted administrative change. Epochs only advance; they never replenish accounts. */
  advanceConnectionEpoch(input: Pick<BudgetConnectionRegistration, 'issuer' | 'tenant' | 'provider' | 'connectionId'>, expected: number, next: number): void {
    this.checkIssuer(input.issuer);
    integer(expected); integer(next);
    if (next <= expected) throw new BudgetAdmissionError('invalid_epoch');
    const key = [input.issuer, input.tenant, input.provider, input.connectionId]; key.forEach(text);
    this.transaction(() => {
      const result = this.db.prepare('UPDATE admission_connections SET epoch=? WHERE issuer=? AND tenant=? AND provider=? AND connection_id=? AND epoch=?')
        .run(next, ...key, expected);
      if (!result.changes) throw new BudgetAdmissionError('authority_mismatch');
      this.event(JSON.stringify(key), 'connection_epoch_advanced');
    });
  }

  advanceGrantEpoch(input: Pick<BudgetAuthenticatedContext, 'issuer' | 'tenant' | 'grantId'>, expected: number, next: number): void {
    this.checkIssuer(input.issuer);
    integer(expected); integer(next);
    if (next <= expected) throw new BudgetAdmissionError('invalid_epoch');
    const key = [input.issuer, input.tenant, input.grantId]; key.forEach(text);
    this.transaction(() => {
      const result = this.db.prepare('UPDATE admission_grants SET epoch=? WHERE issuer=? AND tenant=? AND grant_id=? AND epoch=? AND revoked=0')
        .run(next, ...key, expected);
      if (!result.changes) throw new BudgetAdmissionError('authority_mismatch');
      this.event(JSON.stringify(key), 'grant_epoch_advanced');
    });
  }

  revokeGrant(input: Pick<BudgetAuthenticatedContext, 'issuer' | 'tenant' | 'grantId'>): void {
    this.checkIssuer(input.issuer);
    const key = [input.issuer, input.tenant, input.grantId]; key.forEach(text);
    this.transaction(() => {
      const result = this.db.prepare('UPDATE admission_grants SET revoked=1 WHERE issuer=? AND tenant=? AND grant_id=?').run(...key);
      if (!result.changes) throw new BudgetAdmissionError('authority_mismatch');
      this.event(JSON.stringify(key), 'grant_revoked');
    });
  }

  cancel(input: BudgetAuthenticatedContext, requestKey: string, operation: PreparedBudgetOperation): BudgetRequest {
    const context = contextOf(input);
    this.checkIssuer(context.issuer);
    const fingerprint = operationFingerprint(context, operation);
    return this.transaction(() => {
      const row = this.request(requestKey);
      if (!row) throw new BudgetAdmissionError('unknown_request');
      this.sameRequest(row, fingerprint, context);
      return row.state === 'reserved' ? this.cancelReserved(context, row, 'cancelled_by_host') : view(row);
    });
  }

  private checkReservation(row: RequestRow, accounts: AccountRow[]): void {
    const refs = this.db.prepare('SELECT tenant,grant_id,owner,type FROM admission_request_accounts WHERE issuer=? AND request_key=?')
      .all(this.issuer, row.request_key) as Array<{ tenant: string; grant_id: string; owner: string; type: string }>;
    const key = (a: { tenant: string; grant_id: string; owner: string; type: string }) => JSON.stringify([a.tenant, a.grant_id, a.owner, a.type]);
    if (JSON.stringify(refs.map(key).sort()) !== JSON.stringify(accounts.map(key).sort()) || accounts.some(a => a.reserved < 1)) {
      throw new BudgetAdmissionError('reservation_corrupt');
    }
  }

  private cancelReserved(context: BudgetAuthenticatedContext, row: RequestRow, reason: string): BudgetRequest {
    const accounts = this.authority(context, false);
    this.checkReservation(row, accounts);
    for (const account of accounts) {
      this.db.prepare('UPDATE admission_accounts SET reserved=reserved-1 WHERE issuer=? AND tenant=? AND grant_id=? AND owner=? AND type=?')
        .run(account.issuer, account.tenant, account.grant_id, account.owner, account.type);
    }
    this.db.prepare("UPDATE admission_requests SET state='cancelled',reason=? WHERE issuer=? AND request_key=?")
      .run(reason, this.issuer, row.request_key);
    this.event(row.request_key, 'cancelled');
    return view(this.request(row.request_key)!);
  }

  accounts(input: BudgetAuthenticatedContext): BudgetAccount[] {
    const context = contextOf(input);
    this.checkIssuer(context.issuer);
    return this.transaction(() => this.authority(context).map(({ owner, type, bound, reserved, charged }) => ({ owner, type, bound, reserved, charged })));
  }

  private checkIssuer(issuer: string): void {
    if (issuer !== this.issuer) throw new BudgetAdmissionError('authority_mismatch');
  }
  private sameRegistration(old: string, replacement: string): void {
    if (old !== replacement) throw new BudgetAdmissionError('registration_conflict');
  }
  private sameRequest(row: RequestRow, fingerprint: string, context: BudgetAuthenticatedContext): void {
    if (row.fingerprint !== fingerprint || row.context !== JSON.stringify(context)) throw new BudgetAdmissionError('idempotency_conflict');
  }
  private request(key: string): RequestRow | undefined {
    const row = this.db.prepare('SELECT * FROM admission_requests WHERE issuer=? AND request_key=?').get(this.issuer, key) as RequestRow | undefined;
    if (!row) return undefined;
    try {
      const context = contextOf(JSON.parse(row.context));
      if (context.issuer !== this.issuer || JSON.stringify(context) !== row.context || !/^[a-f0-9]{64}$/.test(row.fingerprint)) throw new Error();
      if (!['reserved', 'dispatch_claimed', 'finalized', 'indeterminate', 'cancelled'].includes(row.state)) throw new Error();
      if (['dispatch_claimed', 'finalized', 'indeterminate'].includes(row.state)) {
        text(row.executor); text(row.fence);
      } else if (row.executor !== null || row.fence !== null) throw new Error();
      if (row.state === 'finalized') {
        if (row.outcome === null || JSON.stringify(safeOutcome(JSON.parse(row.outcome))) !== row.outcome) throw new Error();
      } else if (row.outcome !== null) throw new Error();
      if (row.state === 'cancelled') {
        if (!['cancelled_by_host', 'revoked', 'expired', 'authority_mismatch'].includes(row.reason!)) throw new Error();
      } else if (row.reason !== null) throw new Error();
    } catch { throw new BudgetAdmissionError('store_corrupt', 'Invalid request record'); }
    return row;
  }
  private event(key: string, event: string): void {
    this.db.prepare('INSERT INTO admission_transitions (issuer,request_key,event) VALUES (?,?,?)').run(this.issuer, key, event);
  }
  private connectionAuthority(context: { issuer: string; tenant: string; provider: string; connectionId: string; subject: string; connectionEpoch: number }, active = true): void {
    const row = this.db.prepare('SELECT metadata,epoch FROM admission_connections WHERE issuer=? AND tenant=? AND provider=? AND connection_id=?')
      .get(context.issuer, context.tenant, context.provider, context.connectionId) as { metadata: string; epoch: number } | undefined;
    if (!row) throw new BudgetAdmissionError('authority_mismatch');
    const connection = JSON.parse(row.metadata) as BudgetConnectionRegistration;
    closedFields(connection, ['issuer', 'tenant', 'subject', 'provider', 'connectionId', 'epoch']);
    integer(row.epoch); integer(connection.epoch);
    if (row.epoch < connection.epoch || (active && row.epoch !== context.connectionEpoch)
      || connection.issuer !== context.issuer || connection.tenant !== context.tenant || connection.subject !== context.subject
      || connection.provider !== context.provider || connection.connectionId !== context.connectionId) throw new BudgetAdmissionError('authority_mismatch');
  }
  private grantAuthority(context: BudgetAuthenticatedContext, active = true): BudgetGrantRegistration {
    const row = this.db.prepare('SELECT metadata,epoch,revoked FROM admission_grants WHERE issuer=? AND tenant=? AND grant_id=?')
      .get(context.issuer, context.tenant, context.grantId) as { metadata: string; epoch: number; revoked: number } | undefined;
    if (!row || (active && (row.epoch !== context.grantEpoch || row.revoked))) throw new BudgetAdmissionError('authority_mismatch');
    const grant = JSON.parse(row.metadata) as BudgetGrantRegistration;
    closedFields(grant, ['issuer', 'tenant', 'subject', 'provider', 'connectionId', 'epoch', 'grantId', 'policyVersion', 'connectionEpoch', 'maxCalls']);
    integer(row.epoch); integer(grant.epoch); integer(grant.connectionEpoch); integer(grant.maxCalls);
    if (row.epoch < grant.epoch || grant.issuer !== context.issuer || grant.tenant !== context.tenant || grant.grantId !== context.grantId
      || grant.subject !== context.subject || grant.provider !== context.provider || grant.connectionId !== context.connectionId
      || grant.policyVersion !== context.policyVersion || grant.connectionEpoch !== context.connectionEpoch) throw new BudgetAdmissionError('authority_mismatch');
    this.connectionAuthority(context, active);
    return grant;
  }
  private constraints(value: unknown): DelegationConstraint[] {
    if (!Array.isArray(value)) throw new BudgetAdmissionError('invalid_constraints', 'An explicit constraints array is required');
    const parsed = parseConstraints(value);
    if (!parsed.ok) throw new BudgetAdmissionError('invalid_constraints', parsed.message);
    for (const c of parsed.constraints) {
      const type = constraintTypeOf(c);
      if (c.key !== 'max_calls' || (type !== 'max_lifetime' && type !== 'max_subtree')) throw new BudgetAdmissionError('unsupported_constraint', `Cannot enforce ${c.key}/${type}`);
      integer(this.bound(c));
    }
    return parsed.constraints.sort((a, b) => constraintTypeOf(a).localeCompare(constraintTypeOf(b)));
  }
  private bound(c: DelegationConstraint): number {
    return (c as unknown as Record<string, number>)[constraintTypeOf(c)];
  }
  private insertAccount(context: { issuer: string; tenant: string; grantId: string }, owner: string, type: string, bound: number): void {
    this.db.prepare('INSERT INTO admission_accounts (issuer,tenant,grant_id,owner,type,bound) VALUES (?,?,?,?,?,?)')
      .run(context.issuer, context.tenant, context.grantId, owner, type, bound);
  }
  private account(context: BudgetAuthenticatedContext, owner: string, type: string, bound: number): AccountRow {
    const row = this.db.prepare('SELECT * FROM admission_accounts WHERE issuer=? AND tenant=? AND grant_id=? AND owner=? AND type=?')
      .get(context.issuer, context.tenant, context.grantId, owner, type) as AccountRow | undefined;
    if (!row || row.bound !== bound) throw new BudgetAdmissionError('account_corrupt');
    integer(row.bound); integer(row.reserved); integer(row.charged);
    if (row.reserved > row.bound - row.charged) throw new BudgetAdmissionError('account_corrupt');
    return row;
  }
  private authority(context: BudgetAuthenticatedContext, active = true): AccountRow[] {
    const grant = this.grantAuthority(context, active);
    const chain = this.lineage(context, context.tokenId, true, active);
    const accounts = [this.account(context, context.grantId, 'grant', grant.maxCalls)];
    for (const token of chain) {
      for (const c of token.constraints) {
        const type = constraintTypeOf(c);
        if (token.tokenId === context.tokenId || type === 'max_subtree') {
          accounts.push(this.account(context, token.tokenId, type, this.bound(c)));
        }
      }
    }
    return accounts;
  }

  private attenuates(parent: BudgetTokenRegistration, child: BudgetTokenRegistration): void {
    const result = constraintsSubsume(parent.constraints, child.constraints);
    if (!result.ok) throw new BudgetAdmissionError('invalid_attenuation', result.message);
    if (child.expiresAt > parent.expiresAt) throw new BudgetAdmissionError('invalid_attenuation', 'Child extends parent expiry');
  }

  private lineage(context: BudgetAuthenticatedContext, start: string, matchHolder: boolean, active = true): BudgetTokenRegistration[] {
    const chain: BudgetTokenRegistration[] = [];
    const seen = new Set<string>();
    let cursor: string | null = start;
    const now = Date.now();
    while (cursor !== null) {
      text(cursor);
      if (seen.has(cursor) || chain.length >= 64) throw new BudgetAdmissionError('chain_incomplete', 'Cyclic or excessive lineage');
      seen.add(cursor);
      const row = this.db.prepare('SELECT metadata,revoked FROM admission_tokens WHERE issuer=? AND tenant=? AND grant_id=? AND token_id=?')
        .get(context.issuer, context.tenant, context.grantId, cursor) as { metadata: string; revoked: number } | undefined;
      if (!row) throw new BudgetAdmissionError('chain_incomplete');
      const token = JSON.parse(row.metadata) as BudgetTokenRegistration;
      const expected = { ...context, tokenId: cursor, holder: chain.length === 0 && matchHolder ? context.holder : token.holder };
      if (JSON.stringify(contextOf(token, true)) !== JSON.stringify(expected)) throw new BudgetAdmissionError('authority_mismatch');
      integer(token.expiresAt);
      if (active && row.revoked) throw new BudgetAdmissionError('revoked');
      if (active && token.expiresAt <= now) throw new BudgetAdmissionError('expired');
      token.constraints = this.constraints(token.constraints);
      if (chain.length) this.attenuates(token, chain[chain.length - 1]);
      chain.push(token);
      cursor = token.parentId;
    }
    return chain;
  }

  close(): void {
    if (this.db.open) this.db.close();
  }
}

/** Transport is trusted host code; credentials are supplied there, never here. */
export async function executeBudgetedOperation(
  store: DurableBudgetStore, context: BudgetAuthenticatedContext, requestKey: string,
  operation: PreparedBudgetOperation, executor: string,
  transport: (operation: FrozenBudgetOperation, dispatch: BudgetDispatchFence) => Promise<BudgetOutcome>,
): Promise<BudgetRequest> {
  const reserved = store.reserve(context, requestKey, operation);
  if (reserved.state !== 'reserved') return reserved;
  const claim = store.claim(context, requestKey, operation, executor);
  if (!claim.dispatch) return claim.request;
  try {
    const outcome = await transport(frozenOperation(operation), claim.dispatch);
    return store.finalize(claim.dispatch, outcome);
  } catch {
    // Do not persist exception strings: provider errors can contain credentials/bodies.
    // If even this write fails, the claim remains charged and retries cannot send.
    return store.markIndeterminate(claim.dispatch);
  }
}

/**
 * Running totals for cumulative constraint ceilings.
 *
 * `max_lifetime` bounds the sum of a quantity over every exercise under one
 * token; `max_subtree` bounds it over the token and all its descendants
 * (draft-asor-wimse-agent-delegation-chain-02 Section 4.2). A chain holder
 * can check that a child's bound is no wider than its parent's, but only a
 * single writer can keep the totals: two holders debiting independently
 * would each see room the other already spent.
 * draft-sweeney-wimse-credential-delegation-02 "Constraint Ceilings" makes
 * the Delegation Server that writer: it checks and debits atomically when it
 * authorizes an exercise. This is that store.
 *
 * Model. Every delegation the server issues is registered with its parent
 * and the cumulative constraints it carries. An exercise under delegation D
 * with quantity q on key k is admitted only if, in one transaction:
 *
 *   - D's own `max_lifetime` on k, if any, has room for q, and
 *   - every `max_subtree` on k held by D or any ancestor of D has room for q.
 *
 * Then all of those totals move by q together, or none do. A token whose
 * chain names a parent the ledger does not hold is refused (its ancestors'
 * subtree totals are unknown, so a debit could overspend them).
 *
 * SQLite through better-sqlite3: transactions are synchronous and run under
 * BEGIN IMMEDIATE, so concurrent requests in one process serialize, and a
 * file-backed ledger shared by processes keeps one writer at a time.
 */
import Database from 'better-sqlite3';
import { CUMULATIVE_CONSTRAINT_TYPES, constraintTypeOf, type DelegationConstraint } from '@credninja/attenuation';

/** Longest parent chain walked on a debit; deeper chains are refused. */
const MAX_CHAIN = 64;

export interface CumulativeLedgerRegistration {
  /** Delegation id (receipt `delegationId` / token `jti`). */
  id: string;
  /** The parent delegation's id; absent for a root. */
  parentId?: string;
  /** The delegation's constraints; only `max_lifetime` and `max_subtree` are recorded. */
  constraints: readonly DelegationConstraint[];
}

export type CumulativeDebitResult =
  | { ok: true; debited: Array<{ tokenId: string; key: string; type: 'max_lifetime' | 'max_subtree'; total: number; bound: number }> }
  | {
    ok: false;
    reason: 'unknown_delegation' | 'chain_incomplete' | 'invalid_quantity' | 'exceeded';
    message: string;
    key?: string;
    type?: 'max_lifetime' | 'max_subtree';
    tokenId?: string;
    bound?: number;
    total?: number;
  };

export interface CumulativeLedger {
  /** Record a delegation and its cumulative bounds. Idempotent: a second registration of an id is ignored. */
  register(input: CumulativeLedgerRegistration): void;
  /** Whether the ledger holds a delegation. */
  has(id: string): boolean;
  /** Atomically check and debit `quantities` (key to amount) under delegation `id`. */
  debit(id: string, quantities: Readonly<Record<string, number>>): CumulativeDebitResult;
  /**
   * Give back a debit whose exercise never reached its upstream: each row a
   * successful debit moved, by the amount moved, never below zero.
   */
  refund(debited: ReadonlyArray<{ tokenId: string; key: string; type: 'max_lifetime' | 'max_subtree' }>, quantities: Readonly<Record<string, number>>): void;
  /** Current totals for one delegation, for audit and tests. */
  totals(id: string): Array<{ key: string; type: 'max_lifetime' | 'max_subtree'; total: number; bound: number }>;
  close(): void;
}

type BoundRow = { token_id: string; key: string; type: 'max_lifetime' | 'max_subtree'; bound: number; total: number };

export interface SqliteCumulativeLedgerOptions {
  /** SQLite file path, or ':memory:' (the default) for a ledger that lives as long as the process. */
  path?: string;
}

export class SqliteCumulativeLedger implements CumulativeLedger {
  private readonly db: import('better-sqlite3').Database;

  constructor(options: SqliteCumulativeLedgerOptions = {}) {
    this.db = new Database(options.path ?? ':memory:');
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cumulative_delegations (
        id TEXT PRIMARY KEY,
        parent_id TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cumulative_bounds (
        token_id TEXT NOT NULL,
        key TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('max_lifetime', 'max_subtree')),
        bound REAL NOT NULL,
        total REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (token_id, key, type)
      );
    `);
  }

  register(input: CumulativeLedgerRegistration): void {
    const insertDelegation = this.db.prepare('INSERT OR IGNORE INTO cumulative_delegations (id, parent_id, created_at) VALUES (?, ?, ?)');
    const insertBound = this.db.prepare('INSERT OR IGNORE INTO cumulative_bounds (token_id, key, type, bound) VALUES (?, ?, ?, ?)');
    this.db.transaction(() => {
      const inserted = insertDelegation.run(input.id, input.parentId ?? null, Date.now());
      if (inserted.changes === 0) return;
      for (const c of input.constraints) {
        const type = constraintTypeOf(c);
        if (!(CUMULATIVE_CONSTRAINT_TYPES as readonly string[]).includes(type)) continue;
        insertBound.run(input.id, c.key, type, type === 'max_lifetime' ? (c as { max_lifetime: number }).max_lifetime : (c as { max_subtree: number }).max_subtree);
      }
    }).immediate();
  }

  has(id: string): boolean {
    return this.db.prepare('SELECT 1 FROM cumulative_delegations WHERE id = ?').get(id) !== undefined;
  }

  debit(id: string, quantities: Readonly<Record<string, number>>): CumulativeDebitResult {
    for (const [key, amount] of Object.entries(quantities)) {
      if (typeof amount !== 'number' || !Number.isFinite(amount) || amount < 0) {
        return { ok: false, reason: 'invalid_quantity', key, message: `Quantity for '${key}' must be a finite non-negative number` };
      }
    }
    const parentOf = this.db.prepare('SELECT parent_id FROM cumulative_delegations WHERE id = ?');
    const boundsOf = this.db.prepare('SELECT token_id, key, type, bound, total FROM cumulative_bounds WHERE token_id = ? AND key = ?');
    const update = this.db.prepare('UPDATE cumulative_bounds SET total = total + ? WHERE token_id = ? AND key = ? AND type = ?');

    return this.db.transaction((): CumulativeDebitResult => {
      // Walk D and its ancestors, D first.
      const chain: string[] = [];
      let cursor: string | null = id;
      while (cursor !== null) {
        if (chain.includes(cursor) || chain.length >= MAX_CHAIN) {
          return { ok: false, reason: 'chain_incomplete', tokenId: cursor, message: 'Delegation chain is cyclic or too deep' };
        }
        const row = parentOf.get(cursor) as { parent_id: string | null } | undefined;
        if (!row) {
          return chain.length === 0
            ? { ok: false, reason: 'unknown_delegation', tokenId: id, message: `Delegation ${id} is not held by this ledger` }
            : { ok: false, reason: 'chain_incomplete', tokenId: cursor, message: `Ancestor ${cursor} is not held by this ledger; its running totals are unknown` };
        }
        chain.push(cursor);
        cursor = row.parent_id;
      }

      const touched: BoundRow[] = [];
      for (const [key, amount] of Object.entries(quantities)) {
        for (const tokenId of chain) {
          for (const row of boundsOf.all(tokenId, key) as BoundRow[]) {
            // max_lifetime counts exercises under the token itself only.
            if (row.type === 'max_lifetime' && tokenId !== id) continue;
            if (row.total + amount > row.bound) {
              return {
                ok: false,
                reason: 'exceeded',
                key,
                type: row.type,
                tokenId,
                bound: row.bound,
                total: row.total,
                message: `${row.type} on '${key}' for ${tokenId}: ${row.total} + ${amount} exceeds ${row.bound}`,
              };
            }
            touched.push({ ...row, total: row.total + amount });
          }
        }
      }
      // Every bound checked; only now move the totals, all in this transaction.
      for (const r of touched) update.run(quantities[r.key]!, r.token_id, r.key, r.type);
      return {
        ok: true,
        debited: touched.map((r) => ({ tokenId: r.token_id, key: r.key, type: r.type, total: r.total, bound: r.bound })),
      };
    }).immediate();
  }

  refund(debited: ReadonlyArray<{ tokenId: string; key: string; type: 'max_lifetime' | 'max_subtree' }>, quantities: Readonly<Record<string, number>>): void {
    const update = this.db.prepare('UPDATE cumulative_bounds SET total = MAX(0, total - ?) WHERE token_id = ? AND key = ? AND type = ?');
    this.db.transaction(() => {
      for (const row of debited) {
        const amount = quantities[row.key];
        if (typeof amount === 'number' && Number.isFinite(amount) && amount > 0) update.run(amount, row.tokenId, row.key, row.type);
      }
    }).immediate();
  }

  totals(id: string): Array<{ key: string; type: 'max_lifetime' | 'max_subtree'; total: number; bound: number }> {
    return (this.db.prepare('SELECT key, type, bound, total FROM cumulative_bounds WHERE token_id = ? ORDER BY key, type').all(id) as BoundRow[])
      .map((r) => ({ key: r.key, type: r.type, total: r.total, bound: r.bound }));
  }

  close(): void {
    this.db.close();
  }
}

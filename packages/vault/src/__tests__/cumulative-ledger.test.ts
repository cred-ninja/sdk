import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteCumulativeLedger } from '../cumulative-ledger.js';

const ROOT = [
  { key: 'max_calls', max_lifetime: 5 },
  { key: 'max_spend', max: 100 },
  { key: 'max_spend', max_subtree: 100 },
];

describe('SqliteCumulativeLedger', () => {
  let ledger: SqliteCumulativeLedger;
  afterEach(() => ledger?.close());

  it('debits max_lifetime per token and refuses past the bound', () => {
    ledger = new SqliteCumulativeLedger();
    ledger.register({ id: 'r', constraints: ROOT });
    for (let i = 0; i < 5; i++) expect(ledger.debit('r', { max_calls: 1 }).ok).toBe(true);
    expect(ledger.debit('r', { max_calls: 1 })).toMatchObject({ ok: false, reason: 'exceeded', key: 'max_calls', type: 'max_lifetime', bound: 5, total: 5 });
    expect(ledger.totals('r')).toEqual([
      { key: 'max_calls', type: 'max_lifetime', total: 5, bound: 5 },
      { key: 'max_spend', type: 'max_subtree', total: 0, bound: 100 },
    ]);
  });

  it('debits max_subtree on every ancestor, so siblings share the parent budget', () => {
    ledger = new SqliteCumulativeLedger();
    ledger.register({ id: 'r', constraints: ROOT });
    ledger.register({ id: 'a', parentId: 'r', constraints: [{ key: 'max_spend', max_subtree: 80 }] });
    ledger.register({ id: 'b', parentId: 'r', constraints: [{ key: 'max_spend', max_subtree: 80 }] });
    expect(ledger.debit('a', { max_spend: 60 }).ok).toBe(true);
    // b's own bound has room (0 + 50 <= 80) but the root's does not (60 + 50 > 100).
    expect(ledger.debit('b', { max_spend: 50 })).toMatchObject({ ok: false, reason: 'exceeded', tokenId: 'r', type: 'max_subtree' });
    expect(ledger.debit('b', { max_spend: 40 }).ok).toBe(true);
    expect(ledger.totals('r').find((t) => t.key === 'max_spend')).toMatchObject({ total: 100 });
  });

  it('is all or nothing: a refused debit moves no total', () => {
    ledger = new SqliteCumulativeLedger();
    ledger.register({ id: 'r', constraints: ROOT });
    ledger.register({ id: 'c', parentId: 'r', constraints: [{ key: 'max_calls', max_lifetime: 1 }, { key: 'max_spend', max_subtree: 10 }] });
    expect(ledger.debit('c', { max_calls: 1, max_spend: 50 }).ok).toBe(false);
    expect(ledger.totals('c')).toEqual([
      { key: 'max_calls', type: 'max_lifetime', total: 0, bound: 1 },
      { key: 'max_spend', type: 'max_subtree', total: 0, bound: 10 },
    ]);
    expect(ledger.totals('r').every((t) => t.total === 0)).toBe(true);
  });

  it('does not count a child exercise against the parent max_lifetime', () => {
    ledger = new SqliteCumulativeLedger();
    ledger.register({ id: 'r', constraints: ROOT });
    ledger.register({ id: 'c', parentId: 'r', constraints: [{ key: 'max_calls', max_lifetime: 5 }] });
    for (let i = 0; i < 5; i++) expect(ledger.debit('c', { max_calls: 1 }).ok).toBe(true);
    expect(ledger.debit('r', { max_calls: 1 }).ok).toBe(true);
  });

  it('refuses unknown delegations, broken chains and bad quantities', () => {
    ledger = new SqliteCumulativeLedger();
    expect(ledger.debit('x', { max_calls: 1 })).toMatchObject({ ok: false, reason: 'unknown_delegation' });
    ledger.register({ id: 'orphan', parentId: 'gone', constraints: [{ key: 'max_calls', max_lifetime: 1 }] });
    expect(ledger.debit('orphan', { max_calls: 1 })).toMatchObject({ ok: false, reason: 'chain_incomplete', tokenId: 'gone' });
    ledger.register({ id: 'r', constraints: ROOT });
    expect(ledger.debit('r', { max_spend: -1 })).toMatchObject({ ok: false, reason: 'invalid_quantity' });
    expect(ledger.debit('r', { max_spend: Number.NaN })).toMatchObject({ ok: false, reason: 'invalid_quantity' });
  });

  it('keeps the first registration of an id', () => {
    ledger = new SqliteCumulativeLedger();
    ledger.register({ id: 'r', constraints: [{ key: 'max_calls', max_lifetime: 1 }] });
    ledger.register({ id: 'r', constraints: [{ key: 'max_calls', max_lifetime: 100 }] });
    expect(ledger.totals('r')).toEqual([{ key: 'max_calls', type: 'max_lifetime', total: 0, bound: 1 }]);
  });

  it('persists totals in a file-backed ledger', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cred-ledger-'));
    try {
      const path = join(dir, 'ledger.db');
      ledger = new SqliteCumulativeLedger({ path });
      ledger.register({ id: 'r', constraints: ROOT });
      expect(ledger.debit('r', { max_calls: 3 }).ok).toBe(true);
      ledger.close();
      ledger = new SqliteCumulativeLedger({ path });
      expect(ledger.debit('r', { max_calls: 3 })).toMatchObject({ ok: false, reason: 'exceeded', total: 3 });
    } finally {
      ledger.close();
      ledger = undefined as never;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/**
 * Tamper-evident audit chain (SQLite storage). Each audit row carries an
 * HMAC over the previous row's hash and its own stored fields, under a key
 * derived from the vault passphrase, so editing, deleting or reordering a
 * row is detected, and a copy of the database cannot be re-chained without
 * the passphrase.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import Database from 'better-sqlite3';
import { CredVault } from '../vault.js';
import { SQLiteBackend } from '../storage/sqlite.js';
import { AUDIT_CHAIN_FIELDS, auditChainGenesis, auditChainHash } from '../audit.js';
import type { AuditEvent, AuditRow } from '../audit.js';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function event(id: string, outcome: AuditEvent['outcome'] = 'success'): AuditEvent {
  return {
    id,
    timestamp: new Date(),
    actor: { type: 'agent', id: 'did:key:z6MkAgent' },
    action: 'delegate',
    resource: { type: 'token', id: 'google/alice' },
    outcome,
    correlationId: `corr_${id}`,
    metadata: { n: id },
  };
}

function insertUnchained(db: Database.Database, id: string): void {
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO vault_audit_events (id, timestamp, actor_type, actor_id, action, resource_type, resource_id, outcome, correlation_id, created_at)
    VALUES (?, ?, 'system', 'admin', 'revoke', 'token', 'google/alice', 'success', ?, ?)`).run(id, now, `corr_${id}`, now);
}

async function vaultWith(events: number, passphrase = 'audit-chain-test-passphrase') {
  const dir = mkdtempSync(join(tmpdir(), 'cred-audit-chain-'));
  dirs.push(dir);
  const path = join(dir, 'vault.db');
  const vault = new CredVault({ passphrase, storage: 'sqlite', path });
  await vault.init();
  for (let i = 1; i <= events; i++) vault.writeAuditEvent(event(`evt_${i}`));
  return { vault, path };
}

describe('tamper-evident audit chain', () => {
  it('chains every entry and verifies, reporting the head', async () => {
    const { vault } = await vaultWith(5);
    const result = vault.verifyAuditChain();
    expect(result).toMatchObject({ ok: true, entries: 5, unchained: 0 });
    expect(vault.auditChainHead()).toEqual(result.ok ? result.head : null);
    expect(vault.auditChainHead()!.seq).toBe(5);
  });

  it('detects an edited entry', async () => {
    const { vault, path } = await vaultWith(5);
    const db = new Database(path);
    db.prepare("UPDATE vault_audit_events SET outcome = 'denied' WHERE chain_seq = 3").run();
    db.close();
    expect(vault.verifyAuditChain()).toMatchObject({ ok: false, brokenAt: 3 });
  });

  it('detects a deleted entry, including the newest one against a recorded head', async () => {
    const { vault, path } = await vaultWith(5);
    const recordedHead = vault.auditChainHead();
    const db = new Database(path);
    db.prepare('DELETE FROM vault_audit_events WHERE chain_seq = 2').run();
    db.close();
    expect(vault.verifyAuditChain()).toMatchObject({ ok: false, brokenAt: 2 });

    const second = await vaultWith(5);
    const head = second.vault.auditChainHead();
    const db2 = new Database(second.path);
    db2.prepare('DELETE FROM vault_audit_events WHERE chain_seq = 5').run();
    db2.close();
    // Truncating the tail leaves a valid shorter chain: only a head recorded
    // elsewhere shows the loss.
    expect(recordedHead!.seq).toBe(5);
    expect(head!.seq).toBe(5);
    const after = second.vault.verifyAuditChain();
    expect(after).toMatchObject({ ok: true, entries: 4 });
    expect(after.ok && after.head!.seq).toBe(4);
    expect(after.ok && after.head!.hash).not.toBe(head!.hash);
  });

  it('detects reordered entries', async () => {
    const { vault, path } = await vaultWith(4);
    const db = new Database(path);
    db.exec('UPDATE vault_audit_events SET chain_seq = -1 WHERE chain_seq = 2');
    db.exec('UPDATE vault_audit_events SET chain_seq = 2 WHERE chain_seq = 3');
    db.exec('UPDATE vault_audit_events SET chain_seq = 3 WHERE chain_seq = -1');
    db.close();
    expect(vault.verifyAuditChain().ok).toBe(false);
  });

  it('cannot be re-chained from a copy of the database without the passphrase', async () => {
    const { vault, path } = await vaultWith(3);
    // An attacker with the file edits a row and recomputes every hash with a
    // key of their own: verification under the vault's key still fails.
    const forgedKey = Buffer.alloc(32, 9);
    const db = new Database(path);
    db.prepare("UPDATE vault_audit_events SET outcome = 'denied' WHERE chain_seq = 2").run();
    const rows = db.prepare('SELECT * FROM vault_audit_events ORDER BY chain_seq').all() as Array<AuditRow & { chain_seq: number }>;
    let previous = auditChainGenesis(0);
    for (const row of rows) {
      const hash = auditChainHash(forgedKey, previous, row.chain_seq, row);
      db.prepare('UPDATE vault_audit_events SET chain_hash = ? WHERE chain_seq = ?').run(hash, row.chain_seq);
      previous = hash;
    }
    db.close();
    expect(vault.verifyAuditChain()).toMatchObject({ ok: false, brokenAt: 1 });
  });

  it('counts rows written before the chain existed as unchained and chains new ones', async () => {
    const { vault, path } = await vaultWith(0);
    const db = new Database(path);
    insertUnchained(db, 'evt_legacy');
    db.close();
    vault.writeAuditEvent(event('evt_new'));
    expect(vault.verifyAuditChain()).toMatchObject({ ok: true, entries: 1, unchained: 1 });
  });

  it('detects an unchained row added after the chain started', async () => {
    const { vault, path } = await vaultWith(3);
    const db = new Database(path);
    insertUnchained(db, 'evt_forged');
    db.close();
    expect(vault.verifyAuditChain()).toMatchObject({ ok: false, brokenAt: 1, unchained: 1 });
  });

  it('detects the newest entries being un-chained instead of deleted', async () => {
    const { vault, path } = await vaultWith(5);
    const db = new Database(path);
    db.exec("UPDATE vault_audit_events SET chain_seq = NULL, chain_hash = NULL, outcome = 'denied' WHERE chain_seq >= 4");
    db.close();
    expect(vault.verifyAuditChain()).toMatchObject({ ok: false, brokenAt: 1, unchained: 2 });
  });

  it('detects rows from before the chain being removed or added', async () => {
    const { vault, path } = await vaultWith(0);
    const db = new Database(path);
    insertUnchained(db, 'evt_legacy_1');
    insertUnchained(db, 'evt_legacy_2');
    vault.writeAuditEvent(event('evt_new'));
    expect(vault.verifyAuditChain()).toMatchObject({ ok: true, unchained: 2 });
    db.prepare("DELETE FROM vault_audit_events WHERE id = 'evt_legacy_1'").run();
    db.close();
    expect(vault.verifyAuditChain()).toMatchObject({ ok: false, brokenAt: 1 });
  });

  it('upgrades a database written before the chain existed, in place and idempotently', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cred-audit-chain-'));
    dirs.push(dir);
    const path = join(dir, 'vault.db');
    // The audit table as releases before the chain created it.
    const db = new Database(path);
    db.exec(`CREATE TABLE vault_audit_events (
      id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, actor_type TEXT NOT NULL, actor_id TEXT NOT NULL,
      actor_fingerprint TEXT, action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL,
      outcome TEXT NOT NULL, delegation_chain TEXT, scopes_requested TEXT, scopes_granted TEXT,
      correlation_id TEXT NOT NULL, sensitive_hmac TEXT, metadata_json TEXT, error_message TEXT, created_at TEXT NOT NULL)`);
    insertUnchained(db, 'evt_old_1');
    insertUnchained(db, 'evt_old_2');
    db.close();

    const passphrase = 'audit-chain-test-passphrase';
    const first = new CredVault({ passphrase, storage: 'sqlite', path });
    await first.init();
    first.writeAuditEvent(event('evt_new_1'));
    // A second process (or a restart) opening the upgraded file.
    const second = new CredVault({ passphrase, storage: 'sqlite', path });
    await second.init();
    second.writeAuditEvent(event('evt_new_2'));
    expect(second.verifyAuditChain()).toMatchObject({ ok: true, entries: 2, unchained: 2 });
    expect(first.verifyAuditChain()).toMatchObject({ ok: true, entries: 2, unchained: 2 });
  });

  it('refuses to write an audit row that cannot join the chain', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cred-audit-chain-'));
    dirs.push(dir);
    const backend = new SQLiteBackend(join(dir, 'vault.db'));
    backend.init();
    expect(() => backend.writeAuditEvent(event('evt_1'))).toThrow(/Audit chain key not set/);
  });

  it('keeps the hash input stable, so existing chains still verify', () => {
    const row: AuditRow = {
      id: 'evt_pin', timestamp: '2026-10-30T00:00:00.000Z', actor_type: 'agent', actor_id: 'did:key:z6MkAgent',
      actor_fingerprint: null, action: 'delegate', resource_type: 'token', resource_id: 'google/alice', outcome: 'success',
      delegation_chain: '["a"]', scopes_requested: '["openid"]', scopes_granted: null, correlation_id: 'corr_pin',
      sensitive_hmac: null, metadata_json: '{"n":1}', error_message: null, created_at: '2026-10-30T00:00:01.000Z',
    };
    expect(auditChainHash(Buffer.alloc(32, 7), auditChainGenesis(0), 1, row)).toBe('Yxg0YKGq69LOBIf1RfQTtKtEWihd3RbA97CUMvvYJSE');
    // Every field distinct and non-null, so swapping any two changes the hash.
    const distinct = Object.fromEntries(AUDIT_CHAIN_FIELDS.map((field, i) => [field, `v${String(i + 1).padStart(2, '0')}`])) as unknown as AuditRow;
    expect(auditChainHash(Buffer.alloc(32, 7), auditChainGenesis(0), 1, distinct)).toBe('n-9eyumMc9s49AZPHGp9G0Uu8laY4pKtkItAPxbba2g');
  });

  it('hashes every column of the audit table', async () => {
    const { path } = await vaultWith(0);
    const db = new Database(path);
    const columns = (db.prepare('PRAGMA table_info(vault_audit_events)').all() as Array<{ name: string }>)
      .map((c) => c.name)
      .filter((name) => name !== 'chain_seq' && name !== 'chain_hash');
    db.close();
    expect(new Set(columns)).toEqual(new Set(AUDIT_CHAIN_FIELDS));
  });

  it('keeps one chain across a batch write and single writes', async () => {
    const { vault } = await vaultWith(2);
    vault.writeAuditEvents([event('evt_b1'), event('evt_b2'), event('evt_b3')]);
    vault.writeAuditEvent(event('evt_after'));
    expect(vault.verifyAuditChain()).toMatchObject({ ok: true, entries: 6 });
  });
});

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
import { AUDIT_CHAIN_GENESIS, auditChainHash } from '../audit.js';
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
    const after = second.vault.verifyAuditChain();
    expect(after.ok).toBe(true);
    expect(second.vault.auditChainHead()).not.toEqual(head);
    expect(recordedHead).not.toBeNull();
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
    let previous = AUDIT_CHAIN_GENESIS;
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
    db.prepare(`INSERT INTO vault_audit_events (id, timestamp, actor_type, actor_id, action, resource_type, resource_id, outcome, correlation_id, created_at)
      VALUES ('evt_legacy', ?, 'system', 'admin', 'revoke', 'token', 'google/alice', 'success', 'corr_legacy', ?)`).run(new Date().toISOString(), new Date().toISOString());
    db.close();
    vault.writeAuditEvent(event('evt_new'));
    expect(vault.verifyAuditChain()).toMatchObject({ ok: true, entries: 1, unchained: 1 });
  });

  it('refuses to write an audit row that cannot join the chain', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cred-audit-chain-'));
    dirs.push(dir);
    const backend = new SQLiteBackend(join(dir, 'vault.db'));
    backend.init();
    expect(() => backend.writeAuditEvent(event('evt_1'))).toThrow(/Audit chain key not set/);
  });

  it('keeps one chain across a batch write and single writes', async () => {
    const { vault } = await vaultWith(2);
    vault.writeAuditEvents([event('evt_b1'), event('evt_b2'), event('evt_b3')]);
    vault.writeAuditEvent(event('evt_after'));
    expect(vault.verifyAuditChain()).toMatchObject({ ok: true, entries: 6 });
  });
});

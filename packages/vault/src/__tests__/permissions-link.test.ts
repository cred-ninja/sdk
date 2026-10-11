import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import type { LinkPermissionPort, PermissionPort } from '@credninja/protocol';
import { SQLiteBackend } from '../storage/sqlite.js';
import { FileBackend } from '../storage/file.js';
import { PermissionStore, type CreatePermissionInput } from '../permissions.js';
import { CredVault } from '../vault.js';

const G = 'https://www.googleapis.com/auth/';

function input(overrides: Partial<CreatePermissionInput> = {}): CreatePermissionInput {
  return {
    agentId: 'agt_1',
    connectionId: 'conn_a1',
    allowedScopes: ['calendar.events', 'calendar.readonly', 'gmail.send'],
    requiresApproval: false,
    delegatable: false,
    maxDelegationDepth: 0,
    createdBy: 'link:acme',
    ...overrides,
  };
}

describe('Cred Link permission storage (SQLite)', () => {
  let tmpDir: string;
  let dbPath: string;
  let backend: SQLiteBackend;
  let store: PermissionStore;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cred-permissions-link-'));
    dbPath = join(tmpDir, 'vault.db');
    backend = new SQLiteBackend(dbPath);
    backend.init();
    store = new PermissionStore(backend);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('listForConnection', () => {
    it('returns every agent on the connection and nothing else', async () => {
      await store.create(input({ agentId: 'agt_1' }));
      await store.create(input({ agentId: 'agt_2', allowedScopes: ['gmail.send'] }));
      await store.create(input({ agentId: 'agt_1', connectionId: 'conn_b2' }));
      await store.create(input({ agentId: 'agt_3', connectionId: 'google' }));

      const list = await store.listForConnection('conn_a1');
      expect(list.map((p) => p.agentId).sort()).toEqual(['agt_1', 'agt_2']);
      expect(list.every((p) => p.connectionId === 'conn_a1')).toBe(true);
      expect(list.every((p) => p.createdAt instanceof Date)).toBe(true);
    });

    it('returns [] for a connection with no permissions', async () => {
      expect(await store.listForConnection('conn_none')).toEqual([]);
    });
  });

  describe('intersectForConnection', () => {
    it('narrows every permission on the connection and returns only the changed ones', async () => {
      const a = await store.create(input({ agentId: 'agt_1' }));
      const b = await store.create(input({ agentId: 'agt_2', allowedScopes: ['calendar.readonly'] }));
      const c = await store.create(input({ agentId: 'agt_3', allowedScopes: ['gmail.send'] }));
      const other = await store.create(input({ agentId: 'agt_1', connectionId: 'conn_b2' }));

      const changed = await store.intersectForConnection('conn_a1', ['calendar.readonly', 'drive']);

      expect(changed.map((p) => p.id).sort()).toEqual([a.id, c.id].sort());
      expect((await store.get('agt_1', 'conn_a1'))?.allowedScopes).toEqual(['calendar.readonly']);
      expect((await store.get('agt_2', 'conn_a1'))?.allowedScopes).toEqual(['calendar.readonly']);
      expect((await store.get('agt_3', 'conn_a1'))?.allowedScopes).toEqual([]);
      expect((await store.get('agt_1', 'conn_b2'))?.allowedScopes).toEqual(other.allowedScopes);
      expect((await store.get('agt_2', 'conn_a1'))?.updatedAt).toBe(b.updatedAt);
    });

    it('never widens', async () => {
      await store.create(input({ allowedScopes: ['calendar.readonly'] }));
      const changed = await store.intersectForConnection('conn_a1', ['calendar.readonly', 'gmail.send', 'drive']);
      expect(changed).toEqual([]);
      expect((await store.get('agt_1', 'conn_a1'))?.allowedScopes).toEqual(['calendar.readonly']);
    });

    it('compares canonically: Google long and short names are the same scope', async () => {
      await store.create(input({ agentId: 'agt_1', allowedScopes: [`${G}calendar.readonly`, `${G}gmail.send`] }));
      await store.create(input({ agentId: 'agt_2', allowedScopes: [`${G}calendar.readonly`] }));

      const changed = await store.intersectForConnection('conn_a1', ['calendar.readonly']);

      expect(changed.map((p) => p.agentId)).toEqual(['agt_1']);
      expect(changed[0].allowedScopes).toEqual(['calendar.readonly']);
      // Unchanged as a set, so left as stored.
      expect((await store.get('agt_2', 'conn_a1'))?.allowedScopes).toEqual([`${G}calendar.readonly`]);
    });

    it('bumps updated_at on changed rows and returns them as stored', async () => {
      const created = await store.create(input());
      await new Promise((r) => setTimeout(r, 5));
      const [changed] = await store.intersectForConnection('conn_a1', ['gmail.send']);
      expect(changed.id).toBe(created.id);
      expect(changed.updatedAt > created.updatedAt).toBe(true);
      const stored = await store.get('agt_1', 'conn_a1');
      expect(stored).toEqual(changed);
    });

    it('keeps the other columns intact', async () => {
      await store.create(input({ rateLimit: { maxRequests: 5, windowMs: 1000 }, ttlOverride: 60, delegatable: true, maxDelegationDepth: 2 }));
      const [changed] = await store.intersectForConnection('conn_a1', ['gmail.send']);
      expect(changed).toMatchObject({
        rateLimit: { maxRequests: 5, windowMs: 1000 },
        ttlOverride: 60,
        delegatable: true,
        maxDelegationDepth: 2,
        createdBy: 'link:acme',
      });
    });

    it('narrows an unparseable allowed_scopes row to [] (fail closed)', async () => {
      const created = await store.create(input());
      const db = new Database(dbPath);
      db.prepare('UPDATE vault_permissions SET allowed_scopes = ? WHERE id = ?').run('not json', created.id);
      db.close();

      const changed = await store.intersectForConnection('conn_a1', ['gmail.send']);
      expect(changed).toHaveLength(1);
      expect(changed[0].allowedScopes).toEqual([]);
    });

    it('is atomic: a failing write rolls back every row', async () => {
      // Rows are processed newest first, so agt_2 is rewritten before the
      // trigger aborts on agt_1; the rollback must undo agt_2's write.
      await store.create(input({ agentId: 'agt_1' }));
      await new Promise((r) => setTimeout(r, 5));
      await store.create(input({ agentId: 'agt_2' }));
      const db = new Database(dbPath);
      db.exec(`
        CREATE TRIGGER fail_last BEFORE UPDATE ON vault_permissions
        WHEN NEW.agent_id = 'agt_1'
        BEGIN SELECT RAISE(ABORT, 'boom'); END;
      `);
      db.close();

      await expect(store.intersectForConnection('conn_a1', ['gmail.send'])).rejects.toThrow(/boom/);
      expect((await store.get('agt_1', 'conn_a1'))?.allowedScopes).toEqual(['calendar.events', 'calendar.readonly', 'gmail.send']);
      expect((await store.get('agt_2', 'conn_a1'))?.allowedScopes).toEqual(['calendar.events', 'calendar.readonly', 'gmail.send']);
    });

    it('does not touch rate limit counters', async () => {
      const created = await store.create(input({ rateLimit: { maxRequests: 1, windowMs: 60_000 } }));
      const now = new Date();
      expect(await store.checkRateLimit(created.id, 1, 60_000, now)).toBe(true);
      await store.intersectForConnection('conn_a1', ['gmail.send']);
      expect(await store.checkRateLimit(created.id, 1, 60_000, now)).toBe(false);
    });
  });

  it('PermissionStore satisfies LinkPermissionPort structurally', () => {
    const port: LinkPermissionPort = store;
    const base: PermissionPort = store;
    expect(port).toBe(base);
    expect(store.supportsLinkPermissions()).toBe(true);
  });
});

describe('Cred Link permission storage (file backend)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cred-permissions-link-file-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('is explicitly not supported', async () => {
    const backend = new FileBackend(join(tmpDir, 'vault.json'));
    backend.init();
    const store = new PermissionStore(backend);
    expect(store.supportsLinkPermissions()).toBe(false);
    await expect(store.listForConnection('conn_a1')).rejects.toThrow('Permission storage not supported by this backend');
    await expect(store.intersectForConnection('conn_a1', [])).rejects.toThrow('Permission storage not supported by this backend');
  });
});

describe('CredVault Link permission methods', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cred-vault-link-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('getLinkPermissionPort works on a fresh vault without an explicit init()', async () => {
    const vault = new CredVault({ passphrase: 'pass', storage: 'sqlite', path: join(tmpDir, 'vault.db') });
    const port = vault.getLinkPermissionPort();

    expect(await port.get('agt_1', 'conn_a1')).toBeNull();
    const created = await port.create(input());
    expect(await port.list('agt_1')).toHaveLength(1);
    expect(await port.listForConnection('conn_a1')).toEqual([created]);

    const updated = await port.update(created.id, { allowedScopes: ['calendar.readonly', 'gmail.send'] });
    expect(updated.allowedScopes).toEqual(['calendar.readonly', 'gmail.send']);

    const changed = await port.intersectForConnection('conn_a1', [`${G}gmail.send`]);
    expect(changed).toHaveLength(1);
    expect(changed[0].allowedScopes).toEqual(['gmail.send']);

    await port.revoke(created.id);
    expect(await port.listForConnection('conn_a1')).toEqual([]);
  });

  it('the port and the vault see the same rows', async () => {
    const vault = new CredVault({ passphrase: 'pass', storage: 'sqlite', path: join(tmpDir, 'vault.db') });
    await vault.createPermission(input({ agentId: 'agt_9' }));
    const port = vault.getLinkPermissionPort();
    expect((await port.get('agt_9', 'conn_a1'))?.agentId).toBe('agt_9');
    await vault.intersectPermissionsForConnection('conn_a1', ['gmail.send']);
    expect((await vault.listPermissionsForConnection('conn_a1'))[0].allowedScopes).toEqual(['gmail.send']);
  });

  it('getLinkPermissionPort throws for a file vault', () => {
    const vault = new CredVault({ passphrase: 'pass', storage: 'file', path: join(tmpDir, 'vault.json') });
    expect(() => vault.getLinkPermissionPort()).toThrow('Link permission storage not supported by this backend');
  });
});

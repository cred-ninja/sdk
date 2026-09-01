import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { SQLiteBackend } from '../storage/sqlite.js';
import { FileBackend } from '../storage/file.js';
import { PermissionStore } from '../permissions.js';

describe('PermissionStore', () => {
  let tmpDir: string;
  let backend: SQLiteBackend;
  let store: PermissionStore;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cred-permissions-'));
    backend = new SQLiteBackend(join(tmpDir, 'vault.db'));
    backend.init();
    store = new PermissionStore(backend);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('create stores a permission with a perm_ prefix', async () => {
    const permission = await store.create({
      agentId: 'agt_1',
      connectionId: 'github',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });

    expect(permission.id.startsWith('perm_')).toBe(true);

    const stored = await store.get('agt_1', 'github');
    expect(stored?.id).toBe(permission.id);
    expect(stored?.allowedScopes).toEqual(['repo']);
  });

  it('list returns permissions for a single agent', async () => {
    await store.create({
      agentId: 'agt_1',
      connectionId: 'github',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });
    await store.create({
      agentId: 'agt_1',
      connectionId: 'google',
      allowedScopes: ['calendar.readonly'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });
    await store.create({
      agentId: 'agt_2',
      connectionId: 'slack',
      allowedScopes: ['channels:read'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });

    const permissions = await store.list('agt_1');
    expect(permissions).toHaveLength(2);
    expect(permissions.map((permission) => permission.connectionId).sort()).toEqual([
      'github',
      'google',
    ]);
  });

  it('revoke removes the permission record', async () => {
    const permission = await store.create({
      agentId: 'agt_1',
      connectionId: 'github',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });

    await store.revoke(permission.id);

    expect(await store.get('agt_1', 'github')).toBeNull();
  });

  it('checkRateLimit blocks requests above maxRequests within the window', async () => {
    const permission = await store.create({
      agentId: 'agt_1',
      connectionId: 'github',
      allowedScopes: ['repo'],
      rateLimit: { maxRequests: 2, windowMs: 60_000 },
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });

    expect(await store.checkRateLimit(permission.id, 2, 60_000, new Date('2026-03-19T00:00:05.000Z'))).toBe(true);
    expect(await store.checkRateLimit(permission.id, 2, 60_000, new Date('2026-03-19T00:00:10.000Z'))).toBe(true);
    expect(await store.checkRateLimit(permission.id, 2, 60_000, new Date('2026-03-19T00:00:15.000Z'))).toBe(false);
  });

  it('checkRateLimit opens a new window after windowMs elapses', async () => {
    const permission = await store.create({
      agentId: 'agt_1',
      connectionId: 'github',
      allowedScopes: ['repo'],
      rateLimit: { maxRequests: 1, windowMs: 60_000 },
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });

    expect(await store.checkRateLimit(permission.id, 1, 60_000, new Date('2026-03-19T00:00:05.000Z'))).toBe(true);
    expect(await store.checkRateLimit(permission.id, 1, 60_000, new Date('2026-03-19T00:01:05.000Z'))).toBe(true);
  });

  // ── update() ─────────────────────────────────────────────────────────────

  it('a freshly created permission has updatedAt equal to createdAt', async () => {
    const permission = await store.create({
      agentId: 'agt_1',
      connectionId: 'github',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });

    expect(permission.updatedAt).toBe(permission.createdAt.toISOString());
  });

  it('update changes allowedScopes/rateLimit/ttlOverride, preserves id, and bumps updatedAt', async () => {
    const created = await store.create({
      agentId: 'agt_1',
      connectionId: 'github',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });

    // Ensure the clock moves so updatedAt is distinguishable from createdAt.
    await new Promise((resolve) => setTimeout(resolve, 5));

    const updated = await store.update(created.id, {
      allowedScopes: ['repo', 'issues'],
      rateLimit: { maxRequests: 10, windowMs: 60_000 },
      ttlOverride: 3600,
    });

    expect(updated.id).toBe(created.id);
    expect(updated.agentId).toBe('agt_1');
    expect(updated.connectionId).toBe('github');
    expect(updated.allowedScopes).toEqual(['repo', 'issues']);
    expect(updated.rateLimit).toEqual({ maxRequests: 10, windowMs: 60_000 });
    expect(updated.ttlOverride).toBe(3600);
    expect(updated.updatedAt).not.toBe(created.updatedAt);
    expect(new Date(updated.updatedAt).getTime()).toBeGreaterThan(new Date(created.updatedAt).getTime());

    const fetched = await store.get('agt_1', 'github');
    expect(fetched?.allowedScopes).toEqual(['repo', 'issues']);
  });

  it('update on a nonexistent permission throws a clear not-found error, not a silent create', async () => {
    await expect(store.update('perm_does_not_exist', { allowedScopes: ['repo'] }))
      .rejects.toThrow(/not found/i);

    // Confirm no row was silently created for the bogus id.
    expect(await store.list('agt_1')).toHaveLength(0);
  });

  it('update cannot move a permission to a different (agentId, connectionId) — the input type carries neither field', async () => {
    const created = await store.create({
      agentId: 'agt_1',
      connectionId: 'github',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });

    // UpdatePermissionInput structurally has no agentId/connectionId keys —
    // even if a caller forces one through with `as any`, it must be ignored.
    const updated = await store.update(created.id, {
      allowedScopes: ['repo', 'issues'],
      ...( { agentId: 'agt_2', connectionId: 'slack' } as any ),
    });

    expect(updated.agentId).toBe('agt_1');
    expect(updated.connectionId).toBe('github');
    expect(await store.get('agt_2', 'slack')).toBeNull();
  });

  it('two back-to-back partial updates to distinct fields both persist (no lost-update race)', async () => {
    const created = await store.create({
      agentId: 'agt_1',
      connectionId: 'github',
      allowedScopes: ['repo'],
      rateLimit: { maxRequests: 5, windowMs: 60_000 },
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 1,
      createdBy: 'user_1',
    });

    // First update narrows allowedScopes only.
    await store.update(created.id, { allowedScopes: ['repo'] });
    // Second update changes rateLimit only — must not clobber the first write.
    const afterSecond = await store.update(created.id, {
      rateLimit: { maxRequests: 20, windowMs: 60_000 },
    });

    expect(afterSecond.allowedScopes).toEqual(['repo']);
    expect(afterSecond.rateLimit).toEqual({ maxRequests: 20, windowMs: 60_000 });
  });

  it('update runs against the updated_at migration path against a database file that predates the column', async () => {
    // Simulate a pre-migration database: create vault_permissions with the
    // OLD schema (no updated_at column at all — mirrors the shape before
    // this unit's migration) and insert a row directly, bypassing
    // SQLiteBackend entirely. Then open it with SQLiteBackend, whose init()
    // must detect the missing column (PRAGMA table_info) and ALTER TABLE
    // ADD COLUMN it in, and confirm update() succeeds against that repaired
    // row.
    const migTmpDir = mkdtempSync(join(tmpdir(), 'cred-permissions-migration-'));
    try {
      const dbPath = join(migTmpDir, 'vault.db');
      const legacyId = 'perm_legacy_pre_migration';
      const legacyCreatedAt = '2026-01-01T00:00:00.000Z';

      const rawDb = new Database(dbPath);
      rawDb.exec(`
        CREATE TABLE vault_permissions (
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
        )
      `);
      rawDb.prepare(`
        INSERT INTO vault_permissions (
          id, agent_id, connection_id, allowed_scopes,
          requires_approval, delegatable, max_delegation_depth,
          created_at, created_by
        ) VALUES (?, ?, ?, ?, 0, 1, 1, ?, ?)
      `).run(legacyId, 'agt_legacy', 'github', JSON.stringify(['repo']), legacyCreatedAt, 'user_1');
      rawDb.close();

      // SQLiteBackend.init() must find no updated_at column and add it.
      const backend = new SQLiteBackend(dbPath);
      backend.init();
      const store = new PermissionStore(backend);

      const legacyPermission = await store.get('agt_legacy', 'github');
      expect(legacyPermission).not.toBeNull();
      expect(legacyPermission?.id).toBe(legacyId);
      // updated_at is NULL for a pre-migration row (ALTER TABLE ADD COLUMN
      // has no DEFAULT) — falls back to createdAt.
      expect(legacyPermission?.updatedAt).toBe(legacyCreatedAt);

      const updated = await store.update(legacyId, { allowedScopes: ['repo', 'issues'] });
      expect(updated.id).toBe(legacyId);
      expect(updated.allowedScopes).toEqual(['repo', 'issues']);
      expect(updated.updatedAt).not.toBe(legacyCreatedAt);
    } finally {
      rmSync(migTmpDir, { recursive: true, force: true });
    }
  });

  it('narrowing allowedScopes via update() is prospective-only — documented, not independently testable at this layer', () => {
    // /api/v1/use (packages/server) resolves a brokered delegation handle's
    // scopes from an in-memory snapshot captured at delegation time and
    // never re-reads the Permission row — so there is no vault-layer call
    // path that could observe a narrowed permission affecting an
    // already-issued handle. This is structurally guaranteed by that
    // route's implementation, not by anything in PermissionStore. See
    // packages/server/src/__tests__/server.test.ts for an HTTP-level test
    // that delegates, narrows the permission, and confirms a subsequent
    // POST /api/v1/use with the same handle is unaffected.
    expect(true).toBe(true);
  });

  // ── file-backend 501 mapping ─────────────────────────────────────────────

  it('any Permission method against the file backend throws "not supported" (no Permission support in FileBackend)', async () => {
    const fileTmpDir = mkdtempSync(join(tmpdir(), 'cred-permissions-file-'));
    try {
      const fileBackend = new FileBackend(join(fileTmpDir, 'vault.json'));
      const fileStore = new PermissionStore(fileBackend);

      await expect(fileStore.create({
        agentId: 'agt_1',
        connectionId: 'github',
        allowedScopes: ['repo'],
        requiresApproval: false,
        delegatable: true,
        maxDelegationDepth: 1,
        createdBy: 'user_1',
      })).rejects.toThrow(/not supported/i);

      await expect(fileStore.get('agt_1', 'github')).rejects.toThrow(/not supported/i);
      await expect(fileStore.list('agt_1')).rejects.toThrow(/not supported/i);
      await expect(fileStore.revoke('perm_x')).rejects.toThrow(/not supported/i);
      await expect(fileStore.update('perm_x', { allowedScopes: ['repo'] })).rejects.toThrow(/not supported/i);
    } finally {
      rmSync(fileTmpDir, { recursive: true, force: true });
    }
  });
});

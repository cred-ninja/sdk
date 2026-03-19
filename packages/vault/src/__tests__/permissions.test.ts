import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SQLiteBackend } from '../storage/sqlite.js';
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
});

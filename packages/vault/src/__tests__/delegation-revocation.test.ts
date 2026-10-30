import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { SQLiteBackend } from '../storage/sqlite.js';
import { CredVault } from '../vault.js';
import {
  collectDelegationSubtree,
  DelegationRevokedError,
  MemoryDelegationStore,
  type RecordDelegationInput,
} from '../delegation-revocation.js';

const NOW = '2026-10-21T00:00:00.000Z';
const LATER = '2026-10-21T00:00:05.000Z';

function rec(id: string, parentId: string | null = null, extra: Partial<RecordDelegationInput> = {}): RecordDelegationInput {
  return { id, parentId, service: 'google', userId: 'user-1', ...extra };
}

// root ─┬─ a ─┬─ a1
//       │     └─ a2
//       └─ b ─── b1
// other (unrelated root) ─── o1
function seedTree(store: { storeDelegation(input: RecordDelegationInput, now: string): unknown }) {
  store.storeDelegation(rec('root', null, { agentDid: 'did:key:z6MkRoot' }), NOW);
  store.storeDelegation(rec('a', 'root', { agentDid: 'did:key:z6MkA', chainDepth: 1 }), NOW);
  store.storeDelegation(rec('b', 'root', { agentDid: 'did:key:z6MkB', chainDepth: 1 }), NOW);
  store.storeDelegation(rec('a1', 'a', { chainDepth: 2 }), NOW);
  store.storeDelegation(rec('a2', 'a', { chainDepth: 2 }), NOW);
  store.storeDelegation(rec('b1', 'b', { chainDepth: 2 }), NOW);
  store.storeDelegation(rec('other'), NOW);
  store.storeDelegation(rec('o1', 'other', { chainDepth: 1 }), NOW);
}

describe('collectDelegationSubtree', () => {
  it('walks breadth-first and records the seed that reached each node', () => {
    const edges: Record<string, string[]> = { r: ['a', 'b'], a: ['c'] };
    const { nodes, truncated } = collectDelegationSubtree(['r'], (id) => edges[id] ?? []);
    expect(nodes).toEqual([
      { id: 'r', depth: 0, rootId: 'r' },
      { id: 'a', depth: 1, rootId: 'r' },
      { id: 'b', depth: 1, rootId: 'r' },
      { id: 'c', depth: 2, rootId: 'r' },
    ]);
    expect(truncated).toBe(false);
  });

  it('terminates on a cycle and a self-edge, visiting each node once', () => {
    const edges: Record<string, string[]> = { a: ['b', 'a'], b: ['c', 'a'], c: ['a', 'b'] };
    const { nodes } = collectDelegationSubtree(['a'], (id) => edges[id] ?? []);
    expect(nodes.map((n) => n.id)).toEqual(['a', 'b', 'c']);
  });

  it('ignores duplicate seeds and duplicate edges', () => {
    const edges: Record<string, string[]> = { a: ['b', 'b'], b: [] };
    const { nodes } = collectDelegationSubtree(['a', 'a', 'b'], (id) => edges[id] ?? []);
    expect(nodes.map((n) => n.id)).toEqual(['a', 'b']);
  });

  it('reports truncated when the depth bound leaves children unvisited', () => {
    const edges: Record<string, string[]> = { a: ['b'], b: ['c'], c: ['d'] };
    const { nodes, truncated } = collectDelegationSubtree(['a'], (id) => edges[id] ?? [], { maxDepth: 2 });
    expect(nodes.map((n) => n.id)).toEqual(['a', 'b', 'c']);
    expect(truncated).toBe(true);
  });
});

// The same behavior is required of both stores, so one suite runs on each.
const stores: Array<[string, () => { store: SQLiteBackend | MemoryDelegationStore; cleanup: () => void }]> = [
  ['MemoryDelegationStore', () => ({ store: new MemoryDelegationStore(), cleanup: () => {} })],
  ['SQLiteBackend', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vault-delegations-test-'));
    const backend = new SQLiteBackend(join(dir, 'vault.db'));
    backend.init();
    return { store: backend, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
  }],
];

describe.each(stores)('cascading revocation (%s)', (_name, make) => {
  let store: SQLiteBackend | MemoryDelegationStore;
  let cleanup: () => void;

  beforeEach(() => {
    ({ store, cleanup } = make());
  });

  afterEach(() => cleanup());

  it('records parent linkage', () => {
    seedTree(store);
    expect(store.getDelegation('a1')).toMatchObject({ id: 'a1', parentId: 'a', chainDepth: 2, status: 'active', revokedAt: null });
    expect(store.getDelegation('root')).toMatchObject({ parentId: null, agentDid: 'did:key:z6MkRoot' });
    expect(store.getDelegation('missing')).toBeNull();
  });

  it('revoking the root of a 3-level chain revokes every descendant', () => {
    seedTree(store);
    const { revoked, truncated } = store.revokeDelegationTree({ delegationIds: ['root'] }, LATER);

    expect(truncated).toBe(false);
    expect(revoked.map((r) => r.id).sort()).toEqual(['a', 'a1', 'a2', 'b', 'b1', 'root']);
    expect(revoked.every((r) => r.revokedAncestorId === 'root')).toBe(true);
    expect(revoked.find((r) => r.id === 'a1')).toMatchObject({ depth: 2, parentId: 'a' });
    expect(store.getDelegation('b1')).toMatchObject({ status: 'revoked', revokedAt: LATER, revokedAncestorId: 'root' });
    expect(store.getDelegation('other')?.status).toBe('active');
    expect(store.getDelegation('o1')?.status).toBe('active');
  });

  it('revoking a middle node leaves its parent and the parent\'s other children intact', () => {
    seedTree(store);
    const { revoked } = store.revokeDelegationTree({ delegationIds: ['a'] }, LATER);

    expect(revoked.map((r) => r.id).sort()).toEqual(['a', 'a1', 'a2']);
    for (const id of ['root', 'b', 'b1', 'other', 'o1']) {
      expect(store.getDelegation(id)?.status).toBe('active');
    }
  });

  it('is idempotent: a second revocation reports nothing new', () => {
    seedTree(store);
    store.revokeDelegationTree({ delegationIds: ['a'] }, LATER);
    const again = store.revokeDelegationTree({ delegationIds: ['a', 'a'] }, LATER);
    expect(again.revoked).toEqual([]);

    // A wider revocation later only counts what the first one missed.
    const wider = store.revokeDelegationTree({ delegationIds: ['root'] }, LATER);
    expect(wider.revoked.map((r) => r.id).sort()).toEqual(['b', 'b1', 'root']);
  });

  it('revokes every delegation issued to an agent DID, and their descendants', () => {
    seedTree(store);
    const { revoked } = store.revokeDelegationTree({ agentDid: 'did:key:z6MkB' }, LATER);
    expect(revoked.map((r) => r.id).sort()).toEqual(['b', 'b1']);
    expect(store.getDelegation('root')?.status).toBe('active');
  });

  it('refuses to record a child under a revoked parent, naming the root cause', () => {
    seedTree(store);
    store.revokeDelegationTree({ delegationIds: ['root'] }, LATER);

    let caught: unknown;
    try {
      store.storeDelegation(rec('late', 'a1'), LATER);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(DelegationRevokedError);
    expect(caught).toMatchObject({ code: 'delegation_revoked', revokedAncestorId: 'root' });
    expect(store.getDelegation('late')).toBeNull();
  });

  it('keeps the first write for a replayed id and rejects a self-parent', () => {
    store.storeDelegation(rec('x', 'p1'), NOW);
    store.storeDelegation(rec('x', 'p2'), LATER);
    expect(store.getDelegation('x')?.parentId).toBe('p1');
    expect(() => store.storeDelegation(rec('self', 'self'), NOW)).toThrow('own parent');
  });

  it('cascades through children of a parent that was never recorded', () => {
    // A receipt minted before delegation records existed has no row, but a
    // child recorded since still points at it.
    store.storeDelegation(rec('child', 'legacy_parent'), NOW);
    const { revoked } = store.revokeDelegationTree({ delegationIds: ['legacy_parent'] }, LATER);
    expect(revoked.map((r) => r.id)).toEqual(['child']);
    expect(revoked[0].revokedAncestorId).toBe('legacy_parent');
  });

  it('revokes a tree of 1,110 descendants well under 5 seconds', () => {
    // Fan-out 10 over three levels: 10 + 100 + 1,000 descendants.
    store.storeDelegation(rec('big_root'), NOW);
    let level = ['big_root'];
    for (let depth = 1; depth <= 3; depth++) {
      const next: string[] = [];
      for (const parent of level) {
        for (let i = 0; i < 10; i++) {
          const id = `${parent}_${i}`;
          store.storeDelegation(rec(id, parent, { chainDepth: depth }), NOW);
          next.push(id);
        }
      }
      level = next;
    }

    const started = performance.now();
    const { revoked } = store.revokeDelegationTree({ delegationIds: ['big_root'] }, LATER);
    const elapsedMs = performance.now() - started;

    expect(revoked).toHaveLength(1_111);
    expect(elapsedMs).toBeLessThan(5_000);
  });
});

describe('SQLiteBackend delegation storage', () => {
  let dir: string;
  let backend: SQLiteBackend;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vault-delegations-sqlite-'));
    backend = new SQLiteBackend(join(dir, 'vault.db'));
    backend.init();
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('adds the delegation table to a database created before it existed', () => {
    const legacyPath = join(dir, 'legacy.db');
    const legacy = new Database(legacyPath);
    legacy.exec(`CREATE TABLE vault_agents (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
      scope_ceiling TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'active', created_by TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_seen_at TEXT, revoked_at TEXT)`);
    legacy.prepare(`INSERT INTO vault_agents (id, fingerprint, name, created_by, created_at, updated_at) VALUES ('agt_old', 'fp', 'old', 'admin', ?, ?)`).run(NOW, NOW);
    legacy.close();

    const upgraded = new SQLiteBackend(legacyPath);
    upgraded.init();
    expect(upgraded.getAgent('agt_old')?.id).toBe('agt_old');
    upgraded.storeDelegation(rec('d1'), NOW);
    expect(upgraded.getDelegation('d1')?.status).toBe('active');
  });

  it('keeps the grant behind a Delegation Token across a reopen', () => {
    const grant = {
      credentialHandle: 'ch_1', consentId: 'consent_1', jkt: 'jkt_1', scopes: ['repo'], appClientId: 'local',
      constraints: [{ key: 'max_calls', max_lifetime: 3 }],
      authorizationDetails: [{ type: 'cred_delegation', provider: 'github', operations: ['repo'] }],
    };
    backend.storeDelegation(rec('d1', null, { grant }), NOW);
    const reopened = new SQLiteBackend(join(dir, 'vault.db'));
    reopened.init();
    expect(reopened.getDelegation('d1')?.grant).toEqual(grant);
    backend.storeDelegation(rec('d2'), NOW);
    expect(reopened.getDelegation('d2')?.grant).toBeUndefined();
  });

  it('adds the grant column to a delegation table created before it existed', () => {
    const legacyPath = join(dir, 'legacy-grant.db');
    const legacy = new Database(legacyPath);
    legacy.exec(`CREATE TABLE vault_delegations (id TEXT PRIMARY KEY, parent_id TEXT, agent_did TEXT, service TEXT NOT NULL,
      user_id TEXT NOT NULL, chain_depth INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL,
      expires_at TEXT, revoked_at TEXT, revoked_ancestor_id TEXT)`);
    legacy.close();
    const upgraded = new SQLiteBackend(legacyPath);
    upgraded.init();
    upgraded.storeDelegation(rec('d1', null, { grant: { credentialHandle: 'ch', consentId: 'c', jkt: 'j', scopes: [], appClientId: 'local' } }), NOW);
    expect(upgraded.getDelegation('d1')?.grant?.credentialHandle).toBe('ch');
  });

  it('refuses to record a delegation for a revoked agent', () => {
    backend.storeAgent({
      id: 'agt_gone', did: 'did:key:z6MkGone', fingerprint: 'fp_gone', name: 'gone', scopeCeiling: '[]',
      status: 'revoked', createdBy: 'admin', createdAt: NOW, updatedAt: NOW, lastSeenAt: null, revokedAt: NOW,
    });
    expect(() => backend.storeDelegation(rec('d1', null, { agentDid: 'did:key:z6MkGone' }), NOW))
      .toThrow(DelegationRevokedError);
  });

  it('rolls the whole cascade back when a write fails part-way', () => {
    seedTree(backend);
    // Fail the UPDATE on one descendant: nothing in the subtree may change.
    const raw = new Database(join(dir, 'vault.db'));
    raw.exec(`CREATE TRIGGER fail_b1 BEFORE UPDATE ON vault_delegations WHEN OLD.id = 'b1'
      BEGIN SELECT RAISE(ABORT, 'injected failure'); END`);
    raw.close();

    expect(() => backend.revokeDelegationTree({ delegationIds: ['root'] }, LATER)).toThrow('injected failure');
    for (const id of ['root', 'a', 'a1', 'a2', 'b', 'b1']) {
      expect(backend.getDelegation(id)?.status).toBe('active');
    }
  });
});

describe('CredVault delegation API', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vault-delegations-api-'));
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  for (const storage of ['sqlite', 'file'] as const) {
    it(`records, revokes and reports a cascade (${storage})`, async () => {
      const vault = new CredVault({ passphrase: 'test-passphrase', storage, path: join(dir, `vault.${storage}`) });
      await vault.recordDelegation(rec('root'));
      await vault.recordDelegation(rec('mid', 'root', { chainDepth: 1 }));
      await vault.recordDelegation(rec('leaf', 'mid', { chainDepth: 2 }));

      const result = await vault.revokeDelegations({ delegationIds: ['root'] });
      expect(result.count).toBe(3);
      expect(result.revokedIds).toEqual(['root', 'mid', 'leaf']);
      expect(result.truncated).toBe(false);
      expect(result.elapsedMs).toBeGreaterThanOrEqual(0);
      expect((await vault.getDelegation('leaf'))?.status).toBe('revoked');
      await expect(vault.recordDelegation(rec('late', 'leaf'))).rejects.toBeInstanceOf(DelegationRevokedError);
    });
  }

  it('revokeAgentCascade revokes the agent and everything issued under its DID', async () => {
    const vault = new CredVault({ passphrase: 'test-passphrase', storage: 'sqlite', path: join(dir, 'vault.sqlite') });
    await vault.registerAgent({
      id: 'agt_mid', did: 'did:key:z6MkMid', fingerprint: 'fp_mid', name: 'mid', scopeCeiling: [],
      status: 'active', createdBy: 'admin', createdAt: NOW, updatedAt: NOW,
    });
    await vault.recordDelegation(rec('root', null, { agentDid: 'did:key:z6MkRoot' }));
    await vault.recordDelegation(rec('mid', 'root', { agentDid: 'did:key:z6MkMid', chainDepth: 1 }));
    await vault.recordDelegation(rec('leaf', 'mid', { agentDid: 'did:key:z6MkLeaf', chainDepth: 2 }));

    const result = await vault.revokeAgentCascade('agt_mid');
    expect(result.revokedIds).toEqual(['mid', 'leaf']);
    expect((await vault.getAgent('agt_mid'))?.status).toBe('revoked');
    expect((await vault.getDelegation('root'))?.status).toBe('active');
    await expect(vault.recordDelegation(rec('again', null, { agentDid: 'did:key:z6MkMid' })))
      .rejects.toMatchObject({ code: 'agent_revoked' });
  });
});

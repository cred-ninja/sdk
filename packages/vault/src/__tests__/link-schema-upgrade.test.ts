import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { SqliteLinkStore, LINK_SCHEMA_VERSION } from '../link/index.js';
import { at, confirm, connectActive, driveToConfirm, h, newTx } from './link-fixtures.js';
import { LINK_SCHEMA_V1_SQL } from './link-schema-v1-fixture.js';

/**
 * Regression: a Link database written by the Phase 1 build (user_version 1,
 * no tokens_settled_at, no grant_scopes_at_confirm_json) must open with the
 * current store, upgrade in place and keep its rows. Its activations come
 * back unsettled: the store cannot tell a finished one from one that
 * crashed before the token move, so the server's startup heal resolves each.
 */

function schemaSnapshot(path: string): unknown {
  const db = new Database(path, { readonly: true });
  const snap = {
    version: db.pragma('user_version', { simple: true }),
    objects: db.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").all(),
    rows: Object.fromEntries(['link_clients', 'link_connections', 'link_grants', 'link_transactions']
      .map((t) => [t, db.prepare(`SELECT * FROM ${t} ORDER BY rowid`).all()])),
  };
  db.close();
  return snap;
}

describe('Link schema upgrade from version 1', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'link-upgrade-')); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  /**
   * Builds a genuine version 1 file: the Phase 1 DDL, user_version 1, and
   * rows produced by real flows (copied column by column from a scratch
   * store, so they are exactly what the store writes).
   */
  async function buildV1(): Promise<{ path: string; ids: Record<string, string> }> {
    const scratchPath = join(dir, 'scratch.db');
    const scratch = new SqliteLinkStore(scratchPath);
    await scratch.putClient({
      client_id: 'acme', org_id: 'org_default', name: 'Acme', redirect_uris: ['https://app.example.com/cred/return'],
      origins: ['https://app.example.com'], allow_raw_tokens: false, status: 'active',
      token_endpoint_auth_method: 'client_secret_basic', client_secret_hash: h('secret'), created_at: at(0), updated_at: at(0),
    });
    const activated = await connectActive(scratch);
    const open = newTx({ client_id: 'beta' });
    await driveToConfirm(scratch, open, { accountId: 'acct-open' });
    const cancelled = newTx();
    await scratch.createTransaction(cancelled);
    await scratch.endTransaction({ tid: cancelled.tid, outcome: 'cancelled', now: at(5) });
    // An update confirmed by the old build: it has no recorded grant scopes.
    const inflight = newTx({ intent: 'update', providers: ['google'], connection_id: activated.connection_id });
    await driveToConfirm(scratch, inflight);
    await confirm(scratch, inflight.tid);
    scratch.close();

    const path = join(dir, 'v1.db');
    const v1 = new Database(path);
    v1.exec(LINK_SCHEMA_V1_SQL);
    v1.pragma('user_version = 1');
    v1.exec(`ATTACH DATABASE '${scratchPath.replace(/'/g, "''")}' AS src`);
    for (const table of ['link_clients', 'link_connections', 'link_grants', 'link_transactions']) {
      const cols = (v1.prepare(`PRAGMA main.table_info(${table})`).all() as Array<{ name: string }>).map((c) => c.name).join(', ');
      v1.exec(`INSERT INTO main.${table} (${cols}) SELECT ${cols} FROM src.${table}`);
    }
    v1.exec('DETACH DATABASE src');
    const txCols = (v1.prepare('PRAGMA table_info(link_transactions)').all() as Array<{ name: string }>).map((c) => c.name);
    expect(txCols).not.toContain('tokens_settled_at');
    expect(txCols).not.toContain('grant_scopes_at_confirm_json');
    v1.close();
    return {
      path,
      ids: {
        activated: activated.tid, connection: activated.connection_id, grant: activated.grant_id,
        open: open.tid, cancelled: cancelled.tid, inflight: inflight.tid,
      },
    };
  }

  it('upgrades in place, keeps rows, and leaves migrated activations unsettled for the startup heal', async () => {
    const { path, ids } = await buildV1();
    const before = schemaSnapshot(path) as { rows: Record<string, Array<Record<string, unknown>>> };

    const store = new SqliteLinkStore(path);
    expect(LINK_SCHEMA_VERSION).toBe(2);

    const raw = new Database(path, { readonly: true });
    expect(raw.pragma('user_version', { simple: true })).toBe(2);
    const txCols = (raw.prepare('PRAGMA table_info(link_transactions)').all() as Array<{ name: string }>).map((c) => c.name);
    expect(txCols).toEqual(expect.arrayContaining(['tokens_settled_at', 'grant_scopes_at_confirm_json']));
    const indexes = (raw.prepare("SELECT name FROM sqlite_master WHERE type = 'index'").all() as Array<{ name: string }>).map((r) => r.name);
    expect(indexes).toContain('idx_link_transactions_unsettled');
    // Every pre-existing row survives, with the old columns unchanged.
    for (const table of ['link_clients', 'link_connections', 'link_grants', 'link_transactions']) {
      const after = raw.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all() as Array<Record<string, unknown>>;
      expect(after).toHaveLength(before.rows[table].length);
      after.forEach((row, i) => {
        const { tokens_settled_at: _s, grant_scopes_at_confirm_json: _g, ...old } = row;
        expect(old).toEqual(before.rows[table][i]);
      });
    }
    raw.close();

    // No back-fill: the store cannot tell a finished version 1 activation from
    // one that crashed before the token move, so each comes back unsettled for
    // the server's startup heal. Nothing else gains a value either.
    for (const tid of [ids.activated, ids.open, ids.cancelled, ids.inflight]) {
      const tx = await store.getTransaction(tid as never);
      expect(tx).not.toHaveProperty('tokens_settled_at');
      expect(tx).not.toHaveProperty('grant_scopes_at_confirm');
    }
    expect((await store.listUnsettledActivations()).map((t) => t.tid)).toEqual([ids.activated]);
    expect(await store.getClient('acme')).toMatchObject({ name: 'Acme' });
    expect(await store.getConnection(ids.connection)).toMatchObject({ status: 'active' });
    expect(await store.getGrant(ids.grant)).toMatchObject({ status: 'active' });
    store.close();
  });

  it('an activation that crashed before the token move stays in the heal list after the upgrade', async () => {
    // Also covers a file from an intermediate build that already had tokens_settled_at but was labelled 1.
    const path = join(dir, 'intermediate.db');
    const s = new SqliteLinkStore(path);
    const t = newTx();
    await driveToConfirm(s, t);
    const c = await confirm(s, t.tid);
    const claimed = await s.claimActivation({
      client_id: 'acme', connection_id: c.transaction.connection_id as string, activation_code_hash: h(`code-${t.tid}`), subject: 'user-123', now: at(20),
    });
    expect(claimed.ok).toBe(true);
    await s.commitActivation({ tid: t.tid, now: at(21) });
    // The process stops here: commitStaged and settleActivation never run.
    s.close();
    const raw = new Database(path);
    raw.exec('ALTER TABLE link_transactions DROP COLUMN grant_scopes_at_confirm_json');
    raw.pragma('user_version = 1');
    raw.close();

    const upgraded = new SqliteLinkStore(path);
    expect((await upgraded.listUnsettledActivations()).map((x) => x.tid)).toEqual([t.tid]);
    expect(await upgraded.getConnection(c.transaction.connection_id as string)).toMatchObject({ status: 'active' });
    upgraded.close();
    const check = new Database(path, { readonly: true });
    expect(check.pragma('user_version', { simple: true })).toBe(2);
    check.close();
  });

  it('reopening an upgraded file is a no-op', async () => {
    const { path } = await buildV1();
    new SqliteLinkStore(path).close();
    const once = schemaSnapshot(path);
    new SqliteLinkStore(path).close();
    new SqliteLinkStore(path).close();
    expect(schemaSnapshot(path)).toEqual(once);
  });

  it('the upgraded file works with the current store', async () => {
    const { path, ids } = await buildV1();
    const store = new SqliteLinkStore(path);
    // An update confirmed by the old build has no recorded grant scopes, so its activation is refused.
    const inflight = await store.getTransaction(ids.inflight as never);
    await store.claimActivation({
      client_id: 'acme', connection_id: inflight?.connection_id as string, activation_code_hash: h(`code-${ids.inflight}`), subject: 'user-123', now: at(40),
    });
    await expect(store.commitActivation({ tid: ids.inflight as never, now: at(41) })).rejects.toMatchObject({ code: 'grant_changed' });
    // The heal settles the migrated activation; new flows behave normally, including the settle marker.
    expect(await store.settleActivation({ tid: ids.activated as never, now: at(45) })).toBe(true);
    const fresh = await connectActive(store, { client_id: 'gamma' }, { accountId: 'acct-new' });
    expect((await store.listUnsettledActivations()).map((t) => t.tid)).toEqual([fresh.tid]);
    expect(await store.settleActivation({ tid: fresh.tid, now: at(50) })).toBe(true);
    expect(await store.listUnsettledActivations()).toEqual([]);
    store.close();
  });

  it('a fresh file is created directly at the current version; a newer one is refused', () => {
    const fresh = join(dir, 'fresh.db');
    new SqliteLinkStore(fresh).close();
    const raw = new Database(fresh);
    expect(raw.pragma('user_version', { simple: true })).toBe(LINK_SCHEMA_VERSION);
    raw.pragma(`user_version = ${LINK_SCHEMA_VERSION + 1}`);
    raw.close();
    expect(() => new SqliteLinkStore(fresh)).toThrow(/newer than this build supports/);
  });
});

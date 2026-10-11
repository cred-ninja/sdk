import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { LINK_GRANT_STATUS_FOR_CONNECTION_STATUS } from '@credninja/protocol';
import type { ConnectionId, LinkClient, TransactionId } from '@credninja/protocol';
import { SqliteLinkStore, LinkStoreError, LINK_SCHEMA_VERSION } from '../link/index.js';
import { at, confirm, connectActive, driveToConfirm, h, newIds, newTx } from './link-fixtures.js';

describe('SqliteLinkStore', () => {
  let store: SqliteLinkStore;

  beforeEach(() => {
    store = new SqliteLinkStore(':memory:');
  });

  afterEach(() => {
    store.close();
  });

  // ── Schema ─────────────────────────────────────────────────────────────────

  describe('schema', () => {
    let dir: string;
    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), 'link-store-schema-'));
    });
    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('creates the schema idempotently and keeps data across reopen', async () => {
      const path = join(dir, 'link.db');
      const a = new SqliteLinkStore(path);
      const input = newTx();
      await a.createTransaction(input);
      a.close();

      const b = new SqliteLinkStore(path);
      const c = new SqliteLinkStore(path);
      expect(await b.getTransaction(input.tid)).not.toBeNull();
      b.close();
      c.close();

      const raw = new Database(path);
      expect(raw.pragma('user_version', { simple: true })).toBe(LINK_SCHEMA_VERSION);
      expect(LINK_SCHEMA_VERSION).toBe(1);
      raw.close();
    });

    it('refuses a database from a newer schema version', () => {
      const path = join(dir, 'newer.db');
      const raw = new Database(path);
      raw.pragma(`user_version = ${LINK_SCHEMA_VERSION + 1}`);
      raw.close();
      expect(() => new SqliteLinkStore(path)).toThrow(/newer/);
    });

    it('enforces one live (not pending, not revoked) connection per (client_id, audience, subject, provider_account_id) at the index', async () => {
      const path = join(dir, 'unique.db');
      const s = new SqliteLinkStore(path);
      const { connection_id } = await connectActive(s);
      s.close();

      const raw = new Database(path);
      const row = raw.prepare('SELECT * FROM link_connections WHERE id = ?').get(connection_id) as Record<string, unknown>;
      const insert = raw.prepare(`INSERT INTO link_connections (${Object.keys(row).join(', ')}) VALUES (${Object.keys(row).map((k) => `@${k}`).join(', ')})`);
      expect(() => insert.run({ ...row, id: 'conn_dup1' })).toThrow(/UNIQUE/);
      // Revoked and pending duplicates are allowed: uniqueness covers live rows only.
      expect(() => insert.run({ ...row, id: 'conn_dup2', status: 'revoked' })).not.toThrow();
      expect(() => insert.run({ ...row, id: 'conn_dup3', status: 'pending' })).not.toThrow();
      expect(() => insert.run({ ...row, id: 'conn_dup4', status: 'needs_reauth' })).toThrow(/UNIQUE/);
      raw.close();
    });
  });

  // ── Clients ────────────────────────────────────────────────────────────────

  describe('clients', () => {
    const base = {
      org_id: 'org_default' as const,
      name: 'Acme',
      redirect_uris: ['https://app.example.com/cred/return'],
      origins: ['https://app.example.com'],
      allow_raw_tokens: false,
      status: 'active' as const,
      created_at: at(0),
      updated_at: at(0),
    };

    it('round-trips both auth methods and replaces on put', async () => {
      const secretClient: LinkClient = {
        ...base,
        client_id: 'acme',
        token_endpoint_auth_method: 'client_secret_basic',
        client_secret_hash: h('secret'),
        theme: { appName: 'Acme', accent: '#ff0000' },
      };
      const jwtClient: LinkClient = {
        ...base,
        client_id: 'beta.app',
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'abc', kid: 'k1' }] },
      };
      await store.putClient(secretClient);
      await store.putClient(jwtClient);
      expect(await store.getClient('acme')).toEqual(secretClient);
      expect(await store.getClient('beta.app')).toEqual(jwtClient);
      expect(await store.getClient('nobody')).toBeNull();

      await store.putClient({ ...secretClient, name: 'Acme 2', status: 'disabled', updated_at: at(5) });
      expect(await store.getClient('acme')).toMatchObject({ name: 'Acme 2', status: 'disabled', updated_at: at(5) });
    });
  });

  // ── Transactions: create and request_uri ──────────────────────────────────

  describe('createTransaction', () => {
    it('starts at picker with attempt 0, no handle, canonical scopes', async () => {
      const input = newTx();
      const tx = await store.createTransaction(input);
      expect(tx.step).toBe('picker');
      expect(tx.provider_attempt).toBe(0);
      expect(tx.handle_hash).toBeUndefined();
      expect(tx.request_uri_consumed_at).toBeUndefined();
      expect(tx.requested_scopes.google).toEqual(['calendar.readonly', 'drive.file', 'gmail.send']);
      expect(tx.org_id).toBe('org_default');
      expect(await store.getTransaction(input.tid)).toEqual(tx);
    });

    it('rejects update/reauth without a connection_id', async () => {
      await expect(store.createTransaction(newTx({ intent: 'update', providers: ['google'] }))).rejects.toBeInstanceOf(LinkStoreError);
    });

    it('rejects a duplicate request_uri_hash', async () => {
      const input = newTx();
      await store.createTransaction(input);
      await expect(store.createTransaction({ ...newTx(), request_uri_hash: input.request_uri_hash })).rejects.toThrow(/UNIQUE/);
    });
  });

  describe('enterByRequestUri', () => {
    const cookie = h('cookie');

    async function authorize(input = newTx(), extra: Partial<Parameters<SqliteLinkStore['enterByRequestUri']>[0]> = {}) {
      await store.createTransaction(input);
      const r = await store.enterByRequestUri({
        request_uri_hash: input.request_uri_hash,
        client_id: input.client_id,
        presented_cookie_hash: null,
        new_handle_hash: h('handle-1'),
        new_binding_cookie_hash: cookie,
        mode: 'popup',
        now: at(5),
        ...extra,
      });
      return { input, r };
    }

    it('fresh: consumes the request_uri and sets handle, cookie, mode, theme', async () => {
      const { r } = await authorize(undefined, { theme: { appName: 'Acme' } });
      expect(r.kind).toBe('fresh');
      if (r.kind !== 'fresh') return;
      expect(r.transaction.request_uri_consumed_at).toBe(at(5));
      expect(r.transaction.handle_hash).toBe(h('handle-1'));
      expect(r.transaction.binding_cookie_hash).toBe(cookie);
      expect(r.transaction.mode).toBe('popup');
      expect(r.transaction.theme).toEqual({ appName: 'Acme' });
    });

    it('is single use: a replay without the cookie is rejected and leaves the transaction untouched', async () => {
      const { input } = await authorize();
      const before = await store.getTransaction(input.tid);
      const replay = await store.enterByRequestUri({
        request_uri_hash: input.request_uri_hash,
        presented_cookie_hash: null,
        new_handle_hash: h('attacker-handle'),
        new_binding_cookie_hash: h('attacker-cookie'),
        mode: 'redirect',
        now: at(6),
      });
      expect(replay).toEqual({ kind: 'rejected', reason: 'replayed' });
      const wrongCookie = await store.enterByRequestUri({
        request_uri_hash: input.request_uri_hash,
        presented_cookie_hash: h('other-cookie'),
        new_handle_hash: h('attacker-handle'),
        mode: 'popup',
        now: at(6),
      });
      expect(wrongCookie).toEqual({ kind: 'rejected', reason: 'replayed' });
      expect(await store.getTransaction(input.tid)).toEqual(before);
    });

    it('reentry with the matching cookie rotates the handle only', async () => {
      const { input } = await authorize();
      const r = await store.enterByRequestUri({
        request_uri_hash: input.request_uri_hash,
        presented_cookie_hash: cookie,
        new_handle_hash: h('handle-2'),
        new_binding_cookie_hash: h('new-cookie'),
        mode: 'redirect',
        theme: { appName: 'Other' },
        now: at(7),
      });
      expect(r.kind).toBe('reentry');
      if (r.kind !== 'reentry') return;
      expect(r.transaction.handle_hash).toBe(h('handle-2'));
      expect(r.transaction.binding_cookie_hash).toBe(cookie);
      expect(r.transaction.mode).toBe('popup');
      expect(r.transaction.theme).toBeUndefined();
      expect(r.transaction.request_uri_consumed_at).toBe(at(5));
    });

    it('embedded mode: a consumed request_uri with no binding cookie can never be re-entered', async () => {
      const input = newTx();
      await store.createTransaction(input);
      const first = await store.enterByRequestUri({
        request_uri_hash: input.request_uri_hash, presented_cookie_hash: h('stale-cookie-from-elsewhere'),
        new_handle_hash: h('h1'), mode: 'embedded', now: at(1),
      });
      expect(first.kind).toBe('fresh');
      if (first.kind === 'fresh') expect(first.transaction.binding_cookie_hash).toBeUndefined();
      const before = await store.getTransaction(input.tid);
      for (const presented of [null, '', h('stale-cookie-from-elsewhere')]) {
        expect(await store.enterByRequestUri({
          request_uri_hash: input.request_uri_hash, presented_cookie_hash: presented,
          new_handle_hash: h('h2'), new_binding_cookie_hash: h('c'), mode: 'popup', now: at(2),
        })).toEqual({ kind: 'rejected', reason: 'replayed' });
      }
      expect(await store.getTransaction(input.tid)).toEqual(before);
    });

    it('rejects unknown, client mismatch, expired and finished', async () => {
      expect(await store.enterByRequestUri({
        request_uri_hash: h('nope'), presented_cookie_hash: null, new_handle_hash: h('x'), mode: 'popup', now: at(1),
      })).toEqual({ kind: 'rejected', reason: 'unknown' });

      const a = newTx();
      await store.createTransaction(a);
      expect(await store.enterByRequestUri({
        request_uri_hash: a.request_uri_hash, client_id: 'other', presented_cookie_hash: null, new_handle_hash: h('x'), mode: 'popup', now: at(1),
      })).toEqual({ kind: 'rejected', reason: 'client_mismatch' });
      expect(await store.enterByRequestUri({
        request_uri_hash: a.request_uri_hash, presented_cookie_hash: null, new_handle_hash: h('x'), mode: 'popup', now: at(600),
      })).toEqual({ kind: 'rejected', reason: 'expired' });

      const b = newTx();
      await store.createTransaction(b);
      await store.endTransaction({ tid: b.tid, outcome: 'cancelled', now: at(2) });
      expect(await store.enterByRequestUri({
        request_uri_hash: b.request_uri_hash, presented_cookie_hash: null, new_handle_hash: h('x'), mode: 'popup', now: at(3),
      })).toEqual({ kind: 'rejected', reason: 'finished' });
    });

    it('narrowing never widens and keeps required scopes', async () => {
      const { r } = await authorize(newTx(), {
        narrowed: {
          providers: ['google', 'github'],
          requested_scopes: { google: ['gmail.send', 'drive', 'gmail.readonly'] },
        },
      });
      if (r.kind !== 'fresh') throw new Error(r.kind);
      expect(r.transaction.providers).toEqual(['google']);
      // drive and gmail.readonly were never pushed; calendar.readonly is required.
      expect(r.transaction.requested_scopes).toEqual({ google: ['calendar.readonly', 'gmail.send'] });
      expect(r.transaction.required_scopes).toEqual({ google: ['calendar.readonly'] });
    });
  });

  // ── Transactions: handles ─────────────────────────────────────────────────

  describe('enterByHandle', () => {
    async function authorized(opts: { setCookie?: boolean } = {}) {
      const input = newTx();
      await store.createTransaction(input);
      await store.enterByRequestUri({
        request_uri_hash: input.request_uri_hash,
        presented_cookie_hash: null,
        new_handle_hash: h('h1'),
        new_binding_cookie_hash: opts.setCookie === false ? undefined : h('cookie'),
        mode: opts.setCookie === false ? 'embedded' : 'popup',
        now: at(1),
      });
      return input;
    }

    it('fresh consumes the handle and rotates it; the old handle is then dead', async () => {
      const input = await authorized();
      const r = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: h('cookie'), new_handle_hash: h('h2'), now: at(2),
      });
      expect(r.kind).toBe('fresh');
      if (r.kind === 'fresh') expect(r.transaction.handle_hash).toBe(h('h2'));

      const before = await store.getTransaction(input.tid);
      const replay = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: null, new_handle_hash: h('h3'), now: at(3),
      });
      expect(replay).toEqual({ kind: 'rejected', reason: 'replayed' });
      expect(await store.getTransaction(input.tid)).toEqual(before);

      // h2 is still the live handle.
      const next = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h2'), presented_cookie_hash: h('cookie'), new_handle_hash: h('h4'), now: at(4),
      });
      expect(next.kind).toBe('fresh');
    });

    it('cookie binding: a matching handle is fresh only with the matching cookie', async () => {
      const input = await authorized();
      const before = await store.getTransaction(input.tid);
      const noCookie = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: null,
        new_handle_hash: h('evil-1'), new_binding_cookie_hash: h('evil-cookie'), now: at(2),
      });
      expect(noCookie).toEqual({ kind: 'rejected', reason: 'replayed' });
      const wrongCookie = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: h('other-browser'),
        new_handle_hash: h('evil-2'), now: at(2),
      });
      expect(wrongCookie).toEqual({ kind: 'rejected', reason: 'replayed' });
      const emptyCookie = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: '',
        new_handle_hash: h('evil-3'), now: at(2),
      });
      expect(emptyCookie).toEqual({ kind: 'rejected', reason: 'replayed' });
      expect(await store.getTransaction(input.tid)).toEqual(before);

      // The right browser can still use the same handle afterwards.
      const right = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: h('cookie'), new_handle_hash: h('h2'), now: at(3),
      });
      expect(right.kind).toBe('fresh');
      if (right.kind === 'fresh') {
        expect(right.transaction.handle_hash).toBe(h('h2'));
        expect(right.transaction.binding_cookie_hash).toBe(h('cookie'));
      }
    });

    it('reentry only with the matching cookie, and it invalidates the outstanding handle', async () => {
      const input = await authorized();
      await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: h('cookie'), new_handle_hash: h('h2'), now: at(2),
      });
      const wrong = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: h('wrong'), new_handle_hash: h('hx'), now: at(3),
      });
      expect(wrong).toEqual({ kind: 'rejected', reason: 'replayed' });

      const back = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: h('cookie'), new_handle_hash: h('h3'), now: at(3),
      });
      expect(back.kind).toBe('reentry');
      if (back.kind === 'reentry') {
        expect(back.transaction.handle_hash).toBe(h('h3'));
        expect(back.transaction.step).toBe('picker');
      }
      // h2 was outstanding and is now invalid.
      const stale = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h2'), presented_cookie_hash: null, new_handle_hash: h('h4'), now: at(4),
      });
      expect(stale).toEqual({ kind: 'rejected', reason: 'replayed' });
    });

    it('embedded mode: the first top-level page sets the binding cookie once', async () => {
      const input = await authorized({ setCookie: false });
      expect((await store.getTransaction(input.tid))?.binding_cookie_hash).toBeUndefined();
      const first = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: null,
        new_handle_hash: h('h2'), new_binding_cookie_hash: h('c1'), now: at(2),
      });
      if (first.kind !== 'fresh') throw new Error(first.kind);
      expect(first.transaction.binding_cookie_hash).toBe(h('c1'));
      const second = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h2'), presented_cookie_hash: h('c1'),
        new_handle_hash: h('h3'), new_binding_cookie_hash: h('c2'), now: at(3),
      });
      if (second.kind !== 'fresh') throw new Error(second.kind);
      expect(second.transaction.binding_cookie_hash).toBe(h('c1'));
      // Once set, the cookie binds the handle: another browser holding h3 is refused.
      const before = await store.getTransaction(input.tid);
      expect(await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h3'), presented_cookie_hash: null,
        new_handle_hash: h('h4'), new_binding_cookie_hash: h('c3'), now: at(4),
      })).toEqual({ kind: 'rejected', reason: 'replayed' });
      expect(await store.getTransaction(input.tid)).toEqual(before);
    });

    it('embedded mode: before any cookie is set, a handle alone is fresh and no cookie is required', async () => {
      const input = await authorized({ setCookie: false });
      const r = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: null, new_handle_hash: h('h2'), now: at(2),
      });
      expect(r.kind).toBe('fresh');
      if (r.kind === 'fresh') expect(r.transaction.binding_cookie_hash).toBeUndefined();
      const again = await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h2'), presented_cookie_hash: h('anything'), new_handle_hash: h('h3'), now: at(3),
      });
      expect(again.kind).toBe('fresh');
      // Without a binding cookie there is no reentry: a consumed handle is just replayed.
      expect(await store.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h2'), presented_cookie_hash: h('anything'), new_handle_hash: h('h4'), now: at(4),
      })).toEqual({ kind: 'rejected', reason: 'replayed' });
    });

    it('rejects unknown, client mismatch, expired and finished', async () => {
      const input = await authorized();
      const base = { handle_hash: h('h1'), presented_cookie_hash: h('cookie'), new_handle_hash: h('h2') };
      expect(await store.enterByHandle({ ...base, tid: 'ltx_unknown' as TransactionId, client_id: 'acme', now: at(2) }))
        .toEqual({ kind: 'rejected', reason: 'unknown' });
      expect(await store.enterByHandle({ ...base, tid: input.tid, client_id: 'evil', now: at(2) }))
        .toEqual({ kind: 'rejected', reason: 'client_mismatch' });
      expect(await store.enterByHandle({ ...base, tid: input.tid, client_id: 'acme', now: at(601) }))
        .toEqual({ kind: 'rejected', reason: 'expired' });
      await store.endTransaction({ tid: input.tid, outcome: 'failed', error: 'provider_error', now: at(3) });
      expect(await store.enterByHandle({ ...base, tid: input.tid, client_id: 'acme', now: at(4) }))
        .toEqual({ kind: 'rejected', reason: 'finished' });
    });
  });

  describe('races', () => {
    let dir: string;
    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), 'link-store-race-'));
    });
    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('two connections presenting the same handle at once: exactly one wins (no cookie yet)', async () => {
      const path = join(dir, 'link.db');
      const contenders = Array.from({ length: 8 }, () => new SqliteLinkStore(path));
      const input = newTx();
      await contenders[0].createTransaction(input);
      await contenders[0].enterByRequestUri({
        request_uri_hash: input.request_uri_hash, presented_cookie_hash: null, new_handle_hash: h('h1'),
        mode: 'embedded', now: at(1),
      });
      const results = await Promise.all(contenders.map((s, i) => s.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: null, new_handle_hash: h(`next-${i}`), now: at(2),
      })));
      const winners = results.filter((r) => r.kind === 'fresh');
      expect(winners).toHaveLength(1);
      expect(results.filter((r) => r.kind === 'rejected' && r.reason === 'replayed')).toHaveLength(7);
      const winnerIndex = results.findIndex((r) => r.kind === 'fresh');
      expect((await contenders[3].getTransaction(input.tid))?.handle_hash).toBe(h(`next-${winnerIndex}`));
      contenders.forEach((s) => s.close());
    });

    it('cookie-bound handle raced by the same browser: one fresh, the rest reentry; by other browsers: all replayed', async () => {
      const path = join(dir, 'link.db');
      const contenders = Array.from({ length: 6 }, () => new SqliteLinkStore(path));
      const input = newTx();
      await contenders[0].createTransaction(input);
      await contenders[0].enterByRequestUri({
        request_uri_hash: input.request_uri_hash, presented_cookie_hash: null, new_handle_hash: h('h1'),
        new_binding_cookie_hash: h('cookie'), mode: 'popup', now: at(1),
      });
      const strangers = await Promise.all(contenders.map((s, i) => s.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: i % 2 ? null : h(`other-${i}`),
        new_handle_hash: h(`stranger-${i}`), now: at(2),
      })));
      expect(strangers.every((r) => r.kind === 'rejected' && r.reason === 'replayed')).toBe(true);
      expect((await contenders[0].getTransaction(input.tid))?.handle_hash).toBe(h('h1'));

      const same = await Promise.all(contenders.map((s, i) => s.enterByHandle({
        tid: input.tid, client_id: 'acme', handle_hash: h('h1'), presented_cookie_hash: h('cookie'), new_handle_hash: h(`same-${i}`), now: at(3),
      })));
      expect(same.filter((r) => r.kind === 'fresh')).toHaveLength(1);
      expect(same.filter((r) => r.kind === 'reentry')).toHaveLength(5);
      contenders.forEach((s) => s.close());
    });

    it('two simultaneous request_uri uses: exactly one is fresh', async () => {
      const input = newTx();
      await store.createTransaction(input);
      const call = (i: number) => store.enterByRequestUri({
        request_uri_hash: input.request_uri_hash, presented_cookie_hash: null, new_handle_hash: h(`h-${i}`),
        new_binding_cookie_hash: h(`c-${i}`), mode: 'popup', now: at(1),
      });
      const [a, b] = await Promise.all([call(1), call(2)]);
      expect([a.kind, b.kind].sort()).toEqual(['fresh', 'rejected']);
    });

    it('two simultaneous confirms: one committed, one already_committed with the same ids', async () => {
      const input = newTx();
      await driveToConfirm(store, input);
      const [a, b] = await Promise.all([confirm(store, input.tid), confirm(store, input.tid)]);
      expect([a.kind, b.kind].sort()).toEqual(['already_committed', 'committed']);
      expect(a.transaction.connection_id).toBe(b.transaction.connection_id);
      expect(a.transaction.grant_id).toBe(b.transaction.grant_id);
    });
  });

  // ── advanceTransaction ────────────────────────────────────────────────────

  describe('advanceTransaction', () => {
    it('is compare-and-set on the step', async () => {
      const input = newTx();
      await store.createTransaction(input);
      expect(await store.advanceTransaction({ tid: input.tid, from: 'provider', to: 'confirm', patch: { exchanged_at: at(1) }, now: at(1) })).toBeNull();
      const a = await store.advanceTransaction({ tid: input.tid, from: 'picker', to: 'provider', patch: { provider: 'google' }, now: at(1) });
      expect(a?.step).toBe('provider');
      // A second identical transition loses: the step is no longer picker.
      expect(await store.advanceTransaction({ tid: input.tid, from: 'picker', to: 'provider', patch: { provider: 'slack' }, now: at(2) })).toBeNull();
      expect((await store.getTransaction(input.tid))?.provider).toBe('google');
    });

    it('rejects disallowed transitions, confirm -> done, and provider -> confirm without exchanged_at', async () => {
      const input = newTx();
      await store.createTransaction(input);
      await expect(store.advanceTransaction({ tid: input.tid, from: 'picker', to: 'confirm', patch: {}, now: at(1) }))
        .rejects.toMatchObject({ code: 'invalid_transition' });
      await expect(store.advanceTransaction({ tid: input.tid, from: 'confirm', to: 'done', patch: {}, now: at(1) }))
        .rejects.toMatchObject({ code: 'invalid_transition' });
      await expect(store.advanceTransaction({ tid: input.tid, from: 'provider', to: 'confirm', patch: {}, now: at(1) }))
        .rejects.toMatchObject({ code: 'invalid_input' });
      await expect(store.advanceTransaction({
        tid: input.tid, from: 'picker', to: 'provider', patch: { step: 'done' } as never, now: at(1),
      })).rejects.toMatchObject({ code: 'invalid_input' });
    });

    it('refuses a provider outside the transaction providers', async () => {
      const input = newTx({ providers: ['google'] });
      await store.createTransaction(input);
      await expect(store.advanceTransaction({ tid: input.tid, from: 'picker', to: 'provider', patch: { provider: 'github' }, now: at(1) }))
        .rejects.toMatchObject({ code: 'invalid_input' });
      expect((await store.getTransaction(input.tid))?.step).toBe('picker');
    });

    it('applies the patch, null clears, and confirm -> provider restarts the hop', async () => {
      const input = newTx();
      const { tx } = await driveToConfirm(store, input);
      expect(tx.step).toBe('confirm');
      expect(tx.pkce_verifier).toBeUndefined();
      expect(tx.provider_granted_scopes).toEqual(['calendar.readonly', 'gmail.send']);
      const back = await store.advanceTransaction({
        tid: input.tid, from: 'confirm', to: 'provider',
        patch: { pkce_verifier: 'verifier-2', provider_attempt: 2, exchanged_at: null, provider_granted_scopes: null },
        now: at(30),
      });
      expect(back?.step).toBe('provider');
      expect(back?.provider_attempt).toBe(2);
      expect(back?.exchanged_at).toBeUndefined();
      expect(back?.provider_granted_scopes).toBeUndefined();
    });

    it('returns null when terminal or expired', async () => {
      const a = newTx();
      await store.createTransaction(a);
      expect(await store.advanceTransaction({ tid: a.tid, from: 'picker', to: 'provider', patch: {}, now: at(600) })).toBeNull();
      await store.endTransaction({ tid: a.tid, outcome: 'cancelled', now: at(1) });
      expect(await store.advanceTransaction({ tid: a.tid, from: 'picker', to: 'provider', patch: {}, now: at(2) })).toBeNull();
    });
  });

  // ── commitConfirm ─────────────────────────────────────────────────────────

  describe('commitConfirm', () => {
    it('connect: inserts a pending connection and grant exactly once', async () => {
      const input = newTx();
      await driveToConfirm(store, input);
      const first = await confirm(store, input.tid, { scopes: ['calendar.readonly', 'gmail.send'] });
      expect(first.kind).toBe('committed');
      const tx = first.transaction;
      expect(tx.step).toBe('done');
      expect(tx.creates_connection).toBe(true);
      expect(tx.confirmed_scopes).toEqual(['calendar.readonly', 'gmail.send']);
      expect(tx.activation_code_hash).toBe(h(`code-${input.tid}`));
      expect(tx.confirmed_at).toBe(at(10));

      const conn = await store.getConnection(tx.connection_id as string);
      expect(conn).toMatchObject({
        status: 'pending', version: 1, provider: 'google', subject: 'user-123', client_id: 'acme',
        org_id: 'org_default', provider_account_id: 'google-sub-1', provider_scopes: ['calendar.readonly', 'gmail.send'],
      });
      const grant = await store.getGrantForConnection(tx.connection_id as string);
      expect(grant).toMatchObject({
        id: tx.grant_id, status: 'pending', version: 1, scopes: ['calendar.readonly', 'gmail.send'],
        audience: 'https://www.googleapis.com', org_policy: { usage: 'allow' }, authorization_details_types: [],
      });

      const second = await confirm(store, input.tid, { scopes: ['calendar.readonly'] });
      expect(second.kind).toBe('already_committed');
      expect(second.transaction.connection_id).toBe(tx.connection_id);
      expect(second.transaction.grant_id).toBe(tx.grant_id);
      expect(second.transaction.confirmed_scopes).toEqual(['calendar.readonly', 'gmail.send']);
      expect(await store.listConnections({ client_id: 'acme', subject: 'user-123' })).toHaveLength(1);
    });

    it('requires step confirm', async () => {
      const input = newTx();
      await store.createTransaction(input);
      await expect(confirm(store, input.tid)).rejects.toMatchObject({ code: 'wrong_step' });
      await expect(confirm(store, 'ltx_missing' as TransactionId)).rejects.toMatchObject({ code: 'not_found' });
    });

    it('refuses confirmed scopes the provider did not grant, and hidden scopes', async () => {
      const input = newTx();
      await driveToConfirm(store, input);
      await expect(confirm(store, input.tid, { scopes: ['calendar.readonly', 'drive'] })).rejects.toMatchObject({ code: 'invalid_scopes' });
      expect((await store.getTransaction(input.tid))?.step).toBe('confirm');

      const sf = newTx({ providers: ['salesforce'], requested_scopes: { salesforce: ['api'] }, required_scopes: {} });
      await driveToConfirm(store, sf, { provider: 'salesforce', granted: ['api', 'refresh_token'], accountId: 'sf-1' });
      await expect(confirm(store, sf.tid, { scopes: ['api', 'refresh_token'], accountId: 'sf-1', granted: ['api', 'refresh_token'] }))
        .rejects.toMatchObject({ code: 'invalid_scopes' });
    });

    it('Google identity scopes the provider returns (openid, long-form userinfo.email) never enter a grant', async () => {
      const granted = [
        'openid',
        'https://www.googleapis.com/auth/userinfo.email',
        'email',
        'profile',
        'https://www.googleapis.com/auth/calendar.readonly',
        'gmail.send',
      ];
      const input = newTx();
      const { tx } = await driveToConfirm(store, input, { granted });
      expect(tx.provider_granted_scopes).toEqual(['calendar.readonly', 'email', 'gmail.send', 'openid', 'profile', 'userinfo.email']);
      for (const extra of ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'userinfo.email', 'email', 'profile']) {
        await expect(confirm(store, input.tid, { scopes: ['calendar.readonly', extra], granted }))
          .rejects.toMatchObject({ code: 'invalid_scopes' });
      }
      const ok = await confirm(store, input.tid, { scopes: ['calendar.readonly', 'gmail.send'], granted });
      expect(ok.kind).toBe('committed');
      const connection_id = ok.transaction.connection_id as string;
      // The connection records everything the provider granted; the grant holds data scopes only.
      expect((await store.getConnection(connection_id))?.provider_scopes).toEqual(tx.provider_granted_scopes);
      expect((await store.getGrantForConnection(connection_id))?.scopes).toEqual(['calendar.readonly', 'gmail.send']);

      // Provider scope changes keep hidden scopes out too.
      await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: h(`code-${input.tid}`), subject: 'user-123', now: at(20) });
      await store.commitActivation({ tid: input.tid, now: at(21) });
      const r = await store.applyProviderScopes({ connection_id, provider_scopes: ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'gmail.send'], now: at(30) });
      expect(r?.grant?.scopes).toEqual(['gmail.send']);
    });

    it('a staged update cannot add hidden scopes either (HubSpot oauth)', async () => {
      const first = newTx({ providers: ['hubspot'], requested_scopes: { hubspot: ['crm.objects.contacts.read'] }, required_scopes: {} });
      await driveToConfirm(store, first, { provider: 'hubspot', granted: ['oauth', 'crm.objects.contacts.read'], accountId: 'hub-1' });
      await expect(confirm(store, first.tid, { scopes: ['oauth', 'crm.objects.contacts.read'], accountId: 'hub-1', granted: ['oauth', 'crm.objects.contacts.read'] }))
        .rejects.toMatchObject({ code: 'invalid_scopes' });
      const c = await confirm(store, first.tid, { scopes: ['crm.objects.contacts.read'], accountId: 'hub-1', granted: ['oauth', 'crm.objects.contacts.read'] });
      expect(c.kind).toBe('committed');

      const update = newTx({ intent: 'update', providers: ['hubspot'], connection_id: c.transaction.connection_id, requested_scopes: { hubspot: ['crm.objects.contacts.write'] }, required_scopes: {} });
      await driveToConfirm(store, update, { provider: 'hubspot', granted: ['oauth', 'crm.objects.contacts.read', 'crm.objects.contacts.write'], accountId: 'hub-1' });
      await expect(confirm(store, update.tid, { scopes: ['oauth', 'crm.objects.contacts.write'], accountId: 'hub-1' }))
        .rejects.toMatchObject({ code: 'invalid_scopes' });
    });

    it('allows Cred-enforced catalog scopes the provider does not grant (Notion content)', async () => {
      const input = newTx({ providers: ['notion'], requested_scopes: { notion: ['content'] }, required_scopes: {} });
      await driveToConfirm(store, input, { provider: 'notion', granted: [], accountId: 'notion-bot-1' });
      const c = await confirm(store, input.tid, { scopes: ['content'], granted: [], accountId: 'notion-bot-1' });
      expect(c.kind).toBe('committed');
    });

    it('connect onto a live connection for the same account stages instead of inserting', async () => {
      const existing = await connectActive(store);
      const input = newTx();
      await driveToConfirm(store, input);
      const c = await confirm(store, input.tid, { scopes: ['calendar.readonly', 'gmail.send'] });
      expect(c.kind).toBe('committed');
      expect(c.transaction.creates_connection).toBe(false);
      expect(c.transaction.connection_id).toBe(existing.connection_id);
      expect(c.transaction.grant_id).toBe(existing.grant_id);
      expect(await store.listConnections({ client_id: 'acme', subject: 'user-123' })).toHaveLength(1);
      // Nothing was written to the connection or grant yet.
      expect((await store.getGrant(existing.grant_id))?.scopes).toEqual(['calendar.readonly']);
    });

    it('connect after the old connection was revoked creates a new one', async () => {
      const old = await connectActive(store);
      await store.setConnectionStatus({ connection_id: old.connection_id, status: 'revoked', now: at(30) });
      const input = newTx();
      await driveToConfirm(store, input);
      const c = await confirm(store, input.tid);
      expect(c.transaction.creates_connection).toBe(true);
      expect(c.transaction.connection_id).not.toBe(old.connection_id);
    });

    it('update/reauth: account_mismatch on a different provider account', async () => {
      const existing = await connectActive(store);
      const input = newTx({ intent: 'reauth', providers: ['google'], connection_id: existing.connection_id });
      await driveToConfirm(store, input, { accountId: 'google-sub-OTHER' });
      const c = await confirm(store, input.tid, { accountId: 'google-sub-OTHER' });
      expect(c.kind).toBe('account_mismatch');
      expect(c.transaction.step).toBe('confirm');
      expect(c.transaction.confirmed_at).toBeUndefined();
    });

    it('update/reauth: connection_unavailable when revoked or owned by another subject', async () => {
      const existing = await connectActive(store);
      const foreign = newTx({ intent: 'update', providers: ['google'], connection_id: existing.connection_id, subject: 'user-999' });
      await driveToConfirm(store, foreign);
      expect((await confirm(store, foreign.tid)).kind).toBe('connection_unavailable');

      const unknown = newTx({ intent: 'update', providers: ['google'], connection_id: 'conn_doesnotexist' as ConnectionId });
      await driveToConfirm(store, unknown);
      expect((await confirm(store, unknown.tid)).kind).toBe('connection_unavailable');

      await store.setConnectionStatus({ connection_id: existing.connection_id, status: 'revoked', now: at(30) });
      const revoked = newTx({ intent: 'update', providers: ['google'], connection_id: existing.connection_id });
      await driveToConfirm(store, revoked);
      expect((await confirm(store, revoked.tid)).kind).toBe('connection_unavailable');
    });

    it('update: committed stages onto the existing connection', async () => {
      const existing = await connectActive(store);
      const input = newTx({ intent: 'update', providers: ['google'], connection_id: existing.connection_id, requested_scopes: { google: ['calendar.readonly', 'calendar.events', 'gmail.send'] }, });
      await driveToConfirm(store, input, { granted: ['calendar.readonly', 'gmail.send', 'calendar.events'] });
      const c = await confirm(store, input.tid, { scopes: ['calendar.readonly', 'calendar.events'] });
      expect(c.kind).toBe('committed');
      expect(c.transaction).toMatchObject({ creates_connection: false, connection_id: existing.connection_id, grant_id: existing.grant_id });
    });
  });

  describe('replaceActivationCode', () => {
    it('replaces the hash only while confirmed, unclaimed and live', async () => {
      const input = newTx();
      await driveToConfirm(store, input);
      expect(await store.replaceActivationCode({ tid: input.tid, activation_code_hash: h('c2'), now: at(11) })).toBe(false);
      const c = await confirm(store, input.tid);
      expect(await store.replaceActivationCode({ tid: input.tid, activation_code_hash: h('c2'), now: at(11) })).toBe(true);
      // The old code no longer works.
      expect(await store.claimActivation({
        client_id: 'acme', connection_id: c.transaction.connection_id as string, activation_code_hash: h(`code-${input.tid}`), subject: 'user-123', now: at(12),
      })).toEqual({ ok: false, reason: 'invalid_code' });
      const claim = await store.claimActivation({
        client_id: 'acme', connection_id: c.transaction.connection_id as string, activation_code_hash: h('c2'), subject: 'user-123', now: at(12),
      });
      expect(claim.ok).toBe(true);
      expect(await store.replaceActivationCode({ tid: input.tid, activation_code_hash: h('c3'), now: at(13) })).toBe(false);
    });
  });

  // ── Activation ────────────────────────────────────────────────────────────

  describe('claimActivation', () => {
    async function confirmed(overrides = {}) {
      const input = newTx(overrides);
      await driveToConfirm(store, input);
      const c = await confirm(store, input.tid);
      return { input, connection_id: c.transaction.connection_id as string, code: h(`code-${input.tid}`) };
    }

    it('consumes the code exactly once', async () => {
      const { input, connection_id, code } = await confirmed();
      const first = await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: code, subject: 'user-123', now: at(20) });
      expect(first.ok).toBe(true);
      if (first.ok) expect(first.transaction.activation_claimed_at).toBe(at(20));
      const second = await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: code, subject: 'user-123', now: at(21) });
      expect(second).toEqual({ ok: false, reason: 'invalid_code' });
      expect((await store.getTransaction(input.tid))?.activation_claimed_at).toBe(at(20));
    });

    it('invalid_code for a wrong code, wrong client or wrong connection, changing nothing', async () => {
      const { input, connection_id, code } = await confirmed();
      const before = await store.getTransaction(input.tid);
      for (const attempt of [
        { client_id: 'acme', connection_id, activation_code_hash: h('wrong') },
        { client_id: 'other', connection_id, activation_code_hash: code },
        { client_id: 'acme', connection_id: 'conn_other', activation_code_hash: code },
      ]) {
        expect(await store.claimActivation({ ...attempt, subject: 'user-123', now: at(20) })).toEqual({ ok: false, reason: 'invalid_code' });
      }
      expect(await store.getTransaction(input.tid)).toEqual(before);
    });

    it('connect + subject mismatch: ends the transaction and revokes the connection and grant it created', async () => {
      const { input, connection_id, code } = await confirmed();
      const r = await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: code, subject: 'attacker', now: at(20) });
      expect(r.ok).toBe(false);
      if (r.ok || r.reason !== 'subject_mismatch') throw new Error('expected subject_mismatch');
      expect(r.transaction).toMatchObject({ tid: input.tid, outcome: 'failed', error: 'access_denied', consumed_at: at(20) });
      expect(await store.getConnection(connection_id)).toMatchObject({ status: 'revoked', version: 2 });
      expect(await store.getGrantForConnection(connection_id)).toMatchObject({ status: 'revoked', version: 2 });
      // The code cannot be retried with the right subject.
      expect(await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: code, subject: 'user-123', now: at(21) }))
        .toEqual({ ok: false, reason: 'invalid_code' });
    });

    it('update + subject mismatch: ends the transaction and leaves the existing connection untouched', async () => {
      const existing = await connectActive(store);
      const connBefore = await store.getConnection(existing.connection_id);
      const grantBefore = await store.getGrant(existing.grant_id);
      const input = newTx({ intent: 'update', providers: ['google'], connection_id: existing.connection_id });
      await driveToConfirm(store, input);
      await confirm(store, input.tid);
      const r = await store.claimActivation({
        client_id: 'acme', connection_id: existing.connection_id, activation_code_hash: h(`code-${input.tid}`), subject: 'attacker', now: at(20),
      });
      expect(r.ok === false && r.reason === 'subject_mismatch').toBe(true);
      if (!r.ok && r.reason !== 'invalid_code') expect(r.transaction.outcome).toBe('failed');
      expect(await store.getConnection(existing.connection_id)).toEqual(connBefore);
      expect(await store.getGrant(existing.grant_id)).toEqual(grantBefore);
    });

    it('expired: ends the transaction as expired and revokes what it created (grant expired)', async () => {
      const { input, connection_id, code } = await confirmed();
      const r = await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: code, subject: 'user-123', now: at(600) });
      expect(r.ok === false && r.reason === 'expired').toBe(true);
      expect(await store.getTransaction(input.tid)).toMatchObject({ outcome: 'expired', consumed_at: at(600) });
      expect(await store.getConnection(connection_id)).toMatchObject({ status: 'revoked' });
      expect(await store.getGrantForConnection(connection_id)).toMatchObject({ status: 'expired' });
    });
  });

  describe('commitActivation', () => {
    it('new connection: pending -> active, versions bumped, transaction activated, once only', async () => {
      const input = newTx();
      await driveToConfirm(store, input);
      const c = await confirm(store, input.tid);
      const connection_id = c.transaction.connection_id as string;
      await expect(store.commitActivation({ tid: input.tid, now: at(20) })).rejects.toMatchObject({ code: 'not_claimed' });
      await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: h(`code-${input.tid}`), subject: 'user-123', now: at(20) });
      const r = await store.commitActivation({ tid: input.tid, now: at(21) });
      expect(r.previous_grant_scopes).toBeNull();
      expect(r.connection).toMatchObject({ id: connection_id, status: 'active', version: 2, updated_at: at(21) });
      expect(r.grant).toMatchObject({ id: c.transaction.grant_id, status: 'active', version: 2, scopes: ['calendar.readonly'] });
      expect(await store.getTransaction(input.tid)).toMatchObject({ outcome: 'activated', activated_at: at(21), consumed_at: at(21) });
      await expect(store.commitActivation({ tid: input.tid, now: at(22) })).rejects.toMatchObject({ code: 'terminal' });
    });

    it('staged update: applies provider and grant scopes in place, same ids, versions + 1', async () => {
      const existing = await connectActive(store);
      await store.setConnectionStatus({ connection_id: existing.connection_id, status: 'needs_reauth', reason: 'grant_expired', now: at(25) });
      const connBefore = await store.getConnection(existing.connection_id);
      const grantBefore = await store.getGrant(existing.grant_id);

      const input = newTx({ intent: 'reauth', providers: ['google'], connection_id: existing.connection_id, grant_id: existing.grant_id, requested_scopes: { google: ['calendar.readonly', 'calendar.events', 'gmail.send'] }, });
      await driveToConfirm(store, input, { granted: ['calendar.readonly', 'calendar.events', 'gmail.send'] });
      await confirm(store, input.tid, { scopes: ['calendar.events', 'calendar.readonly'] });
      await store.claimActivation({
        client_id: 'acme', connection_id: existing.connection_id, activation_code_hash: h(`code-${input.tid}`), subject: 'user-123', now: at(40),
      });
      const r = await store.commitActivation({ tid: input.tid, now: at(41) });
      expect(r.previous_grant_scopes).toEqual(['calendar.readonly']);
      expect(r.connection).toMatchObject({
        id: existing.connection_id, status: 'active', version: (connBefore?.version ?? 0) + 1,
        provider_scopes: ['calendar.events', 'calendar.readonly', 'gmail.send'],
      });
      expect(r.connection.status_reason).toBeUndefined();
      expect(r.grant).toMatchObject({
        id: existing.grant_id, status: 'active', version: (grantBefore?.version ?? 0) + 1,
        scopes: ['calendar.events', 'calendar.readonly'],
      });
    });

    it('fails if the created connection was revoked between claim and commit', async () => {
      const input = newTx();
      await driveToConfirm(store, input);
      const c = await confirm(store, input.tid);
      const connection_id = c.transaction.connection_id as string;
      await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: h(`code-${input.tid}`), subject: 'user-123', now: at(20) });
      await store.setConnectionStatus({ connection_id, status: 'revoked', now: at(20) });
      await expect(store.commitActivation({ tid: input.tid, now: at(21) })).rejects.toMatchObject({ code: 'connection_unavailable' });
    });
  });

  // ── Ending and sweeping ──────────────────────────────────────────────────

  describe('endTransaction', () => {
    it('revokes the pending connection and grant the transaction created and returns it once', async () => {
      const input = newTx();
      await driveToConfirm(store, input);
      const c = await confirm(store, input.tid);
      const ended = await store.endTransaction({ tid: input.tid, outcome: 'failed', error: 'required_scope_declined', now: at(15) });
      expect(ended).toMatchObject({
        tid: input.tid, outcome: 'failed', error: 'required_scope_declined', consumed_at: at(15),
        creates_connection: true, connection_id: c.transaction.connection_id,
      });
      expect(await store.getConnection(c.transaction.connection_id as string)).toMatchObject({ status: 'revoked' });
      expect(await store.getGrant(c.transaction.grant_id as string)).toMatchObject({ status: 'revoked' });
      expect(await store.endTransaction({ tid: input.tid, outcome: 'cancelled', now: at(16) })).toBeNull();
      expect(await store.endTransaction({ tid: 'ltx_unknown' as TransactionId, outcome: 'cancelled', now: at(16) })).toBeNull();
    });

    it('update intent: ends without touching the existing connection', async () => {
      const existing = await connectActive(store);
      const before = await store.getConnection(existing.connection_id);
      const input = newTx({ intent: 'update', providers: ['google'], connection_id: existing.connection_id });
      await driveToConfirm(store, input);
      await confirm(store, input.tid);
      const ended = await store.endTransaction({ tid: input.tid, outcome: 'cancelled', now: at(30) });
      expect(ended?.creates_connection).toBe(false);
      expect(await store.getConnection(existing.connection_id)).toEqual(before);
    });

    it('two connects for one account each own their pending rows; ending the loser leaves the winner alone', async () => {
      const first = newTx();
      await driveToConfirm(store, first);
      const c1 = await confirm(store, first.tid);
      const second = newTx();
      await driveToConfirm(store, second);
      const c2 = await confirm(store, second.tid);
      expect(c1.transaction.creates_connection).toBe(true);
      expect(c2.transaction.creates_connection).toBe(true);
      expect(c2.transaction.connection_id).not.toBe(c1.transaction.connection_id);
      await store.claimActivation({
        client_id: 'acme', connection_id: c2.transaction.connection_id as string, activation_code_hash: h(`code-${second.tid}`), subject: 'user-123', now: at(20),
      });
      await store.commitActivation({ tid: second.tid, now: at(21) });
      const winnerBefore = await store.getConnection(c2.transaction.connection_id as string);
      await store.endTransaction({ tid: first.tid, outcome: 'cancelled', now: at(22) });
      expect(await store.getConnection(c1.transaction.connection_id as string)).toMatchObject({ status: 'revoked' });
      expect(await store.getConnection(c2.transaction.connection_id as string)).toEqual(winnerBefore);
    });
  });

  describe('sweepExpiredTransactions', () => {
    it('ends expired transactions, revokes what they created (grant expired), respects limit, skips terminal', async () => {
      const abandoned = newTx();
      await driveToConfirm(store, abandoned);
      const c = await confirm(store, abandoned.tid);
      const idle = newTx({ expires_at: at(300) });
      await store.createTransaction(idle);
      const done = await connectActive(store, {}, { accountId: 'google-sub-2' });
      const live = newTx({ expires_at: at(5000) });
      await store.createTransaction(live);

      expect(await store.sweepExpiredTransactions({ now: at(599), limit: 10 })).toHaveLength(1);
      const swept = await store.sweepExpiredTransactions({ now: at(700), limit: 10 });
      expect(swept.map((t) => t.tid).sort()).toEqual([abandoned.tid].sort());
      expect(swept[0]).toMatchObject({ outcome: 'expired', consumed_at: at(700), creates_connection: true });
      expect(await store.getTransaction(idle.tid)).toMatchObject({ outcome: 'expired', consumed_at: at(599) });
      expect(await store.getConnection(c.transaction.connection_id as string)).toMatchObject({ status: 'revoked' });
      expect(await store.getGrant(c.transaction.grant_id as string)).toMatchObject({ status: 'expired' });
      expect(await store.getTransaction(done.tid)).toMatchObject({ outcome: 'activated' });
      expect(await store.getTransaction(live.tid)).not.toHaveProperty('outcome');
      expect(await store.getConnection(done.connection_id)).toMatchObject({ status: 'active' });
      expect(await store.sweepExpiredTransactions({ now: at(700), limit: 10 })).toEqual([]);
    });

    it('honors limit', async () => {
      for (let i = 0; i < 5; i++) await store.createTransaction(newTx({ expires_at: at(10 + i) }));
      expect(await store.sweepExpiredTransactions({ now: at(100), limit: 2 })).toHaveLength(2);
      expect(await store.sweepExpiredTransactions({ now: at(100), limit: 0 })).toHaveLength(0);
      expect(await store.sweepExpiredTransactions({ now: at(100), limit: 10 })).toHaveLength(3);
    });

    it('leaves a just-claimed activation alone for the grace period', async () => {
      const input = newTx({ expires_at: at(30) });
      await driveToConfirm(store, input);
      const c = await confirm(store, input.tid);
      await store.claimActivation({
        client_id: 'acme', connection_id: c.transaction.connection_id as string, activation_code_hash: h(`code-${input.tid}`), subject: 'user-123', now: at(29),
      });
      expect(await store.sweepExpiredTransactions({ now: at(31), limit: 10 })).toEqual([]);
      const r = await store.commitActivation({ tid: input.tid, now: at(32) });
      expect(r.connection.status).toBe('active');
    });
  });

  // ── Connections and grants ───────────────────────────────────────────────

  describe('setConnectionStatus', () => {
    it('cascades to the grant per LINK_GRANT_STATUS_FOR_CONNECTION_STATUS and bumps versions', async () => {
      const { connection_id, grant_id } = await connectActive(store);
      for (const status of ['needs_reauth', 'frozen', 'active'] as const) {
        const before = await store.getConnection(connection_id);
        const gBefore = await store.getGrant(grant_id);
        const r = await store.setConnectionStatus({ connection_id, status, reason: 'grant_reuse_detected', now: at(50) });
        expect(r?.connection.status).toBe(status);
        expect(r?.connection.version).toBe((before?.version ?? 0) + 1);
        expect(r?.grant?.status).toBe(LINK_GRANT_STATUS_FOR_CONNECTION_STATUS[status]);
        if (gBefore?.status !== LINK_GRANT_STATUS_FOR_CONNECTION_STATUS[status]) {
          expect(r?.grant?.version).toBe((gBefore?.version ?? 0) + 1);
        }
        if (status === 'active') expect(r?.connection.status_reason).toBeUndefined();
        else expect(r?.connection.status_reason).toBe('grant_reuse_detected');
      }
    });

    it('revoked is terminal', async () => {
      const { connection_id, grant_id } = await connectActive(store);
      const r = await store.setConnectionStatus({ connection_id, status: 'revoked', now: at(50) });
      expect(r?.grant?.status).toBe('revoked');
      expect(await store.setConnectionStatus({ connection_id, status: 'active', now: at(51) })).toBeNull();
      expect(await store.setConnectionStatus({ connection_id, status: 'revoked', now: at(51) })).toBeNull();
      expect(await store.getConnection(connection_id)).toMatchObject({ status: 'revoked' });
      expect(await store.getGrant(grant_id)).toMatchObject({ status: 'revoked' });
      expect(await store.setConnectionStatus({ connection_id: 'conn_unknown', status: 'active', now: at(51) })).toBeNull();
    });

    it('never activates a pending connection (activation is the only path), but can revoke it', async () => {
      const input = newTx();
      await driveToConfirm(store, input);
      const c = await confirm(store, input.tid);
      const connection_id = c.transaction.connection_id as string;
      expect(await store.setConnectionStatus({ connection_id, status: 'active', now: at(20) })).toBeNull();
      expect(await store.getConnection(connection_id)).toMatchObject({ status: 'pending' });
      await expect(store.setConnectionStatus({ connection_id, status: 'pending' as never, now: at(20) }))
        .rejects.toMatchObject({ code: 'invalid_input' });
      const r = await store.setConnectionStatus({ connection_id, status: 'revoked', now: at(21) });
      expect(r?.connection.status).toBe('revoked');
    });

    it('does not bump versions for a no-op', async () => {
      const { connection_id } = await connectActive(store);
      const before = await store.getConnection(connection_id);
      const r = await store.setConnectionStatus({ connection_id, status: 'active', now: at(60) });
      expect(r?.connection.version).toBe(before?.version);
    });
  });

  describe('applyProviderScopes', () => {
    it('records the reported scopes and intersects the grant, never widening it', async () => {
      const { connection_id, grant_id } = await connectActive(store, {}, { scopes: ['calendar.readonly', 'gmail.send'] });
      const narrowed = await store.applyProviderScopes({ connection_id, provider_scopes: ['calendar.readonly', 'drive'], now: at(50) });
      expect(narrowed?.connection.provider_scopes).toEqual(['calendar.readonly', 'drive']);
      expect(narrowed?.grant?.scopes).toEqual(['calendar.readonly']);
      expect(narrowed?.previous_grant_scopes).toEqual(['calendar.readonly', 'gmail.send']);
      const g1 = await store.getGrant(grant_id);

      // The provider reporting more never widens the grant.
      const wider = await store.applyProviderScopes({ connection_id, provider_scopes: ['calendar.readonly', 'gmail.send', 'drive'], now: at(51) });
      expect(wider?.grant?.scopes).toEqual(['calendar.readonly']);
      expect(wider?.grant?.version).toBe(g1?.version);
      expect(wider?.connection.provider_scopes).toEqual(['calendar.readonly', 'drive', 'gmail.send']);

      // No change, no bump.
      const same = await store.applyProviderScopes({ connection_id, provider_scopes: ['gmail.send', 'drive', 'calendar.readonly'], now: at(52) });
      expect(same?.connection.version).toBe(wider?.connection.version);
      expect(same?.grant?.version).toBe(wider?.grant?.version);
    });

    it('keeps Cred-enforced scopes that are not provider scopes', async () => {
      const { connection_id } = await connectActive(
        store,
        { providers: ['notion'], requested_scopes: { notion: ['content'] }, required_scopes: {} },
        { accountId: 'notion-bot-1', scopes: ['content'], granted: [], provider: 'notion' },
      );
      const r = await store.applyProviderScopes({ connection_id, provider_scopes: [], now: at(50) });
      expect(r?.grant?.scopes).toEqual(['content']);
    });

    it('returns null for unknown or revoked connections', async () => {
      expect(await store.applyProviderScopes({ connection_id: 'conn_nope', provider_scopes: [], now: at(1) })).toBeNull();
      const { connection_id } = await connectActive(store);
      await store.setConnectionStatus({ connection_id, status: 'revoked', now: at(50) });
      expect(await store.applyProviderScopes({ connection_id, provider_scopes: [], now: at(51) })).toBeNull();
    });
  });

  describe('narrowGrant', () => {
    it('intersects and can never widen', async () => {
      const { grant_id } = await connectActive(store, {}, { scopes: ['calendar.readonly', 'gmail.send'] });
      const wider = await store.narrowGrant({ grant_id, scopes: ['calendar.readonly', 'gmail.send', 'drive'], now: at(50) });
      expect(wider?.grant.scopes).toEqual(['calendar.readonly', 'gmail.send']);
      expect(wider?.grant.version).toBe(2);
      const r = await store.narrowGrant({ grant_id, scopes: ['gmail.send', 'drive'], now: at(51) });
      expect(r?.previous_scopes).toEqual(['calendar.readonly', 'gmail.send']);
      expect(r?.grant.scopes).toEqual(['gmail.send']);
      expect(r?.grant.version).toBe(3);
    });

    it('checks expected_version and requires an active grant', async () => {
      const { grant_id, connection_id } = await connectActive(store, {}, { scopes: ['calendar.readonly', 'gmail.send'] });
      expect(await store.narrowGrant({ grant_id, scopes: ['gmail.send'], expected_version: 1, now: at(50) })).toBeNull();
      expect((await store.narrowGrant({ grant_id, scopes: ['gmail.send'], expected_version: 2, now: at(50) }))?.grant.version).toBe(3);
      await store.setConnectionStatus({ connection_id, status: 'needs_reauth', now: at(51) });
      expect(await store.narrowGrant({ grant_id, scopes: [], now: at(52) })).toBeNull();
      expect(await store.narrowGrant({ grant_id: 'grt_unknown', scopes: [], now: at(52) })).toBeNull();
    });
  });

  describe('ownership lookups', () => {
    it('returns null for a foreign client or subject', async () => {
      const { connection_id, grant_id } = await connectActive(store);
      expect(await store.getClientConnection({ client_id: 'acme', connection_id })).not.toBeNull();
      expect(await store.getClientConnection({ client_id: 'evil', connection_id })).toBeNull();
      expect(await store.getSubjectConnection({ client_id: 'acme', subject: 'user-123', connection_id })).not.toBeNull();
      expect(await store.getSubjectConnection({ client_id: 'acme', subject: 'user-999', connection_id })).toBeNull();
      expect(await store.getSubjectConnection({ client_id: 'evil', subject: 'user-123', connection_id })).toBeNull();
      expect(await store.getConnection('conn_unknown')).toBeNull();
      expect(await store.getGrant(grant_id)).not.toBeNull();
      expect(await store.getGrant('grt_unknown')).toBeNull();
      expect(await store.getGrantForConnection('conn_unknown')).toBeNull();
    });

    it('lists connections newest first and grants by (client, audience, subject)', async () => {
      const a = await connectActive(store, {}, { accountId: 'acct-a' });
      const b = await connectActive(store, { created_at: at(1) }, { accountId: 'acct-b' });
      await connectActive(store, { subject: 'user-999' }, { accountId: 'acct-c' });
      const list = await store.listConnections({ client_id: 'acme', subject: 'user-123' });
      expect(list.map((c) => c.id)).toEqual([b.connection_id, a.connection_id]);
      const grants = await store.listGrants({ client_id: 'acme', audience: 'https://www.googleapis.com', subject: 'user-123' });
      expect(grants.map((g) => g.id).sort()).toEqual([a.grant_id, b.grant_id].sort());
      expect(await store.listGrants({ client_id: 'evil', audience: 'https://www.googleapis.com', subject: 'user-123' })).toEqual([]);
    });
  });

  describe('account-wide reads', () => {
    it('listClients returns every client, any status, ordered by client_id', async () => {
      expect(await store.listClients()).toEqual([]);
      const base = {
        org_id: 'org_default' as const, name: 'App', redirect_uris: [], origins: [], allow_raw_tokens: false,
        token_endpoint_auth_method: 'client_secret_basic' as const, client_secret_hash: h('s'),
        created_at: at(0), updated_at: at(0),
      };
      await store.putClient({ ...base, client_id: 'zeta', status: 'active' });
      await store.putClient({ ...base, client_id: 'alpha', status: 'disabled' });
      await store.putClient({ ...base, client_id: 'Mid.app', status: 'active' });
      const list = await store.listClients();
      expect(list.map((c) => c.client_id)).toEqual(['Mid.app', 'alpha', 'zeta']);
      expect(list.find((c) => c.client_id === 'alpha')?.status).toBe('disabled');
    });

    it('listAccountConnections spans clients and subjects, includes pending, excludes revoked and other accounts', async () => {
      const a = await connectActive(store, { client_id: 'acme' });
      const b = await connectActive(store, { client_id: 'beta', subject: 'user-999' });
      const pendingTx = newTx({ client_id: 'gamma' });
      await driveToConfirm(store, pendingTx);
      const pending = await confirm(store, pendingTx.tid);
      const revoked = await connectActive(store, { client_id: 'delta' });
      await store.setConnectionStatus({ connection_id: revoked.connection_id, status: 'revoked', now: at(50) });
      await connectActive(store, { client_id: 'acme', subject: 'user-777' }, { accountId: 'google-sub-OTHER' });
      await connectActive(
        store,
        { client_id: 'acme', subject: 'user-555', providers: ['github'], requested_scopes: { github: ['read:user'] }, required_scopes: {} },
        { provider: 'github', accountId: 'google-sub-1', scopes: ['read:user'], granted: ['read:user'] },
      );

      const list = await store.listAccountConnections({ provider: 'google', provider_account_id: 'google-sub-1' });
      expect(list.map((c) => c.id).sort()).toEqual([a.connection_id, b.connection_id, pending.transaction.connection_id].sort());
      expect(list.find((c) => c.id === pending.transaction.connection_id)?.status).toBe('pending');
      expect(await store.listAccountConnections({ provider: 'google', provider_account_id: 'nobody' })).toEqual([]);
      expect((await store.listAccountConnections({ provider: 'github', provider_account_id: 'google-sub-1' }))).toHaveLength(1);
    });

    it('listOpenAccountTransactions returns open, exchanged transactions for the account only', async () => {
      // Exchanged and confirmed, not activated: open.
      const confirmed = newTx({ client_id: 'acme' });
      await driveToConfirm(store, confirmed);
      await confirm(store, confirmed.tid);
      // Exchanged, at confirm, another client and subject: open.
      const atConfirm = newTx({ client_id: 'beta', subject: 'user-999' });
      await driveToConfirm(store, atConfirm);
      // Exchanged but past expiry and not yet swept: still open (tokens still staged).
      const lapsed = newTx({ expires_at: at(100) });
      await driveToConfirm(store, lapsed);
      // Not exchanged yet (only at provider): excluded.
      const noExchange = newTx();
      await store.createTransaction(noExchange);
      await store.enterByRequestUri({
        request_uri_hash: noExchange.request_uri_hash, presented_cookie_hash: null, new_handle_hash: h('x'), mode: 'popup', now: at(1),
      });
      await store.advanceTransaction({ tid: noExchange.tid, from: 'picker', to: 'provider', patch: { provider: 'google' }, now: at(2) });
      // Went back to the provider with the exchange cleared: excluded.
      const wentBack = newTx();
      await driveToConfirm(store, wentBack);
      await store.advanceTransaction({
        tid: wentBack.tid, from: 'confirm', to: 'provider',
        patch: { exchanged_at: null, provider_granted_scopes: null, provider_account_id: null }, now: at(20),
      });
      // Terminal (activated, cancelled): excluded.
      const activated = await connectActive(store, { client_id: 'zeta' });
      const cancelled = newTx();
      await driveToConfirm(store, cancelled);
      await store.endTransaction({ tid: cancelled.tid, outcome: 'cancelled', now: at(30) });
      // Other account: excluded.
      const other = newTx();
      await driveToConfirm(store, other, { accountId: 'google-sub-OTHER' });

      const open = await store.listOpenAccountTransactions({ provider: 'google', provider_account_id: 'google-sub-1' });
      expect(open.map((t) => t.tid).sort()).toEqual([confirmed.tid, atConfirm.tid, lapsed.tid].sort());
      expect(open.map((t) => t.tid)).not.toContain(activated.tid);
      expect(open.every((t) => t.exchanged_at !== undefined && t.consumed_at === undefined)).toBe(true);
      expect(await store.listOpenAccountTransactions({ provider: 'github', provider_account_id: 'google-sub-1' })).toEqual([]);

      // Once swept, the lapsed one is gone.
      await store.sweepExpiredTransactions({ now: at(200), limit: 10 });
      expect((await store.listOpenAccountTransactions({ provider: 'google', provider_account_id: 'google-sub-1' })).map((t) => t.tid).sort())
        .toEqual([confirmed.tid, atConfirm.tid].sort());
    });
  });

  describe('input hygiene', () => {
    it('normalizes timestamps and rejects non-ISO now', async () => {
      const input = newTx({ created_at: '2026-10-11T12:00:00Z', expires_at: '2026-10-11T12:10:00Z' });
      const tx = await store.createTransaction(input);
      expect(tx.created_at).toBe('2026-10-11T12:00:00.000Z');
      expect(tx.expires_at).toBe('2026-10-11T12:10:00.000Z');
      await expect(store.sweepExpiredTransactions({ now: 'yesterday', limit: 1 })).rejects.toBeInstanceOf(LinkStoreError);
    });

    it('new ids from commitConfirm must be well formed', async () => {
      const input = newTx();
      await driveToConfirm(store, input);
      const ids = newIds();
      await expect(store.commitConfirm({
        tid: input.tid,
        confirmed_scopes: ['calendar.readonly'],
        activation_code_hash: h('c'),
        new_connection: {
          id: 'bad' as ConnectionId, audience: 'https://www.googleapis.com', provider_account_id: 'google-sub-1',
          provider_scopes: ['calendar.readonly'], custody: 'self',
        },
        new_grant: { id: ids.grant, org_policy: { usage: 'allow' }, authorization_details_types: [] },
        now: at(10),
      })).rejects.toMatchObject({ code: 'invalid_input' });
    });
  });
});

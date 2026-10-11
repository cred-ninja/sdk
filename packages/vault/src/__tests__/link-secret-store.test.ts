import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import type { ConnectionId, TransactionId } from '@credninja/protocol';
import { CredVault, createVault } from '../vault.js';
import type { RefreshAdapter } from '../types.js';
import {
  LINK_STAGED_VAULT_USER_ID_PREFIX,
  LINK_VAULT_USER_ID_PREFIX,
  SqliteLinkStore,
  VaultLinkSecretStore,
  createLinkStorage,
  isReservedLinkVaultUserId,
  linkStagedVaultUserId,
  linkVaultUserId,
} from '../link/index.js';
import * as vaultPackage from '../index.js';
import { LINK_VAULT_ACCESS } from '../link/vault-access.js';
import { ReservedVaultUserIdError } from '../link/index.js';
import { at, confirm, driveToConfirm, h, newTx } from './link-fixtures.js';

const PAST = new Date(Date.now() - 60 * 60 * 1000).toISOString();
const FUTURE = new Date(Date.now() + 60 * 60 * 1000).toISOString();

describe('Link vault ids', () => {
  it('builds the reserved ids and validates their inputs', () => {
    expect(LINK_VAULT_USER_ID_PREFIX).toBe('link:');
    expect(LINK_STAGED_VAULT_USER_ID_PREFIX).toBe('link-staged:');
    expect(linkVaultUserId('conn_abc123')).toBe('link:conn_abc123');
    expect(linkStagedVaultUserId('ltx_abc123')).toBe('link-staged:ltx_abc123');
    expect(() => linkVaultUserId('abc')).toThrow(TypeError);
    expect(() => linkVaultUserId('conn_')).toThrow(TypeError);
    expect(() => linkVaultUserId('ltx_abc')).toThrow(TypeError);
    expect(() => linkStagedVaultUserId('conn_abc')).toThrow(TypeError);
    expect(() => linkStagedVaultUserId('ltx_a-b')).toThrow(TypeError);
  });

  it.each([
    ['link:', true],
    ['link:conn_abc', true],
    ['link:anything at all', true],
    ['link:link:', true],
    ['link-staged:', true],
    ['link-staged:ltx_abc', true],
    ['link-staged:', true],
    ['link', false],
    ['link-', false],
    ['link-staged', false],
    ['link_staged:ltx_abc', false],
    ['linkconn_abc', false],
    ['xlink:conn_abc', false],
    ['user-link:conn_abc', false],
    [' link:conn_abc', false],
    ['Link:conn_abc', false],
    ['LINK-STAGED:ltx_abc', false],
    ['', false],
    ['default', false],
    ['user-123', false],
  ])('isReservedLinkVaultUserId(%j) is %s', (userId, expected) => {
    expect(isReservedLinkVaultUserId(userId)).toBe(expected);
  });

  it('is false for non-strings', () => {
    expect(isReservedLinkVaultUserId(undefined as unknown as string)).toBe(false);
    expect(isReservedLinkVaultUserId(null as unknown as string)).toBe(false);
    expect(isReservedLinkVaultUserId(['link:x'] as unknown as string)).toBe(false);
  });

  it('every id the helpers build is reserved', () => {
    expect(isReservedLinkVaultUserId(linkVaultUserId('conn_x1'))).toBe(true);
    expect(isReservedLinkVaultUserId(linkStagedVaultUserId('ltx_x1'))).toBe(true);
  });

  it('is exported from the package entry point', () => {
    for (const name of [
      'SqliteLinkStore', 'LinkStoreError', 'VaultLinkSecretStore', 'createLinkStorage',
      'LINK_VAULT_USER_ID_PREFIX', 'LINK_STAGED_VAULT_USER_ID_PREFIX',
      'linkVaultUserId', 'linkStagedVaultUserId', 'isReservedLinkVaultUserId',
    ]) {
      expect(vaultPackage).toHaveProperty(name);
    }
  });
});

for (const storage of ['sqlite', 'file'] as const) {
  describe(`VaultLinkSecretStore over a ${storage} vault`, () => {
    let dir: string;
    let vault: CredVault;
    let store: SqliteLinkStore;
    let secrets: VaultLinkSecretStore;

    beforeEach(async () => {
      dir = mkdtempSync(join(tmpdir(), 'link-secrets-'));
      vault = await createVault({
        passphrase: 'link-secret-store-test',
        storage,
        path: join(dir, storage === 'sqlite' ? 'vault.db' : 'vault.json'),
      });
      ({ store, secrets } = createLinkStorage({ vault, path: join(dir, 'link.db') }));
    });

    afterEach(() => {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    });

    /** A transaction at step confirm with provider google and granted scopes recorded. */
    async function atConfirm(granted = ['calendar.readonly', 'gmail.send']) {
      const input = newTx();
      await driveToConfirm(store, input, { granted });
      return input;
    }

    /** Confirm, claim, commitActivation, then commitStaged: the server's order (database commit first). */
    async function activate(tid: TransactionId) {
      const c = await confirm(store, tid);
      const connection_id = c.transaction.connection_id as ConnectionId;
      const claim = await store.claimActivation({
        client_id: 'acme', connection_id, activation_code_hash: h(`code-${tid}`), subject: 'user-123', now: at(20),
      });
      if (!claim.ok) throw new Error(claim.reason);
      await store.commitActivation({ tid, now: at(21) });
      const moved = await secrets.commitStaged(tid, connection_id);
      return { connection_id, moved };
    }

    it('staged round trip, replacement and delete', async () => {
      const input = await atConfirm();
      expect(await secrets.getStaged(input.tid)).toBeNull();
      await secrets.putStaged(input.tid, { access_token: 'ya29.first', refresh_token: '1//r1', expires_at: FUTURE, token_type: 'Bearer' });
      expect(await secrets.getStaged(input.tid)).toEqual({ access_token: 'ya29.first', refresh_token: '1//r1', expires_at: FUTURE });
      await secrets.putStaged(input.tid, { access_token: 'ya29.second' });
      expect(await secrets.getStaged(input.tid)).toEqual({ access_token: 'ya29.second' });
      // Staged tokens sit under the reserved staged id with the provider-granted scopes.
      const raw = await vault.getStored({ provider: 'google', userId: linkStagedVaultUserId(input.tid) }, LINK_VAULT_ACCESS);
      expect(raw?.scopes).toEqual(['calendar.readonly', 'gmail.send']);
      await secrets.deleteStaged(input.tid);
      expect(await secrets.getStaged(input.tid)).toBeNull();
    });

    it('putStaged needs a transaction with a provider', async () => {
      const input = newTx();
      await store.createTransaction(input);
      await expect(secrets.putStaged(input.tid, { access_token: 'x' })).rejects.toThrow(/no provider/);
      await expect(secrets.putStaged('ltx_unknown' as TransactionId, { access_token: 'x' })).rejects.toThrow(/unknown transaction/);
      await expect(secrets.putStaged(input.tid, { access_token: '' })).rejects.toThrow(TypeError);
    });

    it('commitStaged moves tokens to link:<connection_id> with the transaction granted scopes', async () => {
      const input = await atConfirm(['calendar.readonly', 'gmail.send']);
      await secrets.putStaged(input.tid, { access_token: 'ya29.access', refresh_token: '1//refresh', expires_at: FUTURE });
      const { connection_id, moved } = await activate(input.tid);
      expect(moved).toBe(true);
      expect(await secrets.get(connection_id)).toEqual({ access_token: 'ya29.access', refresh_token: '1//refresh', expires_at: FUTURE });
      expect(await secrets.getStaged(input.tid)).toBeNull();

      const entry = await vault.getStored({ provider: 'google', userId: linkVaultUserId(connection_id) }, LINK_VAULT_ACCESS);
      expect(entry).toMatchObject({ accessToken: 'ya29.access', refreshToken: '1//refresh', scopes: ['calendar.readonly', 'gmail.send'] });
      // A second commit has nothing staged.
      expect(await secrets.commitStaged(input.tid, connection_id)).toBe(false);
    });

    it('commitStaged keeps the existing refresh_token when the staged set has none (reauth)', async () => {
      const first = await atConfirm();
      await secrets.putStaged(first.tid, { access_token: 'ya29.v1', refresh_token: '1//keep-me', expires_at: FUTURE });
      const { connection_id } = await activate(first.tid);

      const reauth = newTx({ intent: 'reauth', providers: ['google'], connection_id });
      await driveToConfirm(store, reauth, { granted: ['calendar.readonly', 'calendar.events'] });
      await secrets.putStaged(reauth.tid, { access_token: 'ya29.v2', expires_at: FUTURE });
      await confirm(store, reauth.tid);
      await store.claimActivation({
        client_id: 'acme', connection_id, activation_code_hash: h(`code-${reauth.tid}`), subject: 'user-123', now: at(40),
      });
      await store.commitActivation({ tid: reauth.tid, now: at(41) });
      expect(await secrets.commitStaged(reauth.tid, connection_id)).toBe(true);

      expect(await secrets.get(connection_id)).toEqual({ access_token: 'ya29.v2', refresh_token: '1//keep-me', expires_at: FUTURE });
      const entry = await vault.getStored({ provider: 'google', userId: linkVaultUserId(connection_id) }, LINK_VAULT_ACCESS);
      expect(entry?.scopes).toEqual(['calendar.events', 'calendar.readonly']);
    });

    it('commitStaged refuses a connection the transaction does not belong to', async () => {
      const a = await atConfirm();
      await secrets.putStaged(a.tid, { access_token: 'ya29.a' });
      const { connection_id } = await activate(a.tid);
      const other = newTx({ intent: 'update', providers: ['google'], connection_id: 'conn_someoneelse' as ConnectionId });
      await driveToConfirm(store, other);
      await secrets.putStaged(other.tid, { access_token: 'ya29.b' });
      await expect(secrets.commitStaged(other.tid, connection_id)).rejects.toThrow(/different connection/);
    });

    it('get returns the stored set even when the access token has expired', async () => {
      const input = await atConfirm();
      await secrets.putStaged(input.tid, { access_token: 'ya29.access', refresh_token: '1//refresh', expires_at: FUTURE });
      const { connection_id } = await activate(input.tid);
      await secrets.put(connection_id, { access_token: 'ya29.expired', expires_at: PAST });

      // CredVault refuses the reserved id without the capability; with it, plain get hides expired entries.
      await expect(vault.get({ provider: 'google', userId: linkVaultUserId(connection_id) })).rejects.toBeInstanceOf(ReservedVaultUserIdError);
      expect(await vault.get({ provider: 'google', userId: linkVaultUserId(connection_id) }, LINK_VAULT_ACCESS)).toBeNull();
      // The secret store does not, and put kept the refresh token.
      expect(await secrets.get(connection_id)).toEqual({ access_token: 'ya29.expired', refresh_token: '1//refresh', expires_at: PAST });

      // An expired staged set is readable too.
      const next = newTx({ intent: 'reauth', providers: ['google'], connection_id });
      await driveToConfirm(store, next);
      await secrets.putStaged(next.tid, { access_token: 'ya29.staged-expired', expires_at: PAST });
      expect(await secrets.getStaged(next.tid)).toEqual({ access_token: 'ya29.staged-expired', expires_at: PAST });
    });

    it('works with a CredVault subclass and only ever calls CredVault public methods', async () => {
      // A subclass whose public methods record their calls: the secret store
      // calls CredVault's own prototype methods, so no override is ever hit.
      const calls: string[] = [];
      class RecordingVault extends CredVault {
        override async get(...args: Parameters<CredVault['get']>) { calls.push('get'); return super.get(...args); }
        override async getStored(...args: Parameters<CredVault['getStored']>) { calls.push('getStored'); return super.getStored(...args); }
        override async store(...args: Parameters<CredVault['store']>) { calls.push('store'); return super.store(...args); }
        override async delete(...args: Parameters<CredVault['delete']>) { calls.push('delete'); return super.delete(...args); }
      }
      const sub = new RecordingVault({
        passphrase: 'link-secret-store-test', storage, path: join(dir, storage === 'sqlite' ? 'sub.db' : 'sub.json'),
      });
      const viaSub = new VaultLinkSecretStore({ vault: sub, store });
      const input = await atConfirm();
      await viaSub.putStaged(input.tid, { access_token: 'ya29.f', refresh_token: '1//f', expires_at: FUTURE });
      expect(await viaSub.getStaged(input.tid)).toEqual({ access_token: 'ya29.f', refresh_token: '1//f', expires_at: FUTURE });
      await viaSub.deleteStaged(input.tid);
      expect(await viaSub.getStaged(input.tid)).toBeNull();
      expect(calls).toEqual([]);
      // The entries were written through CredVault's public methods into the subclass instance.
      await viaSub.putStaged(input.tid, { access_token: 'ya29.g', expires_at: PAST });
      expect((await CredVault.prototype.getStored.call(sub, { provider: 'google', userId: linkStagedVaultUserId(input.tid) }, LINK_VAULT_ACCESS))?.accessToken)
        .toBe('ya29.g');
    });

    it('vault.get with an adapter refuses a Link id without the capability, and with it refreshes and keeps scopes', async () => {
      const input = await atConfirm(['calendar.readonly', 'gmail.send']);
      await secrets.putStaged(input.tid, { access_token: 'ya29.old', refresh_token: '1//rt', expires_at: PAST });
      const { connection_id } = await activate(input.tid);

      const calls: string[] = [];
      const adapter: RefreshAdapter = {
        async refreshAccessToken(refreshToken) {
          calls.push(refreshToken);
          return { accessToken: 'ya29.new', expiresIn: 3600 };
        },
      };
      const getInput = { provider: 'google', userId: linkVaultUserId(connection_id), adapter, clientId: 'cid', clientSecret: 'csecret' };
      await expect(vault.get(getInput)).rejects.toBeInstanceOf(ReservedVaultUserIdError);
      expect(calls).toEqual([]);
      const entry = await vault.get(getInput, LINK_VAULT_ACCESS);
      expect(calls).toEqual(['1//rt']);
      expect(entry).toMatchObject({ accessToken: 'ya29.new', refreshToken: '1//rt', scopes: ['calendar.readonly', 'gmail.send'] });
      const after = await secrets.get(connection_id);
      expect(after).toMatchObject({ access_token: 'ya29.new', refresh_token: '1//rt' });
      expect(Date.parse(after?.expires_at ?? '')).toBeGreaterThan(Date.now());
    });

    it('put keeps the refresh token, writes the connection provider scopes, and refuses unknown or revoked connections', async () => {
      const input = await atConfirm();
      await secrets.putStaged(input.tid, { access_token: 'a1', refresh_token: 'r1', expires_at: FUTURE });
      const { connection_id } = await activate(input.tid);
      await secrets.put(connection_id, { access_token: 'a2', expires_at: FUTURE });
      expect(await secrets.get(connection_id)).toEqual({ access_token: 'a2', refresh_token: 'r1', expires_at: FUTURE });
      await secrets.put(connection_id, { access_token: 'a3', refresh_token: 'r2' });
      expect(await secrets.get(connection_id)).toEqual({ access_token: 'a3', refresh_token: 'r2' });

      await store.applyProviderScopes({ connection_id, provider_scopes: ['calendar.readonly'], now: at(50) });
      await secrets.put(connection_id, { access_token: 'a4' });
      expect((await vault.getStored({ provider: 'google', userId: linkVaultUserId(connection_id) }, LINK_VAULT_ACCESS))?.scopes).toEqual(['calendar.readonly']);

      await expect(secrets.put('conn_unknown' as ConnectionId, { access_token: 'x' })).rejects.toThrow(/unknown connection/);
      await store.setConnectionStatus({ connection_id, status: 'revoked', now: at(60) });
      await expect(secrets.put(connection_id, { access_token: 'x' })).rejects.toThrow(/revoked/);
    });

    it('delete removes the tokens; get for unknown or malformed ids is null', async () => {
      const input = await atConfirm();
      await secrets.putStaged(input.tid, { access_token: 'a1' });
      const { connection_id } = await activate(input.tid);
      await secrets.delete(connection_id);
      await secrets.delete(connection_id);
      expect(await secrets.get(connection_id)).toBeNull();
      expect(await secrets.get('conn_unknown' as ConnectionId)).toBeNull();
      expect(await secrets.get('not-an-id' as ConnectionId)).toBeNull();
    });

    it('Link entries stay out of legacy per-user listings', async () => {
      await vault.store({ provider: 'google', userId: 'user-123', accessToken: 'legacy' });
      const input = await atConfirm();
      await secrets.putStaged(input.tid, { access_token: 'ya29.link' });
      const { connection_id } = await activate(input.tid);
      const legacy = await vault.list({ userId: 'user-123' });
      expect(legacy.map((e) => e.accessToken)).toEqual(['legacy']);
      await expect(vault.list({ userId: linkVaultUserId(connection_id) })).rejects.toBeInstanceOf(ReservedVaultUserIdError);
      expect((await vault.list({ userId: linkVaultUserId(connection_id) }, LINK_VAULT_ACCESS)).map((e) => e.accessToken)).toEqual(['ya29.link']);
    });

    it('no token material reaches the Link store; tokens are encrypted in the vault file', async () => {
      const ACCESS = 'ya29.SECRET-ACCESS-abcdef';
      const REFRESH = '1//SECRET-REFRESH-uvwxyz';
      const input = await atConfirm();
      await secrets.putStaged(input.tid, { access_token: ACCESS, refresh_token: REFRESH, expires_at: FUTURE });
      const { connection_id } = await activate(input.tid);

      const results: unknown[] = [
        await store.getTransaction(input.tid),
        await store.getConnection(connection_id),
        await store.getGrantForConnection(connection_id),
        await store.listConnections({ client_id: 'acme', subject: 'user-123' }),
        await store.setConnectionStatus({ connection_id, status: 'needs_reauth', now: at(50) }),
      ];
      const serialized = JSON.stringify(results);
      expect(serialized).not.toContain(ACCESS);
      expect(serialized).not.toContain(REFRESH);
      expect(serialized).not.toMatch(/access_token|refresh_token/);

      store.close();
      const raw = new Database(join(dir, 'link.db'), { readonly: true });
      const tables = raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>;
      const dump = JSON.stringify(tables.map((t) => raw.prepare(`SELECT * FROM ${t.name}`).all()));
      raw.close();
      expect(dump).not.toContain(ACCESS);
      expect(dump).not.toContain(REFRESH);
      store = new SqliteLinkStore(':memory:');

      for (const file of readdirSync(dir)) {
        if (file.startsWith('link.db')) continue;
        const bytes = readFileSync(join(dir, file)).toString('latin1');
        expect(bytes).not.toContain(ACCESS);
        expect(bytes).not.toContain(REFRESH);
      }
    });
  });
}

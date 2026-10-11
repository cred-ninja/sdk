import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { NewLinkTransaction, TransactionId } from '@credninja/protocol';
import { SqliteLinkStore, VaultLinkSecretStore, createLinkStorage } from '../link/index.js';
import { CredVault, createVault } from '../vault.js';
import { at, confirm, connectActive, driveToConfirm, h, newIds, newTx } from './link-fixtures.js';

/**
 * Regressions for defects found in independent review of the Link store.
 * Each case asserts the corrected behavior (packages/protocol link.ts doc
 * comments on LinkStore.commitConfirm and LinkStore.commitActivation).
 */

async function commit(
  store: SqliteLinkStore,
  tid: TransactionId,
  audience: string,
  accountId: string,
  confirmed: string[],
  providerScopes: string[],
) {
  const ids = newIds();
  return store.commitConfirm({
    tid,
    confirmed_scopes: confirmed,
    activation_code_hash: h(`code-${tid}`),
    new_connection: { id: ids.connection, audience, provider_account_id: accountId, provider_scopes: providerScopes, custody: 'self' },
    new_grant: { id: ids.grant, org_policy: { usage: 'allow' }, authorization_details_types: [] },
    now: at(10),
  });
}

describe('review regressions: commitConfirm scope bounds', () => {
  let store: SqliteLinkStore;
  beforeEach(() => { store = new SqliteLinkStore(':memory:'); });
  afterEach(() => { store.close(); });

  it('refuses a grant scope the PAR never requested (GitHub repo when only read:user was pushed)', async () => {
    const input = newTx({ providers: ['github'], requested_scopes: { github: ['read:user'] }, required_scopes: {} });
    await driveToConfirm(store, input, { provider: 'github', granted: ['read:user', 'repo'], accountId: 'gh-1' });
    await expect(commit(store, input.tid, 'https://api.github.com', 'gh-1', ['read:user', 'repo'], ['read:user', 'repo']))
      .rejects.toMatchObject({ code: 'invalid_scopes' });
    expect((await store.getTransaction(input.tid))?.step).toBe('confirm');
    expect(await store.listConnections({ client_id: 'acme', subject: 'user-123' })).toEqual([]);
    // The requested subset still commits.
    const ok = await commit(store, input.tid, 'https://api.github.com', 'gh-1', ['read:user'], ['read:user', 'repo']);
    expect(ok.kind).toBe('committed');
    expect((await store.getGrant(ok.transaction.grant_id as string))?.scopes).toEqual(['read:user']);
  });

  it("refuses Linear 'admin' (never_offer): not requested, and not grantable even if it were", async () => {
    const input = newTx({ providers: ['linear'], requested_scopes: { linear: ['read', 'issues:create'] }, required_scopes: { linear: ['read'] } });
    await driveToConfirm(store, input, { provider: 'linear', granted: ['read', 'issues:create', 'admin'], accountId: 'lin-1' });
    await expect(commit(store, input.tid, 'https://api.linear.app', 'lin-1', ['read', 'admin'], ['read', 'issues:create', 'admin']))
      .rejects.toMatchObject({ code: 'invalid_scopes' });

    // Even a PAR that slipped 'admin' through cannot get it into a grant.
    const pushed = newTx({ providers: ['linear'], requested_scopes: { linear: ['read', 'admin'] }, required_scopes: {} });
    await driveToConfirm(store, pushed, { provider: 'linear', granted: ['read', 'admin'], accountId: 'lin-2' });
    await expect(commit(store, pushed.tid, 'https://api.linear.app', 'lin-2', ['read', 'admin'], ['read', 'admin']))
      .rejects.toMatchObject({ code: 'invalid_scopes' });
  });

  it('applies the requested bound on update, reauth and connect onto a live connection too', async () => {
    const existing = await connectActive(store);
    for (const intent of ['update', 'reauth'] as const) {
      const tx = newTx({ intent, providers: ['google'], connection_id: existing.connection_id, requested_scopes: { google: ['calendar.readonly'] } });
      await driveToConfirm(store, tx, { granted: ['calendar.readonly', 'gmail.send'] });
      await expect(confirm(store, tx.tid, { scopes: ['calendar.readonly', 'gmail.send'] })).rejects.toMatchObject({ code: 'invalid_scopes' });
    }
    const onto = newTx({ requested_scopes: { google: ['calendar.readonly'] } });
    await driveToConfirm(store, onto, { granted: ['calendar.readonly', 'gmail.send'] });
    await expect(confirm(store, onto.tid, { scopes: ['gmail.send'] })).rejects.toMatchObject({ code: 'invalid_scopes' });
  });

  it('the requested bound is the narrowed set, not the pushed one', async () => {
    const input = newTx({ providers: ['google'] });
    await store.createTransaction(input);
    await store.enterByRequestUri({
      request_uri_hash: input.request_uri_hash, presented_cookie_hash: null, new_handle_hash: h('h1'),
      new_binding_cookie_hash: h('c'), mode: 'popup',
      narrowed: { providers: ['google'], requested_scopes: { google: ['calendar.readonly'] } }, now: at(1),
    });
    await store.advanceTransaction({ tid: input.tid, from: 'picker', to: 'provider', patch: { provider: 'google' }, now: at(2) });
    await store.advanceTransaction({
      tid: input.tid, from: 'provider', to: 'confirm',
      patch: { exchanged_at: at(3), provider_granted_scopes: ['calendar.readonly', 'gmail.send'], provider_account_id: 'google-sub-1' },
      now: at(3),
    });
    await expect(confirm(store, input.tid, { scopes: ['gmail.send'] })).rejects.toMatchObject({ code: 'invalid_scopes' });
    expect((await confirm(store, input.tid, { scopes: ['calendar.readonly'] })).kind).toBe('committed');
  });

  it('stores provider_scopes from the exchange result and refuses a caller value that disagrees', async () => {
    const input = newTx();
    // The exchange recorded only calendar.readonly.
    await driveToConfirm(store, input, { granted: ['calendar.readonly'] });
    await expect(commit(store, input.tid, 'https://www.googleapis.com', 'google-sub-1', ['gmail.readonly'], ['gmail.readonly']))
      .rejects.toMatchObject({ code: 'invalid_scopes' });
    await expect(commit(store, input.tid, 'https://www.googleapis.com', 'google-sub-1', ['calendar.readonly'], ['calendar.readonly', 'gmail.readonly']))
      .rejects.toMatchObject({ code: 'invalid_input' });
    const ok = await commit(store, input.tid, 'https://www.googleapis.com', 'google-sub-1', ['calendar.readonly'], ['https://www.googleapis.com/auth/calendar.readonly']);
    expect(ok.kind).toBe('committed');
    expect((await store.getConnection(ok.transaction.connection_id as string))?.provider_scopes).toEqual(['calendar.readonly']);
  });
});

describe('review regressions: concurrent connects for one account never share a pending connection', () => {
  let store: SqliteLinkStore;
  beforeEach(() => { store = new SqliteLinkStore(':memory:'); });
  afterEach(() => { store.close(); });

  async function twoConfirmed() {
    const t1 = newTx();
    await driveToConfirm(store, t1);
    const c1 = await confirm(store, t1.tid);
    const t2 = newTx();
    await driveToConfirm(store, t2, { now: 20 });
    const c2 = await confirm(store, t2.tid, { now: 30 });
    return { t1, t2, c1, c2 };
  }

  async function claim(tx: NewLinkTransaction, connection_id: string, now: number) {
    const r = await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: h(`code-${tx.tid}`), subject: 'user-123', now: at(now) });
    if (!r.ok) throw new Error(r.reason);
  }

  it('each connect gets its own pending connection and grant', async () => {
    const { c1, c2 } = await twoConfirmed();
    expect(c1.transaction.creates_connection).toBe(true);
    expect(c2.transaction.creates_connection).toBe(true);
    expect(c2.transaction.connection_id).not.toBe(c1.transaction.connection_id);
    expect(c2.transaction.grant_id).not.toBe(c1.transaction.grant_id);
    const conns = await store.listConnections({ client_id: 'acme', subject: 'user-123' });
    expect(conns.map((c) => c.status)).toEqual(['pending', 'pending']);
  });

  for (const order of ['first-then-second', 'second-then-first'] as const) {
    it(`first activation wins (${order}); the loser fails and leaves the winner untouched`, async () => {
      const { t1, t2, c1, c2 } = await twoConfirmed();
      const [win, lose] = order === 'first-then-second'
        ? [{ tx: t1, c: c1 }, { tx: t2, c: c2 }]
        : [{ tx: t2, c: c2 }, { tx: t1, c: c1 }];
      const winConn = win.c.transaction.connection_id as string;
      const loseConn = lose.c.transaction.connection_id as string;

      // Both claim before either commits (the racy case).
      await claim(win.tx, winConn, 40);
      await claim(lose.tx, loseConn, 40);
      const activated = await store.commitActivation({ tid: win.tx.tid, now: at(41) });
      expect(activated.connection).toMatchObject({ id: winConn, status: 'active' });
      const winnerConnBefore = await store.getConnection(winConn);
      const winnerGrantBefore = await store.getGrantForConnection(winConn);

      await expect(store.commitActivation({ tid: lose.tx.tid, now: at(42) })).rejects.toMatchObject({ code: 'activation_superseded' });
      expect(await store.getTransaction(lose.tx.tid)).toMatchObject({ outcome: 'failed', error: 'access_denied', consumed_at: at(42) });
      expect(await store.getConnection(loseConn)).toMatchObject({ status: 'revoked' });
      expect(await store.getGrantForConnection(loseConn)).toMatchObject({ status: 'revoked' });
      expect(await store.getConnection(winConn)).toEqual(winnerConnBefore);
      expect(await store.getGrantForConnection(winConn)).toEqual(winnerGrantBefore);

      // The loser is terminal now; nothing it does later touches the winner.
      expect(await store.endTransaction({ tid: lose.tx.tid, outcome: 'cancelled', now: at(43) })).toBeNull();
      expect(await store.sweepExpiredTransactions({ now: at(5000), limit: 10 })).toEqual([]);
      expect(await store.getConnection(winConn)).toEqual(winnerConnBefore);
    });
  }

  it('sweeping an abandoned duplicate revokes only its own rows, never the winner', async () => {
    const { t1, t2, c1, c2 } = await twoConfirmed();
    const winConn = c2.transaction.connection_id as string;
    await claim(t2, winConn, 40);
    await store.commitActivation({ tid: t2.tid, now: at(41) });
    const winnerBefore = await store.getConnection(winConn);
    const winnerGrantBefore = await store.getGrantForConnection(winConn);

    const swept = await store.sweepExpiredTransactions({ now: at(700), limit: 10 });
    const ended = swept.find((t) => t.tid === t1.tid);
    expect(ended).toMatchObject({ outcome: 'expired', creates_connection: true, connection_id: c1.transaction.connection_id });
    expect(ended?.connection_id).not.toBe(winConn);
    expect(await store.getConnection(c1.transaction.connection_id as string)).toMatchObject({ status: 'revoked' });
    expect(await store.getGrantForConnection(c1.transaction.connection_id as string)).toMatchObject({ status: 'expired' });
    expect(await store.getConnection(winConn)).toEqual(winnerBefore);
    expect(await store.getGrantForConnection(winConn)).toEqual(winnerGrantBefore);
  });

  it('a failed claim (subject mismatch) on a duplicate leaves the other flow alone', async () => {
    const { t1, c1, c2 } = await twoConfirmed();
    const r = await store.claimActivation({
      client_id: 'acme', connection_id: c1.transaction.connection_id as string, activation_code_hash: h(`code-${t1.tid}`), subject: 'attacker', now: at(40),
    });
    expect(r.ok).toBe(false);
    expect(await store.getConnection(c1.transaction.connection_id as string)).toMatchObject({ status: 'revoked' });
    expect(await store.getConnection(c2.transaction.connection_id as string)).toMatchObject({ status: 'pending' });
  });

  it('a connect onto a live connection still stages, and activation applies it in place', async () => {
    const existing = await connectActive(store);
    const input = newTx({ requested_scopes: { google: ['calendar.readonly', 'gmail.send'] } });
    await driveToConfirm(store, input);
    const c = await confirm(store, input.tid, { scopes: ['calendar.readonly', 'gmail.send'] });
    expect(c.transaction).toMatchObject({ creates_connection: false, connection_id: existing.connection_id, grant_id: existing.grant_id });
    await claim(input, existing.connection_id, 40);
    const r = await store.commitActivation({ tid: input.tid, now: at(41) });
    expect(r.previous_grant_scopes).toEqual(['calendar.readonly']);
    expect(r.grant.scopes).toEqual(['calendar.readonly', 'gmail.send']);
    expect(r.connection.id).toBe(existing.connection_id);
  });

  it('update or reauth aimed at a pending connection is refused at confirm', async () => {
    const pendingTx = newTx();
    await driveToConfirm(store, pendingTx);
    const pending = await confirm(store, pendingTx.tid);
    const upd = newTx({ intent: 'update', providers: ['google'], connection_id: pending.transaction.connection_id });
    await driveToConfirm(store, upd);
    expect((await confirm(store, upd.tid)).kind).toBe('connection_unavailable');
  });

  it('commitActivation refuses (connection_unavailable) and ends the flow when its own pending connection was revoked', async () => {
    const t = newTx();
    await driveToConfirm(store, t);
    const c = await confirm(store, t.tid);
    const id = c.transaction.connection_id as string;
    await claim(t, id, 40);
    await store.setConnectionStatus({ connection_id: id, status: 'revoked', now: at(40) });
    await expect(store.commitActivation({ tid: t.tid, now: at(41) })).rejects.toMatchObject({ code: 'connection_unavailable' });
    expect(await store.getTransaction(t.tid)).toMatchObject({ outcome: 'failed', consumed_at: at(41) });
  });
});

describe('review regressions: the Link vault capability cannot be captured', () => {
  let dir: string;
  let vault: CredVault;
  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'link-cap-'));
    vault = await createVault({ passphrase: 'cap-test', storage: 'sqlite', path: join(dir, 'vault.db') });
  });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it('a Proxy around a real vault is refused at construction and never receives the symbol', async () => {
    const { store, secrets } = createLinkStorage({ vault, path: join(dir, 'link.db') });
    const input = newTx();
    await driveToConfirm(store, input);
    await secrets.putStaged(input.tid, { access_token: 'ya29.secret-staged' });

    const seen: unknown[] = [];
    const spy = new Proxy(vault, {
      get(target, prop, receiver) {
        const v = Reflect.get(target, prop, receiver);
        if (typeof v !== 'function') return v;
        return (...args: unknown[]) => {
          seen.push(...args);
          return (v as (...a: unknown[]) => unknown).apply(target, args);
        };
      },
    });
    expect(spy instanceof CredVault).toBe(true);
    expect(() => new VaultLinkSecretStore({ vault: spy as CredVault, store })).toThrow(TypeError);
    expect(seen.some((a) => typeof a === 'symbol')).toBe(false);
    store.close();
  });

  it('look-alike objects are refused too', () => {
    const store = new SqliteLinkStore(':memory:');
    const lookAlike = Object.create(CredVault.prototype) as CredVault;
    const plain = {
      get: vault.get.bind(vault), getStored: vault.getStored.bind(vault),
      store: vault.store.bind(vault), delete: vault.delete.bind(vault),
    } as unknown as CredVault;
    for (const candidate of [lookAlike, plain, null, undefined, {}] as unknown[]) {
      expect(() => new VaultLinkSecretStore({ vault: candidate as CredVault, store })).toThrow(TypeError);
    }
    expect(() => createLinkStorage({ vault: plain, path: ':memory:' })).toThrow(TypeError);
    store.close();
  });

  it('overrides on a genuine instance never receive the symbol', async () => {
    const { store, secrets } = createLinkStorage({ vault, path: join(dir, 'link.db') });
    const seen: unknown[] = [];
    const trap = (...args: unknown[]) => { seen.push(...args); throw new Error('override called'); };
    Object.assign(vault, { get: trap, getStored: trap, store: trap, delete: trap, list: trap });
    const input = newTx();
    await driveToConfirm(store, input);
    await secrets.putStaged(input.tid, { access_token: 'ya29.x' });
    expect(await secrets.getStaged(input.tid)).toEqual({ access_token: 'ya29.x' });
    await secrets.deleteStaged(input.tid);
    expect(seen).toEqual([]);
    store.close();
  });
});

describe('review regressions: a confirmed consent never overwrites a later grant change', () => {
  let store: SqliteLinkStore;
  beforeEach(() => { store = new SqliteLinkStore(':memory:'); });
  afterEach(() => { store.close(); });

  const WIDE = { google: ['calendar.readonly', 'calendar.events', 'gmail.send'] };

  /** An active connection whose grant holds calendar.readonly and gmail.send. */
  async function existing() {
    return connectActive(store, { requested_scopes: WIDE }, { scopes: ['calendar.readonly', 'gmail.send'] });
  }

  /** Drive and confirm a transaction that targets the existing grant. */
  async function confirmOnto(
    kind: 'update' | 'reauth' | 'connect',
    connection_id: string,
    scopes = ['calendar.readonly', 'calendar.events'],
    extra: { shown?: string[] | null } = {},
  ) {
    const tx = kind === 'connect'
      ? newTx({ requested_scopes: WIDE })
      : newTx({ intent: kind, providers: ['google'], connection_id: connection_id as never, requested_scopes: WIDE });
    await driveToConfirm(store, tx, { granted: ['calendar.readonly', 'calendar.events', 'gmail.send'] });
    const c = await confirm(store, tx.tid, { scopes, ...extra });
    expect(c.kind).toBe('committed');
    return { tx, c };
  }

  async function claim(tid: TransactionId, connection_id: string, now = 60) {
    const r = await store.claimActivation({ client_id: 'acme', connection_id, activation_code_hash: h(`code-${tid}`), subject: 'user-123', now: at(now) });
    if (!r.ok) throw new Error(r.reason);
  }

  /** Activation must be refused with grant_changed, end the flow, and leave connection and grant exactly as they were. */
  async function expectRefused(tid: TransactionId, connection_id: string) {
    await claim(tid, connection_id);
    const connBefore = await store.getConnection(connection_id);
    const grantBefore = await store.getGrantForConnection(connection_id);
    await expect(store.commitActivation({ tid, now: at(61) })).rejects.toMatchObject({ code: 'grant_changed' });
    expect(await store.getTransaction(tid)).toMatchObject({ outcome: 'failed', error: 'access_denied', consumed_at: at(61) });
    expect(await store.getConnection(connection_id)).toEqual(connBefore);
    expect(await store.getGrantForConnection(connection_id)).toEqual(grantBefore);
    // A refused activation is failed, not activated, so the startup heal never sees it.
    expect((await store.listUnsettledActivations()).map((t) => t.tid)).not.toContain(tid);
  }

  it('records the target grant scopes at confirm (omitted shown_grant_scopes), and none for a connect that creates its own rows', async () => {
    const e = await existing();
    for (const kind of ['update', 'reauth', 'connect'] as const) {
      const { c } = await confirmOnto(kind, e.connection_id);
      expect(c.transaction.grant_scopes_at_confirm).toEqual(['calendar.readonly', 'gmail.send']);
    }
    const created = newTx({ requested_scopes: WIDE });
    await driveToConfirm(store, created, { accountId: 'acct-new' });
    const c = await confirm(store, created.tid, { accountId: 'acct-new', shown: ['gmail.send'] });
    expect(c.transaction.creates_connection).toBe(true);
    expect(c.transaction).not.toHaveProperty('grant_scopes_at_confirm');
  });

  for (const kind of ['update', 'reauth', 'connect'] as const) {
    it(`${kind}: a narrow after confirm wins; activation is refused and the narrow stands`, async () => {
      const e = await existing();
      const { tx } = await confirmOnto(kind, e.connection_id);
      const narrowed = await store.narrowGrant({ grant_id: e.grant_id, scopes: ['calendar.readonly'], now: at(50) });
      expect(narrowed?.grant.scopes).toEqual(['calendar.readonly']);
      await expectRefused(tx.tid, e.connection_id);
      expect((await store.getGrant(e.grant_id))?.scopes).toEqual(['calendar.readonly']);
    });
  }

  it('a provider scope reduction that shrinks the grant after confirm wins', async () => {
    const e = await existing();
    const { tx } = await confirmOnto('update', e.connection_id);
    const r = await store.applyProviderScopes({ connection_id: e.connection_id, provider_scopes: ['calendar.readonly', 'calendar.events'], now: at(50) });
    expect(r?.grant?.scopes).toEqual(['calendar.readonly']);
    await expectRefused(tx.tid, e.connection_id);
    expect((await store.getGrant(e.grant_id))?.scopes).toEqual(['calendar.readonly']);
  });

  it('reauth confirmed while active still activates after the connection went needs_reauth', async () => {
    const e = await existing();
    const { tx } = await confirmOnto('reauth', e.connection_id, ['calendar.readonly', 'gmail.send']);
    const flipped = await store.setConnectionStatus({ connection_id: e.connection_id, status: 'needs_reauth', reason: 'grant_revoked', now: at(50) });
    expect(flipped?.grant?.status).toBe('needs_reauth');
    await claim(tx.tid, e.connection_id);
    const r = await store.commitActivation({ tid: tx.tid, now: at(61) });
    expect(r.connection).toMatchObject({ status: 'active' });
    expect(r.connection.status_reason).toBeUndefined();
    expect(r.grant).toMatchObject({ status: 'active', scopes: ['calendar.readonly', 'gmail.send'] });
    expect(r.grant.version).toBe((flipped?.grant?.version ?? 0) + 1);
  });

  it('another activation that changed the scopes after confirm wins', async () => {
    const e = await existing();
    const first = await confirmOnto('update', e.connection_id, ['calendar.readonly', 'calendar.events']);
    const second = await confirmOnto('update', e.connection_id, ['gmail.send']);
    await claim(first.tx.tid, e.connection_id, 55);
    const r = await store.commitActivation({ tid: first.tx.tid, now: at(56) });
    expect(r.grant.scopes).toEqual(['calendar.events', 'calendar.readonly']);
    await expectRefused(second.tx.tid, e.connection_id);
    expect((await store.getGrant(e.grant_id))?.scopes).toEqual(['calendar.events', 'calendar.readonly']);
  });

  it('another activation that left the scopes identical does not invalidate the confirm', async () => {
    const e = await existing();
    const first = await confirmOnto('reauth', e.connection_id, ['calendar.readonly', 'gmail.send']);
    const second = await confirmOnto('update', e.connection_id, ['calendar.readonly', 'calendar.events']);
    await claim(first.tx.tid, e.connection_id, 55);
    const r1 = await store.commitActivation({ tid: first.tx.tid, now: at(56) });
    expect(r1.grant.scopes).toEqual(['calendar.readonly', 'gmail.send']);
    await claim(second.tx.tid, e.connection_id, 57);
    const r2 = await store.commitActivation({ tid: second.tx.tid, now: at(58) });
    expect(r2.grant.scopes).toEqual(['calendar.events', 'calendar.readonly']);
    expect(r2.previous_grant_scopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('a revoke after confirm is refused as connection_unavailable', async () => {
    const e = await existing();
    const { tx } = await confirmOnto('update', e.connection_id);
    await claim(tx.tid, e.connection_id);
    await store.setConnectionStatus({ connection_id: e.connection_id, status: 'revoked', now: at(60) });
    await expect(store.commitActivation({ tid: tx.tid, now: at(61) })).rejects.toMatchObject({ code: 'connection_unavailable' });
  });

  it('changes that leave the grant scopes untouched do not invalidate the confirm', async () => {
    const e = await existing();
    const { tx } = await confirmOnto('update', e.connection_id);
    // Provider drops a scope the grant never held: the connection changes, the grant scopes do not.
    await store.applyProviderScopes({ connection_id: e.connection_id, provider_scopes: ['calendar.readonly', 'gmail.send', 'drive'], now: at(50) });
    await store.narrowGrant({ grant_id: e.grant_id, scopes: ['calendar.readonly', 'gmail.send', 'drive'], now: at(51) });
    await store.setConnectionStatus({ connection_id: e.connection_id, status: 'frozen', reason: 'grant_reuse_detected', now: at(52) });
    await claim(tx.tid, e.connection_id);
    const r = await store.commitActivation({ tid: tx.tid, now: at(61) });
    expect(r.grant.scopes).toEqual(['calendar.events', 'calendar.readonly']);
    expect(r.connection.status).toBe('active');
  });

  it('legitimate sequences still activate: reauth of a needs_reauth connection, plain update, connect onto live', async () => {
    const e = await existing();
    await store.setConnectionStatus({ connection_id: e.connection_id, status: 'needs_reauth', reason: 'grant_revoked', now: at(30) });
    const reauth = await confirmOnto('reauth', e.connection_id, ['calendar.readonly', 'gmail.send']);
    await claim(reauth.tx.tid, e.connection_id, 40);
    const r1 = await store.commitActivation({ tid: reauth.tx.tid, now: at(41) });
    expect(r1.connection).toMatchObject({ status: 'active' });
    expect(r1.grant).toMatchObject({ status: 'active', scopes: ['calendar.readonly', 'gmail.send'] });

    const update = await confirmOnto('update', e.connection_id, ['calendar.readonly', 'calendar.events']);
    await claim(update.tx.tid, e.connection_id, 50);
    const r2 = await store.commitActivation({ tid: update.tx.tid, now: at(51) });
    expect(r2.grant.scopes).toEqual(['calendar.events', 'calendar.readonly']);
    expect(r2.grant.version).toBe(r1.grant.version + 1);

    const onto = await confirmOnto('connect', e.connection_id, ['gmail.send']);
    await claim(onto.tx.tid, e.connection_id, 60);
    const r3 = await store.commitActivation({ tid: onto.tx.tid, now: at(61) });
    expect(r3.grant.scopes).toEqual(['gmail.send']);
    expect(r3.previous_grant_scopes).toEqual(['calendar.events', 'calendar.readonly']);
  });

  it('a repeated confirm (already_committed) keeps the originally recorded scopes, so the later narrow still wins', async () => {
    const e = await existing();
    const { tx, c } = await confirmOnto('update', e.connection_id);
    expect(c.transaction.grant_scopes_at_confirm).toEqual(['calendar.readonly', 'gmail.send']);
    await store.narrowGrant({ grant_id: e.grant_id, scopes: ['calendar.readonly'], now: at(50) });
    const again = await confirm(store, tx.tid, { scopes: ['calendar.readonly'], shown: ['calendar.readonly'] });
    expect(again.kind).toBe('already_committed');
    expect(again.transaction.grant_scopes_at_confirm).toEqual(['calendar.readonly', 'gmail.send']);
    await expectRefused(tx.tid, e.connection_id);
  });

  it('shown_grant_scopes as an array is recorded in canonical form and must match the live grant', async () => {
    const e = await existing();
    // What the screen showed matches the grant (different order and Google long form): activates.
    const ok = await confirmOnto('update', e.connection_id, ['calendar.readonly', 'calendar.events'], {
      shown: ['gmail.send', 'https://www.googleapis.com/auth/calendar.readonly', 'gmail.send'],
    });
    expect(ok.c.transaction.grant_scopes_at_confirm).toEqual(['calendar.readonly', 'gmail.send']);
    await claim(ok.tx.tid, e.connection_id, 40);
    expect((await store.commitActivation({ tid: ok.tx.tid, now: at(41) })).grant.scopes).toEqual(['calendar.events', 'calendar.readonly']);

    // The screen showed a stale grant: recorded verbatim, refused at activation.
    const stale = await confirmOnto('update', e.connection_id, ['calendar.readonly'], { shown: ['calendar.readonly', 'gmail.send'] });
    expect(stale.c.transaction.grant_scopes_at_confirm).toEqual(['calendar.readonly', 'gmail.send']);
    await expectRefused(stale.tx.tid, e.connection_id);
  });

  it('shown_grant_scopes: null records nothing and activation is refused', async () => {
    const e = await existing();
    const { tx, c } = await confirmOnto('reauth', e.connection_id, ['calendar.readonly', 'gmail.send'], { shown: null });
    expect(c.transaction).not.toHaveProperty('grant_scopes_at_confirm');
    await expectRefused(tx.tid, e.connection_id);
    expect((await store.getGrant(e.grant_id))?.scopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('a malformed shown_grant_scopes is refused at confirm', async () => {
    const e = await existing();
    const tx = newTx({ intent: 'update', providers: ['google'], connection_id: e.connection_id, requested_scopes: WIDE });
    await driveToConfirm(store, tx);
    for (const bad of [['ok', 3], 'calendar.readonly', { a: 1 }] as unknown[]) {
      await expect(confirm(store, tx.tid, { shown: bad as string[] })).rejects.toMatchObject({ code: 'invalid_input' });
    }
    expect((await store.getTransaction(tx.tid))?.step).toBe('confirm');
  });
});

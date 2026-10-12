/**
 * Cred Link polish: the startup heal of unfinished activations.
 *
 * A crash is simulated by running activation's database commit by hand
 * (store.claimActivation + store.commitActivation) and stopping at the
 * chosen point of the token move; a fresh service then opens the same
 * database files (harness.restart) and heals before serving Link.
 */

import crypto from 'node:crypto';
import path from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { PermissionStore, SqliteLinkStore, VaultLinkSecretStore } from '@credninja/vault';
import {
  Browser,
  activate,
  callback,
  confirm,
  connectAndActivate,
  connectFlow,
  delegate,
  makeHarness,
  par,
  registerClient,
  resultOf,
  toProvider,
} from './link-harness.js';
import type { Harness, RegisteredClient } from './link-harness.js';

let h: Harness | null = null;

afterEach(() => {
  vi.restoreAllMocks();
  h?.close();
  h = null;
});

async function harness(): Promise<Harness> {
  h = await makeHarness();
  return h;
}

type CrashPoint = 'before-move' | 'after-vault-write' | 'after-move';

interface Pending {
  connection_id: string;
  code: string;
  subject: string;
}

/** Activation's database commit, then a crash at `point` of the token move. */
async function crashActivation(hx: Harness, client: RegisteredClient, pending: Pending, point: CrashPoint): Promise<string> {
  return (await crashActivationWithTokens(hx, client, pending, point)).tid;
}

async function crashActivationWithTokens(hx: Harness, client: RegisteredClient, pending: Pending, point: CrashPoint) {
  const ctx = hx.server.link!.context;
  const now = new Date().toISOString();
  const claim = await ctx.store.claimActivation({
    client_id: client.client_id,
    connection_id: pending.connection_id,
    activation_code_hash: crypto.createHash('sha256').update(pending.code).digest('hex'),
    subject: pending.subject,
    now,
  });
  if (!claim.ok) throw new Error('claim failed');
  const tid = claim.transaction.tid;
  await ctx.store.commitActivation({ tid, now });
  const staged = await ctx.secrets.getStaged(tid as never);
  expect(staged).not.toBeNull();
  if (point === 'after-vault-write') await ctx.secrets.put(pending.connection_id as never, staged!);
  if (point === 'after-move') {
    expect(await ctx.secrets.commitStaged(tid as never, pending.connection_id as never)).toBe(true);
  }
  return { tid, staged: staged! };
}

async function newConnection(hx: Harness, client: RegisteredClient, subject = 'user-a'): Promise<Pending> {
  const result = await connectFlow(hx.app, client, { parOverrides: { subject } });
  return { connection_id: result.connection_id, code: result.code, subject };
}

async function finishFlow(hx: Harness, requestUri: string, confirmScopes = ['calendar.readonly', 'gmail.send'], pickerScopes?: string[]): Promise<Pending> {
  const browser = new Browser();
  const page = await callback(hx.app, browser, await toProvider(hx.app, browser, requestUri, pickerScopes ? { scopes: pickerScopes } : {}), 'google', 'auth-code-2');
  expect(page.status).toBe(200);
  const result = resultOf(await confirm(hx.app, browser, page.text, confirmScopes));
  if (result.outcome !== 'success') throw new Error(`flow failed: ${JSON.stringify(result)}`);
  return { connection_id: result.connection_id, code: result.code, subject: 'user-a' };
}

async function updateFlow(hx: Harness, client: RegisteredClient, connectionId: string, confirmScopes?: string[]): Promise<Pending> {
  return finishFlow(hx, await par(hx.app, client, { intent: 'update', connection_id: connectionId, scopes: { google: ['calendar.readonly', 'gmail.send'] }, required_scopes: {} }), confirmScopes);
}

async function reauthFlow(hx: Harness, client: RegisteredClient, connectionId: string, agentId?: string): Promise<Pending> {
  const res = await request(hx.app).post(`/link/v1/connections/${connectionId}/reauth`).set('Authorization', client.auth)
    .send({ subject: 'user-a', ...(agentId ? { agent_id: agentId } : {}) });
  expect(res.status).toBe(201);
  return finishFlow(hx, res.body.request_uri);
}

/** Restart, wait for the gate (phase 1) and the background phase (phase 2). */
async function restartAndHeal(hx: Harness) {
  const next = await hx.restart();
  const report = await next.link!.ready;
  const followUps = (await next.link!.healed).follow_ups;
  return { next, report, followUps, ctx: next.link!.context };
}

function healAudits(hx: Harness) {
  return hx.server.vault.queryAuditEvents({ limit: 500 }).filter((e) => (e.actor as { id?: string }).id === 'link:startup-heal');
}

describe('startup heal of unfinished activations', () => {
  it('a normal activation settles: nothing is left for the heal', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    await connectAndActivate(hx.app, client);
    expect(await hx.server.link!.context.store.listUnsettledActivations()).toEqual([]);
    const { report } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([]);
  });

  it('a new connection crashed before the token move: needs_reauth, staged gone, typed code, and a later reauth restores it', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    const tid = await crashActivation(hx, client, pending, 'before-move');
    const revocationsBefore = hx.fake.revocations.length;

    const { report, followUps, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'reverted' }]);
    expect(followUps).toEqual([{ tid, outcome: 'revoked' }]);
    expect(await ctx.store.getConnection(pending.connection_id)).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect(await ctx.secrets.getStaged(tid as never)).toBeNull();
    expect(await ctx.secrets.get(pending.connection_id as never)).toBeNull();
    expect(await ctx.store.listUnsettledActivations()).toEqual([]);
    // The staged tokens belonged to nothing else on the account: revoked.
    expect(hx.fake.revocations.length).toBe(revocationsBefore + 1);
    expect(healAudits(hx).map((e) => (e.metadata as { reason?: string }).reason)).toEqual(['reauth_required']);

    const d = await delegate(hx.app, { connection_id: pending.connection_id });
    expect(d.body.error).toBe('reauth_required');

    const re = await reauthFlow(hx, client, pending.connection_id, 'server-agent');
    expect((await activate(hx.app, client, re.connection_id, re.code)).body.status).toBe('active');
    expect((await delegate(hx.app, { connection_id: pending.connection_id })).status).toBe(200);
  });

  it('an update crashed before the token move: old tokens untouched, needs_reauth, staged gone', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const oldTokens = await hx.server.link!.context.secrets.get(conn as never);
    const pending = await updateFlow(hx, client, conn);
    expect(pending.connection_id).toBe(conn);
    const tid = await crashActivation(hx, client, pending, 'before-move');
    const revocationsBefore = hx.fake.revocations.length;

    const { report, followUps, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'reverted' }]);
    expect(followUps).toEqual([{ tid, outcome: 'not_revoked' }]);
    expect(await ctx.secrets.get(conn as never)).toEqual(oldTokens);
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect(await ctx.secrets.getStaged(tid as never)).toBeNull();
    // The connection still holds its old tokens, so it is not excluded from
    // the account check: no provider revocation.
    expect(hx.fake.revocations.length).toBe(revocationsBefore);
  });

  it('a reauth crashed before the token move: likewise', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const oldTokens = await hx.server.link!.context.secrets.get(conn as never);
    const pending = await reauthFlow(hx, client, conn);
    const tid = await crashActivation(hx, client, pending, 'before-move');

    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'reverted' }]);
    expect(await ctx.secrets.get(conn as never)).toEqual(oldTokens);
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect(await ctx.secrets.getStaged(tid as never)).toBeNull();
  });

  it('crashed after the vault write but before the staged delete: stays active, staged gone, settled', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    const { tid, staged } = await crashActivationWithTokens(hx, client, pending, 'after-vault-write');

    const { report, followUps, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'cleaned' }]);
    expect(followUps).toEqual([{ tid, outcome: 'deleted' }]);
    expect(await ctx.store.getConnection(pending.connection_id)).toMatchObject({ status: 'active' });
    expect(await ctx.secrets.getStaged(tid as never)).toBeNull();
    expect(await ctx.secrets.get(pending.connection_id as never)).toEqual(staged);
    expect(await ctx.store.listUnsettledActivations()).toEqual([]);
    // Activation's onActivate hook never ran, so the requesting agent has no
    // permission yet: that fails closed until the app grants one.
    const before = await delegate(hx.app, { connection_id: pending.connection_id });
    expect(before.status).toBe(403);
    const perm = await request(hx.app).post(`/link/v1/connections/${pending.connection_id}/permissions`).set('Authorization', client.auth)
      .send({ agent_id: 'server-agent', scopes: ['calendar.readonly'] });
    expect(perm.status).toBe(200);
    expect((await delegate(hx.app, { connection_id: pending.connection_id })).status).toBe(200);
  });

  it('a narrowing update crashed after the move gets the permission intersect it missed', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const ctx0 = hx.server.link!.context;
    expect((await ctx0.permissions.get('server-agent', conn))!.allowedScopes).toEqual(['calendar.readonly', 'gmail.send']);
    const pending = await updateFlow(hx, client, conn, ['calendar.readonly']);
    const tid = await crashActivation(hx, client, pending, 'after-move');

    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'settled' }]);
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'active' });
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly']);
    expect((await ctx.permissions.get('server-agent', conn))!.allowedScopes).toEqual(['calendar.readonly']);
  });

  it('crashed after the complete move but before settling: stays active, settled', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    const tid = await crashActivation(hx, client, pending, 'after-move');

    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'settled' }]);
    expect(await ctx.store.getConnection(pending.connection_id)).toMatchObject({ status: 'active' });
    expect(await ctx.store.listUnsettledActivations()).toEqual([]);
    expect(healAudits(hx)).toEqual([]);
  });

  it('a second restart heals nothing', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    await crashActivation(hx, client, await newConnection(hx, client), 'before-move');
    expect((await restartAndHeal(hx)).report.outcomes).toHaveLength(1);
    const audits = healAudits(hx).length;
    expect((await restartAndHeal(hx)).report.outcomes).toEqual([]);
    expect(healAudits(hx).length).toBe(audits);
  });

  it('a slow provider does not hold the gate: revocation and deletion run after it opens', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    const tid = await crashActivation(hx, client, pending, 'before-move');
    hx.fake.revokeDelayMs = 400;
    const next = await hx.restart();
    const report = await next.link!.ready;
    expect(report.outcomes).toEqual([{ tid, outcome: 'reverted' }]);
    // The gate is open: Link answers with the healed state while the
    // revocation is still in flight and the transaction still unsettled.
    const res = await request(next.app).get(`/link/v1/connections/${pending.connection_id}`).query({ subject: 'user-a' }).set('Authorization', client.auth);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('needs_reauth');
    expect(hx.fake.revocations).toEqual([]);
    expect((await next.link!.context.store.listUnsettledActivations()).map((t) => t.tid)).toEqual([tid]);
    expect((await next.link!.healed).follow_ups).toEqual([{ tid, outcome: 'revoked' }]);
    expect(hx.fake.revocations).toHaveLength(1);
    expect(await next.link!.context.store.listUnsettledActivations()).toEqual([]);
  });

  it('a process that dies before the background phase finishes leaves the work for the next start, which treats it as stale', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    const tid = await crashActivation(hx, client, pending, 'before-move');
    // Phase 1 runs; phase 2 never gets to delete (the "process" dies).
    const spy = vi.spyOn(VaultLinkSecretStore.prototype, 'deleteStaged').mockRejectedValue(new Error('killed'));
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const first = await restartAndHeal(hx);
    expect(first.report.outcomes).toEqual([{ tid, outcome: 'reverted' }]);
    expect(first.followUps).toEqual([{ tid, outcome: 'failed' }]);
    expect((await first.ctx.store.listUnsettledActivations()).map((t) => t.tid)).toEqual([tid]);
    spy.mockRestore();
    const revocations = hx.fake.revocations.length;

    // The next start finds it; the connection moved (phase 1 set it to
    // needs_reauth), so it is stale: deleted locally, never revoked again.
    const second = await restartAndHeal(hx);
    expect(second.report.outcomes).toEqual([{ tid, outcome: 'stale' }]);
    expect(second.followUps).toEqual([{ tid, outcome: 'skipped_stale' }]);
    expect(await second.ctx.secrets.getStaged(tid as never)).toBeNull();
    expect(await second.ctx.store.listUnsettledActivations()).toEqual([]);
    expect(hx.fake.revocations.length).toBe(revocations);
    expect(await second.ctx.store.getConnection(pending.connection_id)).toMatchObject({ status: 'needs_reauth' });
  });

  it('a reauth that lands between the two phases makes the background phase skip the revocation', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    // Two crashed activations on two different provider accounts.
    const first = await newConnection(hx, client, 'user-a');
    const tid1 = await crashActivation(hx, client, first, 'before-move');
    hx.fake.googleSub = 'google-sub-bob';
    const second = await newConnection(hx, client, 'user-b');
    const tid2 = await crashActivation(hx, client, second, 'before-move');

    // Phase 2 handles tid1 first; its provider revocation is slow, so the
    // app reconnects the second account in the meantime.
    hx.fake.revokeDelayMs = 300;
    const next = await hx.restart();
    expect((await next.link!.ready).outcomes).toEqual([{ tid: tid1, outcome: 'reverted' }, { tid: tid2, outcome: 'reverted' }]);
    const res = await request(next.app).post(`/link/v1/connections/${second.connection_id}/reauth`).set('Authorization', client.auth)
      .send({ subject: 'user-b', agent_id: 'server-agent' });
    expect(res.status).toBe(201);
    const browser = new Browser();
    const page = await callback(next.app, browser, await toProvider(next.app, browser, res.body.request_uri), 'google', 'auth-code-3');
    const result = resultOf(await confirm(next.app, browser, page.text, ['calendar.readonly', 'gmail.send']));
    if (result.outcome !== 'success') throw new Error('reauth failed');
    expect((await activate(next.app, client, second.connection_id, result.code, 'user-b')).body.status).toBe('active');
    const live = await next.link!.context.secrets.get(second.connection_id as never);

    const done = await next.link!.healed;
    expect(done.follow_ups).toEqual([{ tid: tid1, outcome: 'revoked' }, { tid: tid2, outcome: 'skipped_stale' }]);
    expect(hx.fake.revocations).toHaveLength(1);
    expect(await next.link!.context.store.getConnection(second.connection_id)).toMatchObject({ status: 'active' });
    expect(await next.link!.context.secrets.get(second.connection_id as never)).toEqual(live);
    expect(await next.link!.context.store.listUnsettledActivations()).toEqual([]);
  });

  it('a Link request during the heal is served after it; other routes are not delayed', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    await crashActivation(hx, client, pending, 'before-move');

    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const original = SqliteLinkStore.prototype.listUnsettledActivations;
    vi.spyOn(SqliteLinkStore.prototype, 'listUnsettledActivations').mockImplementation(async function (this: SqliteLinkStore) {
      await gate;
      return original.call(this);
    });
    const next = await hx.restart();
    let healed = false;
    void next.link!.ready.then(() => { healed = true; });

    const order: string[] = [];
    const linkReq = request(next.app).get(`/link/v1/connections/${pending.connection_id}`).query({ subject: 'user-a' }).set('Authorization', client.auth)
      .then((res) => { order.push('link'); return res; });
    const delegateReq = delegate(next.app, { connection_id: pending.connection_id }).then((res) => { order.push('delegate'); return res; });
    const health = await request(next.app).get('/health');
    order.push('health');
    expect(health.status).toBe(200);
    expect(healed).toBe(false);
    release();
    const [linkRes, delegateRes] = await Promise.all([linkReq, delegateReq]);
    expect(order[0]).toBe('health');
    expect(healed).toBe(true);
    // Both saw the healed state, not the half-active one.
    expect(linkRes.status).toBe(200);
    expect(linkRes.body.status).toBe('needs_reauth');
    expect(delegateRes.body.error).toBe('reauth_required');
  });

  it('one transaction that cannot be healed does not block the others and is retried on the next start', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const first = await newConnection(hx, client, 'user-a');
    const tid1 = await crashActivation(hx, client, first, 'before-move');
    const second = await newConnection(hx, client, 'user-b');
    const tid2 = await crashActivation(hx, client, second, 'before-move');

    const original = VaultLinkSecretStore.prototype.getStaged;
    const spy = vi.spyOn(VaultLinkSecretStore.prototype, 'getStaged').mockImplementation(async function (this: VaultLinkSecretStore, tid) {
      if (tid === tid1) throw new Error('vault unavailable');
      return original.call(this, tid);
    });
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid: tid1, outcome: 'failed' }, { tid: tid2, outcome: 'reverted' }]);
    expect(errors.mock.calls.some((c) => String(c[0]).includes('startup heal failed'))).toBe(true);
    expect(JSON.stringify(errors.mock.calls)).not.toContain('vault unavailable');
    expect((await ctx.store.listUnsettledActivations()).map((t) => t.tid)).toEqual([tid1]);
    expect(await ctx.store.getConnection(second.connection_id)).toMatchObject({ status: 'needs_reauth' });

    spy.mockRestore();
    const again = await restartAndHeal(hx);
    expect(again.report.outcomes).toEqual([{ tid: tid1, outcome: 'reverted' }]);
    expect(await again.ctx.store.getConnection(first.connection_id)).toMatchObject({ status: 'needs_reauth' });
  });

  it('does not heal while Link is disabled', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    const tid = await crashActivation(hx, client, pending, 'before-move');
    const disabled = await hx.restart({ linkEnabled: false });
    expect(disabled.link ?? null).toBeNull();
    // Back on: the transaction is still there to heal, untouched meanwhile.
    const { report } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'reverted' }]);
  });
});

/**
 * Turn the Link database back into what a version 1 build wrote: no
 * tokens_settled_at or grant_scopes_at_confirm_json columns, user_version 1.
 * The next start runs the store's 1 to 2 migration (which adds the columns
 * empty), so every activation comes back unsettled.
 */
function downgradeToVersion1(hx: Harness): void {
  hx.server.link?.close();
  const db = new Database(path.join(hx.dir, 'link.sqlite'));
  db.exec('DROP INDEX IF EXISTS idx_link_transactions_unsettled');
  db.exec('ALTER TABLE link_transactions DROP COLUMN tokens_settled_at');
  db.exec('ALTER TABLE link_transactions DROP COLUMN grant_scopes_at_confirm_json');
  db.pragma('user_version = 1');
  db.close();
}

describe('startup heal after an upgrade from a version 1 database', () => {
  it('a healthy version 1 activation is settled; the connection stays active with its tokens', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const tokens = await hx.server.link!.context.secrets.get(conn as never);
    const permission = await hx.server.link!.context.permissions.get('server-agent', conn);
    downgradeToVersion1(hx);

    const { report, followUps, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toHaveLength(1);
    expect(report.outcomes[0].outcome).toBe('settled');
    expect(followUps).toEqual([]);
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'active' });
    expect(await ctx.secrets.get(conn as never)).toEqual(tokens);
    expect(await ctx.permissions.get('server-agent', conn)).toEqual(permission);
    expect(await ctx.store.listUnsettledActivations()).toEqual([]);
    expect(healAudits(hx)).toEqual([]);
    expect((await delegate(hx.app, { connection_id: conn })).status).toBe(200);
    // Once only.
    expect((await restartAndHeal(hx)).report.outcomes).toEqual([]);
  });

  it('a healthy version 1 activation whose connection changed since (narrowed, refreshed) is settled and left alone', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const narrowed = await request(hx.app).post(`/link/v1/connections/${conn}/narrow`).set('Authorization', client.auth)
      .send({ subject: 'user-a', scopes: ['calendar.readonly'] });
    expect(narrowed.status).toBe(200);
    const before = await hx.server.link!.context.store.getConnection(conn);
    downgradeToVersion1(hx);

    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes.map((o) => o.outcome)).toEqual(['settled']);
    expect(await ctx.store.getConnection(conn)).toEqual(before);
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly']);
  });

  it('a version 1 activation that crashed before the token move ends needs_reauth (new connection and update)', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    // New connection: no tokens at all.
    const fresh = await newConnection(hx, client, 'user-a');
    const tid1 = await crashActivation(hx, client, fresh, 'before-move');
    // Update on another account: keeps its old tokens.
    hx.fake.googleSub = 'google-sub-bob';
    const live = await connectAndActivate(hx.app, client, { parOverrides: { subject: 'user-b' } });
    const oldTokens = await hx.server.link!.context.secrets.get(live as never);
    const uri = await par(hx.app, client, { subject: 'user-b', intent: 'update', connection_id: live, scopes: { google: ['calendar.readonly', 'gmail.send'] }, required_scopes: {} });
    const update = { ...(await finishFlow(hx, uri)), subject: 'user-b' };
    const tid2 = await crashActivation(hx, client, update, 'before-move');
    downgradeToVersion1(hx);

    const { report, followUps, ctx } = await restartAndHeal(hx);
    const byTid = Object.fromEntries(report.outcomes.map((o) => [o.tid, o.outcome]));
    expect(byTid[tid1]).toBe('reverted');
    expect(byTid[tid2]).toBe('reverted');
    // The healthy initial activation of the second account is just settled.
    expect(report.outcomes.filter((o) => o.tid !== tid1 && o.tid !== tid2).map((o) => o.outcome)).toEqual(['settled']);
    expect(followUps.map((f) => f.tid).sort()).toEqual([tid1, tid2].sort());
    expect(await ctx.store.getConnection(fresh.connection_id)).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect(await ctx.store.getConnection(live)).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect(await ctx.secrets.get(live as never)).toEqual(oldTokens);
    expect(await ctx.secrets.getStaged(tid1 as never)).toBeNull();
    expect(await ctx.secrets.getStaged(tid2 as never)).toBeNull();
    expect(await ctx.store.listUnsettledActivations()).toEqual([]);
  });

  it('many unsettled rows do not keep the gate closed on provider calls', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conns: string[] = [];
    for (let i = 0; i < 12; i++) conns.push(await connectAndActivate(hx.app, client, { parOverrides: { subject: `user-${i}` } }));
    // The crashed one is on its own provider account, so its staged tokens
    // are revoked (slowly) in phase 2.
    hx.fake.googleSub = 'google-sub-crash';
    const crashed = await newConnection(hx, client, 'user-crash');
    const crashTid = await crashActivation(hx, client, crashed, 'before-move');
    downgradeToVersion1(hx);

    // Every provider call made before the gate opens would be a bug.
    hx.fake.revokeDelayMs = 300;
    const callsBefore = hx.fake.spy!.mock.calls.length;
    const next = await hx.restart();
    const report = await next.link!.ready;
    expect(hx.fake.spy!.mock.calls.length).toBe(callsBefore);
    expect(report.outcomes).toHaveLength(13);
    expect(report.outcomes.filter((o) => o.outcome === 'settled')).toHaveLength(12);
    expect(report.outcomes.find((o) => o.tid === crashTid)!.outcome).toBe('reverted');
    // The gate is open while the one revocation is still in flight.
    const res = await request(next.app).get(`/link/v1/connections/${conns[0]}`).query({ subject: 'user-0' }).set('Authorization', client.auth);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('active');
    expect(hx.fake.revocations).toEqual([]);
    const done = await next.link!.healed;
    expect(done.follow_ups).toEqual([{ tid: crashTid, outcome: 'revoked' }]);
    expect(hx.fake.revocations).toHaveLength(1);
  });
});

describe('startup heal: a finished move whose tokens were refreshed since', () => {
  it('a version 1 activation whose move finished (staged copy left) and whose tokens were refreshed since stays active', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    const { tid, staged } = await crashActivationWithTokens(hx, client, pending, 'after-vault-write');
    // The version 1 build kept serving: a refresh rotated the access token
    // (the refresh path writes only the secret, never the connection row).
    const rotated = { ...staged, access_token: 'rotated-access-token' };
    await hx.server.link!.context.secrets.put(pending.connection_id as never, rotated);
    downgradeToVersion1(hx);

    const { report, followUps, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'cleaned' }]);
    expect(followUps).toEqual([{ tid, outcome: 'deleted' }]);
    expect(await ctx.store.getConnection(pending.connection_id)).toMatchObject({ status: 'active' });
    expect(await ctx.secrets.get(pending.connection_id as never)).toEqual(rotated);
    expect(await ctx.secrets.getStaged(tid as never)).toBeNull();
    expect(await ctx.store.listUnsettledActivations()).toEqual([]);
    expect(hx.fake.revocations).toEqual([]);
  });

  it('a cleaned activation is settled in phase 1, so a failed cleanup and a later refresh change nothing', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    const { tid, staged } = await crashActivationWithTokens(hx, client, pending, 'after-vault-write');
    const spy = vi.spyOn(VaultLinkSecretStore.prototype, 'deleteStaged').mockRejectedValue(new Error('killed'));
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const first = await restartAndHeal(hx);
    expect(first.report.outcomes).toEqual([{ tid, outcome: 'cleaned' }]);
    expect(first.followUps).toEqual([{ tid, outcome: 'failed' }]);
    // Settled although the leftover copy could not be deleted (an orphan).
    expect(await first.ctx.store.listUnsettledActivations()).toEqual([]);
    spy.mockRestore();
    // Served normally: a refresh rotated the access token.
    await first.ctx.secrets.put(pending.connection_id as never, { ...staged, access_token: 'rotated-access-token' });

    const second = await restartAndHeal(hx);
    expect(second.report.outcomes).toEqual([]);
    expect(await second.ctx.store.getConnection(pending.connection_id)).toMatchObject({ status: 'active' });
  });

  it('same refresh token, the move DID happen and the access token was refreshed since: reapplied, stays active, next use refreshes, nothing revoked', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const pending = await updateFlow(hx, client, conn);
    const { tid, staged } = await crashActivationWithTokens(hx, client, pending, 'after-vault-write');
    expect(staged.refresh_token).toBeDefined();
    await hx.server.link!.context.secrets.put(conn as never, { ...staged, access_token: 'rotated-access-token' });

    const before = Date.now();
    const { report, followUps, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'reapplied' }]);
    expect(followUps).toEqual([{ tid, outcome: 'deleted' }]);
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'active' });
    const stored = (await ctx.secrets.get(conn as never))!;
    expect(stored.access_token).toBe(staged.access_token);
    expect(stored.refresh_token).toBe(staged.refresh_token);
    expect(Date.parse(stored.expires_at!)).toBeGreaterThanOrEqual(before - 1000);
    expect(Date.parse(stored.expires_at!)).toBeLessThanOrEqual(Date.now());
    expect(await ctx.store.listUnsettledActivations()).toEqual([]);

    // The next use refreshes with that refresh token before any call.
    const refreshesBefore = hx.fake.refreshCalls;
    const handle = await delegate(hx.app, { connection_id: conn, token_format: 'handle' });
    expect(handle.status).toBe(200);
    expect(hx.fake.refreshCalls).toBe(refreshesBefore + 1);
    expect((await ctx.secrets.get(conn as never))!.access_token).toMatch(/^ya29\.refreshed-/);
    expect(hx.fake.revocations).toEqual([]);
  });

  it('same refresh token, and the forced refresh fails with invalid_grant: the loader moves the connection to needs_reauth', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const pending = await updateFlow(hx, client, conn);
    const { tid, staged } = await crashActivationWithTokens(hx, client, pending, 'after-vault-write');
    await hx.server.link!.context.secrets.put(conn as never, { ...staged, access_token: 'rotated-access-token' });
    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'reapplied' }]);

    hx.fake.refreshMode = 'invalid_grant';
    const d = await delegate(hx.app, { connection_id: conn });
    expect(d.body.error).toBe('grant_revoked');
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'needs_reauth', status_reason: 'grant_revoked' });
    expect(hx.fake.upstream).toEqual([]);
  });

  it('reviewer: a provider that re-issues the same refresh token and a crash before the move: the connection never stays on its pre-activation access token', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client, { confirmScopes: ['calendar.readonly'] });
    const ctx0 = hx.server.link!.context;
    const oldTokens = (await ctx0.secrets.get(conn as never))!;
    expect(oldTokens.refresh_token).toBeDefined();
    // Widening update; the provider answers with a new access token and
    // the SAME refresh token string. Crash after the database commit.
    const pending = await updateFlow(hx, client, conn, ['calendar.readonly', 'gmail.send']);
    const now = new Date().toISOString();
    const claim = await ctx0.store.claimActivation({
      client_id: client.client_id,
      connection_id: conn,
      activation_code_hash: crypto.createHash('sha256').update(pending.code).digest('hex'),
      subject: 'user-a',
      now,
    });
    if (!claim.ok) throw new Error('claim failed');
    const tid = claim.transaction.tid;
    const staged = (await ctx0.secrets.getStaged(tid as never))!;
    await ctx0.secrets.putStaged(tid as never, { ...staged, refresh_token: oldTokens.refresh_token });
    await ctx0.store.commitActivation({ tid, now });
    expect((await ctx0.secrets.get(conn as never))!.access_token).toBe(oldTokens.access_token);

    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'reapplied' }]);
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly', 'gmail.send']);
    const stored = (await ctx.secrets.get(conn as never))!;
    expect(stored.access_token).not.toBe(oldTokens.access_token);
    expect(stored.access_token).toBe(staged.access_token);
    expect(Date.parse(stored.expires_at!)).toBeLessThanOrEqual(Date.now());
    // Next use refreshes before any upstream call.
    const refreshesBefore = hx.fake.refreshCalls;
    expect((await delegate(hx.app, { connection_id: conn })).status).toBe(200);
    expect(hx.fake.refreshCalls).toBe(refreshesBefore + 1);
  });

  it('known limit: an update on a provider that rotates refresh tokens, refreshed after a crash inside the move, ends needs_reauth', async () => {
    // Fails closed (documented in heal.ts and the README): the stored tokens
    // match neither the staged set nor its refresh token, so the heal cannot
    // tell them from the connection's old tokens.
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const pending = await updateFlow(hx, client, conn);
    const { tid, staged } = await crashActivationWithTokens(hx, client, pending, 'after-vault-write');
    const rotated = { ...staged, access_token: 'rotated-access-token', refresh_token: 'rotated-refresh-token' };
    await hx.server.link!.context.secrets.put(conn as never, rotated);

    const { report, followUps, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'reverted' }]);
    // The connection holds tokens, so nothing is revoked at the provider.
    expect(followUps).toEqual([{ tid, outcome: 'not_revoked' }]);
    expect(hx.fake.revocations).toEqual([]);
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect(await ctx.secrets.get(conn as never)).toEqual(rotated);
    expect(await ctx.secrets.getStaged(tid as never)).toBeNull();
  });
});


describe('startup heal: the permission intersect runs in every branch', () => {
  const BOTH = ['calendar.readonly', 'gmail.send'];
  const CAL = ['calendar.readonly'];

  /**
   * A narrowing update (BOTH to CAL) whose database commit happened but whose
   * hooks never ran: server-agent still holds BOTH. `prepare` then shapes the
   * crash into the branch under test.
   */
  async function narrowedWithoutIntersect(prepare: (ctx: NonNullable<Harness['server']['link']>['context'], conn: string, tid: string) => Promise<void>, point: CrashPoint) {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const pending = await updateFlow(hx, client, conn, CAL);
    const tid = await crashActivation(hx, client, pending, point);
    const ctx = hx.server.link!.context;
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(CAL);
    expect((await ctx.permissions.get('server-agent', conn))!.allowedScopes).toEqual(BOTH);
    await prepare(ctx, conn, tid);
    return { hx, conn, tid };
  }

  const cases: Array<[string, CrashPoint, (ctx: NonNullable<Harness['server']['link']>['context'], conn: string, tid: string) => Promise<void>]> = [
    ['reverted', 'before-move', async () => undefined],
    ['settled_reauth', 'before-move', async (ctx, conn, tid) => {
      await ctx.secrets.deleteStaged(tid as never);
      await ctx.secrets.delete(conn as never);
    }],
    ['stale', 'before-move', async (ctx, conn) => {
      await ctx.store.setConnectionStatus({ connection_id: conn, status: 'needs_reauth', reason: 'reauth_required', now: new Date(Date.now() + 5).toISOString() });
    }],
    ['cleaned', 'after-vault-write', async () => undefined],
    ['settled', 'after-move', async () => undefined],
  ];

  for (const [outcome, point, prepare] of cases) {
    it(`${outcome}: the agent Permission is intersected with the current grant before the settle`, async () => {
      const { hx, conn, tid } = await narrowedWithoutIntersect(prepare, point);
      const { report, ctx } = await restartAndHeal(hx);
      expect(report.outcomes).toEqual([{ tid, outcome }]);
      expect((await ctx.permissions.get('server-agent', conn))!.allowedScopes).toEqual(CAL);
      expect(await ctx.store.listUnsettledActivations()).toEqual([]);
    });
  }

  it('an intersect that fails leaves the transaction unsettled and changes nothing else; the next start finishes it', async () => {
    const { hx, conn, tid } = await narrowedWithoutIntersect(async () => undefined, 'before-move');
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const spy = vi.spyOn(PermissionStore.prototype, 'intersectForConnection').mockRejectedValueOnce(new Error('permission store down'));
    const first = await restartAndHeal(hx);
    expect(first.report.outcomes).toEqual([{ tid, outcome: 'failed' }]);
    expect(first.followUps).toEqual([]);
    expect(await first.ctx.store.getConnection(conn)).toMatchObject({ status: 'active' });
    expect((await first.ctx.store.listUnsettledActivations()).map((t) => t.tid)).toEqual([tid]);
    spy.mockRestore();

    const second = await restartAndHeal(hx);
    expect(second.report.outcomes).toEqual([{ tid, outcome: 'reverted' }]);
    expect((await second.ctx.permissions.get('server-agent', conn))!.allowedScopes).toEqual(CAL);
    expect(await second.ctx.store.listUnsettledActivations()).toEqual([]);
  });

  it('reviewer: with the needs_reauth write and the settle both lost, the staged copy is kept and the heal reverts the connection', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client, { confirmScopes: CAL });
    const ctx0 = hx.server.link!.context;
    const oldTokens = (await ctx0.secrets.get(conn as never))!;
    const pending = await updateFlow(hx, client, conn, BOTH);

    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const commit = vi.spyOn(VaultLinkSecretStore.prototype, 'commitStaged').mockRejectedValueOnce(new Error('vault write failed'));
    const status = vi.spyOn(SqliteLinkStore.prototype, 'setConnectionStatus').mockRejectedValueOnce(new Error('SQLITE_BUSY'));
    const settle = vi.spyOn(SqliteLinkStore.prototype, 'settleActivation').mockRejectedValueOnce(new Error('SQLITE_BUSY'));
    expect((await activate(hx.app, client, pending.connection_id, pending.code)).status).not.toBe(200);
    commit.mockRestore();
    status.mockRestore();
    settle.mockRestore();
    const [left] = await ctx0.store.listUnsettledActivations();
    expect(left).toBeDefined();
    expect(await ctx0.secrets.getStaged(left.tid as never)).not.toBeNull();

    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid: left.tid, outcome: 'reverted' }]);
    const connection = (await ctx.store.getConnection(conn))!;
    expect(connection).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(BOTH);
    expect((await ctx.secrets.get(conn as never))!.access_token).toBe(oldTokens.access_token);
    expect(await ctx.secrets.getStaged(left.tid as never)).toBeNull();
  });

  it('reviewer: a narrowing update crashed before the move is intersected by the heal; after reauth and a widening for another agent the old agent does not get the removed scope back', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const pending = await updateFlow(hx, client, conn, CAL);
    await crashActivation(hx, client, pending, 'before-move');

    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes.map((o) => o.outcome)).toEqual(['reverted']);
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(CAL);
    expect((await ctx.permissions.get('server-agent', conn))!.allowedScopes).toEqual(CAL);

    // Reauth with no agent (as mintAgentReauthUrl does) for the grant's scopes.
    const re = await request(hx.app).post(`/link/v1/connections/${conn}/reauth`).set('Authorization', client.auth).send({ subject: 'user-a' });
    expect(re.status).toBe(201);
    const reauth = await finishFlow(hx, re.body.request_uri, CAL, CAL);
    expect((await activate(hx.app, client, reauth.connection_id, reauth.code)).body.status).toBe('active');

    // The backend widens the grant again for a different agent.
    const uri = await par(hx.app, client, { intent: 'update', connection_id: conn, scopes: { google: BOTH }, required_scopes: {}, agent_id: 'other-agent' });
    const widening = await finishFlow(hx, uri, BOTH);
    expect((await activate(hx.app, client, widening.connection_id, widening.code)).status).toBe(200);
    expect((await delegate(hx.app, { connection_id: conn, scopes: ['gmail.send'] })).status).toBe(403);
  });
});

describe('startup heal: the intersect uses the activation\'s previous scopes', () => {
  const BOTH = ['calendar.readonly', 'gmail.send'];
  const CAL = ['calendar.readonly'];

  type Ctx = NonNullable<Harness['server']['link']>['context'];
  const branches: Array<[string, CrashPoint, (ctx: Ctx, conn: string, tid: string, staged: { refresh_token?: string }) => Promise<void>]> = [
    ['reverted', 'before-move', async () => undefined],
    ['settled_reauth', 'before-move', async (ctx, conn, tid) => {
      await ctx.secrets.deleteStaged(tid as never);
      await ctx.secrets.delete(conn as never);
    }],
    ['stale', 'before-move', async (ctx, conn) => {
      await ctx.store.setConnectionStatus({ connection_id: conn, status: 'needs_reauth', reason: 'reauth_required', now: new Date(Date.now() + 5).toISOString() });
    }],
    ['cleaned', 'after-vault-write', async () => undefined],
    ['settled', 'after-move', async () => undefined],
    ['reapplied', 'after-vault-write', async (ctx, conn) => {
      const stored = (await ctx.secrets.get(conn as never))!;
      await ctx.secrets.put(conn as never, { ...stored, access_token: 'rotated-access-token' });
    }],
  ];

  for (const [outcome, point, prepare] of branches) {
    it(`${outcome}: a widening update clips to grant ∩ grant_scopes_at_confirm`, async () => {
      const hx = await harness();
      const client = await registerClient(hx.app);
      const conn = await connectAndActivate(hx.app, client, { confirmScopes: CAL });
      const pending = await updateFlow(hx, client, conn, BOTH);
      const { tid, staged } = await crashActivationWithTokens(hx, client, pending, point);
      await prepare(hx.server.link!.context, conn, tid, staged);
      const spy = vi.spyOn(PermissionStore.prototype, 'intersectForConnection');
      const { report } = await restartAndHeal(hx);
      expect(report.outcomes).toEqual([{ tid, outcome }]);
      expect(spy.mock.calls.map(([id, scopes]) => [id, [...scopes]])).toContainEqual([conn, CAL]);
    });
  }

  it('a transaction that created its connection has no recorded previous scopes: the plain current grant', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const pending = await newConnection(hx, client);
    const tid = await crashActivation(hx, client, pending, 'after-move');
    const spy = vi.spyOn(PermissionStore.prototype, 'intersectForConnection');
    const { report } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'settled' }]);
    expect(spy.mock.calls.map(([id, scopes]) => [id, [...scopes]])).toContainEqual([pending.connection_id, BOTH]);
  });

  it('reviewer: a permission that missed a narrowing intersect does not regain the scope when the heal finishes the widening', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const ctx0 = hx.server.link!.context;
    expect((await ctx0.permissions.get('server-agent', conn))!.allowedScopes).toEqual(BOTH);

    // Miss 1: the narrowing intersect fails.
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const hook = vi.spyOn(ctx0.hooks, 'onGrantUpdated').mockRejectedValueOnce(new Error('permission store down'));
    const narrowed = await request(hx.app).post(`/link/v1/connections/${conn}/narrow`).set('Authorization', client.auth)
      .send({ subject: 'user-a', scopes: CAL });
    expect(narrowed.status).toBe(500);
    expect((await ctx0.permissions.get('server-agent', conn))!.allowedScopes).toEqual(BOTH);
    hook.mockRestore();

    // A widening for another agent; its intersect does not take effect.
    const uri = await par(hx.app, client, { intent: 'update', connection_id: conn, scopes: { google: BOTH }, required_scopes: {}, agent_id: 'other-agent' });
    const widening = await finishFlow(hx, uri, BOTH, BOTH);
    vi.spyOn(ctx0.hooks, 'onGrantUpdated').mockRejectedValueOnce(new Error('process died here'));
    expect((await activate(hx.app, client, widening.connection_id, widening.code)).status).toBe(401);
    expect(await ctx0.store.listUnsettledActivations()).toHaveLength(1);
    vi.restoreAllMocks();

    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes.map((o) => o.outcome)).toEqual(['settled']);
    expect((await ctx.permissions.get('server-agent', conn))!.allowedScopes).toEqual(CAL);
    expect((await delegate(hx.app, { connection_id: conn, scopes: ['gmail.send'] })).status).toBe(403);
  });
});

describe('startup heal: reapplied keeps the newer access token', () => {
  it('the stored token refreshed after the staged one is kept, with the staged refresh token and expires_at now', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const pending = await updateFlow(hx, client, conn);
    const { tid, staged } = await crashActivationWithTokens(hx, client, pending, 'after-vault-write');
    const later = new Date(Date.parse(staged.expires_at!) + 60_000).toISOString();
    await hx.server.link!.context.secrets.put(conn as never, { ...staged, access_token: 'rotated-access-token', expires_at: later });

    const { report, ctx } = await restartAndHeal(hx);
    expect(report.outcomes).toEqual([{ tid, outcome: 'reapplied' }]);
    const stored = (await ctx.secrets.get(conn as never))!;
    expect(stored.access_token).toBe('rotated-access-token');
    expect(stored.refresh_token).toBe(staged.refresh_token);
    expect(Date.parse(stored.expires_at!)).toBeLessThanOrEqual(Date.now());
  });

  it('a staged token newer than the stored one wins, and so does staged when either has no expiry', async () => {
    for (const storedExpiry of ['earlier', 'none'] as const) {
      const hx = await harness();
      const client = await registerClient(hx.app);
      const conn = await connectAndActivate(hx.app, client);
      const pending = await updateFlow(hx, client, conn);
      const { tid, staged } = await crashActivationWithTokens(hx, client, pending, 'after-vault-write');
      const { expires_at: _drop, ...noExpiry } = staged;
      await hx.server.link!.context.secrets.put(conn as never, storedExpiry === 'none'
        ? { ...noExpiry, access_token: 'older-access-token' }
        : { ...staged, access_token: 'older-access-token', expires_at: new Date(Date.parse(staged.expires_at!) - 60_000).toISOString() });
      const { report, ctx } = await restartAndHeal(hx);
      expect(report.outcomes).toEqual([{ tid, outcome: 'reapplied' }]);
      expect({ storedExpiry, token: (await ctx.secrets.get(conn as never))!.access_token }).toEqual({ storedExpiry, token: staged.access_token });
      h?.close();
      h = null;
    }
  });
});

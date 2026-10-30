import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { CredGuard, type CredPolicy } from '@credninja/guard';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

// ── Test fixtures ────────────────────────────────────────────────────────────

const TEST_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const TEST_ADMIN_TOKEN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const TEST_PASSPHRASE = 'test-passphrase-for-cascading-revocation';
const USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

// root ─┬─ mid ─── leaf
//       └─ sibling
const ROOT = 'did:key:z6MkCascadeRoot';
const MID = 'did:key:z6MkCascadeMid';
const SIBLING = 'did:key:z6MkCascadeSibling';
const LEAF = 'did:key:z6MkCascadeLeaf';

let tmpDir: string;

function makeTestConfig(overrides?: Partial<ServerConfig>): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: TEST_PASSPHRASE,
    vaultStorage: 'sqlite',
    vaultPath: path.join(tmpDir, 'vault.sqlite'),
    tofuStorage: 'sqlite',
    tofuPath: path.join(tmpDir, 'tofu.sqlite'),
    adminToken: TEST_ADMIN_TOKEN,
    agentToken: TEST_TOKEN,
    requireDpop: false,
    providers: [
      {
        slug: 'google',
        clientId: 'test-google-client-id',
        clientSecret: 'test-google-client-secret',
        defaultScopes: ['openid', 'email', 'profile'],
      },
    ],
    redirectBaseUri: 'http://localhost:3456',
    // Fixture DIDs here are not real did:keys, so this suite exercises the
    // deprecated legacy sub-delegation path; draft02-exchange.test.ts covers
    // the default caller-identity check.
    requireAgentIdentity: false,
    ...overrides,
  };
}

async function setup(overrides?: Partial<ServerConfig>) {
  const { app, vault } = createServer(makeTestConfig(overrides));
  await vault.init();
  await vault.store({
    provider: 'google',
    userId: 'default',
    accessToken: 'ya29.test-access-token',
    scopes: ['openid', 'email', 'profile'],
  });

  const now = new Date().toISOString();
  for (const [name, did] of [['root', ROOT], ['mid', MID], ['sibling', SIBLING], ['leaf', LEAF]]) {
    await vault.registerAgent({
      id: `agt_${name}`,
      did,
      name: `${name}-agent`,
      fingerprint: `fp_${name}`,
      scopeCeiling: [],
      status: 'active',
      createdBy: 'admin',
      createdAt: now,
      updatedAt: now,
    });
    await vault.createPermission({
      agentId: `agt_${name}`,
      connectionId: 'google',
      allowedScopes: ['openid', 'email'],
      delegatable: true,
      maxDelegationDepth: 5,
      requiresApproval: false,
      createdBy: 'admin',
    });
  }

  return { app, vault };
}

type App = Awaited<ReturnType<typeof setup>>['app'];

async function delegateRoot(app: App) {
  const res = await request(app)
    .post('/api/v1/delegate')
    .set('Authorization', `Bearer ${TEST_TOKEN}`)
    .send({ service: 'google', user_id: 'default', agent_did: ROOT, scopes: ['openid', 'email'], token_format: 'handle' });
  expect(res.status).toBe(200);
  return res.body as { delegation_id: string; receipt: string };
}

async function subdelegate(app: App, parentReceipt: string, agentDid: string) {
  return request(app)
    .post('/api/v1/subdelegate')
    .set('Authorization', `Bearer ${TEST_TOKEN}`)
    .send({ parent_receipt: parentReceipt, agent_did: agentDid, service: 'google', user_id: 'default', appClientId: 'local', scopes: ['openid', 'email'] });
}

async function chain(app: App) {
  const root = await delegateRoot(app);
  const mid = (await subdelegate(app, root.receipt, MID)).body as { delegation_id: string; receipt: string };
  const sibling = (await subdelegate(app, root.receipt, SIBLING)).body as { delegation_id: string; receipt: string };
  const leaf = (await subdelegate(app, mid.receipt, LEAF)).body as { delegation_id: string; receipt: string };
  for (const d of [mid, sibling, leaf]) expect(d.delegation_id).toMatch(/^del_/);
  return { root, mid, sibling, leaf };
}

function use(app: App, delegationId: string) {
  return request(app)
    .post('/api/v1/use')
    .set('Authorization', `Bearer ${TEST_TOKEN}`)
    .send({ delegation_id: delegationId, url: USERINFO_URL, method: 'GET' });
}

function revokeDelegation(app: App, delegationId: string, userId = 'default') {
  return request(app)
    .delete(`/api/v1/delegations/${delegationId}`)
    .query({ user_id: userId })
    .set('Authorization', `Bearer ${TEST_TOKEN}`);
}

function mockUpstream() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(
    JSON.stringify({ sub: 'user-1' }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  ));
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('cascading revocation', () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-cascade-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('records parent linkage for every sub-delegation', async () => {
    const { app, vault } = await setup();
    const { root, mid, leaf } = await chain(app);

    await expect(vault.getDelegation(root.delegation_id)).resolves.toMatchObject({ parentId: null, agentDid: ROOT, chainDepth: 0 });
    await expect(vault.getDelegation(mid.delegation_id)).resolves.toMatchObject({ parentId: root.delegation_id, agentDid: MID, chainDepth: 1 });
    await expect(vault.getDelegation(leaf.delegation_id)).resolves.toMatchObject({ parentId: mid.delegation_id, agentDid: LEAF, chainDepth: 2 });
  });

  it('revoking the root revokes the whole 3-level chain and every handle in it', async () => {
    const { app } = await setup();
    const { root, mid, sibling, leaf } = await chain(app);

    const res = await revokeDelegation(app, root.delegation_id);
    expect(res.status).toBe(200);
    expect(res.body.revoked_count).toBe(4);
    expect([...res.body.revoked_ids].sort()).toEqual(
      [root.delegation_id, mid.delegation_id, sibling.delegation_id, leaf.delegation_id].sort(),
    );
    expect(res.body.truncated).toBe(false);
    expect(res.body.elapsed_ms).toBeLessThan(5_000);

    const fetchSpy = mockUpstream();
    for (const d of [root, mid, sibling, leaf]) {
      const useRes = await use(app, d.delegation_id);
      expect(useRes.status).toBe(401);
      expect(useRes.body).toMatchObject({ error: 'delegation_revoked', revoked_ancestor_id: root.delegation_id });
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('revoking a middle node leaves its parent and the parent\'s other children working', async () => {
    const { app } = await setup();
    const { root, mid, sibling, leaf } = await chain(app);

    const res = await revokeDelegation(app, mid.delegation_id);
    expect(res.status).toBe(200);
    expect([...res.body.revoked_ids].sort()).toEqual([mid.delegation_id, leaf.delegation_id].sort());

    mockUpstream();
    expect((await use(app, root.delegation_id)).status).toBe(200);
    expect((await use(app, sibling.delegation_id)).status).toBe(200);
    expect((await use(app, mid.delegation_id)).status).toBe(401);
    expect((await use(app, leaf.delegation_id)).status).toBe(401);
  });

  it('refuses a new sub-delegation from any revoked descendant receipt', async () => {
    const { app } = await setup();
    const { root, leaf } = await chain(app);
    await revokeDelegation(app, root.delegation_id);

    const res = await subdelegate(app, leaf.receipt, SIBLING);
    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ error: 'delegation_revoked', revoked_ancestor_id: root.delegation_id });
  });

  it('writes one revoke audit event per revoked delegation naming the root cause', async () => {
    const { app, vault } = await setup();
    const { root, mid, leaf } = await chain(app);
    await revokeDelegation(app, mid.delegation_id);

    const events = vault.queryAuditEvents({ action: 'revoke' })
      .filter((e) => e.metadata?.cause === `delegation:${mid.delegation_id}`);
    expect(events.map((e) => e.metadata?.delegationId).sort()).toEqual([mid.delegation_id, leaf.delegation_id].sort());
    const leafEvent = events.find((e) => e.metadata?.delegationId === leaf.delegation_id);
    expect(leafEvent?.metadata).toMatchObject({
      revokedAncestorId: mid.delegation_id,
      parentDelegationId: mid.delegation_id,
      cascadeDepth: 1,
    });
    expect(leafEvent?.resource).toEqual({ type: 'token', id: 'google/default' });
    expect(events.some((e) => e.metadata?.delegationId === root.delegation_id)).toBe(false);
  });

  it('is idempotent and safe against duplicate revocation', async () => {
    const { app } = await setup();
    const { root } = await chain(app);
    expect((await revokeDelegation(app, root.delegation_id)).body.revoked_count).toBe(4);
    const again = await revokeDelegation(app, root.delegation_id);
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ revoked_count: 0, revoked_ids: [] });
  });

  it('answers 404 for an unknown delegation or one owned by another user', async () => {
    const { app } = await setup();
    const { root } = await chain(app);
    expect((await revokeDelegation(app, 'del_does_not_exist')).status).toBe(404);
    expect((await revokeDelegation(app, root.delegation_id, 'someone-else')).status).toBe(404);
    mockUpstream();
    expect((await use(app, root.delegation_id)).status).toBe(200);
  });

  it('revoking an agent cascades to the delegations issued to it and below it', async () => {
    const { app, vault } = await setup();
    const { root, mid, sibling, leaf } = await chain(app);

    const res = await request(app)
      .delete('/admin/agents/agt_mid')
      .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`);
    expect(res.status).toBe(204);

    mockUpstream();
    expect((await use(app, mid.delegation_id)).status).toBe(401);
    expect((await use(app, leaf.delegation_id)).status).toBe(401);
    expect((await use(app, root.delegation_id)).status).toBe(200);
    expect((await use(app, sibling.delegation_id)).status).toBe(200);

    const agentEvent = vault.queryAuditEvents({ action: 'revoke', resourceId: 'agt_mid' })[0];
    expect(agentEvent.metadata).toMatchObject({ revokedCount: 2 });
    const leafEvent = vault.queryAuditEvents({ action: 'revoke' })
      .find((e) => e.metadata?.delegationId === leaf.delegation_id);
    expect(leafEvent?.metadata).toMatchObject({ cause: 'agent:agt_mid', revokedAncestorId: mid.delegation_id });
  });

  it('refuses a request already in flight when the revocation lands before the upstream call', async () => {
    let revokeDuringUse: (() => Promise<unknown>) | null = null;
    const revokeMidFlight: CredPolicy = {
      name: 'revoke-mid-flight',
      async evaluate(ctx) {
        if (ctx.metadata?.brokered && revokeDuringUse) await revokeDuringUse();
        return { decision: 'ALLOW', policy: 'revoke-mid-flight' };
      },
    };
    const { app, vault } = await setup({ guard: new CredGuard({ policies: [revokeMidFlight] }) });
    const { root, leaf } = await chain(app);

    // The handle passed its first revocation check before the guard ran.
    revokeDuringUse = () => vault.revokeDelegations({ delegationIds: [root.delegation_id] });
    const fetchSpy = mockUpstream();
    const res = await use(app, leaf.delegation_id);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('delegation_revoked');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('revokes a tree of 1,110 descendants well under 5 seconds', async () => {
    const { app, vault } = await setup();
    const root = await delegateRoot(app);

    // Fan-out 10 over three levels below the root: 10 + 100 + 1,000.
    let level = [root.delegation_id];
    for (let depth = 1; depth <= 3; depth++) {
      const next: string[] = [];
      for (const parentId of level) {
        for (let i = 0; i < 10; i++) {
          const id = `${parentId}_${i}`;
          await vault.recordDelegation({ id, parentId, service: 'google', userId: 'default', chainDepth: depth });
          next.push(id);
        }
      }
      level = next;
    }

    const started = performance.now();
    const res = await revokeDelegation(app, root.delegation_id);
    const wallMs = performance.now() - started;

    expect(res.status).toBe(200);
    expect(res.body.revoked_count).toBe(1_111);
    expect(res.body.elapsed_ms).toBeLessThan(5_000);
    expect(wallMs).toBeLessThan(5_000);
    await expect(vault.getDelegation(level[level.length - 1])).resolves.toMatchObject({
      status: 'revoked',
      revokedAncestorId: root.delegation_id,
    });
  });

  it('cascades the same way on the file vault backend', async () => {
    const { app, vault } = createServer(makeTestConfig({ vaultStorage: 'file', vaultPath: path.join(tmpDir, 'vault.json') }));
    await vault.init();
    await vault.store({ provider: 'google', userId: 'default', accessToken: 'ya29.test-access-token', scopes: ['openid', 'email'] });

    const res = await request(app)
      .post('/api/v1/delegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({ service: 'google', user_id: 'default', scopes: ['openid', 'email'], token_format: 'handle' });
    expect(res.status).toBe(200);
    await vault.recordDelegation({ id: 'del_file_child', parentId: res.body.delegation_id, service: 'google', userId: 'default' });

    const revoke = await revokeDelegation(app, res.body.delegation_id);
    expect(revoke.body).toMatchObject({ revoked_count: 2 });
    expect((await use(app, res.body.delegation_id)).status).toBe(401);
  });
});

describe('attenuation at sub-delegation time', () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-attenuation-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('rejects a child asking for a scope its parent does not hold', async () => {
    const { app } = await setup();
    const root = await request(app)
      .post('/api/v1/delegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({ service: 'google', user_id: 'default', agent_did: ROOT, scopes: ['openid'], token_format: 'handle' });

    const res = await subdelegate(app, root.body.receipt, MID);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('scope_escalation_denied');
  });

  it('never lets a child handle outlive its parent receipt', async () => {
    const { app } = await setup({ receiptTtlSeconds: 30 });
    const root = await delegateRoot(app);
    const res = await subdelegate(app, root.receipt, MID);
    expect(res.status).toBe(200);
    expect(res.body.expires_in).toBeLessThanOrEqual(30);
  });

  it('rejects a child with a higher classification than its parent', async () => {
    const order = ['public', 'internal', 'confidential'];
    const { app } = await setup();
    const root = await request(app)
      .post('/api/v1/delegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        service: 'google', user_id: 'default', agent_did: ROOT, scopes: ['openid', 'email'], token_format: 'handle',
        constraints: [{ key: 'classification', rank: 'internal', order }],
      });
    expect(root.status).toBe(200);

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: root.body.receipt, agent_did: MID, service: 'google', user_id: 'default', appClientId: 'local',
        scopes: ['openid'], constraints: [{ key: 'classification', rank: 'confidential', order }],
      });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('constraint_escalation_denied');
  });
});

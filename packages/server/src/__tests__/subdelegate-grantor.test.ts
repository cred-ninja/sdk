/**
 * The agent handing off needs leave to hand off — and its own depth cap holds,
 * not only the receiving agent's. These cases mint real receipts through the
 * public routes: a root by DPoP, a genuine depth-1 hop, and the actor token
 * each grantor signs. A refusal must land before any stored credential is read
 * or any child delegation is recorded.
 */
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto, { createPrivateKey, sign } from 'node:crypto';
import { createServer } from '../server.js';
import { actorTokenFor, delegateAs, exerciseAs, newAgent, type AgentIdentity, type App } from './token-helpers.js';
import type { ServerConfig } from '../config.js';
import type { BuiltinAdapterSlug } from '@credninja/oauth';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const PASSPHRASE = 'test-passphrase-not-for-production';
const SCOPES = ['openid', 'email'];
const tmpDirs: string[] = [];

afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** A gate is the boolean pair, plus optionally the row's own scopes. */
type Gate = { delegatable: boolean; maxDelegationDepth: number; allowedScopes?: string[] };
type RoleName = 'origin' | 'parent' | 'child' | 'ghost';
type Role = { agent: AgentIdentity; recordId: string };

function config(dir: string, service: BuiltinAdapterSlug = 'google'): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: PASSPHRASE,
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'sqlite',
    tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: ADMIN,
    agentToken: BEARER,
    allowAgentsWithoutPermission: false,
    allowRawTokens: false,
    providers: [{ slug: service, clientId: 'id', clientSecret: 'secret', defaultScopes: [] }],
    redirectBaseUri: BASE,
  };
}

/** A server with a synthetic stored credential and one Permission per gated role. */
async function setup(
  gates: Partial<Record<RoleName, Gate>>,
  opts: { service?: BuiltinAdapterSlug; storedScopes?: string[]; ceilings?: Partial<Record<RoleName, string[]>> } = {},
) {
  const service = opts.service ?? 'google';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-grantor-'));
  tmpDirs.push(dir);
  const { app, vault } = createServer(config(dir, service));
  await vault.init();
  await vault.store({
    provider: service,
    userId: 'alice',
    accessToken: 'synthetic-upstream-token',
    expiresAt: new Date(Date.now() + 3600_000),
    scopes: opts.storedScopes ?? SCOPES,
  });
  const roles = {} as Record<RoleName, Role>;
  for (const role of ['origin', 'parent', 'child', 'ghost'] as const) {
    const agent = await newAgent();
    const recordId = `agt_${role}`;
    const now = new Date().toISOString();
    await vault.registerAgent!({
      id: recordId,
      did: agent.did,
      name: role,
      fingerprint: `fp_${role}`,
      scopeCeiling: opts.ceilings?.[role] ?? [],
      status: 'active',
      createdBy: 'test',
      createdAt: now,
      updatedAt: now,
    });
    const gate = gates[role];
    if (gate) {
      await vault.createPermission!({
        agentId: recordId,
        connectionId: service,
        allowedScopes: opts.storedScopes ?? SCOPES,
        requiresApproval: false,
        createdBy: 'test',
        ...gate,
      });
    }
    roles[role] = { agent, recordId };
  }
  return { app, vault, service, ...roles };
}

function hop(
  app: App,
  receipt: string,
  grantor: AgentIdentity,
  recipient: AgentIdentity,
  scopes: string[] = SCOPES,
  service = 'google',
) {
  return request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
    parent_receipt: receipt,
    actor_token: actorTokenFor(grantor, '/api/v1/subdelegate', BASE),
    agent_did: recipient.did,
    service,
    user_id: 'alice',
    scopes,
  });
}

/** Count the effects a refusal must not have: a credential read and a recorded child. */
function effectCounters(vault: { get: (...args: never[]) => unknown; recordDelegation: (...args: never[]) => unknown }) {
  const counts = { credentialReads: 0, delegationsRecorded: 0 };
  const get = vault.get.bind(vault);
  const record = vault.recordDelegation.bind(vault);
  vault.get = ((...args: never[]) => {
    counts.credentialReads += 1;
    return get(...args);
  }) as typeof vault.get;
  vault.recordDelegation = ((...args: never[]) => {
    counts.delegationsRecorded += 1;
    return record(...args);
  }) as typeof vault.recordDelegation;
  return counts;
}

/** A receipt signed by this server's receipt key, as the server itself would mint it. */
function signReceipt(payload: Record<string, unknown>): string {
  const seed = crypto.scryptSync(PASSPHRASE, 'cred:local-receipt:v1', 32);
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({
    iss: BASE,
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  })).toString('base64url');
  const signature = sign(null, Buffer.from(`${header}.${body}`, 'utf8'), key).toString('base64url');
  return `${header}.${body}.${signature}`;
}

const PERMISSIVE: Gate = { delegatable: true, maxDelegationDepth: 5 };

describe("the delegating agent's own Permission bounds a sub-delegation", () => {
  it('refuses a grantor whose Permission is not delegatable', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: { delegatable: false, maxDelegationDepth: 5 }, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    const counts = effectCounters(s.vault);
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.code).toBe('delegation_not_allowed');
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(res.body.access_token).toBeUndefined();
  });

  it('refuses a grantor at its depth cap of 0', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: { delegatable: true, maxDelegationDepth: 0 }, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    const counts = effectCounters(s.vault);
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.code).toBe('depth_exceeded');
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(res.body.access_token).toBeUndefined();
  });

  it("refuses one hop past a genuine depth-1 grantor's cap", async () => {
    const s = await setup({ origin: PERMISSIVE, parent: { delegatable: true, maxDelegationDepth: 1 }, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.origin.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    const first = await hop(s.app, root.body.receipt, s.origin.agent, s.parent.agent);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    expect(first.body.chain_depth).toBe(1);
    const counts = effectCounters(s.vault);
    const res = await hop(s.app, first.body.receipt, s.parent.agent, s.child.agent);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.code).toBe('depth_exceeded');
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(res.body.access_token).toBeUndefined();
  });

  it("allows the hop that lands exactly on the grantor's cap", async () => {
    const s = await setup({ origin: PERMISSIVE, parent: { delegatable: true, maxDelegationDepth: 1 }, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.chain_depth).toBe(1);
  });

  it("keeps a permissive grantor working, and attenuates the child's scopes", async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['openid']);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual(['openid']);
    const widened = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['openid', 'profile']);
    expect(widened.status).toBe(403);
    expect(widened.body.code).toBe('scope_escalation_denied');
  });

  it("keeps the recipient's own delegatable and depth gates", async () => {
    const undelegatable = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: { delegatable: false, maxDelegationDepth: 5 } });
    const rootA = await delegateAs(undelegatable.app, undelegatable.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(rootA.status).toBe(200);
    const refused = await hop(undelegatable.app, rootA.body.receipt, undelegatable.parent.agent, undelegatable.child.agent);
    expect(refused.status, JSON.stringify(refused.body)).toBe(403);
    expect(refused.body.code).toBe('delegation_not_allowed');

    const shallow = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: { delegatable: true, maxDelegationDepth: 0 } });
    const rootB = await delegateAs(shallow.app, shallow.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(rootB.status).toBe(200);
    const tooDeep = await hop(shallow.app, rootB.body.receipt, shallow.parent.agent, shallow.child.agent);
    expect(tooDeep.status, JSON.stringify(tooDeep.body)).toBe(403);
    expect(tooDeep.body.code).toBe('depth_exceeded');
  });

  it('leaves a registered grantor that holds no Permission row working as before', async () => {
    // The pre-existing recipient gates still decide when the grantor has no
    // row for this service: there is no grantor Permission to narrow.
    const s = await setup({ child: PERMISSIVE });
    const receipt = signReceipt({
      sub: s.ghost.agent.did,
      service: 'google',
      scopes: SCOPES,
      userId: 'alice',
      appClientId: 'local',
      delegationId: `del_ghost_${crypto.randomUUID()}`,
      chainDepth: 0,
    });
    const res = await hop(s.app, receipt, s.ghost.agent, s.child.agent);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.chain_depth).toBe(1);
  });
});

const RETAINED = SCOPES[0]!;
const DROPPED = SCOPES[1]!;

/** An admin PATCH of one Permission, read back through the vault. */
type PermissionRow = { id: string; allowedScopes?: string[]; expiresAt?: Date };
type PermissionStore = {
  getPermission: (id: string, service: string) => Promise<PermissionRow | null>;
  getPermissionById: (id: string) => Promise<PermissionRow | null>;
};

async function patchPermission(
  app: App,
  vault: PermissionStore,
  agentId: string,
  body: Record<string, unknown>,
  service = 'google',
) {
  const row = await vault.getPermission(agentId, service);
  if (!row) throw new Error(`no Permission for ${agentId}`);
  const res = await request(app).patch(`/admin/permissions/${row.id}`).set('Authorization', `Bearer ${ADMIN}`).send(body);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  const after = await vault.getPermissionById(row.id);
  for (const [key, value] of Object.entries(body)) {
    const actual = key === 'expiresAt' ? after?.expiresAt?.toISOString() : (after as unknown as Record<string, unknown>)?.[key];
    expect(actual, key).toEqual(value);
  }
}

/** Fail the test if anything reaches the network, and count it. */
function noNetwork() {
  const calls: unknown[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation((...args: Parameters<typeof fetch>) => {
    calls.push(args[0]);
    throw new Error('network disabled in this test');
  });
  return calls;
}

describe("the grantor's present scopes and validity bound a sub-delegation", () => {
  it('refuses a handoff that the grantor\'s narrowed record-id row no longer covers', async () => {
    // The grantor held both scopes when the receipt was minted; an admin then
    // narrows its Permission to one. The receipt must not carry the dropped
    // scope any further.
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    await patchPermission(s.app, s.vault, s.parent.recordId, { allowedScopes: [RETAINED] });

    // Inheriting the parent receipt's scopes asks for the dropped one too.
    const counts = effectCounters(s.vault);
    const fetches = noNetwork();
    const inherited = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, SCOPES);
    expect(inherited.status, JSON.stringify(inherited.body)).toBe(403);
    expect(inherited.body.error).toBe('scope_insufficient');
    expect(inherited.body.code).toBe('scope_insufficient');
    expect(inherited.body.scopes).toEqual([DROPPED]);
    expect(inherited.body.access_token).toBeUndefined();
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(fetches).toEqual([]);

    // Asking for the dropped scope alone is the same refusal.
    const explicit = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, [DROPPED]);
    expect(explicit.status, JSON.stringify(explicit.body)).toBe(403);
    expect(explicit.body.error).toBe('scope_insufficient');
    expect(explicit.body.scopes).toEqual([DROPPED]);
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(fetches).toEqual([]);
  });

  it('keeps the retained scope working for the child after that narrowing', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    await patchPermission(s.app, s.vault, s.parent.recordId, { allowedScopes: [RETAINED] });

    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, [RETAINED]);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual([RETAINED]);
    expect(res.body.chain_depth).toBe(1);
    expect(typeof res.body.access_token).toBe('string');
    expect(fetches).toEqual([]);
  });

  it('refuses a handoff that a narrower DID row for the grantor no longer covers', async () => {
    // Two rows for one grantor, merged tightest-first: the record-id row still
    // holds both scopes, the DID row holds one. Neither row may widen the other.
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    await s.vault.createPermission!({
      agentId: s.parent.agent.did,
      connectionId: 'google',
      allowedScopes: [RETAINED],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 5,
      createdBy: 'test',
    });
    expect(await s.vault.getPermission!(s.parent.agent.did, 'google')).toMatchObject({ allowedScopes: [RETAINED] });

    const counts = effectCounters(s.vault);
    const fetches = noNetwork();
    const refused = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, [DROPPED]);
    expect(refused.status, JSON.stringify(refused.body)).toBe(403);
    expect(refused.body.error).toBe('scope_insufficient');
    expect(refused.body.access_token).toBeUndefined();
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(fetches).toEqual([]);

    const allowed = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, [RETAINED]);
    expect(allowed.status, JSON.stringify(allowed.body)).toBe(200);
    expect(allowed.body.scopes).toEqual([RETAINED]);
  });

  it('refuses a handoff once the grantor\'s Permission has expired', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    await patchPermission(s.app, s.vault, s.parent.recordId, { expiresAt: new Date(Date.now() - 60_000).toISOString() });

    const counts = effectCounters(s.vault);
    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, SCOPES);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.error).toBe('permission_expired');
    expect(res.body.access_token).toBeUndefined();
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(fetches).toEqual([]);
  });

  it('refuses a handoff when only one of the grantor\'s two rows is expired', async () => {
    const s = await setup({ origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE });
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    await s.vault.createPermission!({
      agentId: s.parent.agent.did,
      connectionId: 'google',
      allowedScopes: SCOPES,
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 5,
      expiresAt: new Date(Date.now() - 60_000),
      createdBy: 'test',
    });

    const counts = effectCounters(s.vault);
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, [RETAINED]);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.error).toBe('permission_expired');
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
  });
});

/**
 * A derived read scope is Cred's name for access the raw token already carries:
 * `github.read` over a `repo` token reaches private repositories. What the hop
 * would hand on therefore has to be judged against the stored connection's
 * scopes, not against what the receipt happens to name. The stored read is a
 * metadata read (getStored: no refresh, no provider call); the refusal it
 * decides must still release no credential and record no child delegation.
 */
function storedReads(vault: { getStored: (...args: never[]) => unknown }) {
  const counter = { reads: 0 };
  const read = vault.getStored.bind(vault);
  vault.getStored = ((...args: never[]) => {
    counter.reads += 1;
    return read(...args);
  }) as typeof vault.getStored;
  return counter;
}

describe("the grantor's derived read scopes over the stored connection", () => {
  it('refuses a github.read hop from a stale receipt once the grantor is narrowed to public_repo over a repo token', async () => {
    const s = await setup(
      { origin: PERMISSIVE, parent: { ...PERMISSIVE, allowedScopes: ['repo'] }, child: { ...PERMISSIVE, allowedScopes: ['github.read'] } },
      { service: 'github', storedScopes: ['repo'] },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'github', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    // The receipt names the derived read while the token still backed it.
    expect(root.body.scopes).toEqual(['github.read']);
    await patchPermission(s.app, s.vault, s.parent.recordId, { allowedScopes: ['public_repo'] }, 'github');

    const counts = effectCounters(s.vault);
    const stored = storedReads(s.vault);
    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['github.read'], 'github');
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.error).toBe('scope_insufficient');
    expect(res.body.code).toBe('scope_insufficient');
    expect(res.body.scopes).toEqual(['github.read']);
    // No credential released, no child recorded, no refresh and no provider call.
    expect(res.body.access_token).toBeUndefined();
    expect(JSON.stringify(res.body)).not.toContain('synthetic-upstream-token');
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(fetches).toEqual([]);
    // The decision came from exactly one metadata read of the stored row.
    expect(stored.reads).toBe(1);
  });

  it('refuses it when the grantor is narrowed only on its DID row, merged tightest-first', async () => {
    const s = await setup(
      {
        origin: PERMISSIVE,
        parent: { ...PERMISSIVE, allowedScopes: ['repo', 'public_repo'] },
        child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
      },
      { service: 'github', storedScopes: ['repo'] },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'github', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    await s.vault.createPermission!({
      agentId: s.parent.agent.did,
      connectionId: 'github',
      allowedScopes: ['public_repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 5,
      createdBy: 'test',
    });
    expect(await s.vault.getPermission!(s.parent.agent.did, 'github')).toMatchObject({ allowedScopes: ['public_repo'] });

    const counts = effectCounters(s.vault);
    const fetches = noNetwork();
    const refused = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['github.read'], 'github');
    expect(refused.status, JSON.stringify(refused.body)).toBe(403);
    expect(refused.body.error).toBe('scope_insufficient');
    expect(refused.body.scopes).toEqual(['github.read']);
    expect(refused.body.access_token).toBeUndefined();
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(fetches).toEqual([]);

    // Widening the DID row back to the token's own scope allows the same hop, so
    // the refusal above came from that row and not from the service or the token.
    const didRow = await s.vault.getPermission!(s.parent.agent.did, 'github');
    await s.vault.updatePermission!(didRow!.id, { allowedScopes: ['repo'] });
    const allowed = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['github.read'], 'github');
    expect(allowed.status, JSON.stringify(allowed.body)).toBe(200);
    expect(allowed.body.scopes).toEqual(['github.read']);
    expect(typeof allowed.body.access_token).toBe('string');
  });

  it('keeps the public_repo grant deriving github.read over a token that only holds public_repo', async () => {
    const s = await setup(
      { origin: PERMISSIVE, parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] }, child: { ...PERMISSIVE, allowedScopes: ['github.read'] } },
      { service: 'github', storedScopes: ['public_repo'] },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'github', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    expect(root.body.scopes).toEqual(['github.read']);

    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['github.read'], 'github');
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual(['github.read']);
    expect(res.body.chain_depth).toBe(1);
    expect(typeof res.body.access_token).toBe('string');
    expect(fetches).toEqual([]);
  });
});

/** The claims of a receipt the server signed, as the server laid them out. */
function receiptClaims(receipt: string): { scopes?: string[] } {
  return JSON.parse(Buffer.from(receipt.split('.')[1]!, 'base64url').toString('utf8')) as { scopes?: string[] };
}

/**
 * Notion's token carries no scopes — its capabilities are set on the
 * integration — so a stored connection with an empty scope list is the whole
 * connection. Every decision about a derived read has to see that: a row naming
 * only `read_content` reaches no `notion.read`, whether it asks for one itself
 * or hands one on from a receipt minted while its row was `content`. A row
 * naming `content` still does.
 */
describe('a Notion connection with no stored scopes is the whole connection', () => {
  const ask = (app: App, agent: AgentIdentity, scopes: string[]) => delegateAs(
    app, agent, { service: 'notion', user_id: 'alice', scopes }, { bearer: BEARER, base: BASE },
  );

  it('still issues notion.read to a row naming content', async () => {
    const s = await setup({ parent: { ...PERMISSIVE, allowedScopes: ['content'] } }, { service: 'notion', storedScopes: [] });
    const fetches = noNetwork();
    const res = await ask(s.app, s.parent.agent, ['notion.read']);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual(['notion.read']);
    expect(typeof res.body.access_token).toBe('string');
    expect(fetches).toEqual([]);
  });

  it('refuses notion.read to a row naming only read_content, recording no child', async () => {
    const s = await setup({ parent: { ...PERMISSIVE, allowedScopes: ['read_content'] } }, { service: 'notion', storedScopes: [] });
    const counts = effectCounters(s.vault);
    const fetches = noNetwork();
    const res = await ask(s.app, s.parent.agent, ['notion.read']);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.access_token).toBeUndefined();
    expect(JSON.stringify(res.body)).not.toContain('synthetic-upstream-token');
    expect(counts.delegationsRecorded).toBe(0);
    expect(fetches).toEqual([]);
  });

  it('refuses a notion.read hop from a stale receipt once the grantor is narrowed to read_content', async () => {
    const s = await setup(
      {
        origin: PERMISSIVE,
        parent: { ...PERMISSIVE, allowedScopes: ['content'] },
        child: { ...PERMISSIVE, allowedScopes: ['notion.read'] },
      },
      { service: 'notion', storedScopes: [] },
    );
    const root = await ask(s.app, s.parent.agent, ['notion.read']);
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    // The receipt names the derived read while the row was still `content`.
    expect(root.body.scopes).toEqual(['notion.read']);
    await patchPermission(s.app, s.vault, s.parent.recordId, { allowedScopes: ['read_content'] }, 'notion');

    const counts = effectCounters(s.vault);
    const stored = storedReads(s.vault);
    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['notion.read'], 'notion');
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.error).toBe('scope_insufficient');
    expect(res.body.scopes).toEqual(['notion.read']);
    expect(res.body.access_token).toBeUndefined();
    expect(JSON.stringify(res.body)).not.toContain('synthetic-upstream-token');
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(fetches).toEqual([]);
    // One metadata read of the stored row decided it.
    expect(stored.reads).toBe(1);
  });
});

/**
 * The same stored-scope question decides a live use: `/api/v1/use` re-checks the
 * Permission behind a delegation, so a row narrowed after issuance must stop a
 * derived read that only the wider connection backed.
 */
describe('a live Notion delegation stops when its Permission narrows', () => {
  const PAGE = 'https://api.notion.com/v1/pages/abc';

  it('refuses notion.read at use once the row names only read_content', async () => {
    const s = await setup({ parent: { ...PERMISSIVE, allowedScopes: ['content'] } }, { service: 'notion', storedScopes: [] });
    const issued = await delegateAs(s.app, s.parent.agent, { service: 'notion', user_id: 'alice', scopes: ['notion.read'] }, { bearer: BEARER, base: BASE });
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    expect(issued.body.scopes).toEqual(['notion.read']);

    const upstream = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(
      JSON.stringify({ object: 'page' }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    ));
    const allowed = await exerciseAs(s.app, s.parent.agent, issued.body.access_token, { url: PAGE, method: 'GET' }, { base: BASE });
    expect(allowed.status, JSON.stringify(allowed.body)).toBe(200);
    const callsBefore = upstream.mock.calls.length;
    expect(callsBefore).toBeGreaterThan(0);

    await patchPermission(s.app, s.vault, s.parent.recordId, { allowedScopes: ['read_content'] }, 'notion');
    const refused = await exerciseAs(s.app, s.parent.agent, issued.body.access_token, { url: PAGE, method: 'GET' }, { base: BASE });
    expect(refused.status, JSON.stringify(refused.body)).toBe(403);
    expect(refused.body.error).toBe('scope_insufficient');
    // Refused before the provider was called again.
    expect(upstream.mock.calls.length).toBe(callsBefore);
  });
});

/**
 * The receiving Permission bounds a hop as well as the grantor's, so it is read
 * over what the stored connection actually covers: a `public_repo` recipient
 * cannot be issued `github.read` over a `repo` token, and a `public_repo`
 * ceiling cannot cover it there either. Both are issuance-time refusals — no
 * child delegation is recorded and no credential leaves the server.
 */
describe('the receiving Permission is read over the stored connection', () => {
  it('refuses github.read to a recipient row that only names public_repo over a repo token', async () => {
    const s = await setup(
      {
        origin: PERMISSIVE,
        parent: { ...PERMISSIVE, allowedScopes: ['repo'] },
        child: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      },
      { service: 'github', storedScopes: ['repo'] },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'github', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    expect(root.body.scopes).toEqual(['github.read']);

    const counts = effectCounters(s.vault);
    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['github.read'], 'github');
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.access_token).toBeUndefined();
    expect(JSON.stringify(res.body)).not.toContain('synthetic-upstream-token');
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(fetches).toEqual([]);
  });

  it('keeps issuing it to a public_repo recipient over a public_repo token', async () => {
    const s = await setup(
      {
        origin: PERMISSIVE,
        parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
        child: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      },
      { service: 'github', storedScopes: ['public_repo'] },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'github', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    expect(root.body.scopes).toEqual(['github.read']);

    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['github.read'], 'github');
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual(['github.read']);
    expect(fetches).toEqual([]);
  });

  it('refuses github.read to a recipient whose ceiling only names public_repo over a repo token', async () => {
    const s = await setup(
      {
        origin: PERMISSIVE,
        parent: { ...PERMISSIVE, allowedScopes: ['repo'] },
        child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
      },
      { service: 'github', storedScopes: ['repo'], ceilings: { child: ['public_repo'] } },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'github', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);

    const counts = effectCounters(s.vault);
    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['github.read'], 'github');
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.code).toBe('scope_ceiling_exceeded');
    expect(res.body.access_token).toBeUndefined();
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
    expect(fetches).toEqual([]);
  });

  it('keeps it for a public_repo ceiling over a public_repo token', async () => {
    const s = await setup(
      {
        origin: PERMISSIVE,
        parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
        child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
      },
      { service: 'github', storedScopes: ['public_repo'], ceilings: { child: ['public_repo'] } },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'github', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);

    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, ['github.read'], 'github');
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual(['github.read']);
    expect(fetches).toEqual([]);
  });
});

/**
 * The receiving agent's scope ceiling is a hard cap on what a hop selects, so
 * the response, the signed receipt and the audit record name exactly the
 * selection: nothing the recipient was never given can be handed on again.
 */
describe("the receiving agent's ceiling bounds the child receipt", () => {
  it('names only the ceiling-filtered selection in the response, the receipt and the audit record', async () => {
    const s = await setup(
      { origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE },
      { ceilings: { child: [RETAINED] } },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);

    const before = new Set(s.vault.queryAuditEvents({ action: 'delegate' })
      .filter((event) => event.outcome === 'success').map((event) => event.id));
    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, SCOPES);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual([RETAINED]);
    expect(receiptClaims(res.body.receipt).scopes).toEqual([RETAINED]);
    const recorded = s.vault.queryAuditEvents({ action: 'delegate' })
      .filter((event) => event.outcome === 'success' && !before.has(event.id));
    expect(recorded.length).toBeGreaterThan(0);
    for (const event of recorded) expect(event.scopesGranted).toEqual([RETAINED]);
    expect(fetches).toEqual([]);

    // The child's receipt cannot anchor a hop to the scope it never selected.
    const grand = await hop(s.app, res.body.receipt, s.child.agent, s.ghost.agent, [DROPPED]);
    expect(grand.status, JSON.stringify(grand.body)).toBe(403);
    expect(grand.body.access_token).toBeUndefined();
  });

  it('keeps a ceiling that equals the validated grant: the receipt names that grant', async () => {
    const s = await setup(
      { origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE },
      { ceilings: { child: SCOPES } },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);

    const fetches = noNetwork();
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, SCOPES);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual(SCOPES);
    expect(receiptClaims(res.body.receipt).scopes).toEqual(SCOPES);
    expect(fetches).toEqual([]);
  });

  it('still refuses a selection the ceiling leaves empty', async () => {
    const s = await setup(
      { origin: PERMISSIVE, parent: PERMISSIVE, child: PERMISSIVE },
      { ceilings: { child: [RETAINED] } },
    );
    const root = await delegateAs(s.app, s.parent.agent, { service: 'google', user_id: 'alice', scopes: SCOPES }, { bearer: BEARER, base: BASE });
    expect(root.status, JSON.stringify(root.body)).toBe(200);

    const counts = effectCounters(s.vault);
    const res = await hop(s.app, root.body.receipt, s.parent.agent, s.child.agent, [DROPPED]);
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.code).toBe('scope_ceiling_exceeded');
    expect(res.body.access_token).toBeUndefined();
    expect(counts).toEqual({ credentialReads: 0, delegationsRecorded: 0 });
  });
});

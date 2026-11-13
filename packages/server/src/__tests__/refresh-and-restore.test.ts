/**
 * Two paths that refresh a stored provider token on the server.
 *
 * Cold restore: a server that did not issue a handle (another replica, or a
 * restart) rebuilds it on /api/v1/use, and an expired row is refreshed at the
 * provider while doing so. That refresh must wait for the request to prove the
 * key the Delegation Token is bound to: a token presented without that key
 * must not be able to decrypt the row or rotate it at the provider.
 *
 * Delegation: a refresh that states a scope stores it, so a narrowed provider
 * grant is not recorded under the wider list it replaced.
 *
 * Only fetch is stubbed. Vault, adapter, receipts and DPoP are real.
 */
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'node:crypto';
import { createServer } from '../server.js';
import { actorTokenFor, delegateAs, exerciseAs, newAgent, type AgentIdentity } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GMAIL_READ_URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages';
const ISSUED_TOKEN = 'synthetic-issued-access';
const REFRESHED_TOKEN = 'synthetic-refreshed-access';

const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function config(dir: string): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'sqlite',
    tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: ADMIN,
    agentToken: BEARER,
    allowAgentsWithoutPermission: false,
    allowRawTokens: false,
    providers: [{ slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: [] }],
    redirectBaseUri: BASE,
  };
}

/** Provider stub: counts token-endpoint refreshes and records upstream credentials. */
function provider(refreshReply: Record<string, unknown> = { access_token: REFRESHED_TOKEN, expires_in: 3600 }, refreshStatus = 200) {
  const calls = { refresh: 0, upstream: [] as string[] };
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init?: RequestInit) => {
    if (String(input) === TOKEN_URL) {
      calls.refresh += 1;
      return new Response(JSON.stringify(refreshReply), { status: refreshStatus, headers: { 'content-type': 'application/json' } });
    }
    calls.upstream.push(new Headers(init?.headers ?? {}).get('authorization') ?? '');
    return new Response(JSON.stringify({ synthetic: true }), { status: 200, headers: { 'content-type': 'application/json' } });
  }));
  return calls;
}

async function serverWithConnection(dir: string, expiresAt: Date) {
  const server = createServer(config(dir));
  await server.vault.init();
  await server.vault.store({
    provider: 'google',
    userId: 'alice',
    accessToken: ISSUED_TOKEN,
    refreshToken: 'synthetic-stored-refresh',
    scopes: ['gmail.readonly', 'gmail.send'],
    expiresAt,
  });
  return server;
}

/**
 * A handle issued on one server, then a fresh server over the same storage with
 * the row expired, so the next /api/v1/use there restores and must refresh.
 */
type Issuer = Awaited<ReturnType<typeof serverWithConnection>>;

async function restoredWorld(beforeRestart?: (issuer: Issuer, agent: AgentIdentity, permissionId: string) => Promise<void>) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-refresh-restore-'));
  tmpDirs.push(dir);
  const issuer = await serverWithConnection(dir, new Date(Date.now() + 3_600_000));
  const agent = await newAgent();
  const permission = await issuer.vault.createPermission!({
    agentId: agent.did,
    connectionId: 'google',
    allowedScopes: ['gmail.readonly'],
    requiresApproval: false,
    delegatable: false,
    maxDelegationDepth: 1,
    createdBy: 'test',
  });
  const issued = await delegateAs(issuer.app, agent, { service: 'google', user_id: 'alice', scopes: ['gmail.readonly'] }, { bearer: BEARER });
  expect(issued.status, JSON.stringify(issued.body)).toBe(200);
  await issuer.vault.store({
    provider: 'google',
    userId: 'alice',
    accessToken: ISSUED_TOKEN,
    refreshToken: 'synthetic-stored-refresh',
    scopes: ['gmail.readonly', 'gmail.send'],
    expiresAt: new Date(Date.now() - 60_000),
  });
  await beforeRestart?.(issuer, agent, permission.id);
  const restarted = createServer(config(dir));
  await restarted.vault.init();
  return { restarted, agent, token: issued.body.access_token as string };
}

describe('cold restore on /api/v1/use waits for the bound key before refreshing', () => {
  it('refreshes nothing for a proof by a different key', async () => {
    const world = await restoredWorld();
    const intruder: AgentIdentity = await newAgent();
    const calls = provider();

    const response = await exerciseAs(world.restarted.app, intruder, world.token, { url: GMAIL_READ_URL, method: 'GET' }, { base: BASE });

    expect(response.status, JSON.stringify(response.body)).toBe(401);
    expect(calls.refresh).toBe(0);
    expect(calls.upstream).toEqual([]);
    const stored = await world.restarted.vault.getStored({ provider: 'google', userId: 'alice' });
    expect(stored?.refreshToken).toBe('synthetic-stored-refresh');
  });

  it('refreshes nothing when no proof is sent', async () => {
    const world = await restoredWorld();
    const calls = provider();

    const response = await request(world.restarted.app).post('/api/v1/use')
      .set('Authorization', `DPoP ${world.token}`)
      .send({ url: GMAIL_READ_URL, method: 'GET' });

    expect(response.status, JSON.stringify(response.body)).toBe(401);
    expect(calls.refresh).toBe(0);
    expect(calls.upstream).toEqual([]);
  });

  it('refreshes nothing for a key-holding agent that has been suspended', async () => {
    const world = await restoredWorld(async (issuer, agent) => {
      const now = new Date().toISOString();
      await issuer.vault.registerAgent!({
        id: 'agt_suspended', did: agent.did, name: 'suspended', fingerprint: 'fp_suspended',
        scopeCeiling: [], status: 'suspended', createdBy: 'test', createdAt: now, updatedAt: now,
      });
    });
    const calls = provider();

    const response = await exerciseAs(world.restarted.app, world.agent, world.token, { url: GMAIL_READ_URL, method: 'GET' }, { base: BASE });

    expect(response.status, JSON.stringify(response.body)).toBe(403);
    expect(response.body.error).toBe('agent_suspended');
    expect(calls.refresh).toBe(0);
    expect(calls.upstream).toEqual([]);
  });

  it('refreshes nothing for a key-holding agent whose Permission has expired', async () => {
    const world = await restoredWorld(async (issuer, _agent, permissionId) => {
      await issuer.vault.updatePermission!(permissionId, { expiresAt: new Date(Date.now() - 1_000) });
    });
    const calls = provider();

    const response = await exerciseAs(world.restarted.app, world.agent, world.token, { url: GMAIL_READ_URL, method: 'GET' }, { base: BASE });

    expect(response.status, JSON.stringify(response.body)).toBe(403);
    expect(response.body.error).toBe('scope_insufficient');
    expect(calls.refresh).toBe(0);
    expect(calls.upstream).toEqual([]);
    const stored = await world.restarted.vault.getStored({ provider: 'google', userId: 'alice' });
    expect(stored?.refreshToken).toBe('synthetic-stored-refresh');
  });

  it('forwards nothing and leaves the row as it was when the provider refuses the refresh', async () => {
    const world = await restoredWorld();
    const calls = provider({ error: 'invalid_grant' }, 400);

    const response = await exerciseAs(world.restarted.app, world.agent, world.token, { url: GMAIL_READ_URL, method: 'GET' }, { base: BASE });

    expect(response.status, JSON.stringify(response.body)).toBe(401);
    expect(calls.refresh).toBe(1);
    expect(calls.upstream).toEqual([]);
    const stored = await world.restarted.vault.getStored({ provider: 'google', userId: 'alice' });
    expect(stored?.accessToken).toBe(ISSUED_TOKEN);
    expect(stored?.refreshToken).toBe('synthetic-stored-refresh');
  });

  it('refreshes once and forwards the refreshed token for the bound key', async () => {
    const world = await restoredWorld();
    const calls = provider();

    const response = await exerciseAs(world.restarted.app, world.agent, world.token, { url: GMAIL_READ_URL, method: 'GET' }, { base: BASE });

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(calls.refresh).toBe(1);
    expect(calls.upstream).toEqual([`Bearer ${REFRESHED_TOKEN}`]);
  });
});

describe('a refresh on delegation stores the scope the provider states', () => {
  it('records a narrowed scope instead of the wider list it replaced', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-refresh-scope-'));
    tmpDirs.push(dir);
    const server = await serverWithConnection(dir, new Date(Date.now() - 60_000));
    const agent = await newAgent();
    await server.vault.createPermission!({
      agentId: agent.did,
      connectionId: 'google',
      allowedScopes: ['gmail.readonly'],
      requiresApproval: false,
      delegatable: false,
      maxDelegationDepth: 1,
      createdBy: 'test',
    });
    const calls = provider({ access_token: REFRESHED_TOKEN, expires_in: 3600, scope: 'gmail.readonly' });

    const issued = await delegateAs(server.app, agent, { service: 'google', user_id: 'alice', scopes: ['gmail.readonly'] }, { bearer: BEARER });

    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    expect(calls.refresh).toBe(1);
    const stored = await server.vault.getStored({ provider: 'google', userId: 'alice' });
    expect(stored?.accessToken).toBe(REFRESHED_TOKEN);
    expect(stored?.scopes).toEqual(['gmail.readonly']);
  });
});

describe('a refresh on sub-delegation stores the scope the provider states', () => {
  it('records a narrowed scope through the hop credential path', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-refresh-hop-'));
    tmpDirs.push(dir);
    const server = await serverWithConnection(dir, new Date(Date.now() + 3_600_000));
    const parent = await newAgent();
    const child = await newAgent();
    for (const agent of [parent, child]) {
      await server.vault.createPermission!({
        agentId: agent.did,
        connectionId: 'google',
        allowedScopes: ['gmail.readonly'],
        requiresApproval: false,
        delegatable: true,
        maxDelegationDepth: 3,
        createdBy: 'test',
      });
    }
    const root = await delegateAs(server.app, parent, { service: 'google', user_id: 'alice', scopes: ['gmail.readonly'] }, { bearer: BEARER });
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    await server.vault.store({
      provider: 'google',
      userId: 'alice',
      accessToken: ISSUED_TOKEN,
      refreshToken: 'synthetic-stored-refresh',
      scopes: ['gmail.readonly', 'gmail.send'],
      expiresAt: new Date(Date.now() - 60_000),
    });
    const calls = provider({ access_token: REFRESHED_TOKEN, expires_in: 3600, scope: 'gmail.readonly' });

    const hop = await request(server.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: root.body.receipt,
      actor_token: actorTokenFor(parent, '/api/v1/subdelegate', BASE),
      agent_did: child.did,
      service: 'google',
      user_id: 'alice',
      scopes: ['gmail.readonly'],
    });

    expect(hop.status, JSON.stringify(hop.body)).toBe(200);
    expect(calls.refresh).toBe(1);
    const stored = await server.vault.getStored({ provider: 'google', userId: 'alice' });
    expect(stored?.accessToken).toBe(REFRESHED_TOKEN);
    expect(stored?.scopes).toEqual(['gmail.readonly']);
  });
});

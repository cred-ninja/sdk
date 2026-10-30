/**
 * Capabilities end to end: a Delegation Token narrowed to catalogue
 * operations and resources is held to them at exercise, and a child can
 * never widen them.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { newAgent, delegateAs, exerciseAs, actorTokenFor, type App, type AgentIdentity } from './token-helpers.js';

const TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const DRIVE = 'https://www.googleapis.com/auth/drive.readonly';
const FILE_URL = (id: string) => `https://www.googleapis.com/drive/v3/files/${id}`;
const dirs: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

async function setup(agents: AgentIdentity[] = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-cap-'));
  dirs.push(dir);
  const config: ServerConfig = {
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: `cred_admin_${crypto.randomBytes(32).toString('hex')}`, agentToken: TOKEN,
    providers: [{ slug: 'google', clientId: 'cid', clientSecret: 'secret', defaultScopes: [DRIVE] }],
    redirectBaseUri: BASE,
  };
  const { app, vault } = createServer(config);
  await vault.init();
  await vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.cap', expiresAt: new Date(Date.now() + 3600_000), scopes: [DRIVE] });
  for (const agent of agents) {
    await vault.createPermission!({
      agentId: agent.did, connectionId: 'google', allowedScopes: [DRIVE],
      delegatable: true, maxDelegationDepth: 3, requiresApproval: false, createdBy: 'admin',
    });
  }
  return app;
}

const fileOnly = (id: string) => [{ type: 'cred_delegation', provider: 'google', operations: ['drive.files.get'], resources: [`file:${id}`] }];

function mockUpstream() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
}

function claimsOf(jws: string) {
  return JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8'));
}

async function delegateFile(app: App, agent: AgentIdentity, id = 'abc') {
  return delegateAs(app, agent, { service: 'google', user_id: 'alice', scopes: [DRIVE], authorization_details: fileOnly(id) }, { bearer: TOKEN, base: BASE });
}

describe('capabilities at issuance', () => {
  it('carries the requested capabilities in the token and the consent', async () => {
    const agent = await newAgent();
    const app = await setup();
    const res = await delegateFile(app, agent);
    expect(res.status).toBe(200);
    expect(claimsOf(res.body.access_token).authorization_details).toEqual(fileOnly('abc'));
  });

  it('refuses an unknown operation or an unsupported resource kind', async () => {
    const agent = await newAgent();
    const app = await setup();
    for (const details of [
      [{ type: 'cred_delegation', provider: 'google', operations: ['drive.files.delete'] }],
      [{ type: 'cred_delegation', provider: 'google', operations: ['drive.files.list'], resources: ['folder:abc'] }],
    ]) {
      const res = await delegateAs(app, agent, { service: 'google', user_id: 'alice', scopes: [DRIVE], authorization_details: details }, { bearer: TOKEN, base: BASE });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('invalid_authorization_details');
    }
  });
});

describe('capabilities at exercise', () => {
  it('allows the named operation on the named file only', async () => {
    const agent = await newAgent();
    const app = await setup();
    const token = (await delegateFile(app, agent)).body.access_token;
    const upstream = mockUpstream();
    expect((await exerciseAs(app, agent, token, { url: FILE_URL('abc'), method: 'GET' }, { base: BASE })).status).toBe(200);
    const otherFile = await exerciseAs(app, agent, token, { url: FILE_URL('xyz'), method: 'GET' }, { base: BASE });
    expect(otherFile.status).toBe(403);
    expect(otherFile.body.error).toBe('capability_denied');
    const listing = await exerciseAs(app, agent, token, { url: 'https://www.googleapis.com/drive/v3/files', method: 'GET' }, { base: BASE });
    expect(listing.status).toBe(403);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('never lets a method override run a method the capability does not name', async () => {
    const agent = await newAgent();
    const app = await setup();
    const token = (await delegateFile(app, agent)).body.access_token;
    const upstream = mockUpstream();
    const viaHeader = await exerciseAs(app, agent, token, {
      url: FILE_URL('abc'), method: 'GET', extra_headers: { 'X-HTTP-Method-Override': 'DELETE' },
    }, { base: BASE });
    expect(viaHeader.status).toBe(200);
    const [, init] = upstream.mock.calls[0]!;
    expect(new Headers(init!.headers).get('x-http-method-override')).toBeNull();
    for (const key of ['$httpMethod', '_HttpMethod', '_method', 'X-HTTP-Method-Override', 'method']) {
      const viaQuery = await exerciseAs(app, agent, token, { url: `${FILE_URL('abc')}?${key}=DELETE`, method: 'GET' }, { base: BASE });
      expect(viaQuery.status).toBe(400);
    }
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('keeps a token issued without capabilities as broad as its scopes', async () => {
    const agent = await newAgent();
    const app = await setup();
    const token = (await delegateAs(app, agent, { service: 'google', user_id: 'alice', scopes: [DRIVE] }, { bearer: TOKEN, base: BASE })).body.access_token;
    mockUpstream();
    expect((await exerciseAs(app, agent, token, { url: FILE_URL('xyz'), method: 'GET' }, { base: BASE })).status).toBe(200);
  });
});

describe('capabilities across sub-delegation', () => {
  async function subdelegate(app: App, parentReceipt: string, delegator: AgentIdentity, child: AgentIdentity, body: Record<string, unknown> = {}) {
    return request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${TOKEN}`).send({
      parent_receipt: parentReceipt, actor_token: actorTokenFor(delegator, '/api/v1/subdelegate', BASE),
      agent_did: child.did, service: 'google', user_id: 'alice', scopes: [DRIVE], ...body,
    });
  }

  it('passes a narrowed parent\'s capabilities down unchanged', async () => {
    const [root, child] = [await newAgent(), await newAgent()];
    const app = await setup([child]);
    const parent = await delegateFile(app, root);
    const sub = await subdelegate(app, parent.body.receipt, root, child);
    expect(sub.status).toBe(200);
    expect(claimsOf(sub.body.access_token).authorization_details).toEqual(fileOnly('abc'));
    mockUpstream();
    expect((await exerciseAs(app, child, sub.body.access_token, { url: FILE_URL('xyz'), method: 'GET' }, { base: BASE })).status).toBe(403);
  });

  it('refuses a child that asks for more than its parent', async () => {
    const [root, child] = [await newAgent(), await newAgent()];
    const app = await setup([child]);
    const parent = await delegateFile(app, root);
    for (const details of [fileOnly('xyz'), [{ type: 'cred_delegation', provider: 'google', operations: [DRIVE] }]]) {
      const sub = await subdelegate(app, parent.body.receipt, root, child, { authorization_details: details });
      expect(sub.status).toBe(403);
      expect(sub.body.error).toBe('capability_escalation_denied');
    }
  });
});

describe('GitHub capabilities end to end', () => {
  async function githubSetup(extra: Partial<ServerConfig> = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-cap-gh-'));
    dirs.push(dir);
    const { app, vault } = createServer({
      port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
      vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
      adminToken: `cred_admin_${crypto.randomBytes(32).toString('hex')}`, agentToken: TOKEN,
      providers: [{ slug: 'github', clientId: 'cid', clientSecret: 'secret', defaultScopes: ['repo'] }],
      redirectBaseUri: BASE, ...extra,
    });
    await vault.init();
    await vault.store({ provider: 'github', userId: 'alice', accessToken: 'gho_cap', scopes: ['repo', 'read:user'] });
    return app;
  }
  const delegateGh = (app: App, agent: AgentIdentity, details: unknown, extra: Record<string, unknown> = {}) => delegateAs(app, agent, {
    service: 'github', user_id: 'alice', scopes: ['repo', 'read:user'], authorization_details: details, ...extra,
  }, { bearer: TOKEN, base: BASE });

  it('holds a repository-narrowed token to that repository and those operations', async () => {
    const agent = await newAgent();
    const app = await githubSetup();
    const minted = await delegateGh(app, agent, [{ type: 'cred_delegation', provider: 'github', operations: ['github.issues.create'], resources: ['repo:acme/app'] }]);
    expect(minted.status).toBe(200);
    const upstream = mockUpstream();
    const call = (method: string, url: string) => exerciseAs(app, agent, minted.body.access_token, { url, method, ...(method === 'POST' ? { body: { title: 't' } } : {}) }, { base: BASE });
    expect((await call('POST', 'https://api.github.com/repos/Acme/App/issues')).status).toBe(200);
    expect((await call('POST', 'https://api.github.com/repos/victim/secret/issues')).status).toBe(403);
    expect((await call('DELETE', 'https://api.github.com/repos/acme/app')).status).toBe(403);
    expect((await call('GET', 'https://api.github.com/user')).status).toBe(403);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('refuses at issuance a scope operation beside a narrowed one, which would widen it', async () => {
    const agent = await newAgent();
    const app = await githubSetup();
    const res = await delegateGh(app, agent, [
      { type: 'cred_delegation', provider: 'github', operations: ['github.issues.list'], resources: ['repo:a/b'] },
      { type: 'cred_delegation', provider: 'github', operations: ['read:user'] },
    ]);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_authorization_details');
  });

  it('refuses capabilities on a raw token instead of dropping them', async () => {
    const agent = await newAgent();
    const app = await githubSetup({ allowRawTokens: true });
    const res = await delegateGh(app, agent, [{ type: 'cred_delegation', provider: 'github', operations: ['github.issues.list'], resources: ['repo:a/b'] }], { token_format: 'raw' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_authorization_details');
    expect(JSON.stringify(res.body)).not.toContain('gho_cap');
  });
});

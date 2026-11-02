// Regressions from automated review.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { evaluateOperation } from '@credninja/guard';
import { withDerivedScopes, withStoredDerivedScopes } from '@credninja/protocol';
import { createServer } from '../server.js';
import { actorTokenFor, delegateAs, exerciseAs, newAgent, type AgentIdentity } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.unstubAllGlobals());

function config(): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-review-auto-'));
  tmpDirs.push(dir);
  return {
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: BEARER,
    providers: [{ slug: 'salesforce', clientId: 'id', clientSecret: 'secret', defaultScopes: ['api'] }],
    redirectBaseUri: 'http://localhost:3456',
  };
}

const op = (service: string, method: string, url: string, scopes: string[], body?: unknown) => evaluateOperation({ service, method, url, body }, scopes).outcome;

describe('github.read does not reach GraphQL', () => {
  const url = 'https://api.github.com/graphql';
  for (const [name, query] of [
    ['deployKeys', '{ repository(owner: "o", name: "r") { deployKeys(first: 5) { nodes { key } } } }'],
    ['collaborators', '{ repository(owner: "o", name: "r") { collaborators(first: 5) { nodes { login } } } }'],
    ['viewer.publicKeys', '{ viewer { publicKeys(first: 5) { nodes { key } } } }'],
    ['viewer.gists', '{ viewer { gists(first: 5, privacy: ALL) { nodes { name } } } }'],
  ] as const) {
    it(`${name} is refused under github.read, and reached by the provider scope`, () => {
      expect(op('github', 'POST', url, ['github.read'], { query })).toBe('insufficient');
      expect(op('github', 'POST', url, ['repo'], { query })).toBe('allowed');
      expect(op('github', 'POST', url, ['public_repo'], { query })).toBe('allowed');
    });
  }
});

describe('Notion legacy scope names', () => {
  const N = 'https://api.notion.com/v1';
  it('insert_content creates and appends, and nothing else', () => {
    expect(op('notion', 'POST', `${N}/pages`, ['insert_content'], {})).toBe('allowed');
    expect(op('notion', 'POST', `${N}/databases`, ['insert_content'], {})).toBe('allowed');
    expect(op('notion', 'PATCH', `${N}/blocks/abc/children`, ['insert_content'], {})).toBe('allowed');
    expect(op('notion', 'PATCH', `${N}/pages/abc`, ['insert_content'], {})).toBe('insufficient');
    expect(op('notion', 'PATCH', `${N}/blocks/abc`, ['insert_content'], {})).toBe('insufficient');
    expect(op('notion', 'DELETE', `${N}/blocks/abc`, ['insert_content'])).toBe('insufficient');
    expect(op('notion', 'GET', `${N}/pages/abc`, ['insert_content'])).toBe('insufficient');
  });
  it('update_content updates, and does not create, append or delete', () => {
    expect(op('notion', 'PATCH', `${N}/pages/abc`, ['update_content'], {})).toBe('allowed');
    expect(op('notion', 'PATCH', `${N}/blocks/abc`, ['update_content'], {})).toBe('allowed');
    expect(op('notion', 'POST', `${N}/pages`, ['update_content'], {})).toBe('insufficient');
    expect(op('notion', 'PATCH', `${N}/blocks/abc/children`, ['update_content'], {})).toBe('insufficient');
    expect(op('notion', 'DELETE', `${N}/blocks/abc`, ['update_content'])).toBe('insufficient');
    expect(op('notion', 'GET', `${N}/pages/abc`, ['update_content'])).toBe('insufficient');
  });
  it('content alone deletes', () => {
    expect(op('notion', 'DELETE', `${N}/blocks/abc`, ['content'])).toBe('allowed');
  });
  it('neither name derives content, or a read', () => {
    for (const name of ['update_content', 'insert_content']) {
      expect(withStoredDerivedScopes('notion', [name])).toEqual([name]);
      expect(withDerivedScopes('notion', [name])).toEqual([name]);
    }
    expect(withStoredDerivedScopes('notion', ['read_content'])).toEqual(['read_content', 'notion.read']);
    expect(withStoredDerivedScopes('notion', [])).toEqual(['notion.read', 'content']);
  });
});

describe('a Salesforce delegation is bound to the instance it was issued for', () => {
  const ACME = 'https://acme.my.salesforce.com';
  const OTHER = 'https://other.my.salesforce.com';
  const LIMITS = '/services/data/v60.0/limits';

  async function issued() {
    const server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'salesforce', userId: 'alice', accessToken: 'acme-token', refreshToken: 'r', expiresAt: new Date(Date.now() + 3600_000), scopes: ['api'], instanceUrl: ACME });
    const agent = await newAgent();
    await server.vault.createPermission!({ agentId: agent.did, connectionId: 'salesforce', allowedScopes: ['api'], requiresApproval: false, delegatable: true, maxDelegationDepth: 3, createdBy: 'test' });
    const minted = await delegateAs(server.app, agent, { service: 'salesforce', user_id: 'alice' }, { bearer: BEARER });
    expect(minted.status, JSON.stringify(minted.body)).toBe(200);
    return { ...server, agent, minted, token: minted.body.access_token as string };
  }
  function stubUpstream() {
    const upstream = vi.fn(async (_u: unknown, _i?: unknown) => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', upstream);
    return upstream;
  }
  const use = (app: Parameters<typeof exerciseAs>[0], agent: AgentIdentity, token: string, origin: string) => exerciseAs(app, agent, token, { url: `${origin}${LIMITS}`, method: 'GET' });

  it('records the origin in the delegation at issuance', async () => {
    const { vault, minted } = await issued();
    expect((await vault.getDelegation(minted.body.delegation_id))?.grant?.instanceOrigin).toBe(ACME);
  });

  it('a child delegation carries it too', async () => {
    const { app, vault, agent, minted } = await issued();
    const child = await newAgent();
    await vault.createPermission!({ agentId: child.did, connectionId: 'salesforce', allowedScopes: ['api'], requiresApproval: false, delegatable: true, maxDelegationDepth: 3, createdBy: 'test' });
    const sub = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: minted.body.receipt, agent_did: child.did, service: 'salesforce', user_id: 'alice', actor_token: actorTokenFor(agent, '/api/v1/subdelegate'),
    });
    expect(sub.status, JSON.stringify(sub.body)).toBe(200);
    expect((await vault.getDelegation(sub.body.delegation_id))?.grant?.instanceOrigin).toBe(ACME);
  });

  it('after the stored instance changes, an old handle reaches neither host', async () => {
    const { app, vault, agent, token } = await issued();
    const upstream = stubUpstream();
    expect((await use(app, agent, token, ACME)).status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(1);
    await vault.store({ provider: 'salesforce', userId: 'alice', accessToken: 'other-token', expiresAt: new Date(Date.now() + 3600_000), scopes: ['api'], instanceUrl: OTHER });
    for (const origin of [ACME, OTHER]) {
      const res = await use(app, agent, token, origin);
      expect(res.status, origin).toBe(400);
      expect(res.body.error).toBe('salesforce_instance_mismatch');
    }
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('reconnecting to another org through the OAuth flow revokes existing delegations', async () => {
    const { app, vault, agent, token, minted } = await issued();
    const started = await request(app).post('/connect/salesforce/start').set('Authorization', `Bearer ${ADMIN}`).send({ user_id: 'alice', scopes: ['api'] });
    const redirect = await request(app).get(started.body.url).set('Authorization', `Bearer ${ADMIN}`);
    const state = new URL(redirect.headers.location!).searchParams.get('state')!;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ access_token: 'other-token', token_type: 'Bearer', instance_url: OTHER, scope: 'api' }), { status: 200, headers: { 'content-type': 'application/json' } })));
    expect((await request(app).get('/connect/salesforce/callback').query({ code: 'c', state })).status).toBe(200);
    expect((await vault.getDelegation(minted.body.delegation_id))?.status).toBe('revoked');
    const upstream = stubUpstream();
    const res = await use(app, agent, token, OTHER);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('delegation_revoked');
    expect(upstream).not.toHaveBeenCalled();
    // The agent was not at fault: it can be delegated to again, for the new org.
    const again = await delegateAs(app, agent, { service: 'salesforce', user_id: 'alice' }, { bearer: BEARER });
    expect(again.status).toBe(200);
    expect((await vault.getDelegation(again.body.delegation_id))?.grant?.instanceOrigin).toBe(OTHER);
  });

  it('reconnecting to the same org revokes nothing', async () => {
    const { app, vault, minted } = await issued();
    const started = await request(app).post('/connect/salesforce/start').set('Authorization', `Bearer ${ADMIN}`).send({ user_id: 'alice', scopes: ['api'] });
    const redirect = await request(app).get(started.body.url).set('Authorization', `Bearer ${ADMIN}`);
    const state = new URL(redirect.headers.location!).searchParams.get('state')!;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ access_token: 'new', token_type: 'Bearer', instance_url: ACME, scope: 'api' }), { status: 200, headers: { 'content-type': 'application/json' } })));
    await request(app).get('/connect/salesforce/callback').query({ code: 'c', state });
    expect((await vault.getDelegation(minted.body.delegation_id))?.status).toBe('active');
  });
});

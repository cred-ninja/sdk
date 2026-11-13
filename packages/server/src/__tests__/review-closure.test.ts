// Regressions from an independent review of the release candidate, through the public routes.
import { describe, it, expect, afterAll, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { actorTokenFor, delegateAs, exerciseAs, newAgent, type AgentIdentity, type App } from './token-helpers.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const dirs: string[] = [];
afterAll(() => { for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true }); });
afterEach(() => vi.restoreAllMocks());

async function setup(service: string, scopes: string[], overrides: Partial<ServerConfig> = {}, userId = 'alice') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-closure-'));
  dirs.push(dir);
  const server = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: BEARER, redirectBaseUri: 'http://localhost:3456',
    providers: [{ slug: service, clientId: 'id', clientSecret: 'secret', defaultScopes: [] }], ...overrides,
  });
  await server.vault.init();
  await server.vault.store({ provider: service, userId, accessToken: 'tok', expiresAt: new Date(Date.now() + 3600_000), scopes });
  return server;
}
const grant = (app: App, agent: AgentIdentity, service: string, allowedScopes: string[], extra: Record<string, unknown> = {}) =>
  request(app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`).send({ agentId: agent.did, connectionId: service, allowedScopes, ...extra });
const delegate = (app: App, agent: AgentIdentity, service: string, scopes?: string[]) =>
  delegateAs(app, agent, { service, user_id: 'alice', ...(scopes ? { scopes } : {}) }, { bearer: BEARER });
const stubUpstream = () => {
  const calls: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    calls.push(String(url));
    return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
  return calls;
};

describe('public_repo over a token that also reaches private repositories', () => {
  it('is not issued when the connection holds both', async () => {
    const { app } = await setup('github', ['repo', 'public_repo']);
    const agent = await newAgent();
    await grant(app, agent, 'github', ['public_repo']);
    const res = await delegate(app, agent, 'github', ['public_repo']);
    expect(res.body.access_token).toBeUndefined();
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it('stops at /use when a reconnect widens the token after issuance', async () => {
    const { app, vault } = await setup('github', ['public_repo']);
    const agent = await newAgent();
    await grant(app, agent, 'github', ['public_repo']);
    const issued = await delegate(app, agent, 'github', ['public_repo']);
    expect(issued.status).toBe(200);
    await vault.store({ provider: 'github', userId: 'alice', accessToken: 'wider', expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
    const calls = stubUpstream();
    await exerciseAs(app, agent, issued.body.access_token, { url: 'https://api.github.com/repos/o/private', method: 'GET' });
    expect(calls).toEqual([]);
  });
});

describe('the deprecated raw-token opt-in', () => {
  it('refuses a raw token wider than the Permission', async () => {
    const { app } = await setup('google', ['gmail.readonly', 'gmail.send'], { allowRawTokens: true } as Partial<ServerConfig>);
    const agent = await newAgent();
    await grant(app, agent, 'google', ['gmail.readonly']);
    const res = await request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .send({ service: 'google', user_id: 'alice', agent_did: agent.did, token_format: 'raw', allow_raw_tokens: true, appClientId: 'local' });
    expect(res.body.access_token).toBeUndefined();
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

describe('rate limit input', () => {
  it.each([[{ maxRequests: 1, windowMs: 0 }], [{ maxRequests: 1, windowMs: -1000 }], [{ maxRequests: 0, windowMs: 1000 }], [{ maxRequests: 1, windowMs: 1e20 }], [{ maxRequests: 1, windowMs: 'x' }]])('refuses %j', async (rateLimit) => {
    const { app } = await setup('google', ['gmail.readonly']);
    const res = await grant(app, await newAgent(), 'google', ['gmail.readonly'], { rateLimit });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_rate_limit');
  });
});

describe('a suspended agent', () => {
  it('cannot exercise a live token', async () => {
    const { app, vault } = await setup('google', ['gmail.readonly']);
    const agent = await newAgent();
    await grant(app, agent, 'google', ['gmail.readonly']);
    const issued = await delegate(app, agent, 'google');
    const now = new Date().toISOString();
    await vault.registerAgent!({ id: 'agt_s', did: agent.did, name: 's', fingerprint: 'fp_s', scopeCeiling: [], status: 'suspended', createdBy: 'admin', createdAt: now, updatedAt: now } as never);
    const calls = stubUpstream();
    const res = await exerciseAs(app, agent, issued.body.access_token, { url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages', method: 'GET' });
    expect(res.status).toBe(403);
    expect(calls).toEqual([]);
  });
});

describe('sub-delegation', () => {
  it('needs the parent to be allowed to hand off', async () => {
    const { app } = await setup('google', ['gmail.readonly']);
    const parent = await newAgent();
    const child = await newAgent();
    await grant(app, parent, 'google', ['gmail.readonly']);
    await grant(app, child, 'google', ['gmail.readonly'], { delegatable: true, maxDelegationDepth: 2 });
    const root = await delegate(app, parent, 'google');
    const res = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: root.body.receipt, agent_did: child.did, service: 'google', user_id: 'alice', actor_token: actorTokenFor(parent, '/api/v1/subdelegate'),
    });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('delegation_not_allowed');
  });
});

describe('the audit route', () => {
  it('does not show one user the events of a user whose id starts the same', async () => {
    const { app } = await setup('google', ['gmail.readonly'], {}, 'alice/secret');
    const agent = await newAgent();
    await grant(app, agent, 'google', ['gmail.readonly']);
    await delegateAs(app, agent, { service: 'google', user_id: 'alice/secret' }, { bearer: BEARER });
    const res = await request(app).get('/api/v1/audit').query({ user_id: 'alice' }).set('Authorization', `Bearer ${BEARER}`);
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).not.toContain('alice/secret');
  });
});

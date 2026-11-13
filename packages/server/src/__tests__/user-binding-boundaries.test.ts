// An agentRequestVerifier that returns a principal with userId binds the caller
// to that user. This walks every route that takes a user, through the public HTTP
// surface, with one agent key shared by two bound callers, so the only thing
// keeping them apart is the binding.
import { describe, it, expect, afterAll, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createDpopProof } from '@credninja/sdk';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { actorTokenFor, exerciseAs, newAgent, type AgentIdentity, type App } from './token-helpers.js';

const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const tmpDirs: string[] = [];

afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.restoreAllMocks());

/** The caller's user comes from a header the test's verifier trusts, as a real verifier would from a session. */
async function setup(overrides: Partial<ServerConfig> = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-user-binding-'));
  tmpDirs.push(dir);
  const server = createServer({
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'file',
    tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN,
    agentRequestVerifier: (req) => {
      const user = req.headers['x-test-user'];
      return typeof user === 'string'
        ? { ok: true as const, principal: { type: 'custom' as const, principalId: `caller-${user}`, userId: user } }
        : { ok: false as const, status: 401, error: 'no user' };
    },
    providers: [{ slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: ['calendar.readonly'] }],
    redirectBaseUri: BASE,
    ...overrides,
  });
  await server.vault.init();
  for (const userId of ['alice', 'bob']) {
    await server.vault.store({
      provider: 'google',
      userId,
      accessToken: `ya29.${userId}-secret`,
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: ['calendar.readonly'],
    });
  }
  return server;
}

const grant = (app: App, agent: AgentIdentity, extra: Record<string, unknown> = {}) =>
  request(app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`).send({
    agentId: agent.did, connectionId: 'google', allowedScopes: ['calendar.readonly'], ...extra,
  });

const as = (user: string) => ({ 'x-test-user': user });

function delegate(app: App, agent: AgentIdentity, user: string, body: Record<string, unknown> = {}) {
  return request(app).post('/api/v1/delegate').set(as(user))
    .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/api/v1/delegate`))
    .send({ token_format: 'handle', agent_did: agent.did, service: 'google', ...body });
}

describe('a caller bound to one user', () => {
  it('delegates only for that user, however the request names another', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    await grant(app, agent);
    expect((await delegate(app, agent, 'alice', { user_id: 'bob' })).body.error).toBe('user_id_mismatch');
    const own = await delegate(app, agent, 'alice');
    expect(own.status).toBe(200);
    expect(own.body.user_id ?? 'alice').toBe('alice');
    // user_id in the query string must not override the body or the binding.
    const viaQuery = await request(app).post('/api/v1/delegate?user_id=bob').set(as('alice'))
      .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/api/v1/delegate?user_id=bob`))
      .send({ token_format: 'handle', agent_did: agent.did, service: 'google' });
    expect(JSON.stringify(viaQuery.body)).not.toContain('bob');
  });

  it("exercises its own token on its own user's connection, never the other's", async () => {
    const { app } = await setup();
    const agent = await newAgent();
    await grant(app, agent);
    const seen: string[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      seen.push(String(new Headers(init?.headers).get('authorization')));
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    });
    const own = await delegate(app, agent, 'alice');
    const used = await exerciseAs(app, agent, own.body.access_token, {
      url: 'https://www.googleapis.com/calendar/v3/users/me/calendarList', method: 'GET',
    });
    expect(used.status, JSON.stringify(used.body)).toBe(200);
    expect(seen).toEqual(['Bearer ya29.alice-secret']);
  });

  it('cannot read or revoke the other user\'s connections', async () => {
    const { app, vault } = await setup();
    expect((await request(app).get('/api/v1/connections').query({ user_id: 'bob' }).set(as('alice'))).status).toBe(403);
    const own = await request(app).get('/api/v1/connections').set(as('alice'));
    expect(own.status).toBe(200);
    expect(JSON.stringify(own.body)).not.toContain('bob');
    expect((await request(app).delete('/api/v1/connections/google').query({ user_id: 'bob' }).set(as('alice'))).status).toBe(403);
    expect((await request(app).delete('/api/token/google').query({ user_id: 'bob' }).set(as('alice'))).status).toBe(403);
    expect(await vault.getStored({ provider: 'google', userId: 'bob' })).not.toBeNull();
  });

  it('cannot read the other user\'s token through the compatibility route', async () => {
    const { app } = await setup();
    const res = await request(app).get('/api/token/google').query({ user_id: 'bob' }).set(as('alice'));
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).not.toContain('bob-secret');
  });

  it('cannot read the other user\'s audit events, and its own omit them', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    await grant(app, agent);
    await delegate(app, agent, 'bob');
    expect((await request(app).get('/api/v1/audit').query({ user_id: 'bob' }).set(as('alice'))).status).toBe(403);
    expect((await request(app).get('/api/v1/audit/stream').query({ user_id: 'bob' }).set(as('alice'))).status).toBe(403);
    const own = await request(app).get('/api/v1/audit').set(as('alice'));
    expect(own.status).toBe(200);
    expect(JSON.stringify(own.body)).not.toContain('google/bob');
  });

  it('cannot revoke the other user\'s delegation', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    await grant(app, agent);
    const bobs = await delegate(app, agent, 'bob');
    expect(bobs.status).toBe(200);
    const res = await request(app).delete(`/api/v1/delegations/${bobs.body.delegation_id}`).set(as('alice'));
    expect(res.status).toBe(404);
    expect((await request(app).delete(`/delegation/${bobs.body.delegation_id}`).query({ user_id: 'bob' }).set(as('alice'))).status).toBe(403);
  });

  it('revoking its own delegation does not hold the shared agent out for the other user', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    await grant(app, agent);
    const own = await delegate(app, agent, 'alice');
    expect((await request(app).delete(`/api/v1/delegations/${own.body.delegation_id}`).set(as('alice'))).status).toBe(200);
    expect((await delegate(app, agent, 'alice')).body.error).toBe('agent_access_revoked');
    expect((await delegate(app, agent, 'bob')).status).toBe(200);
  });

  it('revoking its own connection leaves the other user\'s delegation working', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    await grant(app, agent);
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    const bobs = await delegate(app, agent, 'bob');
    expect((await request(app).delete('/api/v1/connections/google').set(as('alice'))).status).toBe(204);
    const used = await exerciseAs(app, agent, bobs.body.access_token, {
      url: 'https://www.googleapis.com/calendar/v3/users/me/calendarList', method: 'GET',
    });
    expect(used.status, JSON.stringify(used.body)).toBe(200);
  });

  it('cannot sub-delegate from the other user\'s receipt', async () => {
    const { app } = await setup();
    const parent = await newAgent();
    const child = await newAgent();
    await grant(app, parent, { delegatable: true, maxDelegationDepth: 2 });
    await grant(app, child);
    const root = await delegate(app, parent, 'bob');
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    for (const naming of [{}, { user_id: 'bob' }]) {
      const res = await request(app).post('/api/v1/subdelegate').set(as('alice')).send({
        parent_receipt: root.body.receipt,
        agent_did: child.did,
        service: 'google',
        actor_token: actorTokenFor(parent, '/api/v1/subdelegate'),
        ...naming,
      });
      expect(res.status, JSON.stringify(res.body)).toBeGreaterThanOrEqual(400);
      expect(res.body.delegation_token).toBeUndefined();
    }
  });

  it('cannot redeem a delegation grant minted for the other user', async () => {
    const { app } = await setup();
    const parent = await newAgent();
    const child = await newAgent();
    await grant(app, parent, { delegatable: true, maxDelegationDepth: 2 });
    await grant(app, child, { delegatable: true, maxDelegationDepth: 2 });
    const root = await delegate(app, parent, 'bob');
    const minted = await request(app).post('/api/v1/subdelegate').set(as('bob')).send({
      parent_receipt: root.body.receipt,
      agent_did: child.did,
      service: 'google',
      exchange: 'grant',
      actor_token: actorTokenFor(parent, '/api/v1/subdelegate'),
    });
    expect(minted.status, JSON.stringify(minted.body)).toBe(200);
    const redeemed = await request(app).post('/api/v1/token').set(as('alice')).send({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: minted.body.delegation_grant,
      subject_token_type: 'urn:credninja:params:oauth:token-type:delegation-grant',
      actor_token: actorTokenFor(child, '/api/v1/token'),
      actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(403);
    expect(redeemed.body.error).toBe('user_id_mismatch');
  });

  it('cannot redeem an approval the other user was asked for (CIBA poll)', async () => {
    const hooks: Array<Record<string, unknown>> = [];
    const { app } = await setup({ approvalWebhookUrl: 'https://hooks.example/approvals' });
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      hooks.push(JSON.parse(String(init?.body)));
      return new Response(null, { status: 204 });
    });
    const agent = await newAgent();
    await grant(app, agent, { requiresApproval: true, approver: 'admin' });
    const asked = await request(app).post('/bc-authorize').set(as('bob'))
      .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/bc-authorize`))
      .send({ login_hint: 'bob', service: 'google', agent_did: agent.did, scopes: ['calendar.readonly'], binding_message: 'K7-42' });
    expect(asked.status, JSON.stringify(asked.body)).toBe(200);
    const decided = await request(app).post(`/admin/approvals/${asked.body.auth_req_id}`)
      .set('Authorization', `Bearer ${ADMIN}`).send({ decision: 'approve' });
    expect(decided.status, JSON.stringify(decided.body)).toBe(200);
    const stolen = await request(app).post('/api/v1/token').set(as('alice'))
      .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/api/v1/token`))
      .send({ grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: asked.body.auth_req_id });
    expect(stolen.status, JSON.stringify(stolen.body)).toBe(403);
    expect(stolen.body.error).toBe('user_id_mismatch');
    expect(stolen.body.access_token).toBeUndefined();
    const own = await request(app).post('/api/v1/token').set(as('bob'))
      .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/api/v1/token`))
      .send({ grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: asked.body.auth_req_id });
    expect(own.status, JSON.stringify(own.body)).toBe(200);
  });
});

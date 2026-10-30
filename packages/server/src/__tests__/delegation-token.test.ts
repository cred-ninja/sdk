/**
 * Delegation Tokens (draft-sweeney-wimse-credential-delegation-02 Section
 * 5) replace brokered handles: a DPoP-bound JWT the server issues, persists
 * the state of, and accepts at exercise as `Authorization: DPoP <token>`.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createActorToken, createDpopProof, generateAgentIdentity, type AgentIdentity } from '@credninja/sdk';
import { didKeyConfirmation, receiptContentId, mintDelegationToken, createKeySigner } from '@credninja/attenuation';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

const TEST_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const USERINFO = 'https://www.googleapis.com/oauth2/v3/userinfo';
const PASSPHRASE = 'test-passphrase-not-for-production';

const tmpDirs: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of tmpDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function makeConfig(vaultPath: string): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: PASSPHRASE,
    vaultStorage: 'sqlite',
    vaultPath,
    tofuStorage: 'file',
    tofuPath: path.join(path.dirname(vaultPath), 'tofu.json'),
    adminToken: `cred_admin_${crypto.randomBytes(32).toString('hex')}`,
    agentToken: TEST_TOKEN,
    providers: [{ slug: 'google', clientId: 'cid', clientSecret: 'secret', defaultScopes: ['openid', 'email'] }],
    redirectBaseUri: BASE,
  };
}

async function setup(agents: AgentIdentity[] = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-dt-'));
  tmpDirs.push(dir);
  const vaultPath = path.join(dir, 'vault.sqlite');
  const { app, vault } = createServer(makeConfig(vaultPath));
  await vault.init();
  await vault.store({
    provider: 'google', userId: 'alice', accessToken: 'ya29.dt',
    expiresAt: new Date(Date.now() + 3600 * 1000), scopes: ['openid', 'email'],
  });
  for (const agent of agents) {
    await vault.createPermission!({
      agentId: agent.did, connectionId: 'google', allowedScopes: ['openid', 'email'],
      delegatable: true, maxDelegationDepth: 3, requiresApproval: false, createdBy: 'admin',
    });
  }
  return { app, vault, vaultPath };
}

type App = Parameters<typeof request>[0];

function delegateAs(app: App, agent: AgentIdentity, body: Record<string, unknown> = {}) {
  return request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${TEST_TOKEN}`)
    .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/api/v1/delegate`))
    .send({ service: 'google', user_id: 'alice', scopes: ['openid', 'email'], token_format: 'handle', agent_did: agent.did, ...body });
}

function exercise(app: App, agent: AgentIdentity, token: string) {
  const body = { url: USERINFO, method: 'GET' };
  return request(app).post('/api/v1/use').set('Authorization', `DPoP ${token}`)
    .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/api/v1/use`, token, body))
    .send(body);
}

function claimsOf(jws: string): Record<string, any> {
  return JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8'));
}

function mockUpstream() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ sub: 'alice' }), {
    status: 200, headers: { 'content-type': 'application/json' },
  }));
}

describe('Delegation Token issuance', () => {
  it('issues a DPoP-bound token carrying every required claim', async () => {
    const agent = await generateAgentIdentity();
    const { app, vault } = await setup();
    const res = await delegateAs(app, agent);
    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe('DPoP');
    const header = JSON.parse(Buffer.from(res.body.access_token.split('.')[0], 'base64url').toString('utf8'));
    expect(header.typ).toBe('dt+jwt');
    const claims = claimsOf(res.body.access_token);
    expect(claims).toMatchObject({
      iss: BASE,
      sub: 'alice',
      client_id: agent.did,
      act: { sub: agent.did },
      cnf: { jkt: didKeyConfirmation(agent.did)!.jkt },
      jti: res.body.delegation_id,
      authorization_details: [{ type: 'cred_delegation', provider: 'google', operations: ['openid', 'email'] }],
    });
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(900);
    expect(claims.prf).toEqual([receiptContentId(res.body.receipt)]);
    expect(claims.credential_handle).toMatch(/^ch_[0-9a-f]{32}$/);
    expect(JSON.stringify(claims)).not.toContain('ya29');
    const consent = await vault.getConsent(claims.consent_id);
    expect(consent).toMatchObject({ subject: 'alice', agentDid: agent.did, service: 'google', source: 'connection' });
  });
});

describe('Delegation Token exercise', () => {
  it('survives a server restart: a new process on the same vault accepts the token', async () => {
    const agent = await generateAgentIdentity();
    const { app, vaultPath } = await setup();
    const token = (await delegateAs(app, agent)).body.access_token as string;
    const restarted = createServer(makeConfig(vaultPath));
    await restarted.vault.init();
    const upstream = mockUpstream();
    const res = await exercise(restarted.app, agent, token);
    expect(res.status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(1);
    const [, init] = upstream.mock.calls[0]!;
    expect(new Headers(init!.headers).get('authorization')).toBe('Bearer ya29.dt');
  });

  it('refuses a token the server did not sign, before any upstream call', async () => {
    const agent = await generateAgentIdentity();
    const { app } = await setup();
    const real = claimsOf((await delegateAs(app, agent)).body.access_token);
    const forged = mintDelegationToken(real as any, createKeySigner(crypto.generateKeyPairSync('ed25519').privateKey, 'forged'));
    const upstream = mockUpstream();
    const res = await exercise(app, agent, forged);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
    expect(res.headers['www-authenticate']).toMatch(/^DPoP error="invalid_token"/);
    expect(upstream).not.toHaveBeenCalled();
  });

  it('refuses the receipt presented as a token', async () => {
    const agent = await generateAgentIdentity();
    const { app } = await setup();
    const receipt = (await delegateAs(app, agent)).body.receipt as string;
    const res = await exercise(app, agent, receipt);
    expect(res.status).toBe(401);
    expect(res.body.message).toMatch(/wrong_type/);
  });

  it('refuses the delegation id or the Bearer credential in place of the token', async () => {
    const agent = await generateAgentIdentity();
    const { app } = await setup();
    const minted = await delegateAs(app, agent);
    const res = await request(app).post('/api/v1/use').set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({ delegation_id: minted.body.delegation_id, url: USERINFO, method: 'GET' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_token');
    // RFC 6750 Section 3.1: no token was presented, so the challenge carries no error code.
    expect(res.headers['www-authenticate']).toMatch(/^DPoP algs=/);
  });

  it('keeps a revocation across a restart', async () => {
    const agent = await generateAgentIdentity();
    const { app, vaultPath } = await setup();
    const minted = await delegateAs(app, agent);
    const revoked = await request(app).delete(`/api/v1/delegations/${minted.body.delegation_id}`)
      .query({ user_id: 'alice' }).set('Authorization', `Bearer ${TEST_TOKEN}`);
    expect(revoked.status).toBe(200);
    const restarted = createServer(makeConfig(vaultPath));
    await restarted.vault.init();
    const upstream = mockUpstream();
    const res = await exercise(restarted.app, agent, minted.body.access_token);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('delegation_revoked');
    expect(upstream).not.toHaveBeenCalled();
  });

  it('never revives a token when its connection is revoked and stored again', async () => {
    const agent = await generateAgentIdentity();
    const { app, vault, vaultPath } = await setup();
    const token = (await delegateAs(app, agent)).body.access_token as string;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{}', { status: 200 }));
    const disconnected = await request(app).delete('/api/v1/connections/google')
      .query({ user_id: 'alice' }).set('Authorization', `Bearer ${TEST_TOKEN}`);
    expect(disconnected.status).toBeLessThan(300);
    vi.restoreAllMocks();
    await vault.store({
      provider: 'google', userId: 'alice', accessToken: 'ya29.reconnected',
      expiresAt: new Date(Date.now() + 3600 * 1000), scopes: ['openid', 'email'],
    });
    const upstream = mockUpstream();
    expect((await exercise(app, agent, token)).status).toBe(401);
    const restarted = createServer(makeConfig(vaultPath));
    await restarted.vault.init();
    expect((await exercise(restarted.app, agent, token)).status).toBe(401);
    expect(upstream).not.toHaveBeenCalled();
  });

  it('refuses after a restart to restore a token whose cumulative total this process does not hold', async () => {
    const agent = await generateAgentIdentity();
    const { app, vaultPath } = await setup();
    const minted = await delegateAs(app, agent, { constraints: [{ key: 'max_calls', max_lifetime: 2 }] });
    expect(minted.status).toBe(200);
    mockUpstream();
    expect((await exercise(app, agent, minted.body.access_token)).status).toBe(200);
    const restarted = createServer(makeConfig(vaultPath));
    await restarted.vault.init();
    const res = await exercise(restarted.app, agent, minted.body.access_token);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('cumulative_constraint_unenforceable');
  });

  it('refuses an expired token', async () => {
    const agent = await generateAgentIdentity();
    const { app } = await setup();
    const token = (await delegateAs(app, agent)).body.access_token as string;
    const exp = claimsOf(token).exp as number;
    vi.useFakeTimers({ now: (exp + 1) * 1000, toFake: ['Date'] });
    try {
      const res = await exercise(app, agent, token);
      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(/expired/);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('Delegation Token sub-delegation', () => {
  it('extends prf, keeps the consent, and nests the delegator in act', async () => {
    const [root, child] = [await generateAgentIdentity(), await generateAgentIdentity()];
    const { app } = await setup([child]);
    const parent = await delegateAs(app, root);
    const sub = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
      parent_receipt: parent.body.receipt,
      actor_token: createActorToken(root, `${BASE}/api/v1/subdelegate`),
      agent_did: child.did, service: 'google', user_id: 'alice', scopes: ['openid'],
    });
    expect(sub.status).toBe(200);
    const parentClaims = claimsOf(parent.body.access_token);
    const childClaims = claimsOf(sub.body.access_token);
    expect(childClaims.prf).toEqual([...parentClaims.prf, receiptContentId(sub.body.receipt)]);
    expect(childClaims.consent_id).toBe(parentClaims.consent_id);
    expect(childClaims.act).toEqual({ sub: child.did, act: { sub: root.did } });
    expect(childClaims.authorization_details[0].operations).toEqual(['openid']);
    mockUpstream();
    expect((await exercise(app, child, sub.body.access_token)).status).toBe(200);
  });

  it('never lets a redeemed child outlive its parent, even after the provider token is refreshed', async () => {
    const [root, child] = [await generateAgentIdentity(), await generateAgentIdentity()];
    const { app, vault } = await setup([child]);
    // A provider token expiring in 2 minutes caps the parent at 2 minutes.
    await vault.store({
      provider: 'google', userId: 'alice', accessToken: 'ya29.short',
      expiresAt: new Date(Date.now() + 120 * 1000), scopes: ['openid', 'email'],
    });
    const parent = await delegateAs(app, root);
    expect(parent.body.expires_in).toBeLessThanOrEqual(120);
    const authorized = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
      parent_receipt: parent.body.receipt,
      actor_token: createActorToken(root, `${BASE}/api/v1/subdelegate`),
      agent_did: child.did, service: 'google', user_id: 'alice', scopes: ['openid'], exchange: 'grant',
    });
    expect(authorized.status).toBe(200);
    // The provider token is refreshed before the child redeems the grant.
    await vault.store({
      provider: 'google', userId: 'alice', accessToken: 'ya29.refreshed',
      expiresAt: new Date(Date.now() + 3600 * 1000), scopes: ['openid', 'email'],
    });
    const exchanged = await request(app).post('/api/v1/token').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: authorized.body.delegation_grant,
      subject_token_type: authorized.body.subject_token_type,
      actor_token: createActorToken(child, `${BASE}/api/v1/token`),
      actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    });
    expect(exchanged.status).toBe(200);
    expect(claimsOf(exchanged.body.access_token).exp).toBeLessThanOrEqual(claimsOf(parent.body.access_token).exp);
    expect(exchanged.body.expires_in).toBeLessThanOrEqual(120);
  });

  it('issues the token at the exchange to the agent that redeems the grant', async () => {
    const [root, child] = [await generateAgentIdentity(), await generateAgentIdentity()];
    const { app } = await setup([child]);
    const parent = await delegateAs(app, root);
    const authorized = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
      parent_receipt: parent.body.receipt,
      actor_token: createActorToken(root, `${BASE}/api/v1/subdelegate`),
      agent_did: child.did, service: 'google', user_id: 'alice', scopes: ['openid'], exchange: 'grant',
    });
    expect(authorized.status).toBe(200);
    const exchanged = await request(app).post('/api/v1/token').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: authorized.body.delegation_grant,
      subject_token_type: authorized.body.subject_token_type,
      actor_token: createActorToken(child, `${BASE}/api/v1/token`),
      actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    });
    expect(exchanged.status).toBe(200);
    expect(exchanged.body.token_type).toBe('DPoP');
    // Never past the parent: the child was bounded at authorization.
    expect(claimsOf(exchanged.body.access_token).exp).toBeLessThanOrEqual(claimsOf(parent.body.access_token).exp);
    expect(exchanged.body.issued_token_type).toBe('urn:ietf:params:oauth:token-type:access_token');
    expect(claimsOf(exchanged.body.access_token)).toMatchObject({ jti: authorized.body.delegation_id, client_id: child.did });
    mockUpstream();
    expect((await exercise(app, child, exchanged.body.access_token)).status).toBe(200);
  });
});

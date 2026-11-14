/**
 * /bc-authorize and the Txn-Token requirement: a did:key whose trust domain
 * requires Txn-Tokens, authenticated by the agent token and DPoP (no WIMSE
 * workload, so no transaction), asks for a CIBA-approved delegation. It must
 * not obtain one outside a transaction, the same as on /api/v1/delegate.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createDpopProof } from '@credninja/sdk';
import { createServer } from '../server.js';
import { createReplayCache } from '../identity/types.js';
import { createWimseIdentitySource } from '../identity/wimse.js';
import { newAgent, type App, type AgentIdentity } from './token-helpers.js';
import { trustDomain, txnIssuer } from './wimse-fixture.js';

const TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const dirs: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

async function setup(agent: AgentIdentity) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-bc-txn-'));
  dirs.push(dir);
  const b = trustDomain('domain-b.example');
  const w = b.workload();
  const tts = txnIssuer('domain-b.example');
  const server = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: TOKEN, redirectBaseUri: BASE,
    providers: [{ slug: 'google', clientId: 'cid', clientSecret: 'secret', defaultScopes: ['openid', 'email'] }],
    externalIdentity: {
      sources: [createWimseIdentitySource({ trustDomains: { [b.name]: b.anchors }, replay: createReplayCache() })],
      mappings: [{ kind: 'wimse', subject: w.subject, agentDid: agent.did }],
      // Required (the default): this agent obtains credentials only inside a verified transaction.
      txnTokens: { [b.name]: tts.trust() },
    },
  });
  await server.vault.init();
  await server.vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.ciba', expiresAt: new Date(Date.now() + 3600_000), scopes: ['openid', 'email'] });
  await server.vault.createPermission!({
    agentId: agent.did, connectionId: 'google', allowedScopes: ['openid', 'email'],
    delegatable: false, maxDelegationDepth: 0, requiresApproval: true, approver: 'admin', createdBy: 'admin',
  });
  return server;
}

function bcAuthorize(app: App, agent: AgentIdentity) {
  return request(app).post('/bc-authorize').set('Authorization', `Bearer ${TOKEN}`)
    .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/bc-authorize`))
    .send({ login_hint: 'alice', service: 'google', agent_did: agent.did, scopes: ['openid'], binding_message: 'K7-42' });
}

function poll(app: App, agent: AgentIdentity, authReqId: string) {
  return request(app).post('/api/v1/token').set('Authorization', `Bearer ${TOKEN}`)
    .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/api/v1/token`))
    .send({ grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: authReqId });
}

describe('/bc-authorize with a Txn-required did:key', () => {
  it('issues no delegation outside a transaction to a did:key whose trust domain requires Txn-Tokens', async () => {
    const agent = await newAgent();
    const { app } = await setup(agent);
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    const asked = await bcAuthorize(app, agent);
    let issued = false;
    if (asked.status === 200) {
      await request(app).post(`/admin/approvals/${asked.body.auth_req_id}`).set('Authorization', `Bearer ${ADMIN}`).send({ decision: 'approve' });
      const polled = await poll(app, agent, asked.body.auth_req_id);
      issued = polled.status === 200 && typeof polled.body.access_token === 'string';
    }
    expect(issued).toBe(false);
    expect(asked.status).toBe(403);
    expect(asked.body.error).toBe('txn_token_required');
  });
});

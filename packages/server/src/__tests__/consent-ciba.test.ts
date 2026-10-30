/**
 * Consent and CIBA (draft-sweeney-wimse-credential-delegation-02 Section 8):
 * approval-required permissions, the agent's CIBA poll flow, the built-in
 * approval page and the admin approver, consent reuse and re-consent, a
 * security event, and consent retention.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createDpopProof } from '@credninja/sdk';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { newAgent, delegateAs, exerciseAs, type App, type AgentIdentity } from './token-helpers.js';

const TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const WEBHOOK = 'https://hooks.example/approvals';
const USERINFO = 'https://www.googleapis.com/oauth2/v3/userinfo';
const dirs: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

async function setup(agent: AgentIdentity, approver: 'subject' | 'admin' | 'both' | null, extra: Partial<ServerConfig> = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-ciba-'));
  dirs.push(dir);
  const server = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: TOKEN,
    providers: [{ slug: 'google', clientId: 'cid', clientSecret: 'secret', defaultScopes: ['openid', 'email'] }],
    redirectBaseUri: BASE, approvalWebhookUrl: WEBHOOK, ...extra,
  });
  await server.vault.init();
  await server.vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.ciba', expiresAt: new Date(Date.now() + 3600_000), scopes: ['openid', 'email'] });
  if (approver) {
    await server.vault.createPermission!({
      agentId: agent.did, connectionId: 'google', allowedScopes: ['openid', 'email'],
      delegatable: false, maxDelegationDepth: 0, requiresApproval: true, approver, createdBy: 'admin',
    });
  }
  return server;
}

/** Capture webhook posts; answer upstream API calls with a small JSON body. */
function mockNetwork() {
  const hooks: Array<Record<string, any>> = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    if (String(url) === WEBHOOK) {
      hooks.push(JSON.parse(String(init?.body)));
      return new Response(null, { status: 204 });
    }
    return new Response('{"sub":"alice"}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
  return hooks;
}

const delegate = (app: App, agent: AgentIdentity, scopes = ['openid']) =>
  delegateAs(app, agent, { service: 'google', user_id: 'alice', scopes }, { bearer: TOKEN, base: BASE });

function bcAuthorize(app: App, agent: AgentIdentity, body: Record<string, unknown> = {}) {
  return request(app).post('/bc-authorize').set('Authorization', `Bearer ${TOKEN}`)
    .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/bc-authorize`))
    .send({ login_hint: 'alice', service: 'google', agent_did: agent.did, scopes: ['openid'], binding_message: 'K7-42', ...body });
}

function poll(app: App, agent: AgentIdentity, authReqId: string) {
  return request(app).post('/api/v1/token').set('Authorization', `Bearer ${TOKEN}`)
    .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/api/v1/token`))
    .send({ grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: authReqId });
}

async function approveViaLink(app: App, approveUrl: string, decision: 'approve' | 'deny') {
  const url = new URL(approveUrl);
  const page = await request(app).get(`${url.pathname}${url.search}`);
  expect(page.status).toBe(200);
  expect(page.text).toContain('K7-42');
  return request(app).post(url.pathname).type('form').send({ sig: url.searchParams.get('sig'), decision });
}

const claimsOf = (jws: string) => JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8'));

describe('approval-required permissions', () => {
  it('refuse a direct delegation and point at the CIBA endpoint', async () => {
    const agent = await newAgent();
    const { app } = await setup(agent, 'subject');
    mockNetwork();
    const res = await delegate(app, agent);
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ error: 'approval_required', backchannel_authentication_endpoint: `${BASE}/bc-authorize` });
  });

  it('end the request and say so when the subject\'s channel fails', async () => {
    const agent = await newAgent();
    const { app } = await setup(agent, 'subject');
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('webhook unreachable'));
    const res = await bcAuthorize(app, agent);
    expect(res.status).toBe(502);
    expect(res.body.error).toBe('approval_unavailable');
  });

  it('refuse an approval request when no channel can ask the subject', async () => {
    const agent = await newAgent();
    const { app } = await setup(agent, 'subject', { approvalWebhookUrl: undefined });
    const res = await bcAuthorize(app, agent);
    expect(res.status).toBe(503);
  });
});

describe('the subject approves through the built-in page', () => {
  it('issues the token on approval, records a CIBA consent, and reuses it until asked for more', async () => {
    const agent = await newAgent();
    const { app, vault } = await setup(agent, 'subject');
    const hooks = mockNetwork();
    const asked = await bcAuthorize(app, agent);
    expect(asked.status).toBe(200);
    expect(asked.body).toMatchObject({ auth_req_id: expect.any(String), interval: 5 });
    expect((await poll(app, agent, asked.body.auth_req_id)).body.error).toBe('authorization_pending');
    expect(hooks).toHaveLength(1);
    expect(hooks[0]).toMatchObject({ type: 'cred.approval_requested', subject: 'alice', agent_did: agent.did, binding_message: 'K7-42' });

    expect((await approveViaLink(app, hooks[0]!.approve_url, 'approve')).status).toBe(200);
    // The link is single use.
    expect((await approveViaLink(app, hooks[0]!.approve_url, 'approve').catch(() => ({ status: 404 }))).status).not.toBe(200);

    const issued = await poll(app, agent, asked.body.auth_req_id);
    expect(issued.status).toBe(200);
    expect(issued.body.token_type).toBe('DPoP');
    const consent = await vault.getConsent(claimsOf(issued.body.access_token).consent_id);
    expect(consent).toMatchObject({ source: 'ciba', subject: 'alice', agentDid: agent.did });
    expect((await poll(app, agent, asked.body.auth_req_id)).body.error).toBe('invalid_grant');

    // A later request the consent covers needs no new approval...
    expect((await delegate(app, agent)).status).toBe(200);
    // ...a broader one does (Section 8.3, trigger 1).
    expect((await delegate(app, agent, ['openid', 'email'])).body.error).toBe('approval_required');
  });

  it('reports a denial to the polling agent', async () => {
    const agent = await newAgent();
    const { app } = await setup(agent, 'subject');
    const hooks = mockNetwork();
    const asked = await bcAuthorize(app, agent);
    await approveViaLink(app, hooks[0]!.approve_url, 'deny');
    expect((await poll(app, agent, asked.body.auth_req_id)).body.error).toBe('access_denied');
  });

  it('answers only the agent whose key asked', async () => {
    const [agent, other] = [await newAgent(), await newAgent()];
    const { app } = await setup(agent, 'subject');
    const hooks = mockNetwork();
    const asked = await bcAuthorize(app, agent);
    await approveViaLink(app, hooks[0]!.approve_url, 'approve');
    const stolen = await poll(app, other, asked.body.auth_req_id);
    expect(stolen.status).toBe(401);
    expect(stolen.body.access_token).toBeUndefined();
    expect((await poll(app, agent, asked.body.auth_req_id)).status).toBe(200);
  });

  it('refuses a forged approval link', async () => {
    const agent = await newAgent();
    const { app } = await setup(agent, 'subject');
    const hooks = mockNetwork();
    await bcAuthorize(app, agent);
    const url = new URL(hooks[0]!.approve_url);
    expect((await request(app).get(`${url.pathname}?sig=forged`)).status).toBe(404);
    expect((await request(app).post(url.pathname).type('form').send({ sig: 'forged', decision: 'approve' })).status).toBe(404);
  });
});

describe('an admin approves', () => {
  it('lists the request for admins and issues on their approval, with no subject channel needed', async () => {
    const agent = await newAgent();
    const { app } = await setup(agent, 'admin', { approvalWebhookUrl: undefined });
    mockNetwork();
    const asked = await bcAuthorize(app, agent);
    expect(asked.status).toBe(200);
    const listed = await request(app).get('/admin/approvals').set('Authorization', `Bearer ${ADMIN}`);
    expect(listed.body.approvals.map((a: any) => a.auth_req_id)).toContain(asked.body.auth_req_id);
    expect((await request(app).post(`/admin/approvals/${asked.body.auth_req_id}`).set('Authorization', `Bearer ${TOKEN}`).send({ decision: 'approve' })).status).toBe(401);
    expect((await request(app).post(`/admin/approvals/${asked.body.auth_req_id}`).set('Authorization', `Bearer ${ADMIN}`).send({ decision: 'approve' })).status).toBe(200);
    expect((await poll(app, agent, asked.body.auth_req_id)).status).toBe(200);
  });

  it('needs both the subject and an admin under approver both', async () => {
    const agent = await newAgent();
    const { app } = await setup(agent, 'both');
    const hooks = mockNetwork();
    const asked = await bcAuthorize(app, agent);
    await approveViaLink(app, hooks[0]!.approve_url, 'approve');
    expect((await poll(app, agent, asked.body.auth_req_id)).body.error).toMatch(/authorization_pending|slow_down/);
    await request(app).post(`/admin/approvals/${asked.body.auth_req_id}`).set('Authorization', `Bearer ${ADMIN}`).send({ decision: 'approve' });
    expect((await poll(app, agent, asked.body.auth_req_id)).status).toBe(200);
  });
});

describe('a security event', () => {
  it('revokes consents: issued tokens are refused and the next request asks again', async () => {
    const agent = await newAgent();
    const { app } = await setup(agent, 'subject');
    const hooks = mockNetwork();
    const asked = await bcAuthorize(app, agent);
    await approveViaLink(app, hooks[0]!.approve_url, 'approve');
    const token = (await poll(app, agent, asked.body.auth_req_id)).body.access_token;
    expect((await exerciseAs(app, agent, token, { url: USERINFO, method: 'GET' }, { base: BASE })).status).toBe(200);
    const revoked = await request(app).post('/admin/consents/revoke').set('Authorization', `Bearer ${ADMIN}`)
      .send({ agent_did: agent.did, reason: 'key compromise' });
    expect(revoked.body.revoked_count).toBe(1);
    const refused = await exerciseAs(app, agent, token, { url: USERINFO, method: 'GET' }, { base: BASE });
    expect(refused.status).toBe(401);
    expect(refused.body.error).toBe('consent_revoked');
    expect((await delegate(app, agent)).body.error).toBe('approval_required');
  });
});

describe('consent retention', () => {
  it('refuses a retention under 90 days at startup', async () => {
    const agent = await newAgent();
    await expect(setup(agent, null, { consentRetentionDays: 89 })).rejects.toThrow(/at least 90/);
  });

  it('purges only consents past retention, and audits the purge', async () => {
    const agent = await newAgent();
    const { app, vault, purgeExpiredConsents } = await setup(agent, null);
    mockNetwork();
    const minted = await delegate(app, agent);
    const consentId = claimsOf(minted.body.access_token).consent_id;
    expect(await purgeExpiredConsents(Date.now() + 89 * 86_400_000)).toBe(0);
    expect(await purgeExpiredConsents(Date.now() + 91 * 86_400_000)).toBe(1);
    expect(await vault.getConsent(consentId)).toBeNull();
    const events = vault.queryAuditEvents({ limit: 50 }) as Array<{ metadata?: Record<string, unknown> }>;
    expect(events.some((e) => e.metadata?.stage === 'consent_retention_purge' && e.metadata?.count === 1)).toBe(true);
  });
});

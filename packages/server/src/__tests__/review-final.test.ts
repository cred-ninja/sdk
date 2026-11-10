// Final review regressions.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { createDpopProof } from '@credninja/sdk';
import { evaluateOperation } from '@credninja/guard';
import { createServer } from '../server.js';
import { actorTokenFor, delegateAs, exerciseAs, newAgent, type AgentIdentity } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-review-final-'));
  tmpDirs.push(dir);
  return {
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: BEARER,
    providers: (['github', 'salesforce', 'google'] as const).map((slug) => ({ slug, clientId: 'id', clientSecret: 'secret', defaultScopes: [] })),
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}
type Server = ReturnType<typeof createServer>;
const base = { requiresApproval: false, delegatable: true, maxDelegationDepth: 3, createdBy: 'test' };
async function connected(service: string, scopes: string[], extra: Record<string, unknown> = {}, overrides: Partial<ServerConfig> = {}) {
  const server = createServer(config(overrides));
  await server.vault.init();
  await server.vault.store({ provider: service, userId: 'alice', accessToken: 'upstream', expiresAt: new Date(Date.now() + 3600_000), scopes, ...extra });
  return server;
}
const grant = (server: Server, agent: AgentIdentity, service: string, allowedScopes: string[], extra: Record<string, unknown> = {}) =>
  server.vault.createPermission!({ agentId: agent.did, connectionId: service, allowedScopes, ...base, ...extra });
const ask = (server: Server, agent: AgentIdentity, service: string, body: Record<string, unknown> = {}) => delegateAs(server.app, agent, { service, user_id: 'alice', ...body }, { bearer: BEARER });
const admin = (server: Server, method: 'post' | 'patch' | 'delete', url: string) => request(server.app)[method](url).set('Authorization', `Bearer ${ADMIN}`);
const stub = () => {
  const upstream = vi.fn(async (_u: unknown, _i?: unknown) => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
  vi.stubGlobal('fetch', upstream);
  return upstream;
};
const REPO = 'https://api.github.com/repos/o/private';

describe('public_repo does not derive github.read over a token that holds repo', () => {
  it('at issuance: Permission [public_repo] on stored [repo] is issued nothing', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    await grant(server, agent, 'github', ['public_repo']);
    const plain = await ask(server, agent, 'github');
    expect(plain.status).toBe(400);
    expect(plain.body.error).toBe('invalid_scope');
    const named = await ask(server, agent, 'github', { scopes: ['github.read'] });
    expect(named.status).toBe(403);
    expect(named.body.access_token).toBeUndefined();
  });

  it('a scope ceiling of public_repo does not admit it either', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    const now = new Date().toISOString();
    await server.vault.registerAgent!({ id: 'agt_ceiling', did: agent.did, name: 'c', fingerprint: 'fp_c', scopeCeiling: ['public_repo'], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now });
    await grant(server, agent, 'github', ['github.read']);
    const res = await ask(server, agent, 'github');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_scope');
  });

  it('on a live delegation: PATCH from repo to public_repo leaves it nothing', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    const permission = await grant(server, agent, 'github', ['repo']);
    const token = (await ask(server, agent, 'github')).body.access_token as string;
    const upstream = stub();
    expect((await exerciseAs(server.app, agent, token, { url: REPO, method: 'GET' })).status).toBe(200);
    expect((await admin(server, 'patch', `/admin/permissions/${permission.id}`).send({ allowedScopes: ['public_repo'] })).status).toBe(200);
    const after = await exerciseAs(server.app, agent, token, { url: REPO, method: 'GET' });
    expect(after.status).toBe(403);
    expect(after.body.error).toBe('scope_insufficient');
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('at sub-delegation: a child with Permission [public_repo] under a repo parent gets no github.read', async () => {
    const server = await connected('github', ['repo']);
    const [parent, child] = [await newAgent(), await newAgent()];
    await grant(server, parent, 'github', ['repo']);
    await grant(server, child, 'github', ['public_repo']);
    const root = await ask(server, parent, 'github');
    const sub = await request(server.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: root.body.receipt, agent_did: child.did, service: 'github', user_id: 'alice', scopes: ['github.read'], actor_token: actorTokenFor(parent, '/api/v1/subdelegate'),
    });
    expect(sub.status).toBe(403);
    expect(sub.body.access_token).toBeUndefined();
  });

  it('still derives where the token really is public-only, and from repo', async () => {
    const pub = await connected('github', ['public_repo']);
    const a = await newAgent();
    await grant(pub, a, 'github', ['public_repo']);
    expect((await ask(pub, a, 'github', { scopes: ['github.read'] })).body.scopes).toEqual(['github.read']);
    const whole = await connected('github', ['repo']);
    const b = await newAgent();
    await grant(whole, b, 'github', ['repo']);
    expect((await ask(whole, b, 'github', { scopes: ['github.read'] })).body.scopes).toEqual(['github.read']);
    const explicit = await newAgent();
    await grant(whole, explicit, 'github', ['github.read']);
    expect((await ask(whole, explicit, 'github')).body.scopes).toEqual(['github.read']);
  });
});

describe('reconnecting Salesforce to another org ends what was approved for the old one', () => {
  const ACME = 'https://acme.my.salesforce.com';
  async function reconnect(server: Server, instance: string, userId = 'alice') {
    const started = await admin(server, 'post', '/connect/salesforce/start').send({ user_id: userId, scopes: ['api'] });
    const redirect = await request(server.app).get(started.body.url).set('Authorization', `Bearer ${ADMIN}`);
    const state = new URL(redirect.headers.location!).searchParams.get('state')!;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ access_token: 'new', token_type: 'Bearer', instance_url: instance, scope: 'api' }), { status: 200, headers: { 'content-type': 'application/json' } })));
    await request(server.app).get('/connect/salesforce/callback').query({ code: 'c', state });
    vi.unstubAllGlobals();
  }
  const consent = (server: Server, id: string, subject: string, service: string, agentDid: string) => server.vault.recordConsent({ id, subject, agentDid, service, capabilities: [], source: 'ciba', approvedBy: 'x', expiresAt: null, chainContext: {} } as never);

  it('revokes that subject\'s consents on that service, and no others', async () => {
    const server = await connected('salesforce', ['api'], { instanceUrl: ACME });
    const agent = await newAgent();
    await consent(server, 'consent_old', 'alice', 'salesforce', agent.did);
    await consent(server, 'consent_bob', 'bob', 'salesforce', agent.did);
    await consent(server, 'consent_gh', 'alice', 'github', agent.did);
    await reconnect(server, 'https://other.my.salesforce.com');
    expect(await server.vault.getConsentRevocation('consent_old')).not.toBeNull();
    expect(await server.vault.getConsentRevocation('consent_bob')).toBeNull();
    expect(await server.vault.getConsentRevocation('consent_gh')).toBeNull();
  });

  it('reconnecting to the same org revokes nothing', async () => {
    const server = await connected('salesforce', ['api'], { instanceUrl: ACME });
    const agent = await newAgent();
    await consent(server, 'consent_old', 'alice', 'salesforce', agent.did);
    await reconnect(server, ACME);
    expect(await server.vault.getConsentRevocation('consent_old')).toBeNull();
  });

  it('cancels a pending approval, which cannot then be redeemed', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 204 })));
    const server = await connected('salesforce', ['api'], { instanceUrl: ACME }, { approvalWebhookUrl: 'https://hooks.example.com/a' });
    const agent = await newAgent();
    await grant(server, agent, 'salesforce', ['api'], { requiresApproval: true });
    const asked = await request(server.app).post('/bc-authorize').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(agent, 'POST', 'http://localhost:3456/bc-authorize'))
      .send({ login_hint: 'alice', service: 'salesforce', agent_did: agent.did, scopes: ['api'] });
    expect(asked.status, JSON.stringify(asked.body)).toBe(200);
    vi.unstubAllGlobals();
    await reconnect(server, 'https://other.my.salesforce.com');
    const polled = await request(server.app).post('/api/v1/token').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(agent, 'POST', 'http://localhost:3456/api/v1/token'))
      .send({ grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: asked.body.auth_req_id });
    expect(polled.status).toBe(400);
    expect(polled.body.error).toBe('access_denied');
  });
});

describe('Notion: trashing is not an update', () => {
  const N = 'https://api.notion.com/v1';
  const op = (url: string, scope: string, body: unknown) => evaluateOperation({ service: 'notion', method: 'PATCH', url, body }, [scope]).outcome;

  for (const route of ['pages/abc', 'blocks/abc', 'databases/abc', 'data_sources/abc']) {
    for (const field of ['archived', 'in_trash']) {
      for (const value of [true, false, 'yes', null]) {
        it(`update_content cannot send ${field}=${String(value)} to ${route}, and content can`, () => {
          expect(op(`${N}/${route}`, 'update_content', { [field]: value, title: 'x' })).toBe('insufficient');
          expect(op(`${N}/${route}`, 'content', { [field]: value })).toBe('allowed');
        });
      }
    }
    it(`update_content still updates ${route}`, () => {
      expect(op(`${N}/${route}`, 'update_content', { title: 'x' })).toBe('allowed');
    });
  }

  it('reaches the broker the same way', async () => {
    const server = createServer(config({ providers: [{ slug: 'notion', clientId: 'i', clientSecret: 's', defaultScopes: [] }] }));
    await server.vault.init();
    await server.vault.store({ provider: 'notion', userId: 'alice', accessToken: 'ntn', scopes: ['update_content'] });
    const agent = await newAgent();
    await grant(server, agent, 'notion', ['update_content']);
    const token = (await ask(server, agent, 'notion')).body.access_token as string;
    const upstream = stub();
    const res = await exerciseAs(server.app, agent, token, { url: `${N}/pages/abc`, method: 'PATCH', body: { archived: true } });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('scope_insufficient');
    expect(upstream).not.toHaveBeenCalled();
  });
});

describe('replaying a delegation revocation', () => {
  it('stays idempotent and does not undo a restore', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    const permission = await grant(server, agent, 'github', ['repo']);
    const first = await ask(server, agent, 'github');
    const del = () => request(server.app).delete(`/api/v1/delegations/${first.body.delegation_id}`).set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'alice' });
    expect((await del()).body.revoked_count).toBe(1);
    expect((await ask(server, agent, 'github')).status).toBe(403);
    expect((await admin(server, 'post', `/admin/permissions/${permission.id}/restore`).send({})).status).toBe(200);
    const issued = await ask(server, agent, 'github');
    expect(issued.status).toBe(200);
    const replay = await del();
    expect(replay.status).toBe(200);
    expect(replay.body.revoked_count).toBe(0);
    expect((await ask(server, agent, 'github')).status).toBe(200);
    const claims = JSON.parse(Buffer.from((issued.body.access_token as string).split('.')[1]!, 'base64url').toString()) as { consent_id: string };
    expect(await server.vault.getConsentRevocation(claims.consent_id)).toBeNull();
  });

  it('does not undo a re-grant', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    await grant(server, agent, 'github', ['repo']);
    const first = await ask(server, agent, 'github');
    const del = () => request(server.app).delete(`/api/v1/delegations/${first.body.delegation_id}`).set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'alice' });
    await del();
    expect((await admin(server, 'post', '/admin/permissions').send({ agentId: agent.did, connectionId: 'github', allowedScopes: ['repo'] })).status).toBe(201);
    await del();
    expect((await ask(server, agent, 'github')).status).toBe(200);
  });
});

describe('an expired Permission authorizes no live delegation', () => {
  async function live() {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    const permission = await grant(server, agent, 'github', ['repo']);
    const token = (await ask(server, agent, 'github')).body.access_token as string;
    return { server, agent, permission, token };
  }

  it('patched to expire, a live token stops', async () => {
    const { server, agent, permission, token } = await live();
    const upstream = stub();
    expect((await exerciseAs(server.app, agent, token, { url: REPO, method: 'GET' })).status).toBe(200);
    await admin(server, 'patch', `/admin/permissions/${permission.id}`).send({ expiresAt: new Date(Date.now() - 1000).toISOString() });
    const res = await exerciseAs(server.app, agent, token, { url: REPO, method: 'GET' });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('scope_insufficient');
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('expiring on its own, a live token stops at that moment', async () => {
    const { server, agent, permission, token } = await live();
    const upstream = stub();
    await admin(server, 'patch', `/admin/permissions/${permission.id}`).send({ expiresAt: new Date(Date.now() + 2000).toISOString() });
    expect((await exerciseAs(server.app, agent, token, { url: REPO, method: 'GET' })).status).toBe(200);
    await new Promise((resolve) => setTimeout(resolve, 2100));
    expect((await exerciseAs(server.app, agent, token, { url: REPO, method: 'GET' })).status).toBe(403);
    expect(upstream).toHaveBeenCalledTimes(1);
  });
});

describe('a re-grant does not silently drop what the row held', () => {
  const body = (agent: AgentIdentity, extra: Record<string, unknown> = {}) => ({ agentId: agent.did, connectionId: 'github', allowedScopes: ['repo'], ...extra });

  it.each([
    ['expiresAt', { expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, { expiresAt: new Date(Date.now() + 7_200_000).toISOString() }],
    ['ttlOverride', { ttlOverride: 60 }, { ttlOverride: 120 }],
    ['approver', { requiresApproval: true, approver: 'admin' }, { requiresApproval: true, approver: 'admin' }],
    ['approver', { requiresApproval: true, approver: 'both' }, { requiresApproval: true, approver: 'subject' }],
  ])('%s: refused until the body names it', async (field, held, named) => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    expect((await admin(server, 'post', '/admin/permissions').send(body(agent, held))).status).toBe(201);
    const omit = await admin(server, 'post', '/admin/permissions').send(body(agent, field === 'approver' ? { requiresApproval: true } : {}));
    expect(omit.status, JSON.stringify(omit.body)).toBe(409);
    expect(omit.body.fields).toContain(field);
    expect((await admin(server, 'post', '/admin/permissions').send(body(agent, named))).status).toBe(201);
  });

  it('a body may clear them by naming them', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    await admin(server, 'post', '/admin/permissions').send(body(agent, { ttlOverride: 60, expiresAt: new Date(Date.now() + 3_600_000).toISOString() }));
    expect((await admin(server, 'post', '/admin/permissions').send(body(agent, { ttlOverride: null, expiresAt: null }))).status).toBe(201);
    const after = await server.vault.getPermission!(agent.did, 'github');
    expect(after?.ttlOverride).toBeUndefined();
    expect(after?.expiresAt).toBeUndefined();
  });

  it('an approver of subject needs no naming', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    await admin(server, 'post', '/admin/permissions').send(body(agent, { requiresApproval: true, approver: 'subject' }));
    expect((await admin(server, 'post', '/admin/permissions').send(body(agent, { requiresApproval: true }))).status).toBe(201);
  });

  it('says what replacing does to live delegations, and it is true', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    await admin(server, 'post', '/admin/permissions').send(body(agent, { ttlOverride: 60 }));
    const token = (await ask(server, agent, 'github')).body.access_token as string;
    const refused = await admin(server, 'post', '/admin/permissions').send(body(agent));
    expect(refused.status).toBe(409);
    expect(refused.body.message).toContain('live delegations');
    stub();
    expect((await exerciseAs(server.app, agent, token, { url: REPO, method: 'GET' })).status).toBe(200);
    expect((await admin(server, 'post', '/admin/permissions').send(body(agent, { ttlOverride: null }))).status).toBe(201);
    const after = await exerciseAs(server.app, agent, token, { url: REPO, method: 'GET' });
    expect(after.status).toBe(403);
    expect(after.body.message).toMatch(/replaced|no longer/);
  });

  it('restore keeps live delegations working', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    const created = await admin(server, 'post', '/admin/permissions').send(body(agent, { ttlOverride: 60 }));
    const token = (await ask(server, agent, 'github')).body.access_token as string;
    expect((await admin(server, 'post', `/admin/permissions/${created.body.permission.id}/restore`).send({})).status).toBe(200);
    stub();
    expect((await exerciseAs(server.app, agent, token, { url: REPO, method: 'GET' })).status).toBe(200);
  });
});

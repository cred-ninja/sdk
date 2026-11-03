// Found by running the developer journey against the branch.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { Cred } from '@credninja/sdk';
import { createServer } from '../server.js';
import { delegateAs, exerciseAs, newAgent, type AgentIdentity } from './token-helpers.js';
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-review-onb-'));
  tmpDirs.push(dir);
  return {
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: BEARER,
    providers: (['github', 'salesforce', 'notion', 'google'] as const).map((slug) => ({ slug, clientId: 'id', clientSecret: 'secret', defaultScopes: [] })),
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}
type Server = ReturnType<typeof createServer>;
const grant = (server: Server, agent: AgentIdentity, service: string, allowedScopes: string[]) => server.vault.createPermission!({ agentId: agent.did, connectionId: service, allowedScopes, requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });

describe('a consent link asks the provider for what the provider knows', () => {
  async function scopeAtProvider(service: string, scopes: string[]) {
    const server = createServer(config());
    await server.vault.init();
    const agent = await newAgent();
    await grant(server, agent, service, scopes);
    const res = await delegateAs(server.app, agent, { service, user_id: 'alice', scopes }, { bearer: BEARER });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('consent_required');
    const redirect = await request(server.app).get(new URL(res.body.consent_url).pathname + new URL(res.body.consent_url).search).set('Authorization', `Bearer ${ADMIN}`);
    expect(redirect.status).toBe(302);
    return { server, location: new URL(redirect.headers.location!) };
  }

  it('github.read asks GitHub for repo', async () => {
    const { location } = await scopeAtProvider('github', ['github.read']);
    expect(location.searchParams.get('scope')).toBe('repo');
  });

  it('salesforce.read asks Salesforce for api', async () => {
    const { location } = await scopeAtProvider('salesforce', ['salesforce.read']);
    expect(location.searchParams.get('scope')?.split(' ')).toContain('api');
    expect(location.toString()).not.toContain('salesforce.read');
  });

  it('Notion is asked for no Cred name, and what was chosen is still what gets stored', async () => {
    const { server, location } = await scopeAtProvider('notion', ['notion.read']);
    expect(location.toString()).not.toContain('notion.read');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ access_token: 'ntn', token_type: 'bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })));
    await request(server.app).get('/connect/notion/callback').query({ code: 'c', state: location.searchParams.get('state')! });
    expect((await server.vault.getStored({ provider: 'notion', userId: 'alice' }))?.scopes).toEqual(['notion.read']);
  });

  it('a scope both names keep once, and other providers are untouched', async () => {
    const both = await scopeAtProvider('github', ['repo', 'github.read']);
    expect(both.location.searchParams.get('scope')).toBe('repo');
    const google = await scopeAtProvider('google', ['calendar.readonly']);
    expect(google.location.searchParams.get('scope')).toContain('calendar.readonly');
  });
});

describe('the audit feed names who did what, under fields that say what they are', () => {
  async function setup() {
    const server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'github', userId: 'alice', accessToken: 'gho', expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
    const agent = await newAgent();
    await grant(server, agent, 'github', ['repo']);
    const minted = await delegateAs(server.app, agent, { service: 'github', user_id: 'alice' }, { bearer: BEARER });
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })));
    expect((await exerciseAs(server.app, agent, minted.body.access_token, { url: 'https://api.github.com/repos/o/r', method: 'GET' })).status).toBe(200);
    vi.unstubAllGlobals();
    return { ...server, agent, minted };
  }
  const feed = async (server: Server) => (await request(server.app).get('/api/v1/audit').set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'alice' })).body.entries as Array<Record<string, any>>;

  it('/api/v1/audit carries the actor', async () => {
    const server = await setup();
    const entry = (await feed(server)).find((e) => e.action === 'access');
    expect(entry?.actor).toMatchObject({ type: 'agent', id: server.agent.did, fingerprint: expect.any(String) });
  });

  it('delegation and route fields are not filed under webBotAuth', async () => {
    const server = await setup();
    const entry = (await feed(server)).find((e) => e.action === 'access');
    expect(entry?.metadata.webBotAuth).toBeUndefined();
    expect(entry?.metadata.details).toMatchObject({ delegationId: server.minted.body.delegation_id, origin: 'https://api.github.com', route: '/repos/{id}/{id}', method: 'GET' });
  });

  it('Web Bot Auth fields still are, and only they', async () => {
    const server = await setup();
    server.vault.writeAuditEvent({
      id: 'evt_wba', timestamp: new Date(), actor: { type: 'agent', id: 'agt' }, action: 'delegate', resource: { type: 'token', id: 'github/alice' }, outcome: 'success', correlationId: 'c',
      metadata: { identitySource: 'web-bot-auth', webBotAuthKeyId: 'k', signatureAgent: 's', delegationId: 'del_x' },
    });
    const entry = (await feed(server)).find((e) => e.id === 'evt_wba');
    expect(entry?.metadata.webBotAuth).toEqual({ identitySource: 'web-bot-auth', webBotAuthKeyId: 'k', signatureAgent: 's' });
    expect(entry?.metadata.details).toEqual({ delegationId: 'del_x' });
  });

  it('getAuditLog() returns the actor', async () => {
    const server = await setup();
    const listener = await new Promise<import('node:http').Server>((resolve) => {
      const started = server.app.listen(0, '127.0.0.1', () => resolve(started));
    });
    try {
      const { port } = listener.address() as { port: number };
      const cred = new Cred({ agentToken: BEARER, baseUrl: `http://127.0.0.1:${port}` });
      const entries = await cred.getAuditLog({ userId: 'alice' });
      expect(entries.find((e) => e.action === 'access')?.actor?.id).toBe(server.agent.did);
    } finally {
      await new Promise((resolve) => listener.close(resolve));
    }
  });

  it('a failed proof does not tell a Bearer caller which agent a token is bound to', async () => {
    const server = await setup();
    const thief = await newAgent();
    const res = await exerciseAs(server.app, thief, server.minted.body.access_token, { url: 'https://api.github.com/repos/o/r', method: 'GET' });
    expect(res.status).toBe(401);
    const entry = (await feed(server)).find((e) => e.metadata.errorMessage === 'invalid_dpop_proof');
    expect(entry).toBeDefined();
    expect(JSON.stringify(entry)).not.toContain(server.agent.did);
    const admin = await request(server.app).get('/admin/audit').set('Authorization', `Bearer ${ADMIN}`);
    expect(JSON.stringify(admin.body)).toContain(server.agent.did);
  });

  it('the hash chain is unaffected: this reshapes the response, not the row', async () => {
    const server = await setup();
    await feed(server);
    expect(server.vault.verifyAuditChain().ok).toBe(true);
    const row = server.vault.queryAuditEvents({ limit: 50 }).find((e) => e.action === 'access');
    expect(row?.metadata?.delegationId).toBe(server.minted.body.delegation_id);
  });
});

describe('narrowing a Permission reaches live delegations', () => {
  const GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages';
  async function setup() {
    const server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29', expiresAt: new Date(Date.now() + 3600_000), scopes: ['gmail.readonly', 'gmail.send'] });
    const agent = await newAgent();
    const permission = await grant(server, agent, 'google', ['gmail.readonly', 'gmail.send']);
    const minted = await delegateAs(server.app, agent, { service: 'google', user_id: 'alice' }, { bearer: BEARER });
    expect(minted.body.scopes).toEqual(['gmail.readonly', 'gmail.send']);
    const upstream = vi.fn(async (_u: unknown, _i?: unknown) => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', upstream);
    return { ...server, agent, permission, token: minted.body.access_token as string, upstream };
  }
  const patch = (server: Server, id: string, allowedScopes: string[]) => request(server.app).patch(`/admin/permissions/${id}`).set('Authorization', `Bearer ${ADMIN}`).send({ allowedScopes });

  it('a live token loses what the Permission no longer allows, and keeps the rest', async () => {
    const { app, agent, permission, token, upstream, ...server } = await setup();
    const send = () => exerciseAs(app, agent, token, { url: `${GMAIL}/send`, method: 'POST', body: { raw: 'eA' } });
    expect((await send()).status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(1);
    expect((await patch({ app, ...server } as never, permission.id, ['gmail.readonly'])).status).toBe(200);
    const refused = await send();
    expect(refused.status).toBe(403);
    expect(refused.body.error).toBe('scope_insufficient');
    expect(upstream).toHaveBeenCalledTimes(1);
    expect((await exerciseAs(app, agent, token, { url: GMAIL, method: 'GET' })).status).toBe(200);
  });

  it('narrowed to nothing, a live token does nothing, and says why', async () => {
    const { app, agent, permission, token, upstream, ...server } = await setup();
    await patch({ app, ...server } as never, permission.id, []);
    const res = await exerciseAs(app, agent, token, { url: GMAIL, method: 'GET' });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('scope_insufficient');
    expect(res.body.message).toContain('Permission');
    expect(upstream).not.toHaveBeenCalled();
    const event = server.vault.queryAuditEvents({ limit: 50 }).find((e) => e.errorMessage === 'scope_insufficient');
    expect(event?.actor.id).toBe(agent.did);
  });

  it('holds across a restart', async () => {
    const cfg = config();
    const first = createServer(cfg);
    await first.vault.init();
    await first.vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29', expiresAt: new Date(Date.now() + 3600_000), scopes: ['gmail.readonly', 'gmail.send'] });
    const agent = await newAgent();
    const permission = await grant(first, agent, 'google', ['gmail.readonly', 'gmail.send']);
    const token = (await delegateAs(first.app, agent, { service: 'google', user_id: 'alice' }, { bearer: BEARER })).body.access_token as string;
    await patch(first, permission.id, ['gmail.readonly']);
    const second = createServer(cfg);
    await second.vault.init();
    const upstream = vi.fn(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', upstream);
    expect((await exerciseAs(second.app, agent, token, { url: `${GMAIL}/send`, method: 'POST', body: { raw: 'eA' } })).status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });

  it('a read scope derived from what remains still works', async () => {
    const server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'github', userId: 'alice', accessToken: 'gho', expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
    const agent = await newAgent();
    const permission = await grant(server, agent, 'github', ['repo']);
    const token = (await delegateAs(server.app, agent, { service: 'github', user_id: 'alice' }, { bearer: BEARER })).body.access_token as string;
    await patch(server, permission.id, ['github.read']);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })));
    expect((await exerciseAs(server.app, agent, token, { url: 'https://api.github.com/repos/o/r', method: 'GET' })).status).toBe(200);
    expect((await exerciseAs(server.app, agent, token, { url: 'https://api.github.com/repos/o/r/issues', method: 'POST', body: { title: 't' } })).status).toBe(403);
  });
});

describe('README samples', () => {
  const root = path.resolve(import.meta.dirname ?? __dirname, '../../../..');
  const serverReadme = fs.readFileSync(path.join(root, 'packages/server/README.md'), 'utf8');

  it('the two-machine sample grants the agent, keeps its key, and names a user', () => {
    const section = serverReadme.slice(serverReadme.indexOf('## Two-Machine Setup'));
    const sample = section.slice(0, section.indexOf('\n## ', 10));
    expect(sample).toContain('/admin/permissions');
    expect(sample).toContain('importAgentIdentity');
    expect(sample).not.toContain('await generateAgentIdentity()');
    expect(sample).not.toContain(`userId: 'default'`);
  });

  it('the template README links only to anchors the server README has', () => {
    const template = fs.readFileSync(path.join(root, 'packages/create-cred-app/template/README.md'), 'utf8');
    const anchors = [...template.matchAll(/packages\/server#([a-z0-9-]+)/g)].map((m) => m[1]!);
    expect(anchors.length).toBeGreaterThan(0);
    const headings = new Set([...serverReadme.matchAll(/^#+ (.+)$/gm)].map((m) => m[1]!.toLowerCase().replace(/[^\w\s-]/g, '').trim().replace(/\s+/g, '-')));
    for (const anchor of anchors) expect(headings.has(anchor), anchor).toBe(true);
  });
});

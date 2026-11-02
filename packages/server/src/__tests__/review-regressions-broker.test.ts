// Regressions from an independent read of the broker.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { evaluateOperation } from '@credninja/guard';
import { createServer } from '../server.js';
import { delegateAs, exerciseAs, newAgent } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.unstubAllGlobals());

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-review-'));
  tmpDirs.push(dir);
  return {
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: BEARER,
    providers: (['salesforce', 'notion', 'github', 'google', 'hubspot'] as const).map((slug) => ({ slug, clientId: 'id', clientSecret: 'secret', defaultScopes: [] })),
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}

function stubUpstream() {
  const upstream = vi.fn(async (_url: unknown, _init?: unknown) => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }));
  vi.stubGlobal('fetch', upstream);
  return upstream;
}

async function salesforce(stored: { instanceUrl?: string }, overrides: Partial<ServerConfig> = {}) {
  const server = createServer(config(overrides));
  await server.vault.init();
  await server.vault.store({ provider: 'salesforce', userId: 'alice', accessToken: 'sf-bearer-token', expiresAt: new Date(Date.now() + 3600_000), scopes: ['api'], ...stored });
  const agent = await newAgent();
  await server.vault.createPermission!({ agentId: agent.did, connectionId: 'salesforce', allowedScopes: ['api'], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
  const minted = await delegateAs(server.app, agent, { service: 'salesforce', user_id: 'alice' }, { bearer: BEARER });
  expect(minted.status, JSON.stringify(minted.body)).toBe(200);
  return { ...server, agent, token: minted.body.access_token as string };
}

const LIMITS = '/services/data/v60.0/limits';

describe('a Salesforce token goes only to the connection\'s own instance', () => {
  it('forwards to the stored instance and refuses any other host, before any upstream call', async () => {
    const { app, vault, agent, token } = await salesforce({ instanceUrl: 'https://acme.my.salesforce.com' });
    const upstream = stubUpstream();
    const own = await exerciseAs(app, agent, token, { url: `https://acme.my.salesforce.com${LIMITS}`, method: 'GET' });
    expect(own.status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(1);
    for (const host of ['attacker.my.salesforce.com', 'attacker-site.force.com', 'acme.my.salesforce.com.force.com']) {
      const other = await exerciseAs(app, agent, token, { url: `https://${host}${LIMITS}`, method: 'GET' });
      expect(other.status, host).toBe(400);
      expect(other.body.error).toBe('salesforce_instance_mismatch');
    }
    expect(upstream).toHaveBeenCalledTimes(1);
    expect(String(upstream.mock.calls[0]![0])).toContain('acme.my.salesforce.com');
    const events = vault.queryAuditEvents({ limit: 50 });
    expect(events.find((e) => e.action === 'access' && e.outcome === 'success')?.metadata?.origin).toBe('https://acme.my.salesforce.com');
    const refused = events.find((e) => e.errorMessage === 'salesforce_instance_mismatch');
    expect(refused?.actor.id).toBe(agent.did);
    expect(refused?.metadata?.origin).toBe('refused');
    expect(JSON.stringify(refused)).not.toContain('attacker');
  });

  it('refuses every host when no instance is stored, and says to reconnect', async () => {
    const { app, vault, agent, token } = await salesforce({ instanceUrl: 'https://acme.my.salesforce.com' });
    await vault.store({ provider: 'salesforce', userId: 'alice', accessToken: 'sf-bearer-token', expiresAt: new Date(Date.now() + 3600_000), scopes: ['api'] });
    const upstream = stubUpstream();
    const res = await exerciseAs(app, agent, token, { url: `https://acme.my.salesforce.com${LIMITS}`, method: 'GET' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('salesforce_instance_unknown');
    expect(res.body.message).toContain('Reconnect');
    expect(upstream).not.toHaveBeenCalled();
  });

  it('holds with classification turned off too: there is no opt-out from sending a token to the wrong host', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { app, agent, token } = await salesforce({ instanceUrl: 'https://acme.my.salesforce.com' }, { allowUnclassifiedBrokerCalls: true });
    const upstream = stubUpstream();
    const res = await exerciseAs(app, agent, token, { url: `https://attacker.my.salesforce.com${LIMITS}`, method: 'GET' });
    expect(res.status).toBe(400);
    expect(upstream).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });

  it('the instance survives a token refresh', async () => {
    const { vault } = await salesforce({ instanceUrl: 'https://acme.my.salesforce.com' });
    await vault.store({ provider: 'salesforce', userId: 'bob', accessToken: 'old', refreshToken: 'r', expiresAt: new Date(Date.now() - 1000), scopes: ['api'], instanceUrl: 'https://bob.my.salesforce.com' });
    const entry = await vault.get({
      provider: 'salesforce', userId: 'bob', clientId: 'id', clientSecret: 'secret',
      adapter: { refreshAccessToken: async () => ({ accessToken: 'new', expiresIn: 3600 }) },
    });
    expect(entry?.accessToken).toBe('new');
    expect((await vault.getStored({ provider: 'salesforce', userId: 'bob' }))?.instanceUrl).toBe('https://bob.my.salesforce.com');
  });

  it('the OAuth callback stores the instance the provider names, and refuses one outside the host grammar', async () => {
    for (const [instance, stored] of [['https://acme.my.salesforce.com', 'https://acme.my.salesforce.com'], ['https://evil.example.com', undefined]] as const) {
      const server = createServer(config());
      await server.vault.init();
      const started = await request(server.app).post('/connect/salesforce/start').set('Authorization', `Bearer ${ADMIN}`).send({ user_id: 'alice', scopes: ['api'] });
      expect(started.status).toBe(200);
      const redirect = await request(server.app).get(started.body.url).set('Authorization', `Bearer ${ADMIN}`);
      const state = new URL(redirect.headers.location!).searchParams.get('state')!;
      vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ access_token: 'tok', token_type: 'Bearer', instance_url: instance, scope: 'api refresh_token' }), { status: 200, headers: { 'content-type': 'application/json' } })));
      const back = await request(server.app).get('/connect/salesforce/callback').query({ code: 'c', state });
      vi.unstubAllGlobals();
      const entry = await server.vault.getStored({ provider: 'salesforce', userId: 'alice' });
      if (stored) {
        expect(entry?.instanceUrl).toBe(stored);
      } else {
        expect(back.status).toBeGreaterThanOrEqual(400);
        expect(entry).toBeNull();
      }
    }
  });
});

describe('Notion scopes at /connect', () => {
  async function connectNotion(scopes: string[]) {
    const server = createServer(config());
    await server.vault.init();
    const started = await request(server.app).post('/connect/notion/start').set('Authorization', `Bearer ${ADMIN}`).send({ user_id: 'alice', scopes });
    expect(started.status).toBe(200);
    const redirect = await request(server.app).get(started.body.url).set('Authorization', `Bearer ${ADMIN}`);
    const state = new URL(redirect.headers.location!).searchParams.get('state')!;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ access_token: 'ntn', token_type: 'bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })));
    await request(server.app).get('/connect/notion/callback').query({ code: 'c', state });
    vi.unstubAllGlobals();
    return server;
  }

  it('the page offers only names the operation table knows', async () => {
    const server = createServer(config());
    await server.vault.init();
    const page = await request(server.app).get('/connect').set('Authorization', `Bearer ${ADMIN}`).query({ user_id: 'alice' });
    expect(page.status).toBe(200);
    expect(page.text).toContain('notion.read');
    expect(page.text).not.toMatch(/read_content|update_content|insert_content/);
  });

  it('a connection made read-only stays read-only: content is not derived from it', async () => {
    const server = await connectNotion(['notion.read']);
    expect((await server.vault.getStored({ provider: 'notion', userId: 'alice' }))?.scopes).toEqual(['notion.read']);
    const agent = await newAgent();
    await server.vault.createPermission!({ agentId: agent.did, connectionId: 'notion', allowedScopes: ['content'], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
    const issued = await delegateAs(server.app, agent, { service: 'notion', user_id: 'alice' }, { bearer: BEARER });
    expect(issued.status).toBe(200);
    expect(issued.body.scopes).toEqual(['notion.read']);
    expect((await delegateAs(server.app, agent, { service: 'notion', user_id: 'alice', scopes: ['content'] }, { bearer: BEARER })).status).toBe(403);
  });

  it('an old name is stored as sent, and it does not widen: read_content derives no write', async () => {
    const reader = await connectNotion(['read_content']);
    expect((await reader.vault.getStored({ provider: 'notion', userId: 'alice' }))?.scopes).toEqual(['read_content']);
    const ask = async (server: typeof reader, allowed: string) => {
      const agent = await newAgent();
      await server.vault.createPermission!({ agentId: agent.did, connectionId: 'notion', allowedScopes: [allowed], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
      return (await delegateAs(server.app, agent, { service: 'notion', user_id: 'alice' }, { bearer: BEARER })).body.scopes;
    };
    expect(await ask(reader, 'notion.read')).toEqual(['notion.read']);
    expect(await ask(reader, 'content')).not.toContain('content');
    const writer = await connectNotion(['update_content']);
    expect(await ask(writer, 'update_content')).toEqual(['update_content']);
    expect(await ask(writer, 'content')).toBeUndefined();
  });

  it('a row stored under the old names keeps its meaning: read_content reads, update_content updates, insert_content creates', async () => {
    const page = 'https://api.notion.com/v1/pages/abc';
    const pages = 'https://api.notion.com/v1/pages';
    expect(evaluateOperation({ service: 'notion', method: 'GET', url: page }, ['read_content']).outcome).toBe('allowed');
    expect(evaluateOperation({ service: 'notion', method: 'POST', url: pages, body: {} }, ['read_content']).outcome).toBe('insufficient');
    expect(evaluateOperation({ service: 'notion', method: 'PATCH', url: page, body: {} }, ['update_content']).outcome).toBe('allowed');
    expect(evaluateOperation({ service: 'notion', method: 'POST', url: pages, body: {} }, ['insert_content']).outcome).toBe('allowed');
  });
});

describe('table gaps', () => {
  const op = (service: string, method: string, url: string, scopes: string[]) => evaluateOperation({ service, method, url, ...(method === 'GET' ? {} : { body: {} }) }, scopes).outcome;

  it('drive.googleapis.com, which the allowlist admits, is mapped like the Drive API', () => {
    const files = 'https://drive.googleapis.com/drive/v3/files';
    expect(op('google', 'GET', files, ['drive.readonly'])).toBe('allowed');
    expect(op('google', 'POST', files, ['drive.readonly'])).toBe('insufficient');
    expect(op('google', 'POST', files, ['drive.file'])).toBe('allowed');
    expect(op('google', 'GET', 'https://drive.googleapis.com/gmail/v1/users/me/messages', ['gmail.readonly'])).toBe('not_mapped');
  });

  it('HubSpot\'s legacy tickets scope reads and writes tickets, and nothing else', () => {
    const tickets = 'https://api.hubapi.com/crm/v3/objects/tickets';
    expect(op('hubspot', 'GET', tickets, ['tickets'])).toBe('allowed');
    expect(op('hubspot', 'POST', tickets, ['tickets'])).toBe('allowed');
    expect(op('hubspot', 'POST', `${tickets}/search`, ['tickets'])).toBe('allowed');
    expect(op('hubspot', 'GET', 'https://api.hubapi.com/crm/v3/objects/contacts', ['tickets'])).toBe('insufficient');
    expect(op('hubspot', 'POST', tickets, ['crm.objects.tickets.read'])).toBe('insufficient');
  });

  it('HubSpot ticket properties are mapped', () => {
    const properties = 'https://api.hubapi.com/crm/v3/properties/tickets';
    expect(op('hubspot', 'GET', properties, ['crm.schemas.tickets.read'])).toBe('allowed');
    expect(op('hubspot', 'GET', `${properties}/subject`, ['tickets'])).toBe('allowed');
    expect(op('hubspot', 'GET', properties, ['crm.schemas.contacts.read'])).toBe('insufficient');
  });
});

describe('github.read does not cover administrative reads', () => {
  const GH = 'https://api.github.com';
  const read = (url: string, scope: string) => evaluateOperation({ service: 'github', method: 'GET', url: `${GH}${url}` }, [scope]).outcome;

  it('refuses secrets, hooks, keys and other settings under github.read, which repo itself still reaches', () => {
    for (const url of [
      '/repos/o/r/actions/secrets',
      '/repos/o/r/actions/secrets/public-key',
      '/repos/o/r/actions/variables',
      '/repos/o/r/actions/runners/registration-token',
      '/repos/o/r/dependabot/secrets',
      '/repos/o/r/codespaces/secrets',
      '/repos/o/r/environments/prod/secrets',
      '/repos/o/r/hooks',
      '/repos/o/r/hooks/1/config',
      '/repos/o/r/keys',
      '/repos/o/r/collaborators',
      '/repos/o/r/invitations',
      '/repos/o/r/branches/main/protection',
      '/repos/o/r/secret-scanning/alerts',
      '/repos/o/r/code-scanning/alerts',
      '/repos/o/r/dependabot/alerts',
      '/repos/o/r/rulesets',
      '/repos/o/r/traffic/views',
    ]) {
      expect(read(url, 'github.read'), url).toBe('insufficient');
      expect(read(url, 'repo'), url).toBe('allowed');
    }
  });

  it('refuses account and org settings under github.read', () => {
    for (const url of ['/user/keys', '/user/emails', '/user/gpg_keys', '/orgs/acme/hooks', '/orgs/acme/actions/secrets', '/gists', '/notifications']) {
      expect(read(url, 'github.read'), url).toBe('insufficient');
    }
  });

  it('keeps ordinary repository reads', () => {
    for (const url of [
      '/repos/o/r',
      '/repos/o/r/contents/a/b.txt',
      '/repos/o/r/readme',
      '/repos/o/r/languages',
      '/repos/o/r/branches',
      '/repos/o/r/branches/main',
      '/repos/o/r/tags',
      '/repos/o/r/commits',
      '/repos/o/r/commits/abc',
      '/repos/o/r/compare/a...b',
      '/repos/o/r/git/trees/abc',
      '/repos/o/r/issues',
      '/repos/o/r/issues/1/comments',
      '/repos/o/r/pulls',
      '/repos/o/r/pulls/1/files',
      '/repos/o/r/labels',
      '/repos/o/r/milestones/1',
      '/repos/o/r/releases/latest',
      '/search/issues',
    ]) {
      expect(read(url, 'github.read'), url).toBe('allowed');
    }
  });
});

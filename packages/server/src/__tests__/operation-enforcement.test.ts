// A grant means what it says: every brokered call is classified on the exact
// URL and method forwarded, against a stubbed upstream, with real Permissions
// (no opt-outs unless a test is about one).
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { evaluateOperation, SLACK_MAPPED_METHODS } from '@credninja/guard';
import { LINK_SCOPE_CATALOG } from '@credninja/protocol';
import { createServer } from '../server.js';
import { auditOriginAndRoute } from '../audit-route.js';
import { actorTokenFor, delegateAs, exerciseAs, newAgent, type AgentIdentity, type App } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];

afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.unstubAllGlobals());

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-op-enforcement-'));
  tmpDirs.push(dir);
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'file',
    tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN,
    agentToken: BEARER,
    providers: (['google', 'github', 'slack', 'notion', 'salesforce', 'linear', 'hubspot'] as const).map((slug) => ({ slug, clientId: 'id', clientSecret: 'secret', defaultScopes: [] })),
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}

function stubUpstream(status = 200, headers: Record<string, string> = {}) {
  const upstream = vi.fn(async (_url: unknown, _init?: unknown) => new Response('{"ok":true}', { status, headers: { 'content-type': 'application/json', ...headers } }));
  vi.stubGlobal('fetch', upstream);
  return upstream;
}

type Server = ReturnType<typeof createServer>;

/** A server with one stored connection and an agent granted `granted` of it. */
async function connected(service: string, stored: string[], granted: string[], overrides: Partial<ServerConfig> = {}, permission: Record<string, unknown> = {}) {
  const server: Server = createServer(config(overrides));
  await server.vault.init();
  await server.vault.store({
    provider: service,
    userId: 'alice',
    accessToken: 'upstream-token',
    expiresAt: new Date(Date.now() + 3600_000),
    scopes: stored,
    ...(service === 'salesforce' ? { instanceUrl: 'https://acme.my.salesforce.com' } : {}),
  });
  const agent = await newAgent();
  await grantTo(server, agent, service, granted, permission);
  const minted = await delegateAs(server.app, agent, { service, user_id: 'alice' }, { bearer: BEARER });
  expect(minted.status, JSON.stringify(minted.body)).toBe(200);
  return { ...server, agent, token: minted.body.access_token as string, minted };
}

async function grantTo(server: Server, agent: AgentIdentity, service: string, allowedScopes: string[], permission: Record<string, unknown> = {}) {
  await server.vault.createPermission!({ agentId: agent.did, connectionId: service, allowedScopes, requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test', ...permission });
}

function call(app: App, agent: AgentIdentity, token: string, url: string, method = 'GET', body?: unknown, extraHeaders?: Record<string, string>) {
  return exerciseAs(app, agent, token, { url, method, ...(body === undefined ? {} : { body }), ...(extraHeaders ? { extra_headers: extraHeaders } : {}) });
}

async function expectAllowed(ctx: { app: App; agent: AgentIdentity; token: string }, url: string, method = 'GET', body?: unknown) {
  const upstream = stubUpstream();
  const res = await call(ctx.app, ctx.agent, ctx.token, url, method, body);
  expect(res.status, `${method} ${url}: ${JSON.stringify(res.body)}`).toBe(200);
  expect(upstream).toHaveBeenCalledTimes(1);
  expect(String(upstream.mock.calls[0]![0])).toBe(url);
}

async function expectRefused(ctx: { app: App; agent: AgentIdentity; token: string }, url: string, method: string, body: unknown, error: string, status = 403) {
  const upstream = stubUpstream();
  const res = await call(ctx.app, ctx.agent, ctx.token, url, method, body);
  expect(res.status, `${method} ${url}: ${JSON.stringify(res.body)}`).toBe(status);
  expect(res.body.error).toBe(error);
  expect(upstream).not.toHaveBeenCalled();
}

const GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me';
const CAL = 'https://www.googleapis.com/calendar/v3';

describe('Google', () => {
  it('gmail.readonly allows reading messages and refuses sending, end to end', async () => {
    const ctx = await connected('google', ['gmail.readonly'], ['gmail.readonly']);
    await expectAllowed(ctx, `${GMAIL}/messages`);
    await expectAllowed(ctx, `${GMAIL}/messages/18c2a`);
    await expectRefused(ctx, `${GMAIL}/messages/send`, 'POST', { raw: 'eA' }, 'scope_insufficient');
    await expectRefused(ctx, `${GMAIL}/messages/18c2a`, 'DELETE', undefined, 'scope_insufficient');
    await expectRefused(ctx, `${GMAIL}/drafts`, 'POST', { message: {} }, 'scope_insufficient');
  });

  it('gmail.send sends and cannot read', async () => {
    const ctx = await connected('google', ['gmail.send'], ['gmail.send']);
    await expectAllowed(ctx, `${GMAIL}/messages/send`, 'POST', { raw: 'eA' });
    await expectRefused(ctx, `${GMAIL}/messages`, 'GET', undefined, 'scope_insufficient');
  });

  it('the scope may be stored in its full URL form', async () => {
    const ctx = await connected('google', ['https://www.googleapis.com/auth/gmail.readonly'], ['https://www.googleapis.com/auth/gmail.readonly']);
    await expectAllowed(ctx, `${GMAIL}/messages`);
    await expectRefused(ctx, `${GMAIL}/messages/send`, 'POST', { raw: 'eA' }, 'scope_insufficient');
  });

  it('calendar.readonly refuses creating an event and allows the freeBusy POST', async () => {
    const ctx = await connected('google', ['calendar.readonly'], ['calendar.readonly']);
    await expectAllowed(ctx, `${CAL}/calendars/primary/events`);
    await expectAllowed(ctx, `${CAL}/users/me/calendarList`);
    await expectAllowed(ctx, `${CAL}/freeBusy`, 'POST', { timeMin: 'x', timeMax: 'y', items: [] });
    await expectRefused(ctx, `${CAL}/calendars/primary/events`, 'POST', { summary: 's' }, 'scope_insufficient');
  });

  it('calendar.events creates events', async () => {
    const ctx = await connected('google', ['calendar.events'], ['calendar.events']);
    await expectAllowed(ctx, `${CAL}/calendars/primary/events`, 'POST', { summary: 's' });
  });

  it('read and write Sheets, Docs and Drive scopes are told apart', async () => {
    const sheets = await connected('google', ['spreadsheets.readonly'], ['spreadsheets.readonly']);
    await expectAllowed(sheets, 'https://sheets.googleapis.com/v4/spreadsheets/abc/values/A1');
    await expectRefused(sheets, 'https://sheets.googleapis.com/v4/spreadsheets/abc/values/A1', 'PUT', { values: [] }, 'scope_insufficient');
    const docs = await connected('google', ['documents.readonly'], ['documents.readonly']);
    await expectAllowed(docs, 'https://docs.googleapis.com/v1/documents/abc');
    await expectRefused(docs, 'https://docs.googleapis.com/v1/documents/abc:batchUpdate', 'POST', { requests: [] }, 'scope_insufficient');
    const drive = await connected('google', ['drive.readonly'], ['drive.readonly']);
    await expectAllowed(drive, 'https://www.googleapis.com/drive/v3/files/abc');
    await expectRefused(drive, 'https://www.googleapis.com/drive/v3/files', 'POST', { name: 'x' }, 'scope_insufficient');
  });
});

describe('Slack', () => {
  it('a read scope allows a read method over POST and refuses chat.postMessage', async () => {
    const ctx = await connected('slack', ['channels:read'], ['channels:read']);
    await expectAllowed(ctx, 'https://slack.com/api/conversations.list', 'POST', { limit: 1 });
    await expectAllowed(ctx, 'https://slack.com/api/conversations.list');
    await expectRefused(ctx, 'https://slack.com/api/chat.postMessage', 'POST', { channel: 'C', text: 'x' }, 'scope_insufficient');
  });

  it('a write method runs only over POST, and an unlisted method is not mapped', async () => {
    const ctx = await connected('slack', ['chat:write'], ['chat:write']);
    await expectAllowed(ctx, 'https://slack.com/api/chat.postMessage', 'POST', { channel: 'C', text: 'x' });
    await expectRefused(ctx, 'https://slack.com/api/chat.postMessage?channel=C&text=x', 'GET', undefined, 'operation_not_mapped');
    await expectRefused(ctx, 'https://slack.com/api/admin.users.remove', 'POST', {}, 'operation_not_mapped');
    await expectRefused(ctx, 'https://slack.com/api/CHAT.POSTMESSAGE', 'POST', {}, 'operation_not_mapped');
  });
});

describe('Linear', () => {
  const LINEAR = 'https://api.linear.app/graphql';

  it('read allows a query and refuses a mutation, however it is dressed', async () => {
    const ctx = await connected('linear', ['read'], ['read']);
    await expectAllowed(ctx, LINEAR, 'POST', { query: '{ viewer { id } }' });
    await expectAllowed(ctx, LINEAR, 'POST', { query: 'query Me { viewer { id } }', operationName: 'Me' });
    for (const query of [
      'mutation { issueDelete(id: "x") { success } }',
      'mutation { harmless: issueDelete(id: "x") { success } }',
      'query Read { viewer { id } } mutation Write { issueDelete(id: "x") { success } }',
    ]) {
      await expectRefused(ctx, LINEAR, 'POST', { query, operationName: 'Read' }, 'scope_insufficient');
    }
  });

  it('unparseable bodies, subscriptions, batches and persisted queries are refused', async () => {
    const ctx = await connected('linear', ['read', 'write'], ['read', 'write']);
    for (const body of [
      { query: 'not graphql {' },
      { query: 'subscription { issues { id } }' },
      { query: 'fragment F on Issue { id }' },
      { query: 123 },
      {},
      'query { viewer { id } }',
      [{ query: '{ viewer { id } }' }],
      { query: '{ viewer { id } }', extensions: { persistedQuery: { sha256Hash: 'x' } } },
    ]) {
      await expectRefused(ctx, LINEAR, 'POST', body, 'operation_not_mapped');
    }
    await expectRefused(ctx, LINEAR, 'GET', undefined, 'operation_not_mapped');
  });

  it('write allows a mutation, and the narrow scopes allow only their own', async () => {
    const write = await connected('linear', ['read', 'write'], ['write']);
    await expectAllowed(write, LINEAR, 'POST', { query: 'mutation { issueDelete(id: "x") { success } }' });
    const create = await connected('linear', ['issues:create'], ['issues:create']);
    await expectAllowed(create, LINEAR, 'POST', { query: 'mutation { issueCreate(input: {}) { success } }' });
    await expectRefused(create, LINEAR, 'POST', { query: 'mutation { issueCreate(input: {}) { success } issueDelete(id: "x") { success } }' }, 'scope_insufficient');
    await expectRefused(create, LINEAR, 'POST', { query: 'mutation { issueDelete: issueCreate(input: {}) { success } gone: issueDelete(id: "x") { success } }' }, 'scope_insufficient');
    await expectRefused(create, LINEAR, 'POST', { query: 'mutation { ...F } fragment F on Mutation { issueDelete(id: "x") { success } }' }, 'scope_insufficient');
    await expectRefused(create, LINEAR, 'POST', { query: '{ viewer { id } }' }, 'scope_insufficient');
  });
});

describe('GitHub', () => {
  const GH = 'https://api.github.com';

  it('github.read, derived from stored repo, allows GET and refuses writes and GraphQL mutations', async () => {
    const ctx = await connected('github', ['repo'], ['github.read']);
    expect(ctx.minted.body.scopes).toEqual(['github.read']);
    await expectAllowed(ctx, `${GH}/repos/o/r/issues`);
    await expectAllowed(ctx, `${GH}/graphql`, 'POST', { query: '{ viewer { login } }' });
    await expectRefused(ctx, `${GH}/repos/o/r/contents/a.txt`, 'PUT', { message: 'm', content: 'eA' }, 'scope_insufficient');
    await expectRefused(ctx, `${GH}/repos/o/r/issues`, 'POST', { title: 't' }, 'scope_insufficient');
    await expectRefused(ctx, `${GH}/graphql`, 'POST', { query: 'mutation { createIssue(input: {}) { clientMutationId } }' }, 'scope_insufficient');
    await expectRefused(ctx, `${GH}/graphql`, 'POST', { query: 'mutation { deleteRepository(input: {}) { clientMutationId } }' }, 'operation_not_mapped');
  });

  it('GraphQL: an identity scope runs no query, and repo runs only the listed mutations', async () => {
    const identity = await connected('github', ['read:user'], ['read:user']);
    await expectRefused(identity, `${GH}/graphql`, 'POST', { query: '{ viewer { repositories(first: 1) { totalCount } } }' }, 'scope_insufficient');
    const repo = await connected('github', ['repo'], ['repo']);
    await expectAllowed(repo, `${GH}/graphql`, 'POST', { query: '{ viewer { login } }' });
    await expectAllowed(repo, `${GH}/graphql`, 'POST', { query: 'mutation { addComment(input: {}) { clientMutationId } }' });
    await expectRefused(repo, `${GH}/graphql`, 'POST', { query: 'mutation { deleteRepository(input: {}) { clientMutationId } }' }, 'operation_not_mapped');
    await expectRefused(repo, `${GH}/graphql`, 'POST', { query: 'mutation { createIssue: updateRepository(input: {}) { clientMutationId } }' }, 'operation_not_mapped');
  });

  it('repo writes, but only delete_repo deletes a repository', async () => {
    const ctx = await connected('github', ['repo'], ['repo']);
    await expectAllowed(ctx, `${GH}/repos/o/r/issues`, 'POST', { title: 't' });
    await expectRefused(ctx, `${GH}/repos/o/r`, 'DELETE', undefined, 'scope_insufficient');
  });

  it('a stored scope that does not cover github.read does not derive it', async () => {
    const server: Server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'github', userId: 'alice', accessToken: 't', expiresAt: new Date(Date.now() + 3600_000), scopes: ['read:user'] });
    const agent = await newAgent();
    await grantTo(server, agent, 'github', ['github.read']);
    const res = await delegateAs(server.app, agent, { service: 'github', user_id: 'alice' }, { bearer: BEARER });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_scope');
  });
});

describe('HubSpot', () => {
  const HS = 'https://api.hubapi.com/crm/v3/objects/contacts';

  it('a .read scope allows GET and POST search, and refuses create', async () => {
    const ctx = await connected('hubspot', ['crm.objects.contacts.read'], ['crm.objects.contacts.read']);
    await expectAllowed(ctx, HS);
    await expectAllowed(ctx, `${HS}/42`);
    await expectAllowed(ctx, `${HS}/search`, 'POST', { filterGroups: [] });
    await expectRefused(ctx, HS, 'POST', { properties: {} }, 'scope_insufficient');
    await expectRefused(ctx, `${HS}/42`, 'DELETE', undefined, 'scope_insufficient');
    await expectRefused(ctx, 'https://api.hubapi.com/crm/v3/objects/deals', 'GET', undefined, 'scope_insufficient');
  });

  it('batch endpoints are refused, even with the write scope', async () => {
    const ctx = await connected('hubspot', ['crm.objects.contacts.read', 'crm.objects.contacts.write'], ['crm.objects.contacts.read', 'crm.objects.contacts.write']);
    await expectRefused(ctx, `${HS}/batch/read`, 'POST', { inputs: [] }, 'operation_not_mapped');
    await expectRefused(ctx, `${HS}/batch/create`, 'POST', { inputs: [] }, 'operation_not_mapped');
  });
});

describe('Notion', () => {
  const NOTION = 'https://api.notion.com/v1';

  it('notion.read allows reads and refuses writes', async () => {
    const ctx = await connected('notion', [], ['notion.read']);
    expect(ctx.minted.body.scopes).toEqual(['notion.read']);
    await expectAllowed(ctx, `${NOTION}/pages/abc`);
    await expectAllowed(ctx, `${NOTION}/search`, 'POST', { query: 'x' });
    await expectAllowed(ctx, `${NOTION}/data_sources/abc/query`, 'POST', {});
    await expectRefused(ctx, `${NOTION}/pages`, 'POST', { parent: {} }, 'scope_insufficient');
    await expectRefused(ctx, `${NOTION}/pages/abc`, 'PATCH', { archived: true }, 'scope_insufficient');
    await expectRefused(ctx, `${NOTION}/blocks/abc`, 'DELETE', undefined, 'scope_insufficient');
  });

  it('a delegation with no named read scope is write-capable', async () => {
    const ctx = await connected('notion', [], ['content']);
    await expectAllowed(ctx, `${NOTION}/pages`, 'POST', { parent: {} });
    await expectAllowed(ctx, `${NOTION}/pages/abc`);
  });

  it('a file upload is refused', async () => {
    const ctx = await connected('notion', [], ['content']);
    await expectRefused(ctx, `${NOTION}/file_uploads`, 'POST', {}, 'operation_not_mapped');
  });
});

describe('Salesforce', () => {
  const SF = 'https://acme.my.salesforce.com/services/data/v60.0';

  it('salesforce.read allows reads and refuses writes', async () => {
    const ctx = await connected('salesforce', ['api', 'refresh_token'], ['salesforce.read']);
    expect(ctx.minted.body.scopes).toEqual(['salesforce.read']);
    await expectAllowed(ctx, `${SF}/query?q=SELECT+Id+FROM+Account`);
    await expectAllowed(ctx, `${SF}/sobjects/Account/001`);
    await expectRefused(ctx, `${SF}/sobjects/Account`, 'POST', { Name: 'x' }, 'scope_insufficient');
    await expectRefused(ctx, `${SF}/sobjects/Account/001`, 'PATCH', { Name: 'x' }, 'scope_insufficient');
    await expectRefused(ctx, `${SF}/sobjects/Account/001`, 'DELETE', undefined, 'scope_insufficient');
  });

  it('api writes, and composite, tooling and Apex REST are not mapped', async () => {
    const ctx = await connected('salesforce', ['api'], ['api']);
    await expectAllowed(ctx, `${SF}/sobjects/Account`, 'POST', { Name: 'x' });
    await expectRefused(ctx, `${SF}/composite/batch`, 'POST', { batchRequests: [] }, 'operation_not_mapped');
    await expectRefused(ctx, `${SF}/composite/sobjects`, 'POST', { records: [] }, 'operation_not_mapped');
    await expectRefused(ctx, `${SF}/tooling/query?q=x`, 'GET', undefined, 'operation_not_mapped');
    await expectRefused(ctx, 'https://acme.my.salesforce.com/services/apexrest/Delete', 'GET', undefined, 'operation_not_mapped');
  });
});

describe('derived read scopes reach every grant path', () => {
  it('a scope ceiling of the derived scope, or of its source, admits it', async () => {
    const server: Server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'github', userId: 'alice', accessToken: 't', expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
    const now = new Date().toISOString();
    const narrow = await newAgent();
    await server.vault.registerAgent!({ id: 'agt_narrow', did: narrow.did, name: 'n', fingerprint: 'fp_n', scopeCeiling: ['github.read'], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now });
    await grantTo(server, narrow, 'github', ['repo', 'github.read']);
    const capped = await delegateAs(server.app, narrow, { service: 'github', user_id: 'alice' }, { bearer: BEARER });
    expect(capped.status, JSON.stringify(capped.body)).toBe(200);
    expect(capped.body.scopes).toEqual(['github.read']);
    const overReach = await delegateAs(server.app, narrow, { service: 'github', user_id: 'alice', scopes: ['repo'] }, { bearer: BEARER });
    expect(overReach.status).toBe(403);
    expect(overReach.body.error).toBe('scope_ceiling_exceeded');

    const wide = await newAgent();
    await server.vault.registerAgent!({ id: 'agt_wide', did: wide.did, name: 'w', fingerprint: 'fp_w', scopeCeiling: ['repo'], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now });
    await grantTo(server, wide, 'github', ['github.read']);
    const asked = await delegateAs(server.app, wide, { service: 'github', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER });
    expect(asked.status, JSON.stringify(asked.body)).toBe(200);
    expect(asked.body.scopes).toEqual(['github.read']);
  });

  for (const [service, stored, parentScope, childScope, url] of [
    ['github', ['repo'], 'repo', 'github.read', 'https://api.github.com/repos/o/r'],
    ['salesforce', ['api'], 'api', 'salesforce.read', 'https://acme.my.salesforce.com/services/data/v60.0/sobjects/Account/001'],
    ['notion', [], 'content', 'notion.read', 'https://api.notion.com/v1/pages/abc'],
  ] as const) {
    it(`${service}: a child can narrow to ${childScope}, not the other way round`, async () => {
      const ctx = await connected(service, [...stored], [parentScope], {}, { delegatable: true, maxDelegationDepth: 3 });
      const child = await newAgent();
      await grantTo(ctx, child, service, [childScope], { delegatable: true, maxDelegationDepth: 3 });
      const sub = await request(ctx.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
        parent_receipt: ctx.minted.body.receipt,
        agent_did: child.did,
        service,
        user_id: 'alice',
        scopes: [childScope],
        actor_token: actorTokenFor(ctx.agent, '/api/v1/subdelegate'),
      });
      expect(sub.status, JSON.stringify(sub.body)).toBe(200);
      expect(sub.body.scopes).toEqual([childScope]);
      await expectAllowed({ app: ctx.app, agent: child, token: sub.body.access_token }, url);

      const grandchild = await newAgent();
      await grantTo(ctx, grandchild, service, [parentScope], { delegatable: true, maxDelegationDepth: 3 });
      const widened = await request(ctx.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
        parent_receipt: sub.body.receipt,
        agent_did: grandchild.did,
        service,
        user_id: 'alice',
        scopes: [parentScope],
        actor_token: actorTokenFor(child, '/api/v1/subdelegate'),
      });
      expect(widened.status).toBe(403);
    });
  }

  it('renewal through the default-request path: a child asking for nothing keeps the derived scope', async () => {
    const ctx = await connected('github', ['repo'], ['github.read'], {}, { delegatable: true, maxDelegationDepth: 3 });
    const child = await newAgent();
    await grantTo(ctx, child, 'github', ['github.read'], { delegatable: true, maxDelegationDepth: 3 });
    const sub = await request(ctx.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: ctx.minted.body.receipt,
      agent_did: child.did,
      service: 'github',
      user_id: 'alice',
      actor_token: actorTokenFor(ctx.agent, '/api/v1/subdelegate'),
    });
    expect(sub.status, JSON.stringify(sub.body)).toBe(200);
    expect(sub.body.scopes).toEqual(['github.read']);
  });

  it('renewal: a child of a repo parent asking for nothing gets what the parent has, not both names', async () => {
    const ctx = await connected('github', ['repo'], ['repo'], {}, { delegatable: true, maxDelegationDepth: 3 });
    const child = await newAgent();
    await grantTo(ctx, child, 'github', ['repo'], { delegatable: true, maxDelegationDepth: 3 });
    const sub = await request(ctx.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: ctx.minted.body.receipt,
      agent_did: child.did,
      service: 'github',
      user_id: 'alice',
      actor_token: actorTokenFor(ctx.agent, '/api/v1/subdelegate'),
    });
    expect(sub.status, JSON.stringify(sub.body)).toBe(200);
    expect(sub.body.scopes).toEqual(['repo']);
  });

  it('the sub-delegation ceiling site: a child capped to the derived scope is issued only that', async () => {
    const ctx = await connected('github', ['repo'], ['repo'], {}, { delegatable: true, maxDelegationDepth: 3 });
    const child = await newAgent();
    const now = new Date().toISOString();
    await ctx.vault.registerAgent!({ id: 'agt_capped', did: child.did, name: 'c', fingerprint: 'fp_c', scopeCeiling: ['github.read'], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now });
    await grantTo(ctx, child, 'github', ['repo', 'github.read'], { delegatable: true, maxDelegationDepth: 3 });
    const sub = await request(ctx.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: ctx.minted.body.receipt,
      agent_did: child.did,
      service: 'github',
      user_id: 'alice',
      scopes: ['github.read'],
      actor_token: actorTokenFor(ctx.agent, '/api/v1/subdelegate'),
    });
    expect(sub.status, JSON.stringify(sub.body)).toBe(200);
    expect(sub.body.scopes).toEqual(['github.read']);
    await expectRefused({ app: ctx.app, agent: child, token: sub.body.access_token }, 'https://api.github.com/repos/o/r/issues', 'POST', { title: 't' }, 'scope_insufficient');
  });

  it('error order is unchanged: a narrow Permission and a wider request is scope_escalation_denied', async () => {
    const ctx = await connected('github', ['repo'], ['github.read']);
    const res = await delegateAs(ctx.app, ctx.agent, { service: 'github', user_id: 'alice', scopes: ['repo'] }, { bearer: BEARER });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('scope_escalation_denied');
  });

  it('a derived scope cannot be asked for unless the Permission allows it', async () => {
    const ctx = await connected('github', ['repo'], ['repo']);
    const res = await delegateAs(ctx.app, ctx.agent, { service: 'github', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('scope_escalation_denied');
  });

  it('a derived scope for another provider covers nothing', async () => {
    const server: Server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'slack', userId: 'alice', accessToken: 't', expiresAt: new Date(Date.now() + 3600_000), scopes: ['channels:read'] });
    const agent = await newAgent();
    await grantTo(server, agent, 'slack', ['github.read']);
    const res = await delegateAs(server.app, agent, { service: 'slack', user_id: 'alice', scopes: ['github.read'] }, { bearer: BEARER });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('scope_escalation_denied');
  });

  it('a capability token narrowed to the derived scope is held to it, and catalogue reads work under it', async () => {
    const ctx = await connected('github', ['repo'], ['repo', 'github.read']);
    const scoped = await delegateAs(ctx.app, ctx.agent, {
      service: 'github',
      user_id: 'alice',
      authorization_details: [{ type: 'cred_delegation', provider: 'github', operations: ['github.read'] }],
    }, { bearer: BEARER });
    expect(scoped.status, JSON.stringify(scoped.body)).toBe(200);
    const narrowed = { app: ctx.app, agent: ctx.agent, token: scoped.body.access_token as string };
    await expectAllowed(narrowed, 'https://api.github.com/repos/o/r');
    await expectRefused(narrowed, 'https://api.github.com/repos/o/r/issues', 'POST', { title: 't' }, 'capability_denied');

    const read = await connected('github', ['repo'], ['github.read']);
    const catalogue = await delegateAs(read.app, read.agent, {
      service: 'github',
      user_id: 'alice',
      authorization_details: [{ type: 'cred_delegation', provider: 'github', operations: ['github.repos.get'], resources: ['repo:o/r'] }],
    }, { bearer: BEARER });
    expect(catalogue.status, JSON.stringify(catalogue.body)).toBe(200);
    await expectAllowed({ app: read.app, agent: read.agent, token: catalogue.body.access_token }, 'https://api.github.com/repos/o/r');
    const writeOp = await delegateAs(read.app, read.agent, {
      service: 'github',
      user_id: 'alice',
      authorization_details: [{ type: 'cred_delegation', provider: 'github', operations: ['github.issues.create'] }],
    }, { bearer: BEARER });
    expect(writeOp.status).toBe(400);
  });
});

describe('fail closed', () => {
  it('an unmapped URL is refused and audited', async () => {
    const ctx = await connected('github', ['repo'], ['repo']);
    await expectRefused(ctx, 'https://api.github.com/enterprises/acme/settings', 'GET', undefined, 'operation_not_mapped');
    const event = ctx.vault.queryAuditEvents({ limit: 50 }).find((e) => e.errorMessage === 'operation_not_mapped');
    expect(event?.actor.id).toBe(ctx.agent.did);
    expect(event?.metadata).toMatchObject({ method: 'GET', origin: 'https://api.github.com' });
  });

  it('a scope the table does not know is refused as not mapped, and audited', async () => {
    const ctx = await connected('github', ['made:up'], ['made:up']);
    await expectRefused(ctx, 'https://api.github.com/repos/o/r', 'GET', undefined, 'operation_not_mapped');
    expect(ctx.vault.queryAuditEvents({ limit: 50 }).some((e) => e.errorMessage === 'operation_not_mapped')).toBe(true);
  });

  it('a grant that does not cover the call is audited as scope_insufficient', async () => {
    const ctx = await connected('google', ['gmail.readonly'], ['gmail.readonly']);
    await expectRefused(ctx, `${GMAIL}/messages/send`, 'POST', { raw: 'eA' }, 'scope_insufficient');
    const event = ctx.vault.queryAuditEvents({ limit: 50 }).find((e) => e.errorMessage === 'scope_insufficient');
    expect(event?.actor.id).toBe(ctx.agent.did);
    expect(event?.metadata).toMatchObject({ method: 'POST', access: 'write', route: '/gmail/v1/users/me/messages/send' });
    expect(JSON.stringify(event)).not.toContain('eA');
  });

  it('encoded or dot-segment paths, doubled slashes and trailing-dot hosts cannot reach a write endpoint', async () => {
    const ctx = await connected('google', ['gmail.readonly'], ['gmail.readonly']);
    for (const url of [
      'https://gmail.googleapis.com/gmail/v1/users/me/messages%2Fsend',
      'https://gmail.googleapis.com/gmail/v1/users/me/messages%2fsend',
      'https://gmail.googleapis.com/gmail/v1/users/me/messages/%252e/send',
      'https://gmail.googleapis.com/gmail/v1//users/me/messages/send',
      'https://gmail.googleapis.com./gmail/v1/users/me/messages/send',
    ]) {
      await expectRefused(ctx, url, 'POST', { raw: 'eA' }, `URL is not allowed for google with the delegated scopes`, 400);
    }
    // URL parsing resolves dot segments, %2e included, before any check: the call is judged as what it really is.
    for (const url of [
      'https://gmail.googleapis.com/gmail/v1/users/me/labels/../messages/send',
      'https://gmail.googleapis.com/gmail/v1/users/me/%2e%2e/me/messages/send',
      'https://gmail.googleapis.com/gmail/v1/users/me/messages/%2E%2e/messages/send',
      'https://gmail.googleapis.com/gmail/v1/users/me/messages\\send',
    ]) {
      await expectRefused(ctx, url, 'POST', { raw: 'eA' }, 'scope_insufficient');
    }
    // An encoded plain letter is a literal the table will not match, in any position.
    await expectRefused(ctx, 'https://gmail.googleapis.com/gmail/v1/users/me/messages/s%65nd', 'POST', { raw: 'eA' }, 'operation_not_mapped');
    await expectRefused(ctx, 'https://gmail.googleapis.com/gmail/v1/users/me/messages/x%65/trash', 'GET', undefined, 'operation_not_mapped');
    // A matrix parameter some servers strip cannot hide a segment.
    await expectRefused(ctx, 'https://gmail.googleapis.com/gmail/v1/users/me/messages;x=1/send', 'POST', { raw: 'eA' }, 'operation_not_mapped');
    await expectRefused(ctx, `${GMAIL}/messages/send/`, 'POST', { raw: 'eA' }, 'operation_not_mapped');
  });

  it('every method override channel is refused, not silently dropped', async () => {
    const ctx = await connected('google', ['gmail.readonly'], ['gmail.readonly']);
    const message = `${GMAIL}/messages/1`;
    for (const key of ['$httpMethod', '_HttpMethod', '_method', 'x-http-method-override', 'method']) {
      await expectRefused(ctx, `${message}?${encodeURIComponent(key)}=DELETE`, 'GET', undefined, 'invalid_request', 400);
    }
    const upstream = stubUpstream();
    for (const header of ['X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override', 'x-http-method-override', 'X-Original-URL', 'X-Rewrite-URL']) {
      const res = await call(ctx.app, ctx.agent, ctx.token, message, 'GET', undefined, { [header]: 'DELETE' });
      expect(res.status, header).toBe(400);
      expect(res.body.error).toBe('invalid_request');
    }
    const writer = await connected('google', ['gmail.send', 'gmail.readonly'], ['gmail.send', 'gmail.readonly']);
    for (const key of ['_method', '$httpMethod', '_HttpMethod', 'X-HTTP-Method-Override']) {
      const res = await call(writer.app, writer.agent, writer.token, `${GMAIL}/messages/send`, 'POST', { [key]: 'DELETE', raw: 'eA' });
      expect(res.status, key).toBe(400);
      expect(res.body.error).toBe('invalid_request');
    }
    expect(upstream).not.toHaveBeenCalled();
    const audited = writer.vault.queryAuditEvents({ limit: 50 }).find((e) => e.errorMessage === 'method_override_refused');
    expect(audited?.actor.id).toBe(writer.agent.did);
  });

  it('a body field merely named method is not an override', async () => {
    const ctx = await connected('linear', ['read'], ['read']);
    await expectAllowed(ctx, 'https://api.linear.app/graphql', 'POST', { query: '{ viewer { id } }', variables: { method: 'x' } });
  });

  it('batch and multipart endpoints are refused', async () => {
    const ctx = await connected('google', ['drive', 'gmail.modify'], ['drive', 'gmail.modify']);
    await expectRefused(ctx, 'https://www.googleapis.com/batch/drive/v3', 'POST', {}, 'URL is not allowed for google with the delegated scopes', 400);
    await expectRefused(ctx, 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', 'POST', {}, 'operation_not_mapped');
    await expectRefused(ctx, 'https://www.googleapis.com/drive/v3/files?uploadType=multipart', 'POST', {}, 'operation_not_mapped');
    await expectRefused(ctx, `${GMAIL}/messages/batchDelete`, 'POST', { ids: [] }, 'operation_not_mapped');
  });

  it('a Content-Type mismatch cannot hide a method', async () => {
    const ctx = await connected('linear', ['read'], ['read']);
    const upstream = stubUpstream();
    for (const contentType of ['application/graphql', 'multipart/form-data; boundary=x', 'application/x-www-form-urlencoded', 'text/plain']) {
      const res = await call(ctx.app, ctx.agent, ctx.token, 'https://api.linear.app/graphql', 'POST', { query: '{ viewer { id } }' }, { 'Content-Type': contentType });
      expect(res.status, contentType).toBe(403);
      expect(res.body.error).toBe('operation_not_mapped');
    }
    expect(upstream).not.toHaveBeenCalled();
    const fine = await call(ctx.app, ctx.agent, ctx.token, 'https://api.linear.app/graphql', 'POST', { query: '{ viewer { id } }' }, { 'content-type': 'application/json; charset=utf-8' });
    expect(fine.status).toBe(200);
  });

  it('a redirect is not followed, and the token does not travel', async () => {
    const ctx = await connected('google', ['gmail.readonly'], ['gmail.readonly']);
    const upstream = stubUpstream(302, { location: 'https://evil.example.com/steal' });
    const res = await call(ctx.app, ctx.agent, ctx.token, `${GMAIL}/messages`);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe(302);
    expect(upstream).toHaveBeenCalledTimes(1);
    expect((upstream.mock.calls[0]![1] as RequestInit).redirect).toBe('manual');
    expect(JSON.stringify(res.body)).not.toContain('evil.example.com');
  });

  it('a narrowed capability token cannot exercise a wider parent scope', async () => {
    const ctx = await connected('google', ['gmail.readonly', 'gmail.send'], ['gmail.readonly', 'gmail.send']);
    const narrowed = await delegateAs(ctx.app, ctx.agent, {
      service: 'google',
      user_id: 'alice',
      authorization_details: [{ type: 'cred_delegation', provider: 'google', operations: ['gmail.readonly'] }],
    }, { bearer: BEARER });
    expect(narrowed.status, JSON.stringify(narrowed.body)).toBe(200);
    const token = { app: ctx.app, agent: ctx.agent, token: narrowed.body.access_token as string };
    await expectAllowed(token, `${GMAIL}/messages`);
    await expectRefused(token, `${GMAIL}/messages/send`, 'POST', { raw: 'eA' }, 'capability_denied');
  });
});

describe('the tables agree with what the rest of the code says', () => {
  const WRITES: Record<string, Array<[string, string, unknown?]>> = {
    google: [
      ['POST', 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {}],
      ['POST', 'https://www.googleapis.com/calendar/v3/calendars/primary/events', {}],
      ['POST', 'https://www.googleapis.com/drive/v3/files', {}],
      ['PUT', 'https://sheets.googleapis.com/v4/spreadsheets/a/values/A1', {}],
      ['POST', 'https://docs.googleapis.com/v1/documents/a:batchUpdate', {}],
    ],
    github: [['POST', 'https://api.github.com/repos/o/r/issues', {}], ['PATCH', 'https://api.github.com/user', {}], ['POST', 'https://api.github.com/graphql', { query: 'mutation { createIssue(input: {}) { clientMutationId } }' }]],
    slack: [['POST', 'https://slack.com/api/chat.postMessage', {}], ['POST', 'https://slack.com/api/files.getUploadURLExternal', {}]],
    linear: [['POST', 'https://api.linear.app/graphql', { query: 'mutation { issueDelete(id: "x") { success } }' }]],
    hubspot: [['POST', 'https://api.hubapi.com/crm/v3/objects/contacts', {}]],
    salesforce: [['POST', 'https://acme.my.salesforce.com/services/data/v60.0/sobjects/Account', {}]],
    notion: [['POST', 'https://api.notion.com/v1/pages', {}]],
  };

  it('no scope the Link catalog labels read can reach a write', () => {
    const reads = LINK_SCOPE_CATALOG.filter((entry) => entry.access === 'read');
    expect(reads.length).toBeGreaterThan(10);
    for (const entry of reads) {
      for (const [method, url, body] of WRITES[entry.provider]!) {
        const verdict = evaluateOperation({ service: entry.provider, method, url, body }, [entry.scope]);
        expect(verdict.outcome, `${entry.provider} ${entry.scope} ${method} ${url}`).not.toBe('allowed');
      }
    }
  });

  it('the audit log can name every Slack method the table maps', () => {
    for (const name of SLACK_MAPPED_METHODS) {
      expect(auditOriginAndRoute(`https://slack.com/api/${name}`, () => true).route).toBe(`/api/${name}`);
    }
  });
});

describe('raw tokens', () => {
  it('a derived read scope is never issued as a raw token, which could write', async () => {
    const server: Server = createServer(config({ allowRawTokens: true }));
    await server.vault.init();
    await server.vault.store({ provider: 'github', userId: 'alice', accessToken: 'gho_full', expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
    const agent = await newAgent();
    await grantTo(server, agent, 'github', ['github.read']);
    const res = await request(server.app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .send({ service: 'github', user_id: 'alice', token_format: 'raw', agent_did: agent.did });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_scope');
    expect(JSON.stringify(res.body)).not.toContain('gho_full');
  });

  it('a raw request naming no agent is issued what is stored, with no derived scope', async () => {
    const server: Server = createServer(config({ allowRawTokens: true }));
    await server.vault.init();
    await server.vault.store({ provider: 'github', userId: 'alice', accessToken: 'gho_full', expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
    const res = await request(server.app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .send({ service: 'github', user_id: 'alice', token_format: 'raw' });
    expect(res.status).toBe(200);
    expect(res.body.scopes).toEqual(['repo']);
  });
});

describe('Guard narrowing to nothing', () => {
  it('a Notion delegation left with no scopes covers nothing', async () => {
    const { evaluateOperation } = await import('@credninja/guard');
    expect(evaluateOperation({ service: 'notion', method: 'POST', url: 'https://api.notion.com/v1/pages', body: {} }, []).outcome).toBe('insufficient');
    expect(evaluateOperation({ service: 'notion', method: 'GET', url: 'https://api.notion.com/v1/pages/x' }, []).outcome).toBe('insufficient');
  });
});

describe('the opt-out', () => {
  it('restores the old behavior, warns at startup and marks each audit event', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const ctx = await connected('google', ['gmail.readonly'], ['gmail.readonly'], { allowUnclassifiedBrokerCalls: true });
    expect(warn.mock.calls.some(([m]) => String(m).includes('CRED_ALLOW_UNCLASSIFIED_BROKER_CALLS=true'))).toBe(true);
    warn.mockRestore();
    await expectAllowed(ctx, `${GMAIL}/messages/send`, 'POST', { raw: 'eA' });
    const event = ctx.vault.queryAuditEvents({ limit: 50 }).find((e) => e.action === 'access' && e.outcome === 'success');
    expect(event?.metadata?.enforcementOptOuts).toEqual(['unclassified_broker_calls']);
    // The family check still applies: this was never a way out of the URL allowlist.
    await expectRefused(ctx, 'https://www.googleapis.com/drive/v3/files', 'GET', undefined, 'URL is not allowed for google with the delegated scopes', 400);
  });

  it('with it off, nothing warns about it and events carry no marker', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const ctx = await connected('google', ['gmail.readonly'], ['gmail.readonly']);
    expect(warn.mock.calls.some(([m]) => String(m).includes('CRED_ALLOW_UNCLASSIFIED_BROKER_CALLS'))).toBe(false);
    warn.mockRestore();
    await expectAllowed(ctx, `${GMAIL}/messages`);
    const event = ctx.vault.queryAuditEvents({ limit: 50 }).find((e) => e.action === 'access' && e.outcome === 'success');
    expect(event?.metadata?.enforcementOptOuts).toBeUndefined();
  });
});

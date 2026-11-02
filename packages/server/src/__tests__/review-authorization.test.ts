// Authorization regressions: what a scope list means on each grant path.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { CredGuard, type CredPolicy, narrowedScopeStaysExposed, withDerivedScopes, withStoredDerivedScopes } from '@credninja/guard';
import { createServer } from '../server.js';
import { actorTokenFor, delegateAs, newAgent, type AgentIdentity } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.unstubAllGlobals());

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-review-auth-'));
  tmpDirs.push(dir);
  return {
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: BEARER,
    providers: (['notion', 'github', 'google', 'hubspot'] as const).map((slug) => ({ slug, clientId: 'id', clientSecret: 'secret', defaultScopes: [] })),
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}

type Server = ReturnType<typeof createServer>;
const grant = (server: Server, agent: AgentIdentity, service: string, allowedScopes: string[], extra: Record<string, unknown> = {}) =>
  server.vault.createPermission!({ agentId: agent.did, connectionId: service, allowedScopes, requiresApproval: false, delegatable: true, maxDelegationDepth: 3, createdBy: 'test', ...extra });
async function connected(service: string, scopes: string[], overrides: Partial<ServerConfig> = {}) {
  const server = createServer(config(overrides));
  await server.vault.init();
  await server.vault.store({ provider: service, userId: 'alice', accessToken: 'upstream', expiresAt: new Date(Date.now() + 3600_000), scopes });
  return server;
}
const delegate = (server: Server, agent: AgentIdentity, service: string, body: Record<string, unknown> = {}) =>
  delegateAs(server.app, agent, { service, user_id: 'alice', ...body }, { bearer: BEARER });
const subdelegate = (server: Server, parent: AgentIdentity, receipt: string, child: AgentIdentity, service: string, body: Record<string, unknown> = {}) =>
  request(server.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
    parent_receipt: receipt, agent_did: child.did, service, user_id: 'alice', actor_token: actorTokenFor(parent, '/api/v1/subdelegate'), ...body,
  });

describe('the whole-connection rule applies only to stored connection scopes', () => {
  it('splits the helper: an empty grant list stays empty, an empty stored list does not', () => {
    expect(withDerivedScopes('notion', [])).toEqual([]);
    expect(withStoredDerivedScopes('notion', [])).toEqual(expect.arrayContaining(['notion.read', 'content']));
    expect(withDerivedScopes('notion', ['update_content'])).not.toContain('content');
    expect(withStoredDerivedScopes('notion', ['update_content'])).not.toContain('content');
    expect(withStoredDerivedScopes('notion', ['read_content'])).not.toContain('content');
    expect(withDerivedScopes('notion', ['content'])).toContain('notion.read');
    expect(withDerivedScopes('github', [])).toEqual([]);
    expect(withStoredDerivedScopes('github', [])).toEqual([]);
  });

  it('a child whose Permission allows nothing gets nothing under a Notion parent', async () => {
    const server = await connected('notion', []);
    const parent = await newAgent();
    await grant(server, parent, 'notion', ['content']);
    const root = await delegate(server, parent, 'notion');
    expect(root.status).toBe(200);
    const child = await newAgent();
    await grant(server, child, 'notion', []);
    const sub = await subdelegate(server, parent, root.body.receipt, child, 'notion');
    expect(sub.status, JSON.stringify(sub.body)).toBe(403);
    expect(sub.body.access_token).toBeUndefined();
  });

  it('an empty ceiling is still no ceiling, and an empty Permission still grants nothing at /delegate', async () => {
    const server = await connected('notion', []);
    const agent = await newAgent();
    await grant(server, agent, 'notion', []);
    const res = await delegate(server, agent, 'notion');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_scope');
  });
});

describe('a Permission covers what its scopes derive', () => {
  it('Permission [repo] plus a request for github.read returns github.read', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    await grant(server, agent, 'github', ['repo']);
    const res = await delegate(server, agent, 'github', { scopes: ['github.read'] });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual(['github.read']);
    const plain = await delegate(server, agent, 'github');
    expect(plain.body.scopes).toEqual(['repo']);
  });

  it('and not the reverse: Permission [github.read] plus a request for repo is refused', async () => {
    const server = await connected('github', ['repo']);
    const agent = await newAgent();
    await grant(server, agent, 'github', ['github.read']);
    const res = await delegate(server, agent, 'github', { scopes: ['repo'] });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('scope_escalation_denied');
  });

  it('a wildcard Permission reaches a matching stored scope at /delegate and at /subdelegate, and no other', async () => {
    const server = await connected('hubspot', ['crm.objects.contacts.read', 'crm.objects.deals.read', 'oauth']);
    const agent = await newAgent();
    await grant(server, agent, 'hubspot', ['crm.objects.*']);
    const root = await delegate(server, agent, 'hubspot');
    expect(root.status, JSON.stringify(root.body)).toBe(200);
    expect(root.body.scopes.sort()).toEqual(['crm.objects.contacts.read', 'crm.objects.deals.read']);
    expect((await delegate(server, agent, 'hubspot', { scopes: ['oauth'] })).status).toBe(403);
    const child = await newAgent();
    await grant(server, child, 'hubspot', ['crm.objects.contacts.*']);
    const sub = await subdelegate(server, agent, root.body.receipt, child, 'hubspot', { scopes: ['crm.objects.contacts.read'] });
    expect(sub.status, JSON.stringify(sub.body)).toBe(200);
    expect(sub.body.scopes).toEqual(['crm.objects.contacts.read']);
    const refused = await subdelegate(server, agent, root.body.receipt, child, 'hubspot', { scopes: ['crm.objects.deals.read'] });
    expect(refused.status).toBe(403);
  });
});

describe('the chain verifier uses the same coverage', () => {
  it('three hops: repo, github.read, github.read verify through ancestor_receipts', async () => {
    const server = await connected('github', ['repo']);
    const [a, b, c] = [await newAgent(), await newAgent(), await newAgent()];
    await grant(server, a, 'github', ['repo']);
    await grant(server, b, 'github', ['github.read']);
    await grant(server, c, 'github', ['github.read']);
    const root = await delegate(server, a, 'github');
    const mid = await subdelegate(server, a, root.body.receipt, b, 'github', { scopes: ['github.read'] });
    expect(mid.status, JSON.stringify(mid.body)).toBe(200);
    const leaf = await subdelegate(server, b, mid.body.receipt, c, 'github', { scopes: ['github.read'], ancestor_receipts: [root.body.receipt] });
    expect(leaf.status, JSON.stringify(leaf.body)).toBe(200);
    expect(leaf.body.scopes).toEqual(['github.read']);
  });
});

describe('Guard sees what the agent could be issued', () => {
  it('a request naming no scope shows Guard the Permission\'s scopes, not the whole connection', async () => {
    const seen: string[][] = [];
    const policy: CredPolicy = { name: 'record', evaluate: (ctx) => {
      seen.push([...ctx.requestedScopes]);
      return { decision: 'ALLOW', policy: 'record' };
    } };
    const server = await connected('google', ['calendar.readonly', 'gmail.send'], { guard: new CredGuard({ policies: [policy] }) });
    const agent = await newAgent();
    await grant(server, agent, 'google', ['calendar.readonly']);
    const res = await delegate(server, agent, 'google');
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(seen[0]).toEqual(['calendar.readonly']);
    expect(res.body.scopes).toEqual(['calendar.readonly']);
  });

  it('a policy keyed on a scope the agent cannot get does not refuse it', async () => {
    const policy: CredPolicy = { name: 'no-send', evaluate: (ctx) => (ctx.requestedScopes.includes('gmail.send')
      ? { decision: 'DENY', policy: 'no-send', reason: 'send' }
      : { decision: 'ALLOW', policy: 'no-send' }) };
    const server = await connected('google', ['calendar.readonly', 'gmail.send'], { guard: new CredGuard({ policies: [policy] }) });
    const agent = await newAgent();
    await grant(server, agent, 'google', ['calendar.readonly']);
    expect((await delegate(server, agent, 'google')).status).toBe(200);
  });

  it('an agent with no Permission is still told what fixes it, under a Guard', async () => {
    const policy: CredPolicy = { name: 'allow', evaluate: () => ({ decision: 'ALLOW', policy: 'allow' }) };
    const server = await connected('google', ['calendar.readonly'], { guard: new CredGuard({ policies: [policy] }) });
    const res = await delegate(server, await newAgent(), 'google');
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('permission_required');
  });
});

describe('narrowedScopeStaysExposed', () => {
  it('names a remaining partitioned scope when the token holds a wider or sibling one', () => {
    expect(narrowedScopeStaysExposed('google', ['drive.file'], ['drive', 'drive.file'])).toBe(true);
    expect(narrowedScopeStaysExposed('google', ['drive.metadata.readonly'], ['drive.readonly', 'drive.metadata.readonly'])).toBe(true);
    expect(narrowedScopeStaysExposed('slack', ['channels:read'], ['channels:read', 'groups:read'])).toBe(true);
    expect(narrowedScopeStaysExposed('slack', ['im:history'], ['im:history', 'channels:history'])).toBe(true);
  });

  it('is false when nothing partitioned remains, or nothing beyond it is held', () => {
    expect(narrowedScopeStaysExposed('google', ['drive.file'], ['drive.file'])).toBe(false);
    expect(narrowedScopeStaysExposed('google', ['drive.readonly'], ['drive', 'drive.readonly'])).toBe(false);
    expect(narrowedScopeStaysExposed('google', ['gmail.readonly'], ['gmail.send', 'gmail.readonly'])).toBe(false);
    expect(narrowedScopeStaysExposed('slack', ['channels:read'], ['channels:read', 'chat:write'])).toBe(false);
    expect(narrowedScopeStaysExposed('slack', ['channels:read', 'groups:read'], ['channels:read', 'groups:read'])).toBe(false);
    expect(narrowedScopeStaysExposed('github', ['repo'], ['repo', 'workflow'])).toBe(false);
  });
});


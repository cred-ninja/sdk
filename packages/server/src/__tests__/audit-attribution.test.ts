// The audit log answers which agent did what: brokered calls name the agent,
// the delegation and a redacted route, and refusals are events too.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { CredGuard, type CredPolicy } from '@credninja/guard';
import { createServer } from '../server.js';
import { auditOriginAndRoute } from '../audit-route.js';
import { delegateAs, exerciseAs, newAgent, type AgentIdentity, type App } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];
const CAL = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';

afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.restoreAllMocks());

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-audit-attr-'));
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
    providers: [{ slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: ['calendar.readonly'] }],
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}

async function setup(overrides: Partial<ServerConfig> = {}) {
  const server = createServer(config(overrides));
  await server.vault.init();
  await server.vault.store({
    provider: 'google',
    userId: 'alice',
    accessToken: 'ya29.audit-attribution',
    expiresAt: new Date(Date.now() + 3600_000),
    scopes: ['calendar.readonly'],
  });
  return server;
}

async function issued(app: App, vault: Awaited<ReturnType<typeof setup>>['vault'], extra: Record<string, unknown> = {}) {
  const agent = await newAgent();
  await vault.createPermission!({
    agentId: agent.did,
    connectionId: 'google',
    allowedScopes: ['calendar.readonly'],
    requiresApproval: false,
    delegatable: false,
    maxDelegationDepth: 1,
    createdBy: 'test',
  });
  const res = await delegateAs(app, agent, { service: 'google', user_id: 'alice', ...extra }, { bearer: BEARER });
  expect(res.status).toBe(200);
  return { agent, token: res.body.access_token as string, delegationId: res.body.delegation_id as string };
}

function stubUpstream(status = 200) {
  const upstream = vi.fn(async (_url: unknown, _init?: unknown) => new Response('{"items":[]}', { status, headers: { 'content-type': 'application/json' } }));
  vi.stubGlobal('fetch', upstream);
  return upstream;
}

function use(app: App, agent: AgentIdentity, token: string, url = CAL, method = 'GET', body?: unknown) {
  return exerciseAs(app, agent, token, { url, method, ...(body === undefined ? {} : { body }) });
}

const eventsOf = async (vault: Awaited<ReturnType<typeof setup>>['vault']) => vault.queryAuditEvents({ limit: 200 });

describe('auditOriginAndRoute', () => {
  it('keeps the provider\'s path words and hides identifiers', () => {
    expect(auditOriginAndRoute('https://api.github.com/repos/octocat/hello-world/issues/12')).toEqual({
      origin: 'https://api.github.com',
      route: '/repos/{id}/{id}/issues/{id}',
    });
    expect(auditOriginAndRoute('https://gmail.googleapis.com/gmail/v1/users/me/messages/18c2a/trash').route).toBe('/gmail/v1/users/me/messages/{id}/trash');
    expect(auditOriginAndRoute('https://acme.my.salesforce.com/services/data/v60.0/sobjects/Account/001').route).toBe('/services/data/v60.0/sobjects/{id}/{id}');
  });

  it('keeps a Slack method name, and only on Slack', () => {
    expect(auditOriginAndRoute('https://slack.com/api/chat.postMessage').route).toBe('/api/chat.postMessage');
    expect(auditOriginAndRoute('https://api.example.com/api/chat.postMessage').route).toBe('/api/{id}');
  });

  it('records no query string, fragment or credentials', () => {
    const { origin, route } = auditOriginAndRoute('https://user:hunter2@api.github.com/repos?access_token=ghp_secret#frag');
    expect(origin).toBe('https://api.github.com');
    expect(route).toBe('/repos');
    expect(`${origin}${route}`).not.toMatch(/ghp_secret|hunter2|frag|\?/);
  });

  it('hides a token carried in the path', () => {
    for (const secret of ['ya29.a0AfH6SMBx-secretvalue', 'xoxb-1234-5678-abcdefg', 'ghp_16C7e42F292c6912E7710c838347Ae178B4a', 'lowercasesecretwithnodigits']) {
      expect(auditOriginAndRoute(`https://api.github.com/repos/${secret}/issues`).route).toBe('/repos/{id}/issues');
    }
  });

  it('caps an oversized path and escapes non-printable input', () => {
    const { route } = auditOriginAndRoute(`https://api.github.com/${'a/'.repeat(5000)}`);
    expect(route!.length).toBeLessThanOrEqual(256);
    expect(route!.endsWith('/...')).toBe(true);
    const odd = auditOriginAndRoute('https://api.github.com/repos/\u0001‮%0a%00/😀/issues').route!;
    expect(odd).toBe('/repos/{id}/{id}/issues');
  });

  it('answers null for what is not a URL, and caps a long host', () => {
    expect(auditOriginAndRoute('not a url')).toEqual({ origin: null, route: null });
    expect(auditOriginAndRoute(`https://${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.example.com/x`).origin).toBeNull();
    expect(auditOriginAndRoute('javascript:alert(1)')).toEqual({ origin: null, route: null });
  });
});

describe('who did what', () => {
  it('a brokered success names the did:key agent, its key, the delegation and the redacted route', async () => {
    const { app, vault } = await setup();
    stubUpstream();
    const { agent, token, delegationId } = await issued(app, vault);
    const res = await use(app, agent, token, `${CAL}?q=secret-search&access_token=leak`);
    expect(res.status).toBe(200);
    const event = (await eventsOf(vault)).find((e) => e.action === 'access' && e.outcome === 'success');
    expect(event?.actor.id).toBe(agent.did);
    expect(event?.actor.fingerprint).toEqual(expect.any(String));
    expect(event?.metadata).toMatchObject({
      delegationId,
      origin: 'https://www.googleapis.com',
      route: '/calendar/v3/calendars/{id}/events',
      method: 'GET',
    });
    expect(JSON.stringify(event)).not.toMatch(/secret-search|access_token=leak|\?q=/);
  });

  it('the cumulative denial names the agent', async () => {
    const { app, vault } = await setup();
    stubUpstream();
    const { agent, token } = await issued(app, vault, { constraints: [{ key: 'request_bytes', max_lifetime: 1 }] });
    const res = await use(app, agent, token, CAL, 'POST', { way: 'over the budget' });
    expect(res.status).toBe(403);
    const event = (await eventsOf(vault)).find((e) => e.action === 'deny' && e.errorMessage === 'cumulative_constraint_exceeded');
    expect(event?.actor.id).toBe(agent.did);
  });

  it('a failed upstream status is attributed the same way', async () => {
    const { app, vault } = await setup();
    stubUpstream(500);
    const { agent, token, delegationId } = await issued(app, vault);
    expect((await use(app, agent, token)).status).toBe(200);
    const event = (await eventsOf(vault)).find((e) => e.action === 'access' && e.outcome === 'error');
    expect(event?.actor.id).toBe(agent.did);
    expect(event?.metadata).toMatchObject({ delegationId, route: '/calendar/v3/calendars/{id}/events', status: 500 });
  });
});

describe('refusals are events', () => {
  it('a Guard denial at /api/v1/use writes an event for the agent', async () => {
    const deny: CredPolicy = { name: 'deny-all', evaluate: () => ({ decision: 'DENY', policy: 'deny-all', reason: 'no' }) };
    const allowFirst: CredPolicy = { name: 'deny-use', evaluate: (ctx) => (ctx.targetUrl ? deny.evaluate(ctx) : { decision: 'ALLOW', policy: 'deny-use' }) };
    const { app, vault } = await setup({ guard: new CredGuard({ policies: [allowFirst] }) });
    stubUpstream();
    const { agent, token, delegationId } = await issued(app, vault);
    expect((await use(app, agent, token, `${CAL}?secret=1`)).status).toBe(403);
    const event = (await eventsOf(vault)).find((e) => e.action === 'deny' && e.errorMessage === 'guard_denied');
    expect(event?.actor.id).toBe(agent.did);
    expect(event?.metadata).toMatchObject({ delegationId, policy: 'deny-all', route: '/calendar/v3/calendars/{id}/events' });
    expect(JSON.stringify(event)).not.toContain('secret=1');
  });

  it('a Guard denial on the delegate route writes an event', async () => {
    const deny: CredPolicy = { name: 'deny-all', evaluate: () => ({ decision: 'DENY', policy: 'deny-all', reason: 'no' }) };
    const { app, vault } = await setup({ guard: new CredGuard({ policies: [deny] }) });
    const agent = await newAgent();
    const res = await delegateAs(app, agent, { service: 'google', user_id: 'alice' }, { bearer: BEARER });
    expect(res.status).toBe(403);
    const event = (await eventsOf(vault)).find((e) => e.action === 'deny' && e.errorMessage === 'guard_denied');
    expect(event?.metadata).toMatchObject({ policy: 'deny-all', path: '/api/v1/delegate' });
    expect(event?.resource.id).toBe('google/alice');
    // The agent_did in the body is not yet proven here: it is recorded as a claim, never as the actor.
    expect(event?.actor.id).not.toBe(agent.did);
    expect(event?.metadata?.claimedAgentDid).toBe(agent.did);
  });

  it('a refused URL writes an event with no path or query from the request', async () => {
    const { app, vault } = await setup();
    const upstream = stubUpstream();
    const { agent, token, delegationId } = await issued(app, vault);
    const res = await use(app, agent, token, 'https://evil.example.com/steal/tok_secret?x=tok_query');
    expect(res.status).toBe(400);
    expect(upstream).not.toHaveBeenCalled();
    const event = (await eventsOf(vault)).find((e) => e.action === 'deny' && e.errorMessage === 'url_refused');
    expect(event?.actor.id).toBe(agent.did);
    expect(event?.metadata).toMatchObject({ delegationId, origin: 'https://evil.example.com', route: '/{id}/{id}' });
    expect(JSON.stringify(event)).not.toMatch(/tok_secret|tok_query/);
  });

  it('a method override writes an event', async () => {
    const { app, vault } = await setup();
    stubUpstream();
    const { agent, token } = await issued(app, vault);
    expect((await use(app, agent, token, `${CAL}?_method=DELETE`)).status).toBe(400);
    const event = (await eventsOf(vault)).find((e) => e.errorMessage === 'method_override_refused');
    expect(event?.actor.id).toBe(agent.did);
  });

  it('an unreachable upstream writes an event, without the error text', async () => {
    const { app, vault } = await setup();
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('connect ECONNREFUSED tok_in_error'); }));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const { agent, token, delegationId } = await issued(app, vault);
    expect((await use(app, agent, token)).status).toBe(502);
    const event = (await eventsOf(vault)).find((e) => e.errorMessage === 'upstream_unreachable');
    expect(event?.actor.id).toBe(agent.did);
    expect(event?.outcome).toBe('error');
    expect(event?.metadata).toMatchObject({ delegationId, route: '/calendar/v3/calendars/{id}/events' });
    expect(JSON.stringify(event)).not.toContain('tok_in_error');
  });

  it('a flood of denials by one agent writes one event, then one summary with the count', async () => {
    const { app, vault, flushAuditAggregates } = await setup();
    stubUpstream();
    const { agent, token } = await issued(app, vault);
    for (let i = 0; i < 25; i += 1) {
      expect((await use(app, agent, token, `https://evil.example.com/${i}`)).status).toBe(400);
    }
    const before = (await eventsOf(vault)).filter((e) => e.errorMessage === 'url_refused');
    expect(before).toHaveLength(1);
    flushAuditAggregates();
    const after = (await eventsOf(vault)).filter((e) => e.errorMessage === 'url_refused');
    expect(after).toHaveLength(2);
    const summary = after.find((e) => e.metadata?.aggregated === true);
    expect(summary?.metadata?.repeats).toBe(24);
    expect(summary?.actor.id).toBe(agent.did);
  });

  it('aggregates per agent: another agent\'s denial still writes its own event', async () => {
    const { app, vault } = await setup();
    stubUpstream();
    const one = await issued(app, vault);
    const two = await issued(app, vault);
    await use(app, one.agent, one.token, 'https://evil.example.com/a');
    await use(app, one.agent, one.token, 'https://evil.example.com/b');
    await use(app, two.agent, two.token, 'https://evil.example.com/c');
    const events = (await eventsOf(vault)).filter((e) => e.errorMessage === 'url_refused');
    expect(events.map((e) => e.actor.id).sort()).toEqual([one.agent.did, two.agent.did].sort());
  });

  it('a successful call is never aggregated', async () => {
    const { app, vault } = await setup();
    stubUpstream();
    const { agent, token } = await issued(app, vault);
    for (let i = 0; i < 3; i += 1) await use(app, agent, token);
    expect((await eventsOf(vault)).filter((e) => e.action === 'access' && e.outcome === 'success')).toHaveLength(3);
  });
});

describe('the hash chain', () => {
  it('verifies across rows written in the old shape and rows in the new one', async () => {
    const cfg = config();
    const first = createServer(cfg);
    await first.vault.init();
    await first.vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.chain', expiresAt: new Date(Date.now() + 3600_000), scopes: ['calendar.readonly'] });
    first.vault.writeAuditEvent({
      id: 'evt_old_shape',
      timestamp: new Date(),
      actor: { type: 'agent', id: 'server-agent' },
      action: 'access',
      resource: { type: 'connection', id: 'google/alice' },
      outcome: 'success',
      correlationId: 'old',
      metadata: { brokered: true, method: 'GET', status: 200 },
    });
    stubUpstream();
    const { agent, token } = await issued(first.app, first.vault);
    expect((await use(first.app, agent, token)).status).toBe(200);
    await use(first.app, agent, token, 'https://evil.example.com/x');
    first.flushAuditAggregates();

    const check = first.vault.verifyAuditChain();
    expect(check.ok).toBe(true);
    // The old row is still exactly as written.
    const old = (await eventsOf(first.vault)).find((e) => e.id === 'evt_old_shape');
    expect(old?.actor.id).toBe('server-agent');
    expect(old?.metadata).toEqual({ brokered: true, method: 'GET', status: 200 });
    const admin = await request(first.app).get('/admin/audit/verify').set('Authorization', `Bearer ${ADMIN}`);
    expect(admin.status).toBe(200);
  });
});

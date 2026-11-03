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
import { EventEmitter } from 'node:events';
import { REFUSED_ORIGIN, auditOriginAndRoute, createRefusalAggregator, flushOnShutdown } from '../audit-route.js';
import type { AuditEvent } from '@credninja/vault';
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
    providers: [
      { slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: ['calendar.readonly'] },
      { slug: 'salesforce', clientId: 'id', clientSecret: 'secret', defaultScopes: ['api'] },
    ],
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

const KNOWN = (origin: string) => ['https://api.github.com', 'https://gmail.googleapis.com', 'https://slack.com'].includes(origin) || origin.endsWith('.salesforce.com');

describe('auditOriginAndRoute', () => {
  it('keeps the provider\'s path words and hides identifiers', () => {
    expect(auditOriginAndRoute('https://api.github.com/repos/octocat/hello-world/issues/12', KNOWN)).toEqual({
      origin: 'https://api.github.com',
      route: '/repos/{id}/{id}/issues/{id}',
    });
    expect(auditOriginAndRoute('https://gmail.googleapis.com/gmail/v1/users/me/messages/18c2a/trash', KNOWN).route).toBe('/gmail/v1/users/me/messages/{id}/trash');
    expect(auditOriginAndRoute('https://acme.my.salesforce.com/services/data/v60.0/sobjects/Account/001', KNOWN).route).toBe('/services/data/v60.0/sobjects/{id}/{id}');
  });

  it('keeps a listed Slack method name, and only on Slack', () => {
    expect(auditOriginAndRoute('https://slack.com/api/chat.postMessage', KNOWN).route).toBe('/api/chat.postMessage');
    expect(auditOriginAndRoute('https://api.example.com/api/chat.postMessage', KNOWN).route).toBe('/api/{id}');
  });

  it('hides a Slack path segment that only looks like a method name', () => {
    for (const lookalike of ['secret.token', 'customer.Acme', 'alice.smith.example', 'chat.postMessageX']) {
      expect(auditOriginAndRoute(`https://slack.com/api/${lookalike}`, KNOWN).route).toBe('/api/{id}');
    }
  });

  it('records an origin verbatim only when it is a known provider host', () => {
    expect(auditOriginAndRoute('https://api.github.com/repos', KNOWN).origin).toBe('https://api.github.com');
    expect(auditOriginAndRoute('https://tok-secret.attacker.example/x', KNOWN).origin).toBe(REFUSED_ORIGIN);
    expect(auditOriginAndRoute('https://api.github.com.attacker.example/x', KNOWN).origin).toBe(REFUSED_ORIGIN);
    expect(auditOriginAndRoute('https://api.github.com:8443/x', KNOWN).origin).toBe(REFUSED_ORIGIN);
    expect(auditOriginAndRoute('http://api.github.com/x', KNOWN).origin).toBe(REFUSED_ORIGIN);
  });

  it('records no query string, fragment or credentials', () => {
    const { origin, route } = auditOriginAndRoute('https://user:hunter2@api.github.com/repos?access_token=ghp_secret#frag', KNOWN);
    expect(origin).toBe('https://api.github.com');
    expect(route).toBe('/repos');
    expect(`${origin}${route}`).not.toMatch(/ghp_secret|hunter2|frag|\?/);
  });

  it('hides a token carried in the path', () => {
    for (const secret of ['ya29.a0AfH6SMBx-secretvalue', 'xoxb-1234-5678-abcdefg', 'ghp_16C7e42F292c6912E7710c838347Ae178B4a', 'lowercasesecretwithnodigits']) {
      expect(auditOriginAndRoute(`https://api.github.com/repos/${secret}/issues`, KNOWN).route).toBe('/repos/{id}/issues');
    }
  });

  it('caps an oversized path and escapes non-printable input', () => {
    const { route } = auditOriginAndRoute(`https://api.github.com/${'a/'.repeat(5000)}`, KNOWN);
    expect(route!.length).toBeLessThanOrEqual(256);
    expect(route!.endsWith('/...')).toBe(true);
    const odd = auditOriginAndRoute('https://api.github.com/repos/\u0001‮%0a%00/😀/issues', KNOWN).route!;
    expect(odd).toBe('/repos/{id}/{id}/issues');
  });

  it('answers the marker and no route for what is not an http URL', () => {
    expect(auditOriginAndRoute('not a url', KNOWN)).toEqual({ origin: REFUSED_ORIGIN, route: null });
    expect(auditOriginAndRoute('javascript:alert(1)', KNOWN)).toEqual({ origin: REFUSED_ORIGIN, route: null });
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
    const res = await use(app, agent, token, `${CAL}?q=over-the-budget`);
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
    expect(event?.metadata).toMatchObject({ policy: 'deny-all', route: '/api/v1/delegate', claimedUserId: 'alice' });
    // user_id is not authorized here either: a claim, under a resource in no user's feed.
    expect(event?.resource.id).toBe('guard-denial:google');
    // The agent_did in the body is not yet proven here: it is recorded as a claim, never as the actor.
    expect(event?.actor.id).not.toBe(agent.did);
    expect(event?.metadata?.claimedAgentDid).toBe(agent.did);
  });

  it('a Guard denial cannot forge an event into another user\'s feed', async () => {
    const deny: CredPolicy = { name: 'deny-all', evaluate: () => ({ decision: 'DENY', policy: 'deny-all', reason: 'no' }) };
    const { app, vault } = await setup({ guard: new CredGuard({ policies: [deny] }) });
    const agent = await newAgent();
    for (const body of [
      { service: 'google/victim', user_id: 'x' },
      { service: 'google', user_id: 'victim/extra' },
      { service: 'google', user_id: 'victim' },
      { service: 'not-configured', user_id: 'victim' },
    ]) {
      expect((await delegateAs(app, agent, body, { bearer: BEARER })).status).toBe(403);
    }
    const denials = (await eventsOf(vault)).filter((e) => e.errorMessage === 'guard_denied');
    for (const event of denials) {
      expect(event.resource.id).not.toContain('/');
      expect(event.resource.id).not.toContain('victim');
    }
    expect(denials.map((e) => e.resource.id).sort()).toEqual(['guard-denial:google', 'guard-denial:unknown']);
    const feed = await request(app).get('/api/v1/audit').set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'victim' });
    expect(feed.status).toBe(200);
    expect(JSON.stringify(feed.body)).not.toContain('guard_denied');
  });

  it('a user-less Guard denial is found under its service in the admin log, and in no user\'s feed', async () => {
    const deny: CredPolicy = { name: 'deny-all', evaluate: () => ({ decision: 'DENY', policy: 'deny-all', reason: 'no' }) };
    const { app } = await setup({ guard: new CredGuard({ policies: [deny] }) });
    await delegateAs(app, await newAgent(), { service: 'google', user_id: 'alice' }, { bearer: BEARER });
    await delegateAs(app, await newAgent(), { service: 'not-configured', user_id: 'alice' }, { bearer: BEARER });
    const admin = (service: string) => request(app).get('/admin/audit').set('Authorization', `Bearer ${ADMIN}`).query({ service });
    const google = (await admin('google')).body.entries;
    const googleDenials = (google as Array<{ metadata: { errorMessage?: string }; service: string; userId: string | null }>).filter((e) => e.metadata.errorMessage === 'guard_denied');
    expect(googleDenials).toHaveLength(1);
    expect(googleDenials[0]).toMatchObject({ service: 'google', userId: null });
    expect(JSON.stringify((await admin('github')).body)).not.toContain('guard_denied');
    expect(JSON.stringify((await admin('guard-denial:google')).body)).not.toContain('guard_denied');
    for (const user_id of ['alice', 'undefined', 'guard-denial:google', 'unknown', 'null', '']) {
      const feed = await request(app).get('/api/v1/audit').set('Authorization', `Bearer ${BEARER}`).query({ user_id });
      expect(JSON.stringify(feed.body), user_id).not.toContain('guard_denied');
    }
  });

  it('a Guard denial for a bound user is in that user\'s feed; a single-user server files it under default', async () => {
    const deny: CredPolicy = { name: 'deny-all', evaluate: () => ({ decision: 'DENY', policy: 'deny-all', reason: 'no' }) };
    const bound = await setup({
      agentToken: undefined,
      agentRequestVerifier: () => ({ ok: true, principal: { type: 'external-runtime', principalId: 'agt_bound', userId: 'alice' } }),
      guard: new CredGuard({ policies: [deny] }),
    });
    await delegateAs(bound.app, await newAgent(), { service: 'google' }, { bearer: BEARER });
    expect((await eventsOf(bound.vault)).find((e) => e.errorMessage === 'guard_denied')?.resource.id).toBe('google/alice');

    const single = await setup({ singleUserMode: true, guard: new CredGuard({ policies: [deny] }) });
    await delegateAs(single.app, await newAgent(), { service: 'google' }, { bearer: BEARER });
    expect((await eventsOf(single.vault)).find((e) => e.errorMessage === 'guard_denied')?.resource.id).toBe('google/default');
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
    expect(event?.metadata).toMatchObject({ delegationId, origin: REFUSED_ORIGIN, route: '/{id}/{id}' });
    expect(JSON.stringify(event)).not.toMatch(/tok_secret|tok_query|evil\.example/);
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

  it('a noisy refusal does not hide a different one', async () => {
    const { app, vault, flushAuditAggregates } = await setup();
    stubUpstream();
    const { agent, token } = await issued(app, vault);
    await use(app, agent, token, 'https://evil.example.com/1');
    await use(app, agent, token, 'https://evil.example.com/2');
    await use(app, agent, token, 'https://evil.example.com/repos/x', 'GET');
    await use(app, agent, token, 'https://evil.example.com/1', 'POST', { a: 1 });
    const second = await issued(app, vault);
    await use(app, second.agent, second.token, 'https://evil.example.com/1');
    flushAuditAggregates();
    const events = (await eventsOf(vault)).filter((e) => e.errorMessage === 'url_refused');
    const firsts = events.filter((e) => e.metadata?.aggregated !== true);
    expect(firsts.map((e) => `${e.metadata?.method} ${e.metadata?.route}`).sort()).toEqual(['GET /repos/{id}', 'GET /{id}', 'GET /{id}', 'POST /{id}']);
    expect(events.filter((e) => e.metadata?.aggregated === true)).toHaveLength(1);
  });

  it('two delegations of one agent are counted apart', () => {
    const written: AuditEvent[] = [];
    const aggregator = createRefusalAggregator({ write: (event) => written.push(event) });
    const event = (delegationId: string): AuditEvent => ({
      id: crypto.randomUUID(),
      timestamp: new Date(),
      actor: { type: 'agent', id: 'did:key:zA' },
      action: 'deny',
      resource: { type: 'token', id: 'google/alice' },
      outcome: 'denied',
      correlationId: 'c',
      errorMessage: 'url_refused',
      metadata: { delegationId, method: 'GET', origin: 'refused', route: '/{id}' },
    });
    aggregator.record(event('del_1'));
    aggregator.record(event('del_1'));
    aggregator.record(event('del_2'));
    expect(written.map((e) => e.metadata?.delegationId)).toEqual(['del_1', 'del_2']);
  });

  it('keeps its bound: distinct refusals past maxKeys write summaries, never grow the map', () => {
    const written: AuditEvent[] = [];
    const aggregator = createRefusalAggregator({ write: (event) => written.push(event), maxKeys: 2 });
    const event = (route: string): AuditEvent => ({
      id: crypto.randomUUID(), timestamp: new Date(), actor: { type: 'agent', id: 'a' }, action: 'deny',
      resource: { type: 'token', id: 'g/u' }, outcome: 'denied', correlationId: 'c', errorMessage: 'e', metadata: { route },
    });
    aggregator.record(event('/1'));
    aggregator.record(event('/1'));
    aggregator.record(event('/2'));
    aggregator.record(event('/3'));
    expect(written.filter((e) => e.metadata?.aggregated === true).map((e) => e.metadata?.route)).toEqual(['/1']);
    aggregator.record(event('/1'));
    expect(written.filter((e) => e.metadata?.route === '/1' && e.metadata?.aggregated !== true)).toHaveLength(2);
  });

  function refusal(metadata: Record<string, unknown>, actor = 'did:key:zA'): AuditEvent {
    return {
      id: crypto.randomUUID(), timestamp: new Date(), actor: { type: 'agent', id: actor }, action: 'deny',
      resource: { type: 'token', id: 'guard-denial:google' }, outcome: 'denied', correlationId: 'c', errorMessage: 'guard_denied', metadata,
    };
  }

  it('values a caller chooses cannot mint new refusals: the first is kept and the rest counted', () => {
    const written: AuditEvent[] = [];
    const aggregator = createRefusalAggregator({ write: (event) => written.push(event) });
    for (let i = 0; i < 500; i += 1) aggregator.record(refusal({ policy: 'p', route: '/r', claimedUserId: `user-${i}`, claimedAgentDid: `did:key:z${i % 3}` }));
    expect(written).toHaveLength(1);
    expect(written[0]!.metadata?.claimedUserId).toBe('user-0');
    aggregator.flush();
    expect(written).toHaveLength(2);
    expect(written[1]!.metadata).toMatchObject({
      aggregated: true,
      repeats: 499,
      claimedUserId: 'user-0',
      distinctClaims: { claimedUserId: 32, claimedAgentDid: 3 },
      distinctClaimsCapped: 32,
    });
  });

  it('caps first writes per actor per window, and collapses the rest into one marked summary', () => {
    let clock = 1_000_000;
    const written: AuditEvent[] = [];
    const aggregator = createRefusalAggregator({ write: (event) => written.push(event), now: () => clock, maxFirstWritesPerActor: 3 });
    for (let i = 0; i < 10; i += 1) aggregator.record(refusal({ route: `/varied/${i}` }));
    expect(written).toHaveLength(3);
    aggregator.record(refusal({ route: '/other-actor' }, 'did:key:zB'));
    expect(written).toHaveLength(4);
    // A refusal already written still counts against itself, not the cap.
    aggregator.record(refusal({ route: '/varied/0' }));
    clock += 61_000;
    aggregator.flushExpired();
    const summaries = written.filter((e) => e.metadata?.aggregated === true);
    expect(summaries.find((e) => e.metadata?.overflow === true)?.metadata).toMatchObject({ repeats: 7, route: '/varied/3' });
    expect(summaries.find((e) => e.metadata?.overflow !== true)?.metadata).toMatchObject({ repeats: 1, route: '/varied/0' });
    expect(written).toHaveLength(6);
    // A new window starts over.
    aggregator.record(refusal({ route: '/varied/9' }));
    expect(written).toHaveLength(7);
  });

  it('a flood of varied paths through the server writes a bounded number of rows', async () => {
    const { app, vault, flushAuditAggregates } = await setup();
    stubUpstream();
    const { agent, token } = await issued(app, vault);
    for (let i = 0; i < 40; i += 1) {
      // Each depth is a different route template.
      await use(app, agent, token, `https://evil.example.com${'/x'.repeat(i + 1)}`);
    }
    expect((await eventsOf(vault)).filter((e) => e.errorMessage === 'url_refused')).toHaveLength(20);
    flushAuditAggregates();
    const after = (await eventsOf(vault)).filter((e) => e.errorMessage === 'url_refused');
    expect(after).toHaveLength(21);
    expect(after.find((e) => e.metadata?.overflow === true)?.metadata?.repeats).toBe(20);
  });

  it('a Salesforce host is recorded only when it is the connection\'s stored instance', async () => {
    const { app, vault } = await setup();
    await vault.store({ provider: 'salesforce', userId: 'alice', accessToken: 'sf', expiresAt: new Date(Date.now() + 3600_000), scopes: ['api'], instanceUrl: 'https://acme.my.salesforce.com' });
    stubUpstream();
    const agent = await newAgent();
    await vault.createPermission!({ agentId: agent.did, connectionId: 'salesforce', allowedScopes: ['api'], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
    const minted = await delegateAs(app, agent, { service: 'salesforce', user_id: 'alice' }, { bearer: BEARER });
    expect(minted.status, JSON.stringify(minted.body)).toBe(200);
    expect((await use(app, agent, minted.body.access_token, 'https://tok-secret.my.salesforce.com/services/data/v60.0/limits')).status).toBe(400);
    const refused = (await eventsOf(vault)).find((e) => e.errorMessage === 'salesforce_instance_mismatch');
    expect(refused?.metadata?.origin).toBe(REFUSED_ORIGIN);
    expect(JSON.stringify(refused)).not.toContain('tok-secret');
    expect((await use(app, agent, minted.body.access_token, 'https://acme.my.salesforce.com/services/data/v60.0/limits')).status).toBe(200);
    expect((await eventsOf(vault)).find((e) => e.action === 'access' && e.outcome === 'success')?.metadata?.origin).toBe('https://acme.my.salesforce.com');
  });

  it('flushes on SIGTERM and SIGINT, then exits with the signal status', () => {
    for (const [signal, code] of [['SIGTERM', 143], ['SIGINT', 130]] as const) {
      const proc = Object.assign(new EventEmitter(), { exit: vi.fn() });
      const flush = vi.fn();
      flushOnShutdown(flush, proc as never);
      proc.emit(signal);
      expect(flush).toHaveBeenCalledTimes(1);
      expect(proc.exit).toHaveBeenCalledWith(code);
    }
    const proc = Object.assign(new EventEmitter(), { exit: vi.fn() });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    flushOnShutdown(() => { throw new Error('disk full'); }, proc as never);
    proc.emit('SIGTERM');
    expect(proc.exit).toHaveBeenCalledWith(143);
  });

  it('writes every capability denial, with its details', async () => {
    const { app, vault } = await setup();
    await vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.drive', expiresAt: new Date(Date.now() + 3600_000), scopes: ['drive.readonly'] });
    stubUpstream();
    const agent = await newAgent();
    await vault.createPermission!({ agentId: agent.did, connectionId: 'google', allowedScopes: ['drive.readonly'], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
    const minted = await delegateAs(app, agent, {
      service: 'google',
      user_id: 'alice',
      authorization_details: [{ type: 'cred_delegation', provider: 'google', operations: ['drive.files.get'], resources: ['file:abc'] }],
    }, { bearer: BEARER });
    expect(minted.status).toBe(200);
    const token = minted.body.access_token as string;
    const refused = await Promise.all(['https://www.googleapis.com/drive/v3/files/other', 'https://www.googleapis.com/drive/v3/files'].map((url) => use(app, agent, token, url)));
    expect(refused.map((r) => r.status)).toEqual([403, 403]);
    await use(app, agent, token, 'https://www.googleapis.com/drive/v3/files/other');
    const events = (await eventsOf(vault)).filter((e) => e.errorMessage === 'capability_denied');
    expect(events).toHaveLength(3);
    expect(events.map((e) => e.metadata?.route).sort()).toEqual(['/drive/v3/files', '/drive/v3/files/{id}', '/drive/v3/files/{id}']);
    expect(events.every((e) => e.actor.id === agent.did && e.metadata?.origin === 'https://www.googleapis.com')).toBe(true);
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

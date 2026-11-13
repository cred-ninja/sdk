/**
 * External identity on the server: a source's verified identity replaces the
 * agent token, maps by exact configuration to an existing agent, and from
 * then on runs as that agent's DID. Sources here are fakes so each server
 * rule is tested alone; identity-wimse and identity-tailscale test the real
 * verifiers.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'node:crypto';
import { CredGuard, type CredPolicy } from '@credninja/guard';
import { createDpopProof } from '@credninja/sdk';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { IdentityRefusal, type ExternalIdentitySource, type VerifiedExternalIdentity } from '../identity/types.js';
import { delegateAs, exerciseAs, newAgent, type AgentIdentity } from './token-helpers.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const SUBJECT = 'spiffe://prod.example/ns/agents/sa/planner';
const CALENDAR = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
const dirs: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

type Outcome = VerifiedExternalIdentity | null | IdentityRefusal;

/** A source that returns whatever the test sets, only when X-Fake-Id is sent. */
function fakeSource(kind: 'wimse' | 'tailscale', outcome: () => Outcome): ExternalIdentitySource {
  return {
    kind,
    async authenticate(req) {
      if (req.headers['x-fake-id'] === undefined) return null;
      const o = outcome();
      if (o instanceof IdentityRefusal) throw o;
      return o;
    },
  };
}

function identity(over: Partial<VerifiedExternalIdentity> = {}): VerifiedExternalIdentity {
  return {
    kind: 'wimse', subject: SUBJECT, trustDomain: 'prod.example', attributes: {},
    proof: 'wpt', expiresAt: Math.floor(Date.now() / 1000) + 300, ...over,
  };
}

async function setup(opts: {
  sources?: (agent: AgentIdentity) => ExternalIdentitySource[];
  subject?: string;
  status?: 'active' | 'suspended' | 'revoked';
  register?: boolean;
  config?: Partial<ServerConfig>;
} = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-external-identity-'));
  dirs.push(dir);
  const agent = await newAgent();
  const sources = opts.sources?.(agent) ?? [fakeSource('wimse', () => identity())];
  const server = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'sqlite', tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: ADMIN, agentToken: BEARER, redirectBaseUri: BASE,
    providers: [{ slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: [] }],
    externalIdentity: {
      sources,
      mappings: [{ kind: sources[0]?.kind ?? 'wimse', subject: opts.subject ?? SUBJECT, agentDid: agent.did }],
    },
    ...opts.config,
  });
  await server.vault.init();
  await server.tofu.init();
  if (opts.register !== false) {
    const now = new Date().toISOString();
    await server.vault.registerAgent({
      id: `agt_${crypto.randomBytes(6).toString('hex')}`, did: agent.did, fingerprint: crypto.randomBytes(16).toString('hex'),
      name: 'planner', scopeCeiling: [], status: opts.status ?? 'active', createdBy: 'admin', createdAt: now, updatedAt: now,
    });
  }
  await server.vault.store({
    provider: 'google', userId: 'default', accessToken: 'ya29.external', refreshToken: '1//r',
    expiresAt: new Date(Date.now() + 3600_000), scopes: ['calendar.readonly'],
  });
  const perm = await request(server.app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`)
    .send({ agentId: agent.did, connectionId: 'google', allowedScopes: ['calendar.readonly'] });
  return { ...server, agent, permissionId: perm.body.permission?.id as string };
}

const connections = (app: any, headers: Record<string, string> = {}) => {
  const req = request(app).get('/api/v1/connections?user_id=default');
  for (const [k, v] of Object.entries(headers)) req.set(k, v);
  return req;
};

/** POST /api/v1/delegate authenticated by the fake source, with the agent's DPoP. */
function delegateExternally(app: any, agent: AgentIdentity, body: Record<string, unknown> = {}) {
  return request(app).post('/api/v1/delegate')
    .set('X-Fake-Id', '1')
    .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/api/v1/delegate`))
    .send({ token_format: 'handle', agent_did: agent.did, service: 'google', user_id: 'default', scopes: ['calendar.readonly'], ...body });
}

describe('external identity replaces the agent token', () => {
  it('authenticates a mapped, active agent without the agent token', async () => {
    const { app } = await setup();
    expect((await connections(app, { 'X-Fake-Id': '1' })).status).toBe(200);
    // Control: without the source credential and without the token, refused.
    expect((await connections(app)).status).toBe(401);
  });

  it('keeps the agent token path unchanged when a request carries no source credential', async () => {
    const { app } = await setup();
    expect((await connections(app, { Authorization: `Bearer ${BEARER}` })).status).toBe(200);
  });

  it('refuses an unmapped subject and writes a deny event', async () => {
    const { app, vault } = await setup({ subject: 'spiffe://prod.example/ns/agents/sa/other' });
    const res = await connections(app, { 'X-Fake-Id': '1' });
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toBe('WPT');
    expect(res.body).toEqual({ error: 'invalid_workload_identity' });
    const denies = await vault.queryAuditEvents({ action: 'deny' });
    expect(denies.some((e: any) => e.metadata?.reason === 'unmapped')).toBe(true);
  });

  it('never creates an agent: a mapping to an agent the vault does not hold is refused', async () => {
    const { app, vault, agent } = await setup({ register: false });
    expect((await connections(app, { 'X-Fake-Id': '1' })).status).toBe(401);
    expect(await vault.getAgentByDid(agent.did)).toBeNull();
  });

  for (const status of ['suspended', 'revoked'] as const) {
    it(`refuses a ${status} agent`, async () => {
      const { app } = await setup({ status });
      expect((await connections(app, { 'X-Fake-Id': '1' })).status).toBe(401);
    });
  }

  it('re-checks the agent on every request: revoking it blocks the next call', async () => {
    const { app, vault, agent } = await setup();
    expect((await connections(app, { 'X-Fake-Id': '1' })).status).toBe(200);
    const record = await vault.getAgentByDid(agent.did);
    await vault.revokeAgent(record!.id);
    expect((await connections(app, { 'X-Fake-Id': '1' })).status).toBe(401);
  });

  it('does not fall back to the agent token when the source refuses', async () => {
    const { app } = await setup({ sources: () => [fakeSource('wimse', () => new IdentityRefusal('wimse', 'replay', 'jti seen'))] });
    const res = await connections(app, { 'X-Fake-Id': '1', Authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid_workload_identity' });
  });

  it('refuses an identity that has expired', async () => {
    const { app } = await setup({ sources: () => [fakeSource('wimse', () => identity({ expiresAt: Math.floor(Date.now() / 1000) - 1 }))] });
    expect((await connections(app, { 'X-Fake-Id': '1' })).status).toBe(401);
  });

  it('refuses a request two sources both claim', async () => {
    const { app } = await setup({ sources: () => [fakeSource('wimse', () => identity()), fakeSource('wimse', () => identity())] });
    expect((await connections(app, { 'X-Fake-Id': '1' })).status).toBe(401);
  });

  it('issues a handle to the mapped agent, and refuses a body naming another agent', async () => {
    const { app, agent } = await setup();
    const ok = await delegateExternally(app, agent);
    expect(ok.status).toBe(200);
    expect(ok.body.token_type).toBe('DPoP');
    const other = await newAgent();
    const mismatch = await request(app).post('/api/v1/delegate')
      .set('X-Fake-Id', '1')
      .set('DPoP', createDpopProof(other, 'POST', `${BASE}/api/v1/delegate`))
      .send({ token_format: 'handle', agent_did: other.did, service: 'google', user_id: 'default', scopes: ['calendar.readonly'] });
    expect(mismatch.status).toBe(403);
    expect(mismatch.body.error).toBe('agent_mismatch');
  });
});

describe('a channel identity (Tailscale) also needs the agent key', () => {
  const tailscale = () => [fakeSource('tailscale', () => identity({ kind: 'tailscale', subject: 'tailscale:node:nXYZ', trustDomain: 'ex.ts.net', proof: 'channel' }))];

  it('requires a DPoP proof by the mapped agent on every request', async () => {
    const { app, agent } = await setup({ sources: tailscale, subject: 'tailscale:node:nXYZ' });
    const url = `${BASE}/api/v1/connections`;
    const proof = createDpopProof(agent, 'GET', url);
    expect((await connections(app, { 'X-Fake-Id': '1', DPoP: proof })).status).toBe(200);
    // The same proof again is a replay.
    expect((await connections(app, { 'X-Fake-Id': '1', DPoP: proof })).status).toBe(401);
    // No proof: the node alone is not the agent.
    const bare = await connections(app, { 'X-Fake-Id': '1' });
    expect(bare.status).toBe(401);
    expect(bare.body).toEqual({ error: 'invalid_tailnet_identity' });
  });

  it('refuses a proof by a second agent on the same node', async () => {
    const { app } = await setup({ sources: tailscale, subject: 'tailscale:node:nXYZ' });
    const neighbour = await newAgent();
    const res = await connections(app, { 'X-Fake-Id': '1', DPoP: createDpopProof(neighbour, 'GET', `${BASE}/api/v1/connections`) });
    expect(res.status).toBe(401);
  });
});

describe('Guard sees only proven identity', () => {
  it('passes the verified external identity to Guard, never one the body claims', async () => {
    const seen: any[] = [];
    const probe: CredPolicy = {
      name: 'probe',
      evaluate(ctx) {
        seen.push({ agentDid: ctx.agentDid, external: ctx.externalIdentity, source: ctx.identitySource });
        return { decision: ctx.externalIdentity?.subject === SUBJECT ? 'ALLOW' : 'DENY', reason: 'subject', policy: 'probe' };
      },
    };
    const { app, agent } = await setup({ config: { guard: new CredGuard({ policies: [probe] }) } });
    expect((await delegateExternally(app, agent)).status).toBe(200);
    expect(seen[0]).toEqual({ agentDid: agent.did, source: 'did', external: { kind: 'wimse', subject: SUBJECT, trustDomain: 'prod.example', attributes: {} } });
    // Control: the agent token path, with a body claiming the identity, is denied.
    const forged = await delegateAs(app, agent, {
      service: 'google', user_id: 'default', scopes: ['calendar.readonly'],
      metadata: { externalIdentity: { kind: 'wimse', subject: SUBJECT } }, externalIdentity: { subject: SUBJECT },
    }, { bearer: BEARER, base: BASE });
    expect(forged.status).toBe(403);
    expect(seen[1].external).toBeUndefined();
  });

  it('gives Guard on /api/v1/use the DPoP-proven agent DID', async () => {
    const seen: Array<string | undefined> = [];
    const probe: CredPolicy = {
      name: 'probe',
      evaluate(ctx) {
        if (ctx.metadata?.brokered) seen.push(ctx.agentDid);
        return { decision: 'ALLOW', policy: 'probe' };
      },
    };
    const { app, agent } = await setup({ config: { guard: new CredGuard({ policies: [probe] }) } });
    const minted = await delegateAs(app, agent, { service: 'google', user_id: 'default', scopes: ['calendar.readonly'] }, { bearer: BEARER, base: BASE });
    expect(minted.status).toBe(200);
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{"items":[]}', { status: 200, headers: { 'content-type': 'application/json' } }));
    const used = await exerciseAs(app, agent, minted.body.access_token, { url: CALENDAR, method: 'GET' }, { base: BASE });
    expect(used.status).toBe(200);
    expect(seen).toEqual([agent.did]);
  });
});

describe('requiresApproval holds for tokens already issued', () => {
  it('turning approval on revokes live delegations, so the next use is refused', async () => {
    const { app, agent, permissionId } = await setup();
    const minted = await delegateAs(app, agent, { service: 'google', user_id: 'default', scopes: ['calendar.readonly'] }, { bearer: BEARER, base: BASE });
    expect(minted.status).toBe(200);
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{"items":[]}', { status: 200, headers: { 'content-type': 'application/json' } }));
    const token = minted.body.access_token as string;
    expect((await exerciseAs(app, agent, token, { url: CALENDAR, method: 'GET' }, { base: BASE })).status).toBe(200);

    const patched = await request(app).patch(`/admin/permissions/${permissionId}`).set('Authorization', `Bearer ${ADMIN}`).send({ requiresApproval: true });
    expect(patched.status).toBe(200);
    const calls = fetchSpy.mock.calls.length;
    const after = await exerciseAs(app, agent, token, { url: CALENDAR, method: 'GET' }, { base: BASE });
    expect(after.status).not.toBe(200);
    expect(fetchSpy.mock.calls.length).toBe(calls);
  });

  it('leaves live delegations alone when a PATCH does not turn approval on', async () => {
    const { app, agent, permissionId } = await setup();
    const minted = await delegateAs(app, agent, { service: 'google', user_id: 'default', scopes: ['calendar.readonly'] }, { bearer: BEARER, base: BASE });
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{"items":[]}', { status: 200, headers: { 'content-type': 'application/json' } }));
    await request(app).patch(`/admin/permissions/${permissionId}`).set('Authorization', `Bearer ${ADMIN}`).send({ ttlOverride: 600 });
    expect((await exerciseAs(app, agent, minted.body.access_token, { url: CALENDAR, method: 'GET' }, { base: BASE })).status).toBe(200);
  });
});

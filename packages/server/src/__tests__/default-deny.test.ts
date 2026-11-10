// Default deny and sticky revocation on the legacy (non-Link) delegation
// paths: a did:key agent gets what it was granted, and a revocation holds
// against a new key, a new delegation and a sub-delegation.
import { describe, it, expect, vi, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createServer } from '../server.js';
import { createDpopProof } from '@credninja/sdk';
import { actorTokenFor, delegateAs, exerciseAs, newAgent, type AgentIdentity, type App } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];

afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-default-deny-'));
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

const STORED = ['calendar.readonly', 'gmail.readonly', 'gmail.send'];

async function setup(overrides: Partial<ServerConfig> = {}) {
  const server = createServer(config(overrides));
  await server.vault.init();
  await server.vault.store({
    provider: 'google',
    userId: 'alice',
    accessToken: 'ya29.default-deny',
    expiresAt: new Date(Date.now() + 3600_000),
    scopes: STORED,
  });
  return server;
}

function grant(app: App, agent: AgentIdentity, allowedScopes: string[], extra: Record<string, unknown> = {}) {
  return request(app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`).send({
    agentId: agent.did,
    connectionId: 'google',
    allowedScopes,
    ...extra,
  });
}

function revokePermission(app: App, id: string) {
  return request(app).delete(`/admin/permissions/${id}`).set('Authorization', `Bearer ${ADMIN}`);
}

function delegate(app: App, agent: AgentIdentity, body: Record<string, unknown> = {}) {
  return delegateAs(app, agent, { service: 'google', user_id: 'alice', ...body }, { bearer: BEARER });
}

function revokeDelegation(app: App, id: string) {
  return request(app).delete(`/api/v1/delegations/${id}`).set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'alice' });
}

describe('default deny', () => {
  it('an agent with a Permission gets its limited scopes, not the whole connection', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    expect((await grant(app, agent, ['calendar.readonly'])).status).toBe(201);
    const res = await delegate(app, agent);
    expect(res.status).toBe(200);
    expect(res.body.scopes).toEqual(['calendar.readonly']);
  });

  it('an agent with no Permission is refused, with an error naming the fix', async () => {
    const { app } = await setup();
    const res = await delegate(app, await newAgent());
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('permission_required');
    expect(res.body.message).toContain('/admin/permissions');
    expect(res.body.access_token).toBeUndefined();
  });

  it('a Permission under the agent record id also authorizes its did:key', async () => {
    const { app, vault } = await setup();
    const agent = await newAgent();
    const now = new Date().toISOString();
    await vault.registerAgent!({
      id: 'agt_registered',
      did: agent.did,
      name: 'registered',
      fingerprint: 'fp_registered',
      scopeCeiling: [],
      status: 'active',
      createdBy: 'admin',
      createdAt: now,
      updatedAt: now,
    });
    await vault.createPermission!({
      agentId: 'agt_registered',
      connectionId: 'google',
      allowedScopes: ['gmail.readonly'],
      requiresApproval: false,
      delegatable: false,
      maxDelegationDepth: 1,
      createdBy: 'test',
    });
    const res = await delegate(app, agent);
    expect(res.status).toBe(200);
    expect(res.body.scopes).toEqual(['gmail.readonly']);
  });

  it('a raw-token request naming an agent is held to the same rule', async () => {
    const { app } = await setup({ allowRawTokens: true });
    const agent = await newAgent();
    const res = await request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .send({ service: 'google', user_id: 'alice', token_format: 'raw', agent_did: agent.did });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('permission_required');
    expect(res.body.access_token).toBeUndefined();
  });

  it('a fresh did:key under the same agent token gets nothing after a revocation', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    const created = await grant(app, agent, ['calendar.readonly']);
    expect((await revokePermission(app, created.body.permission.id)).status).toBe(204);
    const fresh = await delegate(app, await newAgent());
    expect(fresh.status).toBe(403);
    expect(fresh.body.error).toBe('permission_required');
  });

  it('refuses every agent on a vault backend with no Permission storage, and says why', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-default-deny-file-'));
    tmpDirs.push(dir);
    const { app, vault } = createServer(config({ vaultStorage: 'file', vaultPath: path.join(dir, 'vault.json') }));
    await vault.init();
    await vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.file', scopes: STORED });
    const res = await delegate(app, await newAgent());
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('permission_required');
    expect(res.body.message).toContain('VAULT_STORAGE=sqlite');
  });

  it('the opt-out restores issuing to an agent with no Permission, warns at startup and marks the audit event', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { app, vault } = await setup({ allowAgentsWithoutPermission: true });
    expect(warn.mock.calls.some(([m]) => String(m).includes('CRED_ALLOW_AGENTS_WITHOUT_PERMISSION=true'))).toBe(true);
    warn.mockRestore();
    const agent = await newAgent();
    const res = await delegate(app, agent);
    expect(res.status).toBe(200);
    expect(res.body.scopes).toEqual(STORED);
    const events = await vault.queryAuditEvents({ limit: 50 });
    const issued = events.find((e) => e.action === 'delegate' && e.outcome === 'success');
    expect(issued?.metadata?.enforcementOptOuts).toEqual(['agents_without_permission']);
  });

  it('with no opt-out set, nothing warns about the opt-outs and events carry no marker', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { app, vault } = await setup();
    expect(warn.mock.calls.some(([m]) => /CRED_ALLOW_AGENTS_WITHOUT_PERMISSION|CRED_ALLOW_REDELEGATION_AFTER_REVOCATION/.test(String(m)))).toBe(false);
    warn.mockRestore();
    const agent = await newAgent();
    await grant(app, agent, ['calendar.readonly']);
    await delegate(app, agent);
    const events = await vault.queryAuditEvents({ limit: 50 });
    expect(events.find((e) => e.action === 'delegate')?.metadata?.enforcementOptOuts).toBeUndefined();
  });
});

describe('sticky revocation', () => {
  it('after a Permission is revoked, delegation is refused and not widened', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    const created = await grant(app, agent, ['calendar.readonly']);
    expect((await delegate(app, agent)).body.scopes).toEqual(['calendar.readonly']);
    expect((await revokePermission(app, created.body.permission.id)).status).toBe(204);
    const after = await delegate(app, agent);
    expect(after.status).toBe(403);
    expect(after.body.error).toBe('agent_access_revoked');
    expect(after.body.access_token).toBeUndefined();
  });

  it('the revocation survives a restart', async () => {
    const cfg = config();
    const first = createServer(cfg);
    await first.vault.init();
    await first.vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.restart', scopes: STORED });
    const agent = await newAgent();
    const created = await grant(first.app, agent, ['calendar.readonly']);
    await revokePermission(first.app, created.body.permission.id);

    const second = createServer(cfg);
    await second.vault.init();
    const after = await delegate(second.app, agent);
    expect(after.status).toBe(403);
    expect(after.body.error).toBe('agent_access_revoked');
  });

  it('a revoked delegation\'s agent cannot immediately re-delegate, even with a Permission', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    await grant(app, agent, ['calendar.readonly']);
    const first = await delegate(app, agent);
    expect(first.status).toBe(200);
    expect((await revokeDelegation(app, first.body.delegation_id)).status).toBe(200);
    const again = await delegate(app, agent);
    expect(again.status).toBe(403);
    expect(again.body.error).toBe('agent_access_revoked');
  });

  it('a delegation revocation holds only for that user and service', async () => {
    const { app, vault } = await setup();
    await vault.store({ provider: 'google', userId: 'bob', accessToken: 'ya29.bob', expiresAt: new Date(Date.now() + 3600_000), scopes: STORED });
    const agent = await newAgent();
    await grant(app, agent, ['calendar.readonly']);
    const first = await delegate(app, agent);
    await revokeDelegation(app, first.body.delegation_id);
    expect((await delegate(app, agent)).status).toBe(403);
    expect((await delegate(app, agent, { user_id: 'bob' })).status).toBe(200);
  });

  it('a cascade reaches the agents below the revoked delegation', async () => {
    const { app } = await setup();
    const parent = await newAgent();
    const child = await newAgent();
    await grant(app, parent, ['calendar.readonly'], { delegatable: true, maxDelegationDepth: 2 });
    await grant(app, child, ['calendar.readonly'], { delegatable: true, maxDelegationDepth: 2 });
    const root = await delegate(app, parent);
    expect(root.status).toBe(200);
    const sub = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: root.body.receipt,
      agent_did: child.did,
      service: 'google',
      user_id: 'alice',
      actor_token: actorTokenFor(parent, '/api/v1/subdelegate'),
    });
    expect(sub.status).toBe(200);
    await revokeDelegation(app, root.body.delegation_id);
    const again = await delegate(app, child);
    expect(again.status).toBe(403);
    expect(again.body.error).toBe('agent_access_revoked');
  });

  it('a sub-delegation to a revoked agent is refused', async () => {
    const { app } = await setup();
    const parent = await newAgent();
    const child = await newAgent();
    await grant(app, parent, ['calendar.readonly'], { delegatable: true, maxDelegationDepth: 2 });
    await grant(app, child, ['calendar.readonly'], { delegatable: true, maxDelegationDepth: 2 });
    const root = await delegate(app, parent);
    const childFirst = await delegate(app, child);
    await revokeDelegation(app, childFirst.body.delegation_id);
    const sub = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: root.body.receipt,
      agent_did: child.did,
      service: 'google',
      user_id: 'alice',
      actor_token: actorTokenFor(parent, '/api/v1/subdelegate'),
    });
    expect(sub.status).toBe(403);
    expect(sub.body.error).toBe('agent_access_revoked');
  });

  function bcAuthorize(app: App, agent: AgentIdentity) {
    return request(app).post('/bc-authorize').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(agent, 'POST', 'http://localhost:3456/bc-authorize'))
      .send({ login_hint: 'alice', service: 'google', agent_did: agent.did, scopes: ['calendar.readonly'] });
  }

  it('/bc-authorize refuses an agent with no Permission, and one whose access was revoked', async () => {
    const { app } = await setup({ approvalWebhookUrl: 'https://hooks.example.com/approve' });
    const none = await bcAuthorize(app, await newAgent());
    expect(none.status).toBe(403);
    expect(none.body.error).toBe('permission_required');

    const agent = await newAgent();
    const created = await grant(app, agent, ['calendar.readonly'], { requiresApproval: true });
    await revokePermission(app, created.body.permission.id);
    const revoked = await bcAuthorize(app, agent);
    expect(revoked.status).toBe(403);
    expect(revoked.body.error).toBe('agent_access_revoked');
  });

  it('a delegation grant cannot be redeemed once the receiving agent is held out', async () => {
    const { app } = await setup();
    const parent = await newAgent();
    const child = await newAgent();
    await grant(app, parent, ['calendar.readonly'], { delegatable: true, maxDelegationDepth: 2 });
    await grant(app, child, ['calendar.readonly'], { delegatable: true, maxDelegationDepth: 2 });
    const root = await delegate(app, parent);
    const issued = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: root.body.receipt,
      agent_did: child.did,
      service: 'google',
      user_id: 'alice',
      exchange: 'grant',
      actor_token: actorTokenFor(parent, '/api/v1/subdelegate'),
    });
    expect(issued.status).toBe(200);
    const childOwn = await delegate(app, child);
    await revokeDelegation(app, childOwn.body.delegation_id);
    const redeemed = await request(app).post('/api/v1/token').set('Authorization', `Bearer ${BEARER}`).send({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: issued.body.delegation_grant,
      subject_token_type: 'urn:credninja:params:oauth:token-type:delegation-grant',
      actor_token: actorTokenFor(child, '/api/v1/token'),
      actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    });
    expect(redeemed.status).toBe(403);
    expect(redeemed.body.error).toBe('agent_access_revoked');
    expect(redeemed.body.access_token).toBeUndefined();
  });

  it('revoking a Permission ends the agent\'s live delegations on that service', async () => {
    const realFetch = globalThis.fetch;
    const upstream = vi.fn(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', upstream);
    try {
      const { app } = await setup();
      const agent = await newAgent();
      const created = await grant(app, agent, ['calendar.readonly']);
      const token = (await delegate(app, agent)).body.access_token as string;
      await revokePermission(app, created.body.permission.id);
      const used = await exerciseAs(app, agent, token, { url: 'https://www.googleapis.com/calendar/v3/users/me/calendarList', method: 'GET' });
      expect(used.status).toBe(401);
      expect(used.body.error).toBe('delegation_revoked');
      expect(upstream).not.toHaveBeenCalled();
    } finally {
      vi.stubGlobal('fetch', realFetch);
    }
  });

  it('re-granting restores the agent, at the new limits', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    const created = await grant(app, agent, ['calendar.readonly', 'gmail.readonly']);
    await revokePermission(app, created.body.permission.id);
    expect((await delegate(app, agent)).status).toBe(403);
    expect((await grant(app, agent, ['gmail.readonly'])).status).toBe(201);
    const after = await delegate(app, agent);
    expect(after.status).toBe(200);
    expect(after.body.scopes).toEqual(['gmail.readonly']);
  });

  it('re-granting also clears a delegation revocation', async () => {
    const { app } = await setup();
    const agent = await newAgent();
    await grant(app, agent, ['calendar.readonly']);
    const first = await delegate(app, agent);
    await revokeDelegation(app, first.body.delegation_id);
    expect((await delegate(app, agent)).status).toBe(403);
    expect((await grant(app, agent, ['calendar.readonly'])).status).toBe(201);
    expect((await delegate(app, agent)).status).toBe(200);
  });

  it('disconnecting a connection does not hold its agents out after it is reconnected', async () => {
    const { app, vault } = await setup();
    const agent = await newAgent();
    await grant(app, agent, ['calendar.readonly']);
    expect((await delegate(app, agent)).status).toBe(200);
    expect((await request(app).delete('/api/v1/connections/google').set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'alice' })).status).toBe(204);
    await vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.again', expiresAt: new Date(Date.now() + 3600_000), scopes: STORED });
    expect((await delegate(app, agent)).status).toBe(200);
  });

  it('the opt-out restores re-delegation after a revoked delegation, warns and marks the audit event', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { app, vault } = await setup({ allowRedelegationAfterRevocation: true });
    expect(warn.mock.calls.some(([m]) => String(m).includes('CRED_ALLOW_REDELEGATION_AFTER_REVOCATION=true'))).toBe(true);
    warn.mockRestore();
    const agent = await newAgent();
    await grant(app, agent, ['calendar.readonly']);
    const first = await delegate(app, agent);
    await revokeDelegation(app, first.body.delegation_id);
    const again = await delegate(app, agent);
    expect(again.status).toBe(200);
    const events = await vault.queryAuditEvents({ limit: 50 });
    const reissued = events.filter((e) => e.action === 'delegate' && e.outcome === 'success');
    expect(reissued.some((e) => (e.metadata?.enforcementOptOuts as string[] | undefined)?.includes('redelegation_after_revocation'))).toBe(true);
  });

  it('both opt-outs together restore the old widening, and say so in the audit log', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { app, vault } = await setup({ allowAgentsWithoutPermission: true, allowRedelegationAfterRevocation: true });
    warn.mockRestore();
    const agent = await newAgent();
    const created = await grant(app, agent, ['calendar.readonly']);
    await revokePermission(app, created.body.permission.id);
    const after = await delegate(app, agent);
    expect(after.status).toBe(200);
    expect(after.body.scopes).toEqual(STORED);
    const events = await vault.queryAuditEvents({ limit: 50 });
    const marked = events.find((e) => e.action === 'delegate' && e.outcome === 'success');
    expect(marked?.metadata?.enforcementOptOuts).toEqual(expect.arrayContaining(['agents_without_permission', 'redelegation_after_revocation']));
  });
});

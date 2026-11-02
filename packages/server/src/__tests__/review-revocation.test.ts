// Revocation regressions: re-granting, holds per user, opt-outs and retries.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { createDpopProof } from '@credninja/sdk';
import { createServer } from '../server.js';
import { actorTokenFor, delegateAs, newAgent, type AgentIdentity } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.restoreAllMocks());

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-review-rev-'));
  tmpDirs.push(dir);
  return {
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: BEARER,
    providers: [{ slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: [] }],
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}

const SCOPES = ['calendar.readonly', 'gmail.readonly', 'gmail.send'];
type Server = ReturnType<typeof createServer>;
async function setup(overrides: Partial<ServerConfig> = {}) {
  const server = createServer(config(overrides));
  await server.vault.init();
  for (const userId of ['alice', 'bob']) {
    await server.vault.store({ provider: 'google', userId, accessToken: `ya29.${userId}`, expiresAt: new Date(Date.now() + 3600_000), scopes: SCOPES });
  }
  return server;
}
const admin = (server: Server, method: 'get' | 'post' | 'delete', url: string) => request(server.app)[method](url).set('Authorization', `Bearer ${ADMIN}`);
const grant = (server: Server, agent: AgentIdentity, body: Record<string, unknown>) => admin(server, 'post', '/admin/permissions').send({ agentId: agent.did, connectionId: 'google', allowedScopes: ['calendar.readonly'], ...body });
const ask = (server: Server, agent: AgentIdentity, userId = 'alice', body: Record<string, unknown> = {}) => delegateAs(server.app, agent, { service: 'google', user_id: userId, ...body }, { bearer: BEARER });
const revokeDelegation = (server: Server, id: string, userId = 'alice') => request(server.app).delete(`/api/v1/delegations/${id}`).set('Authorization', `Bearer ${BEARER}`).query({ user_id: userId });

describe('re-granting keeps the limits an operator set', () => {
  it('POST refuses to replace a Permission with an approval gate or rate limit unless the body names them', async () => {
    const server = await setup({ approvalWebhookUrl: 'https://hooks.example.com/a' });
    const agent = await newAgent();
    expect((await grant(server, agent, { requiresApproval: true })).status).toBe(201);
    const silently = await grant(server, agent, {});
    expect(silently.status).toBe(409);
    expect(silently.body.error).toBe('permission_limits_would_drop');
    expect(silently.body.message).toContain('restore');
    expect((await server.vault.getPermission!(agent.did, 'google'))?.requiresApproval).toBe(true);
    expect((await grant(server, agent, { requiresApproval: false })).status).toBe(201);

    const limited = await newAgent();
    await grant(server, limited, { rateLimit: { maxRequests: 5, windowMs: 1000 } });
    expect((await grant(server, limited, {})).status).toBe(409);
    expect((await grant(server, limited, { rateLimit: null })).status).toBe(201);
  });

  it('restore ends a hold and keeps the Permission exactly as it was', async () => {
    const server = await setup();
    const agent = await newAgent();
    const created = await grant(server, agent, { rateLimit: { maxRequests: 50, windowMs: 1000 }, allowedScopes: ['calendar.readonly'] });
    const first = await ask(server, agent);
    await revokeDelegation(server, first.body.delegation_id);
    const held = await ask(server, agent);
    expect(held.status).toBe(403);
    expect(held.body.message).toContain(`/admin/permissions/`);
    expect(held.body.message).toContain('/restore');

    const restored = await admin(server, 'post', `/admin/permissions/${created.body.permission.id}/restore`).send({});
    expect(restored.status, JSON.stringify(restored.body)).toBe(200);
    expect(restored.body.holds_ended).toBe(1);
    const after = await server.vault.getPermission!(agent.did, 'google');
    expect(after?.rateLimit).toEqual({ maxRequests: 50, windowMs: 1000 });
    expect((await ask(server, agent)).status).toBe(200);
  });

  it('restore answers 404 for a Permission that no longer exists, and names what to do', async () => {
    const server = await setup();
    const res = await admin(server, 'post', '/admin/permissions/perm_missing/restore').send({});
    expect(res.status).toBe(404);
    expect(res.body.message).toContain('POST /admin/permissions');
  });
});

describe('holds are per user', () => {
  it('restoring one user does not lift another\'s, and the admin route lists them', async () => {
    const server = await setup();
    const agent = await newAgent();
    const created = await grant(server, agent, {});
    for (const userId of ['alice', 'bob']) {
      const issued = await ask(server, agent, userId);
      await revokeDelegation(server, issued.body.delegation_id, userId);
    }
    const listed = await admin(server, 'get', '/admin/agent-holds').query({ agent_id: agent.did });
    expect(listed.status).toBe(200);
    expect(listed.body.holds.map((h: { user_id: string }) => h.user_id).sort()).toEqual(['alice', 'bob']);
    expect(listed.body.holds[0]).toMatchObject({ agent_id: agent.did, service: 'google', cause: expect.stringContaining('delegation:') });

    const res = await admin(server, 'post', `/admin/permissions/${created.body.permission.id}/restore`).send({ user_id: 'alice' });
    expect(res.body.holds_ended).toBe(1);
    expect((await ask(server, agent, 'alice')).status).toBe(200);
    expect((await ask(server, agent, 'bob')).status).toBe(403);
    const left = await admin(server, 'get', '/admin/agent-holds').query({ user_id: 'bob' });
    expect(left.body.holds).toHaveLength(1);
    expect((await admin(server, 'get', '/admin/agent-holds').query({ user_id: 'alice' })).body.holds).toHaveLength(0);
    expect((await request(server.app).get('/admin/agent-holds')).status).toBeGreaterThanOrEqual(401);
  });
});

describe('a revocation ends the consent behind it', () => {
  it('DELETE /admin/permissions/:id revokes the agent\'s consents on that service only', async () => {
    const server = await setup();
    const agent = await newAgent();
    const created = await grant(server, agent, {});
    const issued = await ask(server, agent);
    const consentId = JSON.parse(Buffer.from(issued.body.access_token.split('.')[1], 'base64url').toString()).consent_id;
    await server.vault.recordConsent({ id: 'consent_other', subject: 'alice', agentDid: agent.did, service: 'github', capabilities: [], source: 'delegation', approvedBy: 'x', expiresAt: null, chainContext: {} } as never);
    await admin(server, 'delete', `/admin/permissions/${created.body.permission.id}`);
    expect(await server.vault.getConsentRevocation(consentId)).not.toBeNull();
    expect(await server.vault.getConsentRevocation('consent_other')).toBeNull();
  });

  it('a delegation revocation revokes the consents for that user only', async () => {
    const server = await setup();
    const agent = await newAgent();
    await grant(server, agent, {});
    const claims = (token: string) => JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()) as { consent_id: string };
    const a = await ask(server, agent, 'alice');
    const b = await ask(server, agent, 'bob');
    await revokeDelegation(server, a.body.delegation_id, 'alice');
    expect(await server.vault.getConsentRevocation(claims(a.body.access_token).consent_id)).not.toBeNull();
    expect(await server.vault.getConsentRevocation(claims(b.body.access_token).consent_id)).toBeNull();
  });
});

describe('the single opt-out does not let a new key escape a revocation', () => {
  it('refuses an unregistered did:key on a service and user with a hold, and only there', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const server = await setup({ allowAgentsWithoutPermission: true });
    expect(warn.mock.calls.some(([m]) => String(m).includes('CRED_ALLOW_AGENTS_WITHOUT_PERMISSION=true') && String(m).includes('revo'))).toBe(true);
    const agent = await newAgent();
    expect((await ask(server, await newAgent())).status).toBe(200);
    const issued = await ask(server, agent);
    await revokeDelegation(server, issued.body.delegation_id);
    const fresh = await ask(server, await newAgent());
    expect(fresh.status).toBe(403);
    expect(fresh.body.error).toBe('agent_access_revoked');
    expect((await ask(server, await newAgent(), 'bob')).status).toBe(200);
  });

  it('a Permission-level hold counts for every user', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const server = await setup({ allowAgentsWithoutPermission: true });
    const agent = await newAgent();
    const created = await grant(server, agent, {});
    await admin(server, 'delete', `/admin/permissions/${created.body.permission.id}`);
    expect((await ask(server, await newAgent(), 'bob')).status).toBe(403);
  });
});

describe('raw tokens', () => {
  const raw = (server: Server, body: Record<string, unknown>) => request(server.app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`).send({ service: 'google', user_id: 'alice', token_format: 'raw', ...body });

  it('an anonymous raw request is refused unless the agents opt-out is set too', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const strict = await setup({ allowRawTokens: true });
    const refused = await raw(strict, {});
    expect(refused.status).toBe(403);
    expect(refused.body.error).toBe('permission_required');
    expect(refused.body.access_token).toBeUndefined();
    const route = await request(strict.app).get('/api/token/google').set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'alice' });
    expect(route.status).toBe(403);
    expect(route.body.error).toBe('permission_required');

    const open = await setup({ allowRawTokens: true, allowAgentsWithoutPermission: true });
    expect((await raw(open, {})).status).toBe(200);
    expect((await request(open.app).get('/api/token/google').set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'alice' })).status).toBe(200);
    const events = open.vault.queryAuditEvents({ limit: 50 }).filter((e) => e.outcome === 'success' && (e.metadata?.enforcementOptOuts as string[] | undefined)?.includes('raw_tokens'));
    expect(events).toHaveLength(2);
    expect(events[0]!.metadata?.enforcementOptOuts).toContain('agents_without_permission');
  });

  it('a did:key raw request whose Permission intersects nothing is refused, not given the token', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const server = await setup({ allowRawTokens: true });
    const agent = await newAgent();
    await grant(server, agent, { allowedScopes: ['drive.readonly'] });
    const res = await raw(server, { agent_did: agent.did });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('no_scopes_granted');
    expect(res.body.access_token).toBeUndefined();
  });

  it('a did:key raw request with a Permission is marked', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const server = await setup({ allowRawTokens: true });
    const agent = await newAgent();
    await grant(server, agent, {});
    expect((await raw(server, { agent_did: agent.did })).status).toBe(200);
    expect(server.vault.queryAuditEvents({ limit: 50 }).find((e) => e.action === 'delegate')?.metadata?.enforcementOptOuts).toEqual(['raw_tokens']);
  });
});

describe('the revocation opt-out is marked wherever it lets a call through', () => {
  it('grant redemption at /api/v1/token', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const server = await setup({ allowRedelegationAfterRevocation: true });
    const [parent, child] = [await newAgent(), await newAgent()];
    await grant(server, parent, { delegatable: true, maxDelegationDepth: 3 });
    await grant(server, child, { delegatable: true, maxDelegationDepth: 3 });
    const root = await ask(server, parent);
    const issued = await request(server.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`).send({
      parent_receipt: root.body.receipt, agent_did: child.did, service: 'google', user_id: 'alice', exchange: 'grant', actor_token: actorTokenFor(parent, '/api/v1/subdelegate'),
    });
    const own = await ask(server, child);
    await revokeDelegation(server, own.body.delegation_id);
    const redeemed = await request(server.app).post('/api/v1/token').set('Authorization', `Bearer ${BEARER}`).send({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: issued.body.delegation_grant,
      subject_token_type: 'urn:credninja:params:oauth:token-type:delegation-grant',
      actor_token: actorTokenFor(child, '/api/v1/token'), actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    });
    expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    const event = server.vault.queryAuditEvents({ limit: 50 }).find((e) => e.metadata?.stage === 'token_exchange');
    expect(event?.metadata?.enforcementOptOuts).toEqual(['redelegation_after_revocation']);
  });

  it('/bc-authorize', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(null, { status: 204 }));
    const server = await setup({ allowRedelegationAfterRevocation: true, approvalWebhookUrl: 'https://hooks.example.com/a' });
    const agent = await newAgent();
    await server.vault.recordAgentRevocations([{ agentId: agent.did, service: 'google', userId: 'alice', cause: 'delegation:x', revokedAt: new Date().toISOString() }]);
    await grant(server, agent, { requiresApproval: true });
    await server.vault.recordAgentRevocations([{ agentId: agent.did, service: 'google', userId: 'alice', cause: 'delegation:x', revokedAt: new Date().toISOString() }]);
    const asked = await request(server.app).post('/bc-authorize').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(agent, 'POST', 'http://localhost:3456/bc-authorize'))
      .send({ login_hint: 'alice', service: 'google', agent_did: agent.did, scopes: ['calendar.readonly'] });
    expect(asked.status, JSON.stringify(asked.body)).toBe(200);
    const event = server.vault.queryAuditEvents({ limit: 50 }).find((e) => e.metadata?.stage === 'approval_requested');
    expect(event?.metadata?.enforcementOptOuts).toEqual(['redelegation_after_revocation']);
  });
});

describe('a retried revocation stays correct', () => {
  it('holds and consent revocations commit with the delegations, so none can be left behind', async () => {
    const server = await setup();
    const agent = await newAgent();
    await grant(server, agent, {});
    const issued = await ask(server, agent);
    const realRecord = server.vault.recordAgentRevocations.bind(server.vault);
    // Nothing writes holds after the transaction any more.
    server.vault.recordAgentRevocations = vi.fn(async () => { throw new Error('disk full'); }) as never;
    const first = await revokeDelegation(server, issued.body.delegation_id);
    expect(first.status).toBe(200);
    server.vault.recordAgentRevocations = realRecord;
    expect((await ask(server, agent)).body.error).toBe('agent_access_revoked');
  });

  it('a delegation already revoked by a disconnect gets no hold from a later revocation by id', async () => {
    const server = await setup();
    const agent = await newAgent();
    await grant(server, agent, {});
    const issued = await ask(server, agent);
    await request(server.app).delete('/api/v1/connections/google').set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'alice' });
    await server.vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.again', expiresAt: new Date(Date.now() + 3600_000), scopes: SCOPES });
    const res = await revokeDelegation(server, issued.body.delegation_id);
    expect(res.status).toBe(200);
    expect(res.body.revoked_count).toBe(0);
    expect((await ask(server, agent)).status).toBe(200);
  });

  it('a failed Permission delete can be retried: delegations are ended before the row goes', async () => {
    const server = await setup();
    const agent = await newAgent();
    const created = await grant(server, agent, {});
    const issued = await ask(server, agent);
    const realCascade = server.vault.revokeDelegations.bind(server.vault);
    vi.spyOn(console, 'error').mockImplementation(() => {});
    server.vault.revokeDelegations = vi.fn(async () => { throw new Error('busy'); }) as never;
    const failed = await admin(server, 'delete', `/admin/permissions/${created.body.permission.id}`);
    expect(failed.status).toBeGreaterThanOrEqual(500);
    expect(await server.vault.getPermission!(agent.did, 'google')).not.toBeNull();
    server.vault.revokeDelegations = realCascade;
    expect((await admin(server, 'delete', `/admin/permissions/${created.body.permission.id}`)).status).toBe(204);
    expect((await server.vault.getDelegation(issued.body.delegation_id))?.status).toBe('revoked');
  });
});

describe('a Permission under both the DID and the record id', () => {
  it('applies the intersection of their limits', async () => {
    const server = await setup({ approvalWebhookUrl: 'https://hooks.example.com/a' });
    const agent = await newAgent();
    const now = new Date().toISOString();
    await server.vault.registerAgent!({ id: 'agt_both', did: agent.did, name: 'b', fingerprint: 'fp_b', scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now });
    const base = { connectionId: 'google', requiresApproval: false, delegatable: true, maxDelegationDepth: 3, createdBy: 'test' };
    await server.vault.createPermission!({ ...base, agentId: agent.did, allowedScopes: ['calendar.readonly', 'gmail.readonly'] });
    await server.vault.createPermission!({ ...base, agentId: 'agt_both', allowedScopes: ['gmail.readonly', 'gmail.send'] });
    const res = await ask(server, agent);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scopes).toEqual(['gmail.readonly']);
    await server.vault.createPermission!({ ...base, agentId: agent.did, allowedScopes: ['gmail.readonly'], requiresApproval: true });
    expect((await ask(server, agent)).body.error).toBe('approval_required');
  });

  it('with the tighter expiry', async () => {
    const server = await setup();
    const agent = await newAgent();
    const now = new Date().toISOString();
    await server.vault.registerAgent!({ id: 'agt_exp', did: agent.did, name: 'e', fingerprint: 'fp_e', scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now });
    const base = { connectionId: 'google', requiresApproval: false, delegatable: true, maxDelegationDepth: 3, createdBy: 'test', allowedScopes: ['gmail.readonly'] };
    await server.vault.createPermission!({ ...base, agentId: agent.did, expiresAt: new Date(Date.now() - 1000) });
    await server.vault.createPermission!({ ...base, agentId: 'agt_exp' });
    expect((await ask(server, agent)).body.error).toBe('permission_expired');
  });
});

import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { newAgent, delegateAs, exerciseAs, actorTokenFor, type AgentIdentity } from './token-helpers.js';

const ADMIN_TOKEN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;

const tmpDirs: string[] = [];

function makeConfig(overrides?: Partial<ServerConfig>): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-handle-'));
  tmpDirs.push(dir);
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'file',
    tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN_TOKEN,
    requireAgentIdentity: false,
    requireDpop: false, allowRawTokens: true,
    agentRequestVerifier: (req) => {
      const agent = req.get('X-Test-Agent');
      return agent
        ? { ok: true, principal: { type: 'external-runtime', principalId: `agt_${agent}` } }
        : { ok: false, status: 401, error: 'invalid test agent' };
    },
    providers: [
      {
        slug: 'google',
        clientId: 'test-google-client-id',
        clientSecret: 'test-google-client-secret',
        defaultScopes: ['openid', 'email', 'profile'],
      },
    ],
    redirectBaseUri: 'http://localhost:3456',
    webBotAuthNonceStore: 'memory',
    ...overrides,
  };
}

async function serverWithGoogle() {
  const { app, vault } = createServer(makeConfig());
  await vault.init();
  await vault.store({
    provider: 'google',
    userId: 'default',
    accessToken: 'ya29.handle-token',
    refreshToken: '1//refresh-token',
    expiresAt: new Date(Date.now() + 3600 * 1000),
    scopes: ['calendar.readonly'],
  });
  return { app, vault };
}

const BASE = 'http://localhost:3456';
const CALENDAR = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';

/** Mint a Delegation Token for `agent` (the caller is the test runtime `runtime`). */
function mintHandle(app: any, agent: AgentIdentity, body: Record<string, unknown> = {}, runtime = 'alpha') {
  return delegateAs(app, agent, { service: 'google', user_id: 'default', scopes: ['calendar.readonly'], ...body },
    { bearer: 'unused', base: BASE, headers: { 'X-Test-Agent': runtime } });
}

function useHandle(app: any, agent: AgentIdentity, token: string, runtime = 'alpha') {
  return exerciseAs(app, agent, token, { url: CALENDAR, method: 'GET' }, { base: BASE, headers: { 'X-Test-Agent': runtime } });
}

function mockUpstream() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ items: [] }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }));
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of tmpDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('brokered handle hardening', () => {
  it('returns a key-bound Delegation Token when token_format is omitted', async () => {
    const { app } = await serverWithGoogle();
    const agent = await newAgent();
    const res = await delegateAs(app, agent, { service: 'google', user_id: 'default', scopes: ['calendar.readonly'], token_format: undefined },
      { bearer: 'unused', base: BASE, headers: { 'X-Test-Agent': 'alpha' } });
    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe('DPoP');
    expect(res.body.access_token.split('.')).toHaveLength(3);
    expect(JSON.stringify(res.body)).not.toContain('ya29.handle-token');
    expect(Buffer.from(res.body.access_token.split('.')[1], 'base64url').toString()).not.toContain('ya29');
  });

  it('still returns the provider token when raw is requested explicitly', async () => {
    const { app } = await serverWithGoogle();
    const res = await request(app).post('/api/v1/delegate').set('X-Test-Agent', 'alpha')
      .send({ service: 'google', user_id: 'default', scopes: ['calendar.readonly'], token_format: 'raw' });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBe('ya29.handle-token');
  });

  it('refuses a token presented without the agent key: another agent, or a leaked token with no proof', async () => {
    const { app } = await serverWithGoogle();
    const alpha = await newAgent();
    const mallory = await newAgent();
    const minted = await mintHandle(app, alpha);
    expect(minted.status).toBe(200);
    const token = minted.body.access_token as string;
    const fetchSpy = mockUpstream();

    // Another agent with its own key (and the same runtime identity) is refused.
    const stolen = await useHandle(app, mallory, token);
    expect(stolen.status).toBe(401);
    expect(stolen.body.error).toBe('invalid_dpop_proof');
    // A leaked token with no proof at all is refused.
    const bare = await request(app).post('/api/v1/use').set('X-Test-Agent', 'alpha')
      .set('Authorization', `DPoP ${token}`).send({ url: CALENDAR, method: 'GET' });
    expect(bare.status).toBe(401);
    expect(fetchSpy).not.toHaveBeenCalled();

    const own = await useHandle(app, alpha, token);
    expect(own.status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('ends live handles and revokes at the provider when the connection is revoked', async () => {
    const { app } = await serverWithGoogle();
    const alpha = await newAgent();
    const minted = await mintHandle(app, alpha);
    expect(minted.status).toBe(200);
    const fetchSpy = mockUpstream();

    const revoked = await request(app)
      .delete('/api/v1/connections/google?user_id=default')
      .set('X-Test-Agent', 'alpha');
    expect(revoked.status).toBe(204);

    const afterRevoke = await useHandle(app, alpha, minted.body.access_token);
    expect(afterRevoke.status).toBe(401);
    expect(afterRevoke.body.error).toBe('delegation_revoked');

    await vi.waitFor(() => {
      const revokeCall = fetchSpy.mock.calls.find(([url]) => String(url).includes('oauth2.googleapis.com/revoke'));
      expect(revokeCall).toBeDefined();
    });
    const upstreamCalls = fetchSpy.mock.calls.filter(([url]) => String(url).includes('googleapis.com/calendar'));
    expect(upstreamCalls).toHaveLength(0);
  });

  it('refuses a handle whose connection was removed outside this process', async () => {
    const { app, vault } = await serverWithGoogle();
    const alpha = await newAgent();
    const minted = await mintHandle(app, alpha);
    const fetchSpy = mockUpstream();

    // Another process sharing the vault deletes the connection directly.
    await vault.delete({ provider: 'google', userId: 'default' });

    const res = await useHandle(app, alpha, minted.body.access_token);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('connection_revoked');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('revokes with the refresh token even when the stored access token has expired', async () => {
    const { app, vault } = createServer(makeConfig());
    await vault.init();
    await vault.store({
      provider: 'google',
      userId: 'default',
      accessToken: 'ya29.expired',
      refreshToken: '1//still-valid-refresh',
      expiresAt: new Date(Date.now() - 60_000),
      scopes: ['calendar.readonly'],
    });
    const fetchSpy = mockUpstream();

    const revoked = await request(app)
      .delete('/api/v1/connections/google?user_id=default')
      .set('X-Test-Agent', 'alpha');
    expect(revoked.status).toBe(204);

    await vi.waitFor(() => {
      const revokeCall = fetchSpy.mock.calls.find(([url]) => String(url).includes('oauth2.googleapis.com/revoke'));
      expect(revokeCall).toBeDefined();
      expect(decodeURIComponent(`${String(revokeCall![0])} ${String(revokeCall![1]?.body ?? '')}`)).toContain('1//still-valid-refresh');
    });
  });

  it('binds a handle to the agent key, not the caller identity: a keyless caller is refused whatever the verifier says', async () => {
    const { app, vault } = createServer(makeConfig({
      agentRequestVerifier: () => ({ ok: true, principal: { type: 'external-runtime' } }),
    }));
    await vault.init();
    await vault.store({
      provider: 'google',
      userId: 'default',
      accessToken: 'ya29.anon',
      expiresAt: new Date(Date.now() + 3600 * 1000),
      scopes: ['calendar.readonly'],
    });

    const handle = await request(app)
      .post('/api/v1/delegate')
      .send({ service: 'google', user_id: 'default', scopes: ['calendar.readonly'] });
    expect(handle.status).toBe(400);
    expect(handle.body.error).toBe('agent_key_required');

    // With a key the same anonymous runtime gets a token, bound to that key.
    const agent = await newAgent();
    const keyed = await delegateAs(app, agent, { service: 'google', user_id: 'default', scopes: ['calendar.readonly'] }, { bearer: 'unused', base: BASE });
    expect(keyed.status).toBe(200);
    expect(keyed.body.cnf.jkt).toBeTruthy();

    const raw = await request(app)
      .post('/api/v1/delegate')
      .send({ service: 'google', user_id: 'default', scopes: ['calendar.readonly'], token_format: 'raw' });
    expect(raw.status).toBe(200);
    expect(raw.body.access_token).toBe('ya29.anon');
  });

  it('refuses a sub-delegation whose permission requires human approval', async () => {
    const { app, vault } = await serverWithGoogle();
    const childAgent = await newAgent();
    await vault.createPermission({
      agentId: childAgent.did,
      connectionId: 'google',
      allowedScopes: ['calendar.readonly'],
      delegatable: true,
      maxDelegationDepth: 2,
      requiresApproval: true,
      createdBy: 'test',
    });
    const parent = await newAgent();
    const root = await mintHandle(app, parent, {}, 'parent');
    expect(root.status).toBe(200);

    const child = await request(app)
      .post('/api/v1/subdelegate')
      .set('X-Test-Agent', 'child')
      .send({
        parent_receipt: root.body.receipt,
        actor_token: actorTokenFor(parent, '/api/v1/subdelegate', BASE),
        agent_did: childAgent.did,
        service: 'google',
        user_id: 'default',
        scopes: ['calendar.readonly'],
      });
    expect(child.status).toBe(403);
    expect(child.body.error).toBe('approval_required');
  });

  it('refuses a sub-delegation under an expired permission', async () => {
    const { app, vault } = await serverWithGoogle();
    const childAgent = await newAgent();
    await vault.createPermission({
      agentId: childAgent.did,
      connectionId: 'google',
      allowedScopes: ['calendar.readonly'],
      delegatable: true,
      maxDelegationDepth: 2,
      requiresApproval: false,
      expiresAt: new Date(Date.now() - 1000),
      createdBy: 'test',
    });
    const parent = await newAgent();
    const root = await mintHandle(app, parent, {}, 'parent');

    const child = await request(app)
      .post('/api/v1/subdelegate')
      .set('X-Test-Agent', 'child')
      .send({
        parent_receipt: root.body.receipt,
        actor_token: actorTokenFor(parent, '/api/v1/subdelegate', BASE),
        agent_did: childAgent.did,
        service: 'google',
        user_id: 'default',
        scopes: ['calendar.readonly'],
      });
    expect(child.status).toBe(403);
    expect(child.body.error).toBe('permission_expired');
  });
});

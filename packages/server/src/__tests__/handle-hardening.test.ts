import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

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

function mintHandle(app: any, agent: string, body: Record<string, unknown> = {}) {
  return request(app)
    .post('/api/v1/delegate')
    .set('X-Test-Agent', agent)
    .send({ service: 'google', user_id: 'default', scopes: ['calendar.readonly'], ...body });
}

function useHandle(app: any, agent: string, delegationId: string) {
  return request(app)
    .post('/api/v1/use')
    .set('X-Test-Agent', agent)
    .send({
      delegation_id: delegationId,
      url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      method: 'GET',
    });
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
  it('returns a brokered handle when token_format is omitted', async () => {
    const { app } = await serverWithGoogle();
    const res = await mintHandle(app, 'alpha');
    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe('Delegation');
    expect(res.body.access_token).toBeUndefined();
  });

  it('still returns the provider token when raw is requested explicitly', async () => {
    const { app } = await serverWithGoogle();
    const res = await mintHandle(app, 'alpha', { token_format: 'raw' });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBe('ya29.handle-token');
  });

  it('refuses a handle presented by a caller other than the one it was minted for', async () => {
    const { app } = await serverWithGoogle();
    const minted = await mintHandle(app, 'alpha');
    const fetchSpy = mockUpstream();

    const stolen = await useHandle(app, 'mallory', minted.body.delegation_id);
    expect(stolen.status).toBe(404);
    expect(fetchSpy).not.toHaveBeenCalled();

    const own = await useHandle(app, 'alpha', minted.body.delegation_id);
    expect(own.status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('ends live handles and revokes at the provider when the connection is revoked', async () => {
    const { app } = await serverWithGoogle();
    const minted = await mintHandle(app, 'alpha');
    expect(minted.status).toBe(200);
    const fetchSpy = mockUpstream();

    const revoked = await request(app)
      .delete('/api/v1/connections/google?user_id=default')
      .set('X-Test-Agent', 'alpha');
    expect(revoked.status).toBe(204);

    const afterRevoke = await useHandle(app, 'alpha', minted.body.delegation_id);
    expect(afterRevoke.status).toBe(404);

    await vi.waitFor(() => {
      const revokeCall = fetchSpy.mock.calls.find(([url]) => String(url).includes('oauth2.googleapis.com/revoke'));
      expect(revokeCall).toBeDefined();
    });
    const upstreamCalls = fetchSpy.mock.calls.filter(([url]) => String(url).includes('googleapis.com/calendar'));
    expect(upstreamCalls).toHaveLength(0);
  });

  it('refuses a sub-delegation whose permission requires human approval', async () => {
    const { app, vault } = await serverWithGoogle();
    await vault.createPermission({
      agentId: 'did:key:child',
      connectionId: 'google',
      allowedScopes: ['calendar.readonly'],
      delegatable: true,
      maxDelegationDepth: 2,
      requiresApproval: true,
      createdBy: 'test',
    });
    const root = await mintHandle(app, 'parent', { agent_did: 'did:key:parent' });
    expect(root.status).toBe(200);

    const child = await request(app)
      .post('/api/v1/subdelegate')
      .set('X-Test-Agent', 'child')
      .send({
        parent_receipt: root.body.receipt,
        agent_did: 'did:key:child',
        service: 'google',
        user_id: 'default',
        scopes: ['calendar.readonly'],
      });
    expect(child.status).toBe(403);
    expect(child.body.error).toBe('approval_required');
  });

  it('refuses a sub-delegation under an expired permission', async () => {
    const { app, vault } = await serverWithGoogle();
    await vault.createPermission({
      agentId: 'did:key:child',
      connectionId: 'google',
      allowedScopes: ['calendar.readonly'],
      delegatable: true,
      maxDelegationDepth: 2,
      requiresApproval: false,
      expiresAt: new Date(Date.now() - 1000),
      createdBy: 'test',
    });
    const root = await mintHandle(app, 'parent', { agent_did: 'did:key:parent' });

    const child = await request(app)
      .post('/api/v1/subdelegate')
      .set('X-Test-Agent', 'child')
      .send({
        parent_receipt: root.body.receipt,
        agent_did: 'did:key:child',
        service: 'google',
        user_id: 'default',
        scopes: ['calendar.readonly'],
      });
    expect(child.status).toBe(403);
    expect(child.body.error).toBe('permission_expired');
  });
});

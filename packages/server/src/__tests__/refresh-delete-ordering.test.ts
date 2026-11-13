// Deleting a connection while one of its tokens is being refreshed must not
// bring the connection back when the refresh finishes.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { GoogleAdapter } from '@credninja/oauth';
import { createServer } from '../server.js';
import { delegateAs, newAgent } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.restoreAllMocks());

function config(): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-refresh-delete-'));
  tmpDirs.push(dir);
  return {
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: BEARER,
    providers: [{ slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: [] }],
    redirectBaseUri: 'http://localhost:3456',
  };
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

describe('connection delete during an in-flight token refresh', () => {
  it('keeps the connection deleted and issues nothing from the refreshed token', async () => {
    const server = createServer(config());
    await server.vault.init();
    await server.vault.store({
      provider: 'google', userId: 'alice', accessToken: 'ya29.expired', refreshToken: 'fixture-refresh',
      expiresAt: new Date(Date.now() - 1000), scopes: ['calendar.readonly'],
    });
    const agent = await newAgent();
    const granted = await request(server.app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`)
      .send({ agentId: agent.did, connectionId: 'google', allowedScopes: ['calendar.readonly'] });
    expect(granted.status, JSON.stringify(granted.body)).toBe(201);

    const started = deferred();
    const release = deferred();
    const refresh = vi.spyOn(GoogleAdapter.prototype, 'refreshAccessToken').mockImplementation(async () => {
      started.resolve();
      await release.promise;
      return { access_token: 'ya29.refreshed', refresh_token: 'fixture-rotated', expires_in: 3600, token_type: 'Bearer' };
    });

    const delegation = Promise.resolve(delegateAs(server.app, agent, { service: 'google', user_id: 'alice', scopes: ['calendar.readonly'] }, { bearer: BEARER }));
    await started.promise;

    const deleted = await request(server.app).delete('/api/v1/connections/google')
      .set('Authorization', `Bearer ${BEARER}`).query({ user_id: 'alice' });
    expect(deleted.status).toBe(204);
    release.resolve();

    const issued = await delegation;
    expect(refresh).toHaveBeenCalledTimes(1);
    // The delegate route answers a missing connection with consent_required.
    expect(issued.status, JSON.stringify(issued.body)).toBe(403);
    expect(issued.body.error).toBe('consent_required');
    expect(issued.body).not.toHaveProperty('delegation_token');
    expect(await server.vault.getStored({ provider: 'google', userId: 'alice' })).toBeNull();

    // Nothing to delegate from afterwards either.
    const again = await delegateAs(server.app, agent, { service: 'google', user_id: 'alice', scopes: ['calendar.readonly'] }, { bearer: BEARER });
    expect(again.status).toBe(403);
    expect(again.body.error).toBe('consent_required');
  });
});

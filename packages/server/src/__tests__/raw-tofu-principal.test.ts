/**
 * The deprecated raw-token opt-in proves the key of the agent a request names.
 * A TOFU principal (`tofu:<agentId>`) has a key on record, so naming it in
 * `agent_did` must not stand in for its proof: without this check, anyone with
 * the agent token could take a raw provider token under that principal's
 * Permission, even after the TOFU agent was revoked.
 */
import { afterAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto, { generateKeyPairSync } from 'node:crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const PROVIDER_TOKEN = 'synthetic-provider-token';
const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
});

async function rawServerWithTofuPrincipal() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-raw-tofu-'));
  dirs.push(dir);
  const config: ServerConfig = {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'sqlite',
    tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: ADMIN,
    agentToken: BEARER,
    redirectBaseUri: 'http://localhost:3456',
    allowRawTokens: true,
    providers: [{ slug: 'github', clientId: 'id', clientSecret: 'secret', defaultScopes: [] }],
  };
  const server = createServer(config);
  await server.vault.init();
  await server.tofu.init();
  await server.vault.store({
    provider: 'github', userId: 'alice', accessToken: PROVIDER_TOKEN, scopes: ['repo'],
    expiresAt: new Date(Date.now() + 3_600_000),
  });
  const publicKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const registered = await server.tofu.registerAgent({ publicKey, initialScopes: ['repo'] });
  const granted = await request(server.app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`)
    .send({ agentId: `tofu:${registered.agentId}`, connectionId: 'github', allowedScopes: ['repo'] });
  expect(granted.status, JSON.stringify(granted.body)).toBe(201);
  return { server, principal: `tofu:${registered.agentId}`, fingerprint: registered.fingerprint };
}

describe('raw tokens and a named TOFU principal', () => {
  it('refuses a raw token to a TOFU principal named without its proof, before and after revocation', async () => {
    const { server, principal, fingerprint } = await rawServerWithTofuPrincipal();
    const ask = () => request(server.app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .send({ service: 'github', user_id: 'alice', token_format: 'raw', agent_did: principal });

    const named = await ask();
    expect(named.status, JSON.stringify(named.body)).toBe(401);
    expect(named.body.error).toBe('agent_key_required');
    expect(JSON.stringify(named.body)).not.toContain(PROVIDER_TOKEN);

    await server.tofu.revokeAgent(fingerprint);
    const afterRevoke = await ask();
    expect(afterRevoke.status).toBe(401);
    expect(JSON.stringify(afterRevoke.body)).not.toContain(PROVIDER_TOKEN);
  });
});

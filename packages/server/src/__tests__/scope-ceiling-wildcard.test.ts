// Wildcard-aware per-agent scope ceilings, exercised through the HTTP surface
// at each of the three enforcement sites: the direct-delegation request
// check, the stored-consent filter, and the sub-delegation cap.
import { describe, it, expect, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { createPrivateKey, sign } from 'node:crypto';
import { createActorToken } from '@credninja/sdk';
import { createServer } from '../server.js';
import { newAgent, delegateAs } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const TEST_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const TEST_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-ceiling-wildcard-vault.sqlite');
const TEST_TOFU_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-ceiling-wildcard-tofu.sqlite');
const TEST_PASSPHRASE = 'test-passphrase-for-wildcard-ceilings';

function makeTestConfig(): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: TEST_PASSPHRASE,
    vaultStorage: 'sqlite',
    vaultPath: TEST_VAULT_PATH,
    tofuStorage: 'sqlite',
    tofuPath: TEST_TOFU_PATH,
    adminToken: `cred_admin_${crypto.randomBytes(32).toString('hex')}`,
    agentToken: TEST_TOKEN,
    requireDpop: false,
    providers: [
      {
        slug: 'google',
        clientId: 'test-google-client-id',
        clientSecret: 'test-google-client-secret',
        defaultScopes: ['openid', 'email', 'profile'],
      },
    ],
    redirectBaseUri: 'http://localhost:3456',
  };
}

function getTestSigningKey() {
  const seed = crypto.scryptSync(TEST_PASSPHRASE, 'cred:local-receipt:v1', 32);
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      seed,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
}

function createTestReceipt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify({
    iss: 'http://localhost:3456',
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  })).toString('base64url');
  const signatureInput = Buffer.from(`${header}.${payloadB64}`, 'utf8');
  const signature = sign(null, signatureInput, getTestSigningKey()).toString('base64url');
  return `${header}.${payloadB64}.${signature}`;
}

describe('wildcard scope ceilings over HTTP', () => {
  afterAll(() => {
    for (const base of [TEST_VAULT_PATH, TEST_TOFU_PATH]) {
      for (const suffix of ['', '.salt', '.check']) {
        const p = base + suffix;
        if (fs.existsSync(p)) fs.unlinkSync(p);
      }
    }
  });

  async function setup(childCeiling: string[]) {
  const wild = await newAgent();
  const wildChild = await newAgent();
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();
    await vault.store({
      provider: 'google',
      userId: 'default',
      accessToken: 'ya29.test-access-token',
      scopes: ['calendar.readonly', 'calendar.events.read', 'mail.send'],
    });
    const now = new Date().toISOString();
    if (vault.registerAgent) {
      await vault.registerAgent({
        id: 'agt_wild',
        did: wild.did,
        name: 'wild-agent',
        fingerprint: 'fp_wild',
        scopeCeiling: ['calendar.*'],
        status: 'active',
        createdBy: 'admin',
        createdAt: now,
        updatedAt: now,
      });
      await vault.registerAgent({
        id: 'agt_wildchild',
        did: wildChild.did,
        name: 'wild-child-agent',
        fingerprint: 'fp_wildchild',
        scopeCeiling: childCeiling,
        status: 'active',
        createdBy: 'admin',
        createdAt: now,
        updatedAt: now,
      });
    }
    if (vault.createPermission) {
      await vault.createPermission({
        agentId: 'agt_wildchild',
        connectionId: 'google',
        allowedScopes: ['calendar.readonly', 'calendar.events.read'],
        delegatable: true,
        maxDelegationDepth: 3,
        requiresApproval: false,
        createdBy: 'admin',
      });
    }
    return { app, vault, wild, wildChild };
  }

  it('direct delegation permits a request under a wildcard ceiling', async () => {
    const { app, wild } = await setup(['calendar.*']);
    const res = await delegateAs(app, wild, {
        service: 'google',
        user_id: 'default',
        appClientId: 'app_123',
        agent_did: wild.did,
        scopes: ['calendar.readonly'],
    }, { bearer: TEST_TOKEN });
    expect(res.status).toBe(200);
    expect(res.body.scopes).toEqual(['calendar.readonly']);
  });

  it('direct delegation rejects a request outside a wildcard ceiling', async () => {
    const { app, wild } = await setup(['calendar.*']);
    const res = await delegateAs(app, wild, {
        service: 'google',
        user_id: 'default',
        appClientId: 'app_123',
        agent_did: wild.did,
        scopes: ['mail.send'],
    }, { bearer: TEST_TOKEN });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('scope_ceiling_exceeded');
  });

  it('stored-consent filtering keeps only ceiling-covered scopes on a no-scopes request', async () => {
    const { app, wild } = await setup(['calendar.*']);
    const res = await delegateAs(app, wild, {
        service: 'google',
        user_id: 'default',
        appClientId: 'app_123',
        agent_did: wild.did,
    }, { bearer: TEST_TOKEN });
    expect(res.status).toBe(200);
    expect(res.body.scopes).toEqual(expect.arrayContaining(['calendar.readonly', 'calendar.events.read']));
    expect(res.body.scopes).not.toContain('mail.send');
  });

  it('sub-delegation grants scopes under the child wildcard ceiling', async () => {
    const { app, wild, wildChild } = await setup(['calendar.*']);
    const parentReceipt = createTestReceipt({
      sub: wild.did,
      service: 'google',
      scopes: ['calendar.readonly', 'calendar.events.read'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_wild_parent',
      chainDepth: 0,
    });
    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        actor_token: createActorToken(wild, 'http://localhost:3456/api/v1/subdelegate'),
        agent_did: wildChild.did,
        service: 'google',
        user_id: 'default',
        scopes: ['calendar.readonly'],
      });
    expect(res.status).toBe(200);
    expect(res.body.scopes).toEqual(['calendar.readonly']);
  });

  it('sub-delegation rejects when nothing granted fits the child wildcard ceiling', async () => {
    const { app, wild, wildChild } = await setup(['mail.*']);
    const parentReceipt = createTestReceipt({
      sub: wild.did,
      service: 'google',
      scopes: ['calendar.readonly', 'calendar.events.read'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_wild_parent',
      chainDepth: 0,
    });
    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        actor_token: createActorToken(wild, 'http://localhost:3456/api/v1/subdelegate'),
        agent_did: wildChild.did,
        service: 'google',
        user_id: 'default',
        scopes: ['calendar.readonly'],
      });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('scope_ceiling_exceeded');
  });
});

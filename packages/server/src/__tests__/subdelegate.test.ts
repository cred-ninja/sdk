import { describe, it, expect, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

// ── Test fixtures ────────────────────────────────────────────────────────────

const TEST_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const TEST_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-subdelegate-vault.sqlite');
const TEST_PASSPHRASE = 'test-passphrase-for-subdelegation';

function makeTestConfig(overrides?: Partial<ServerConfig>): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: TEST_PASSPHRASE,
    vaultStorage: 'sqlite',
    vaultPath: TEST_VAULT_PATH,
    agentToken: TEST_TOKEN,
    providers: [
      {
        slug: 'google',
        clientId: 'test-google-client-id',
        clientSecret: 'test-google-client-secret',
        defaultScopes: ['openid', 'email', 'profile'],
      },
    ],
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}

// ── Receipt helpers (mirror the server/SDK key derivation) ───────────────────

function getTestSigningKey() {
  const seed = crypto.createHash('sha256')
    .update(`cred-local-receipt:${TEST_PASSPHRASE}`)
    .digest();
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
    iss: 'did:key:local-cred',
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  })).toString('base64url');
  const signatureInput = Buffer.from(`${header}.${payloadB64}`, 'utf8');
  const signature = sign(null, signatureInput, getTestSigningKey()).toString('base64url');
  return `${header}.${payloadB64}.${signature}`;
}

function createBadSignatureReceipt(payload: Record<string, unknown>): string {
  // Sign with a different key to produce invalid signature
  const badSeed = crypto.createHash('sha256').update('wrong-key').digest();
  const badKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      badSeed,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify({
    iss: 'did:key:local-cred',
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  })).toString('base64url');
  const signatureInput = Buffer.from(`${header}.${payloadB64}`, 'utf8');
  const signature = sign(null, signatureInput, badKey).toString('base64url');
  return `${header}.${payloadB64}.${signature}`;
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('POST /api/v1/subdelegate', () => {
  afterAll(() => {
    for (const suffix of ['', '.salt']) {
      const p = TEST_VAULT_PATH + suffix;
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  });

  async function setupVaultWithTokenAndPermissions(config?: Partial<ServerConfig>) {
    const { app, vault } = createServer(makeTestConfig(config));
    await vault.init();

    // Store a token for google
    await vault.store({
      provider: 'google',
      userId: 'default',
      accessToken: 'ya29.test-access-token',
      scopes: ['openid', 'email', 'profile', 'calendar.readonly'],
    });

    // Register parent and child agents
    const now = new Date().toISOString();
    if (vault.registerAgent) {
      await vault.registerAgent({
        id: 'agt_parent',
        did: 'did:key:z6MkParent',
        name: 'parent-agent',
        fingerprint: 'fp_parent',
        scopeCeiling: ['openid', 'email', 'profile', 'calendar.readonly'],
        status: 'active',
        createdBy: 'admin',
        createdAt: now,
        updatedAt: now,
      });
      await vault.registerAgent({
        id: 'agt_child',
        did: 'did:key:z6MkChild',
        name: 'child-agent',
        fingerprint: 'fp_child',
        scopeCeiling: ['openid', 'email'],
        status: 'active',
        createdBy: 'admin',
        createdAt: now,
        updatedAt: now,
      });
    }

    // Create permissions for child agent
    if (vault.createPermission) {
      await vault.createPermission({
        agentId: 'agt_child',
        connectionId: 'google',
        allowedScopes: ['openid', 'email'],
        delegatable: true,
        maxDelegationDepth: 3,
        requiresApproval: false,
        createdBy: 'admin',
      });
    }

    return { app, vault };
  }

  it('rejects requests without parent_receipt', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({ agent_did: 'did:key:z6MkChild', service: 'google' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('parent_receipt');
  });

  it('rejects requests without agent_did', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({ parent_receipt: parentReceipt, service: 'google' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('agent_did');
  });

  it('rejects requests without service', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({ parent_receipt: parentReceipt, agent_did: 'did:key:z6MkChild' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('service');
  });

  it('rejects tampered/invalid receipt signatures', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    const badReceipt = createBadSignatureReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: badReceipt,
        agent_did: 'did:key:z6MkChild',
        service: 'google',
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('signature');
  });

  it('rejects malformed receipt (not 3 parts)', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: 'not.a.valid.receipt.with.five.parts',
        agent_did: 'did:key:z6MkChild',
        service: 'google',
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('format');
  });

  it('rejects service mismatch between receipt and request', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'github',
      scopes: ['repo'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        agent_did: 'did:key:z6MkChild',
        service: 'google',  // mismatch!
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Service');
  });

  it('rejects user mismatch between receipt and request', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid'],
      userId: 'admin-user',
      appClientId: 'local',
      delegationId: 'del_parent',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',  // mismatch!
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('User');
  });

  it('rejects when no credentials are stored for the service', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    // Create a permission so validation passes, but don't store any token
    if (vault.createPermission) {
      await vault.createPermission({
        agentId: 'did:key:z6MkChild',
        connectionId: 'google',
        allowedScopes: ['openid', 'email'],
        delegatable: true,
        maxDelegationDepth: 3,
        requiresApproval: false,
        createdBy: 'admin',
      });
    }

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
      });

    expect(res.status).toBe(404);
    expect(res.body.error).toContain('No credentials');
  });

  it('rejects unauthenticated requests', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .send({ parent_receipt: 'x.y.z', agent_did: 'did:key:z', service: 'google' });

    expect(res.status).toBe(401);
  });

  it('issues a child delegation with valid parent receipt and permissions', async () => {
    const { app, vault } = await setupVaultWithTokenAndPermissions();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent123',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
        scopes: ['openid', 'email'],
      });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBe('ya29.test-access-token');
    expect(res.body.token_type).toBe('Bearer');
    expect(res.body.service).toBe('google');
    expect(res.body.scopes).toEqual(['openid', 'email']);
    expect(res.body.delegation_id).toMatch(/^del_/);
    expect(res.body.receipt).toBeDefined();
    expect(res.body.chain_depth).toBe(1);
    expect(res.body.parent_delegation_id).toBe('del_parent123');
  });

  it('attenuates scopes to the intersection of parent and permission', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();

    // Parent has wide scopes, child permission only allows openid + email
    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email', 'profile', 'calendar.readonly'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_wide',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
        // Don't specify scopes — should get intersection of parent + permission
      });

    expect(res.status).toBe(200);
    // Permission allows ['openid', 'email'], parent has all 4 — intersection is ['openid', 'email']
    expect(res.body.scopes).toEqual(expect.arrayContaining(['openid', 'email']));
    expect(res.body.scopes).not.toContain('profile');
    expect(res.body.scopes).not.toContain('calendar.readonly');
  });

  it('rejects scope escalation beyond parent receipt', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_narrow',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
        scopes: ['openid', 'email'],  // email not in parent!
      });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('scope_escalation_denied');
  });

  it('rejects when max delegation depth is exceeded', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();

    // maxDelegationDepth is 3, parent is already at depth 3
    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_deep',
      chainDepth: 3,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
        scopes: ['openid'],
      });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('depth_exceeded');
  });

  it('child receipt can be verified and contains lineage fields', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_verify_parent',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
        scopes: ['openid'],
      });

    expect(res.status).toBe(200);

    // Decode the child receipt
    const childReceipt = res.body.receipt;
    const parts = childReceipt.split('.');
    expect(parts).toHaveLength(3);

    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    expect(payload.sub).toBe('did:key:z6MkChild');
    expect(payload.service).toBe('google');
    expect(payload.scopes).toEqual(['openid']);
    expect(payload.chainDepth).toBe(1);
    expect(payload.parentDelegationId).toBe('del_verify_parent');
    expect(payload.parentReceiptHash).toBeDefined();
    expect(payload.parentReceiptHash).toHaveLength(64); // SHA-256 hex

    // Verify the receipt signature using the same key
    const sigInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
    const pubKey = createPublicKey(getTestSigningKey());
    const { verify: cryptoVerify } = await import('node:crypto');
    const valid = cryptoVerify(null, sigInput, pubKey, Buffer.from(parts[2], 'base64url'));
    expect(valid).toBe(true);
  });
});

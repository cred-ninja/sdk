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
const TEST_ADMIN_TOKEN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const TEST_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-subdelegate-vault.sqlite');
const TEST_TOFU_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-subdelegate-tofu.sqlite');
const TEST_PASSPHRASE = 'test-passphrase-for-subdelegation';

function makeTestConfig(overrides?: Partial<ServerConfig>): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: TEST_PASSPHRASE,
    vaultStorage: 'sqlite',
    vaultPath: TEST_VAULT_PATH,
    tofuStorage: 'sqlite',
    tofuPath: TEST_TOFU_PATH,
    adminToken: TEST_ADMIN_TOKEN,
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
  const badSeed = crypto.scryptSync('wrong-key', 'cred:local-receipt:v1', 32);
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
    for (const base of [TEST_VAULT_PATH, TEST_TOFU_PATH]) {
      for (const suffix of ['', '.salt']) {
        const p = base + suffix;
        if (fs.existsSync(p)) fs.unlinkSync(p);
      }
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
    // Sub-delegation always returns a brokered handle, never the raw
    // provider token — see the "sub-delegation is always brokered" tests.
    expect(res.body.access_token).toBeUndefined();
    expect(res.body.token_type).toBe('Delegation');
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

  it('always returns a brokered handle even when raw token_format is requested', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_raw_request',
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
        token_format: 'raw',
      });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeUndefined();
    expect(res.body.token_type).toBe('Delegation');
    expect(res.body.token_format_enforced).toBe('brokered');
    expect(res.body.requested_token_format).toBe('raw');
  });

  it('rejects sub-delegation for services with no brokered-use path', async () => {
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: 'irrelevant.receipt.value',
        agent_did: 'did:key:z6MkChild',
        service: 'linear',
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('brokered_format_unsupported');
  });

  it('denies sub-delegation when the parent agent has been revoked', async () => {
    const { app, vault } = await setupVaultWithTokenAndPermissions();
    await vault.revokeAgent('agt_parent');

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_revoked',
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

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('ancestor_agent_revoked');
  });

  it('denies sub-delegation when the parent agent is suspended', async () => {
    const { app, vault } = await setupVaultWithTokenAndPermissions();
    const now = new Date().toISOString();
    await vault.registerAgent({
      id: 'agt_parent',
      did: 'did:key:z6MkParent',
      name: 'parent-agent',
      fingerprint: 'fp_parent',
      scopeCeiling: ['openid', 'email', 'profile', 'calendar.readonly'],
      status: 'suspended',
      createdBy: 'admin',
      createdAt: now,
      updatedAt: now,
    });

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_suspended',
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

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('ancestor_agent_suspended');
  });

  it('still allows sub-delegation when the parent DID has no agent record (unknown-agent behavior)', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkUnknownParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_unknown',
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
  });

  it('denies a two-hop-removed sub-delegation when a revoked grandparent is still in the chain', async () => {
    // Regression test for the full-lineage ancestor check: a revoked
    // grandparent must block new descendants even when the immediate
    // parent presenting the receipt is still active. This exercises the
    // real POST /api/v1/subdelegate route end-to-end for both hops so the
    // `lineage` claim is populated exactly as it would be in production
    // (not hand-forged in the test).
    const { app, vault } = createServer(makeTestConfig());
    await vault.init();

    await vault.store({
      provider: 'google',
      userId: 'default',
      accessToken: 'ya29.grandparent-chain-token',
      scopes: ['openid', 'email'],
    });

    const now = new Date().toISOString();
    await vault.registerAgent({
      id: 'agt_grandparent',
      did: 'did:key:z6MkGrandparent',
      name: 'grandparent-agent',
      fingerprint: 'fp_grandparent',
      scopeCeiling: ['openid', 'email'],
      status: 'active',
      createdBy: 'admin',
      createdAt: now,
      updatedAt: now,
    });
    await vault.registerAgent({
      id: 'agt_parent',
      did: 'did:key:z6MkParent',
      name: 'parent-agent',
      fingerprint: 'fp_parent',
      scopeCeiling: ['openid', 'email'],
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
    await vault.createPermission({
      agentId: 'agt_parent',
      connectionId: 'google',
      allowedScopes: ['openid', 'email'],
      delegatable: true,
      maxDelegationDepth: 5,
      requiresApproval: false,
      createdBy: 'admin',
    });
    await vault.createPermission({
      agentId: 'agt_child',
      connectionId: 'google',
      allowedScopes: ['openid', 'email'],
      delegatable: true,
      maxDelegationDepth: 5,
      requiresApproval: false,
      createdBy: 'admin',
    });

    // Root receipt, signed by the grandparent (chainDepth 0, no ancestors).
    const grandparentReceipt = createTestReceipt({
      sub: 'did:key:z6MkGrandparent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_grandparent',
      chainDepth: 0,
    });

    // Hop 1: grandparent -> parent. Minted for real by the server, so its
    // `lineage` claim is exactly what production would produce.
    const hop1 = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: grandparentReceipt,
        agent_did: 'did:key:z6MkParent',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
        scopes: ['openid', 'email'],
      });
    expect(hop1.status).toBe(200);
    expect(hop1.body.chain_depth).toBe(1);
    const parentReceipt = hop1.body.receipt as string;

    // Sanity check: the parent's own receipt now carries the grandparent in
    // its lineage claim.
    const parentPayload = JSON.parse(Buffer.from(parentReceipt.split('.')[1], 'base64url').toString('utf8'));
    expect(parentPayload.lineage).toEqual(['did:key:z6MkGrandparent']);

    // The grandparent is revoked *after* the parent receipt was minted —
    // the parent agent itself remains active throughout.
    await vault.revokeAgent('agt_grandparent');

    // Hop 2: parent (still active) attempts to sub-delegate to a fresh
    // child two hops down from the now-revoked grandparent.
    const hop2 = await request(app)
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

    expect(hop2.status).toBe(403);
    expect(hop2.body.error).toBe('ancestor_agent_revoked');
    expect(JSON.stringify(hop2.body)).not.toContain('ya29.grandparent-chain-token');
  });

  it('rejects an expired parent receipt', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_expired',
      chainDepth: 0,
      exp: Math.floor(Date.now() / 1000) - 3600,
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

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('expired');
  });

  it('rejects a legacy receipt (no exp claim) older than the configured receipt TTL', async () => {
    const { app } = await setupVaultWithTokenAndPermissions({ receiptTtlSeconds: 5 });

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_legacy',
      chainDepth: 0,
      iat: Math.floor(Date.now() / 1000) - 60, // no exp field, well past the 5s TTL
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

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('expired');
  });

  it('accepts a legacy receipt (no exp claim) within the configured receipt TTL', async () => {
    const { app } = await setupVaultWithTokenAndPermissions({ receiptTtlSeconds: 3600 });

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_legacy_fresh',
      chainDepth: 0,
      iat: Math.floor(Date.now() / 1000) - 5,
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
  });

  // ── Monotonic expiry ────────────────────────────────────────────────────
  // A child receipt never outlives its parent. Mirrors
  // attenu-guard tests/vectors/reject_nonmonotonic_exp.json.

  // Server-minted receipts always carry numeric exp and iat; the cast keeps
  // the assertions below type-sound without an `any`.
  function decodeReceiptPayload(receipt: string): { exp: number; iat: number } & Record<string, unknown> {
    return JSON.parse(
      Buffer.from(receipt.split('.')[1], 'base64url').toString('utf8'),
    ) as { exp: number; iat: number } & Record<string, unknown>;
  }

  it('bounds the child receipt exp by the parent exp', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();
    const nowSeconds = Math.floor(Date.now() / 1000);
    const parentExp = nowSeconds + 120; // well under the default receipt TTL

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_short_exp',
      chainDepth: 0,
      exp: parentExp,
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
    const child = decodeReceiptPayload(res.body.receipt);
    expect(child.exp).toBeLessThanOrEqual(parentExp);
    expect(child.exp).toBeGreaterThan(nowSeconds);
  });

  it('keeps the TTL-derived exp when the parent expires later than the TTL', async () => {
    const { app } = await setupVaultWithTokenAndPermissions({ receiptTtlSeconds: 300 });
    const nowSeconds = Math.floor(Date.now() / 1000);

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_long_exp',
      chainDepth: 0,
      exp: nowSeconds + 86400,
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
    const child = decodeReceiptPayload(res.body.receipt);
    expect(child.exp).toBeLessThanOrEqual(nowSeconds + 300 + 5);
  });

  it('bounds a child by iat plus TTL when the parent is a legacy receipt without exp', async () => {
    const { app } = await setupVaultWithTokenAndPermissions({ receiptTtlSeconds: 600 });
    const nowSeconds = Math.floor(Date.now() / 1000);
    const parentIat = nowSeconds - 500; // 100 seconds of life left under a 600 second TTL

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_legacy',
      chainDepth: 0,
      iat: parentIat,
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
    const child = decodeReceiptPayload(res.body.receipt);
    expect(child.exp).toBeLessThanOrEqual(parentIat + 600);
  });

  it('rejects a parent that verifies inside clock skew but has no life left to delegate', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();
    const nowSeconds = Math.floor(Date.now() / 1000);

    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_expiring',
      chainDepth: 0,
      exp: nowSeconds - 10, // past exp, inside the 60 second skew allowance
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
    expect(res.body.error).toBe('parent_expiring');
  });

  // ── ancestor_receipts: offline chain verification at the route ──────────
  // Mirrors attenu-guard tests/vectors/reject_spliced_parent.json.

  function sha256Hex(receipt: string): string {
    return crypto.createHash('sha256').update(receipt).digest('hex');
  }

  it('accepts ancestor_receipts when the parent is the leaf of a chain the server would have minted', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();
    const nowSeconds = Math.floor(Date.now() / 1000);

    const rootReceipt = createTestReceipt({
      sub: 'did:key:z6MkRoot',
      service: 'google',
      scopes: ['openid', 'email', 'profile'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_root',
      chainDepth: 0,
      exp: nowSeconds + 3600,
    });
    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_linked',
      chainDepth: 1,
      exp: nowSeconds + 900,
      parentDelegationId: 'del_root',
      parentReceiptHash: sha256Hex(rootReceipt),
      lineage: ['did:key:z6MkRoot'],
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        ancestor_receipts: [rootReceipt],
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
        scopes: ['openid'],
      });

    expect(res.status).toBe(200);
    expect(res.body.chain_depth).toBe(2);
  });

  it('rejects ancestor_receipts that splice the parent under a root it was never derived from', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();
    const nowSeconds = Math.floor(Date.now() / 1000);

    const realRoot = createTestReceipt({
      sub: 'did:key:z6MkRoot',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_root_real',
      chainDepth: 0,
      exp: nowSeconds + 3600,
    });
    const broaderRoot = createTestReceipt({
      sub: 'did:key:z6MkOtherRoot',
      service: 'google',
      scopes: ['openid', 'email', 'profile', 'calendar.readonly'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_root_broad',
      chainDepth: 0,
      exp: nowSeconds + 3600,
    });
    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_spliced',
      chainDepth: 1,
      exp: nowSeconds + 900,
      parentDelegationId: 'del_root_real',
      parentReceiptHash: sha256Hex(realRoot),
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        ancestor_receipts: [broaderRoot],
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
        scopes: ['openid'],
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('chain_invalid');
    expect(res.body.reason).toBe('parent_hash_mismatch');
    expect(res.body.hop).toBe(1);
  });

  it('rejects a malformed ancestor_receipts value', async () => {
    const { app } = await setupVaultWithTokenAndPermissions();
    const parentReceipt = createTestReceipt({
      sub: 'did:key:z6MkParent',
      service: 'google',
      scopes: ['openid', 'email'],
      userId: 'default',
      appClientId: 'local',
      delegationId: 'del_parent_badancestors',
      chainDepth: 0,
    });

    const res = await request(app)
      .post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({
        parent_receipt: parentReceipt,
        ancestor_receipts: 'not-an-array',
        agent_did: 'did:key:z6MkChild',
        service: 'google',
        user_id: 'default',
        appClientId: 'local',
        scopes: ['openid'],
      });

    expect(res.status).toBe(400);
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

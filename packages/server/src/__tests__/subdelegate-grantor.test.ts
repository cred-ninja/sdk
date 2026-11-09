import { describe, it, expect, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import crypto, { createPrivateKey, sign } from 'node:crypto';
import { createServer } from '../server.js';
import { newAgent, actorTokenFor, type AgentIdentity } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

/**
 * POST /api/v1/subdelegate must gate on the GRANTOR's Permission.
 *
 * Regression coverage for a privately reported issue: the route passed the
 * RECEIVING agent's Permission (`agent_did` in the request body) into
 * validateSubDelegation, so a delegating agent whose own Permission had
 * `delegatable: false` (or `maxDelegationDepth: 0`) could still sub-delegate
 * whenever the receiving agent's Permission allowed it — and a receiving
 * agent with `delegatable: false` was wrongly blocked from receiving. The
 * recipient's Permission decides only which scopes it may hold; its
 * delegatable/depth govern the next hop, when it is the grantor.
 */

const PARENT = await newAgent();
const CHILD = await newAgent();
const GRANDCHILD = await newAgent();

const TEST_TOKEN = 'test-agent-token-grantor';
const TEST_ADMIN_TOKEN = 'test-admin-token-grantor';
const TEST_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-subdelegate-grantor-vault.sqlite');
const TEST_TOFU_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-subdelegate-grantor-tofu.sqlite');
const TEST_PASSPHRASE = 'test-passphrase-for-grantor-gate';

function makeTestConfig(): ServerConfig {
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
  };
}

function createTestReceipt(payload: Record<string, unknown>): string {
  const seed = crypto.scryptSync(TEST_PASSPHRASE, 'cred:local-receipt:v1', 32);
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify({
    iss: makeTestConfig().redirectBaseUri,
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  })).toString('base64url');
  const signature = sign(null, Buffer.from(`${header}.${payloadB64}`, 'utf8'), key).toString('base64url');
  return `${header}.${payloadB64}.${signature}`;
}

interface PermSpec {
  allowedScopes: string[];
  delegatable: boolean;
  maxDelegationDepth: number;
}

async function setup(opts: { parent: PermSpec; child: PermSpec; grandchild?: PermSpec }) {
  const { app, vault } = createServer(makeTestConfig());
  await vault.init();
  await vault.store({
    provider: 'google',
    userId: 'default',
    accessToken: 'provider-access-token',
    scopes: ['openid', 'email', 'profile', 'calendar.readonly'],
  });

  const now = new Date().toISOString();
  const agents: Array<[string, AgentIdentity]> = [
    ['agt_parent', PARENT],
    ['agt_child', CHILD],
    ['agt_grandchild', GRANDCHILD],
  ];
  for (const [id, agent] of agents) {
    await vault.registerAgent!({
      id,
      did: agent.did,
      name: id,
      fingerprint: `fp_${id}`,
      scopeCeiling: ['openid', 'email', 'profile', 'calendar.readonly'],
      status: 'active',
      createdBy: 'admin',
      createdAt: now,
      updatedAt: now,
    });
  }

  await vault.createPermission!({
    agentId: 'agt_parent', connectionId: 'google', requiresApproval: false, createdBy: 'admin', ...opts.parent,
  });
  await vault.createPermission!({
    agentId: 'agt_child', connectionId: 'google', requiresApproval: false, createdBy: 'admin', ...opts.child,
  });
  if (opts.grandchild) {
    await vault.createPermission!({
      agentId: 'agt_grandchild', connectionId: 'google', requiresApproval: false, createdBy: 'admin', ...opts.grandchild,
    });
  }
  return { app, vault };
}

function parentReceipt(chainDepth = 0): string {
  return createTestReceipt({
    sub: PARENT.did,
    service: 'google',
    scopes: ['openid', 'email'],
    userId: 'default',
    appClientId: 'local',
    delegationId: `del_parent_${chainDepth}`,
    chainDepth,
  });
}

function subdelegate(app: Parameters<typeof request>[0], receipt: string, actor: AgentIdentity, child: AgentIdentity, scopes?: string[]) {
  return request(app)
    .post('/api/v1/subdelegate')
    .set('Authorization', `Bearer ${TEST_TOKEN}`)
    .send({
      parent_receipt: receipt,
      actor_token: actorTokenFor(actor, '/api/v1/subdelegate'),
      agent_did: child.did,
      service: 'google',
      user_id: 'default',
      appClientId: 'local',
      ...(scopes ? { scopes } : {}),
    });
}

const ALLOWING: PermSpec = { allowedScopes: ['openid', 'email'], delegatable: true, maxDelegationDepth: 3 };

describe('POST /api/v1/subdelegate — grantor permission gate', () => {
  afterAll(() => {
    for (const base of [TEST_VAULT_PATH, TEST_TOFU_PATH]) {
      for (const suffix of ['', '.salt', '.check']) {
        const p = base + suffix;
        if (fs.existsSync(p)) fs.unlinkSync(p);
      }
    }
  });

  it('blocks when the GRANTOR delegatable is false, even though the recipient allows delegation', async () => {
    const { app } = await setup({
      parent: { allowedScopes: ['openid', 'email'], delegatable: false, maxDelegationDepth: 3 },
      child: ALLOWING,
    });
    const res = await subdelegate(app, parentReceipt(), PARENT, CHILD, ['openid', 'email']);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('delegation_not_allowed');
  });

  it('blocks when the GRANTOR maxDelegationDepth is 0', async () => {
    const { app } = await setup({
      parent: { allowedScopes: ['openid', 'email'], delegatable: true, maxDelegationDepth: 0 },
      child: ALLOWING,
    });
    const res = await subdelegate(app, parentReceipt(), PARENT, CHILD, ['openid', 'email']);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('depth_exceeded');
  });

  it('allows depth exactly equal to the grantor max, and blocks one past it', async () => {
    const { app } = await setup({
      parent: { allowedScopes: ['openid', 'email'], delegatable: true, maxDelegationDepth: 1 },
      child: ALLOWING,
    });
    const ok = await subdelegate(app, parentReceipt(0), PARENT, CHILD, ['openid', 'email']);
    expect(ok.status).toBe(200);
    expect(ok.body.chain_depth).toBe(1);

    const tooDeep = await subdelegate(app, parentReceipt(1), PARENT, CHILD, ['openid', 'email']);
    expect(tooDeep.status).toBe(403);
    expect(tooDeep.body.code).toBe('depth_exceeded');
  });

  it('allows a recipient whose own delegatable is false — that flag gates the NEXT hop, not receipt', async () => {
    const { app } = await setup({
      parent: ALLOWING,
      child: { allowedScopes: ['openid', 'email'], delegatable: false, maxDelegationDepth: 0 },
      grandchild: ALLOWING,
    });
    const hop1 = await subdelegate(app, parentReceipt(), PARENT, CHILD, ['openid', 'email']);
    expect(hop1.status).toBe(200);

    // When that recipient tries to delegate onward, ITS delegatable=false now gates.
    const hop2 = await subdelegate(app, hop1.body.receipt, CHILD, GRANDCHILD, ['openid', 'email']);
    expect(hop2.status).toBe(403);
    expect(hop2.body.code).toBe('delegation_not_allowed');
  });

  it('still attenuates granted scopes to the recipient allowedScopes', async () => {
    const { app } = await setup({
      parent: ALLOWING,
      child: { allowedScopes: ['openid'], delegatable: true, maxDelegationDepth: 3 },
    });
    const res = await subdelegate(app, parentReceipt(), PARENT, CHILD, ['openid', 'email']);
    expect(res.status).toBe(200);
    expect(res.body.scopes).toEqual(['openid']);
  });

  it('valid delegation still succeeds when the grantor allows it', async () => {
    const { app } = await setup({ parent: ALLOWING, child: ALLOWING });
    const res = await subdelegate(app, parentReceipt(), PARENT, CHILD, ['openid', 'email']);
    expect(res.status).toBe(200);
    expect(res.body.chain_depth).toBe(1);
    expect(res.body.scopes).toEqual(['openid', 'email']);
  });
});

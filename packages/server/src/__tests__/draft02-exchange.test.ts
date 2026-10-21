/**
 * draft-sweeney-wimse-credential-delegation-02 on the server: receipts
 * signed behind the signer interface (EdDSA default, ES256 by key), the
 * accepted-algorithm list, the cumulative ledger across hops, the
 * Sub-Delegation Exchange single-use grant, and Chain-Verifiable Profile
 * tokens in the draft-asor-wimse-agent-delegation-chain-02 format.
 */
import { afterAll, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import crypto, { createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import {
  createVerificationKey,
  signCompactJws,
  staticKeyResolver,
  verifyAgentDelegationChain,
} from '@credninja/attenuation';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

const TEST_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const TEST_ADMIN_TOKEN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const DIR = import.meta.dirname ?? __dirname;
const TEST_VAULT_PATH = path.join(DIR, '../../.test-draft02-vault.sqlite');
const TEST_TOFU_PATH = path.join(DIR, '../../.test-draft02-tofu.sqlite');
const TEST_PASSPHRASE = 'test-passphrase-for-draft02';
const BASE = 'http://localhost:3456';

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
    providers: [{ slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: ['openid'] }],
    redirectBaseUri: BASE,
    ...overrides,
  };
}

function derivedReceiptKey(): KeyObject {
  const seed = crypto.scryptSync(TEST_PASSPHRASE, 'cred:local-receipt:v1', 32);
  return createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes: Uint8Array): string {
  let n = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
  let out = '';
  while (n > 0n) { out = BASE58[Number(n % 58n)] + out; n /= 58n; }
  return out;
}

interface Agent { did: string; privateKey: KeyObject }
function newAgent(): Agent {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { did: `did:key:z${base58(Buffer.concat([Buffer.from([0xed, 0x01]), raw]))}`, privateKey };
}

function actorToken(agent: Agent, overrides: Record<string, unknown> = {}, key: KeyObject = agent.privateKey): string {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: agent.did, sub: agent.did, aud: `${BASE}/api/v1/token`, iat: now, exp: now + 120, jti: crypto.randomUUID(), ...overrides };
  return signCompactJws(claims, { alg: 'EdDSA', kid: agent.did, sign: (input) => crypto.sign(null, input, key) });
}

function decode(jws: string, part: 0 | 1): Record<string, any> {
  return JSON.parse(Buffer.from(jws.split('.')[part]!, 'base64url').toString('utf8'));
}

const ROOT = newAgent();
const CHILD = newAgent();
const SIBLING = newAgent();

async function setup(overrides?: Partial<ServerConfig>) {
  const { app, vault } = createServer(makeTestConfig(overrides));
  await vault.init();
  await vault.store({
    provider: 'google',
    userId: 'alice',
    accessToken: 'ya29.draft02',
    expiresAt: new Date(Date.now() + 3600 * 1000),
    scopes: ['openid', 'email', 'profile'],
  });
  for (const agent of [CHILD, SIBLING]) {
    await vault.createPermission!({
      agentId: agent.did,
      connectionId: 'google',
      allowedScopes: ['openid', 'email', 'profile'],
      delegatable: true,
      maxDelegationDepth: 3,
      requiresApproval: false,
      createdBy: 'admin',
    });
  }
  return { app, vault };
}

function delegateRoot(app: Parameters<typeof request>[0], body: Record<string, unknown> = {}) {
  return request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
    service: 'google',
    user_id: 'alice',
    scopes: ['openid', 'email'],
    agent_did: ROOT.did,
    token_format: 'handle',
    ...body,
  });
}

function subdelegate(app: Parameters<typeof request>[0], parentReceipt: string, agent: Agent, body: Record<string, unknown> = {}, delegator: Agent = ROOT) {
  return request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
    parent_receipt: parentReceipt,
    // The delegating agent proves it is the agent the parent receipt names.
    actor_token: actorToken(delegator, { aud: `${BASE}/api/v1/subdelegate` }),
    agent_did: agent.did,
    service: 'google',
    user_id: 'alice',
    scopes: ['openid'],
    ...body,
  });
}

function use(app: Parameters<typeof request>[0], delegationId: string, quantities?: Record<string, number>) {
  return request(app).post('/api/v1/use').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
    delegation_id: delegationId,
    url: 'https://www.googleapis.com/oauth2/v3/userinfo',
    method: 'GET',
    ...(quantities ? { quantities } : {}),
  });
}

function exchange(app: Parameters<typeof request>[0], grant: string, actor: string) {
  return request(app).post('/api/v1/token').set('Authorization', `Bearer ${TEST_TOKEN}`).type('form').send({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: grant,
    subject_token_type: 'urn:credninja:params:oauth:token-type:delegation-grant',
    actor_token: actor,
    actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
  });
}

afterAll(() => {
  for (const base of [TEST_VAULT_PATH, TEST_TOFU_PATH]) {
    for (const suffix of ['', '.salt', '-wal', '-shm']) {
      if (fs.existsSync(base + suffix)) fs.unlinkSync(base + suffix);
    }
  }
});

describe('receipt signing', () => {
  it('signs EdDSA by default with kid, and binds cnf to the did:key', async () => {
    const { app } = await setup();
    const res = await delegateRoot(app);
    expect(res.status).toBe(200);
    const header = decode(res.body.receipt, 0);
    expect(header.alg).toBe('EdDSA');
    expect(header.kid).toBe(createVerificationKey(derivedReceiptKey()).kid);
    const payload = decode(res.body.receipt, 1);
    expect(payload).toMatchObject({ sub: 'alice', client_id: ROOT.did, act: { sub: ROOT.did }, jti: payload.delegationId });
    expect(payload.cnf.jkt).toBeTypeOf('string');
  });

  it('signs ES256 when given a P-256 key, and the receipt anchors a sub-delegation', async () => {
    const pem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
    const { app } = await setup({ receiptSigningKeyPem: pem });
    const root = await delegateRoot(app);
    expect(decode(root.body.receipt, 0).alg).toBe('ES256');
    const child = await subdelegate(app, root.body.receipt, CHILD);
    expect(child.status).toBe(200);
    expect(decode(child.body.receipt, 1).act).toEqual({ sub: CHILD.did, act: { sub: ROOT.did } });
  });

  it('rejects a receipt whose alg is not on the accepted list, even with a valid signature', async () => {
    const { app } = await setup();
    const root = await delegateRoot(app);
    const pem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
    const strict = await setup({ receiptSigningKeyPem: pem, receiptAcceptedAlgs: ['ES256'] });
    const child = await subdelegate(strict.app, root.body.receipt, CHILD);
    expect(child.status).toBe(403);
    expect(child.body.error).toMatch(/signature/i);
  });

  it('needs a custom signer\'s verification key, and then verifies its own receipts', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const signer = { alg: 'EdDSA' as const, kid: 'hsm-1', sign: (input: Uint8Array) => crypto.sign(null, input, privateKey) };
    expect(() => createServer(makeTestConfig({ receiptSigner: signer }))).toThrow(/receiptVerificationKeys/);
    const { app } = await setup({ receiptSigner: signer, receiptVerificationKeys: [createVerificationKey(privateKey, 'hsm-1')] });
    const root = await delegateRoot(app);
    expect(decode(root.body.receipt, 0).kid).toBe('hsm-1');
    expect((await subdelegate(app, root.body.receipt, CHILD)).status).toBe(200);
  });

  it('keeps the legacy claim layout when configured', async () => {
    const { app } = await setup({ receiptClaimLayout: 'legacy' });
    const root = await delegateRoot(app);
    const payload = decode(root.body.receipt, 1);
    expect(payload.sub).toBe(ROOT.did);
    expect(payload.act).toBeUndefined();
    const child = await subdelegate(app, root.body.receipt, CHILD);
    expect(child.status).toBe(200);
  });
});

describe('caller identity on /api/v1/subdelegate', () => {
  it('rejects a valid receipt presented by a different agent', async () => {
    const { app } = await setup();
    const root = await delegateRoot(app);
    const res = await subdelegate(app, root.body.receipt, CHILD, {}, SIBLING);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('agent_identity_mismatch');
  });

  it('rejects a call without an actor token', async () => {
    const { app } = await setup();
    const root = await delegateRoot(app);
    const res = await subdelegate(app, root.body.receipt, CHILD, { actor_token: undefined });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('agent_identity_required');
  });

  it('rejects an actor token addressed to another endpoint, and a replayed one', async () => {
    const { app } = await setup();
    const root = await delegateRoot(app);
    const wrongAud = await subdelegate(app, root.body.receipt, CHILD, { actor_token: actorToken(ROOT) });
    expect(wrongAud.body.error).toBe('agent_identity_mismatch');
    const once = actorToken(ROOT, { aud: `${BASE}/api/v1/subdelegate`, jti: 'subdelegate-once' });
    expect((await subdelegate(app, root.body.receipt, CHILD, { actor_token: once })).status).toBe(200);
    expect((await subdelegate(app, root.body.receipt, SIBLING, { actor_token: once })).body.error).toBe('agent_identity_mismatch');
  });

  it('accepts the matching agent', async () => {
    const { app } = await setup();
    const root = await delegateRoot(app);
    expect((await subdelegate(app, root.body.receipt, CHILD)).status).toBe(200);
  });

  it('keeps the legacy behaviour with the flag off, and warns at startup', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { app } = await setup({ requireAgentIdentity: false });
    expect(warn.mock.calls.some((c) => String(c[0]).includes('CRED_REQUIRE_AGENT_IDENTITY=false'))).toBe(true);
    warn.mockRestore();
    const root = await delegateRoot(app);
    const res = await subdelegate(app, root.body.receipt, CHILD, { actor_token: undefined });
    expect(res.status).toBe(200);
  });
});

describe('cumulative ledger across hops', () => {
  it('debits every ancestor max_subtree, so siblings share the root budget', async () => {
    const { app } = await setup();
    const root = await delegateRoot(app, { constraints: [{ key: 'max_spend', max_subtree: 100 }] });
    expect(root.status).toBe(200);
    const a = await subdelegate(app, root.body.receipt, CHILD, { constraints: [{ key: 'max_spend', max_subtree: 80 }] });
    const b = await subdelegate(app, root.body.receipt, SIBLING, { constraints: [{ key: 'max_spend', max_subtree: 80 }] });
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    expect((await use(app, a.body.delegation_id, { max_spend: 60 })).status).toBe(200);
    const over = await use(app, b.body.delegation_id, { max_spend: 50 });
    expect(over.status).toBe(403);
    expect(over.body).toMatchObject({ error: 'cumulative_constraint_exceeded', type: 'max_subtree' });
    expect(over.body.message).toContain(root.body.delegation_id);
    expect((await use(app, b.body.delegation_id, { max_spend: 40 })).status).toBe(200);
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    fetchSpy.mockRestore();
  });
});

describe('Sub-Delegation Exchange', () => {
  async function grantFor(agent: Agent) {
    const { app } = await setup();
    const root = await delegateRoot(app);
    const res = await subdelegate(app, root.body.receipt, agent, { exchange: 'grant' });
    expect(res.status).toBe(200);
    return { app, res };
  }

  it('authorizes with a single-use grant and issues the child to the agent it names', async () => {
    const { app, res } = await grantFor(CHILD);
    expect(res.body.delegation_grant).toBeTypeOf('string');
    expect(res.body.agent_did).toBe(CHILD.did);
    // The child receipt anchors further hops, so the delegator never sees it.
    expect(res.body.receipt).toBeUndefined();
    // No handle exists until the grant is redeemed.
    expect((await use(app, res.body.delegation_id)).status).toBe(404);

    const issued = await exchange(app, res.body.delegation_grant, actorToken(CHILD));
    expect(issued.status).toBe(200);
    expect(issued.body).toMatchObject({
      delegation_id: res.body.delegation_id,
      access_token: res.body.delegation_id,
      issued_token_type: 'urn:credninja:params:oauth:token-type:delegation-handle',
      chain_depth: 1,
    });
    expect(decode(issued.body.receipt, 1)).toMatchObject({ client_id: CHILD.did, delegationId: res.body.delegation_id });

    const again = await exchange(app, res.body.delegation_grant, actorToken(CHILD));
    expect(again.status).toBe(400);
    expect(again.body.error).toBe('invalid_grant');
  });

  it('rejects an exchange whose actor is not the agent the grant names, without consuming the grant', async () => {
    const { app, res } = await grantFor(CHILD);
    const wrongKey = await exchange(app, res.body.delegation_grant, actorToken(CHILD, {}, SIBLING.privateKey));
    expect(wrongKey.status).toBe(401);
    const wrongDid = await exchange(app, res.body.delegation_grant, actorToken(SIBLING));
    expect(wrongDid.status).toBe(401);
    expect((await exchange(app, res.body.delegation_grant, actorToken(CHILD))).status).toBe(200);
  });

  it('rejects a replayed, over-long, or wrongly addressed actor token', async () => {
    const { app, res } = await grantFor(CHILD);
    const now = Math.floor(Date.now() / 1000);
    expect((await exchange(app, res.body.delegation_grant, actorToken(CHILD, { exp: now + 600 }))).status).toBe(401);
    expect((await exchange(app, res.body.delegation_grant, actorToken(CHILD, { aud: 'https://other.example.com' }))).status).toBe(401);
    const replayed = actorToken(CHILD, { jti: 'once' });
    const second = await grantFor(CHILD);
    expect((await exchange(second.app, second.res.body.delegation_grant, replayed)).status).toBe(200);
    const third = await subdelegate(second.app, (await delegateRoot(second.app)).body.receipt, CHILD, { exchange: 'grant' });
    expect((await exchange(second.app, third.body.delegation_grant, replayed)).status).toBe(401);
  });

  it('refuses to redeem a grant whose parent was revoked after authorization', async () => {
    const { app } = await setup();
    const root = await delegateRoot(app);
    const res = await subdelegate(app, root.body.receipt, CHILD, { exchange: 'grant' });
    expect(res.status).toBe(200);
    const revoke = await request(app)
      .delete(`/api/v1/delegations/${root.body.delegation_id}?user_id=alice`)
      .set('Authorization', `Bearer ${TEST_TOKEN}`);
    expect(revoke.status).toBe(200);
    const issued = await exchange(app, res.body.delegation_grant, actorToken(CHILD));
    expect(issued.status).toBe(401);
    expect(issued.body.error).toBe('delegation_revoked');
  });

  it('rejects an unknown grant and a wrong grant_type', async () => {
    const { app } = await setup();
    expect((await exchange(app, 'nope', actorToken(CHILD))).body.error).toBe('invalid_grant');
    const bad = await request(app).post('/api/v1/token').set('Authorization', `Bearer ${TEST_TOKEN}`).send({ grant_type: 'client_credentials' });
    expect(bad.body.error).toBe('unsupported_grant_type');
  });
});

describe('Chain-Verifiable Profile', () => {
  const resolveKey = staticKeyResolver([createVerificationKey(derivedReceiptKey())]);

  it('issues agent_delegation tokens that a chain-only verifier accepts', async () => {
    const { app } = await setup();
    const root = await delegateRoot(app, {
      token_profile: 'agent_delegation',
      audience: 'https://rs.example.com',
      max_depth: 2,
      constraints: [{ key: 'egress', rank: 'internal', order: ['none', 'internal', 'any'] }],
    });
    expect(root.status).toBe(200);
    const t0 = root.body.agent_delegation_token as string;
    const p0 = decode(t0, 1);
    expect(p0).toMatchObject({
      iss: BASE,
      sub: 'alice',
      client_id: ROOT.did,
      aud: 'https://rs.example.com',
      jti: root.body.delegation_id,
      del_depth: 0,
      del_max_depth: 3,
      authorization_details: [{ type: 'agent_delegation', scopes: ['openid', 'email'] }],
    });
    expect(decode(root.body.receipt, 1).chain_profile).toEqual({ format: 'agent_delegation', jti: root.body.delegation_id, scope_mapping: 'identity' });

    const child = await subdelegate(app, root.body.receipt, CHILD, {
      token_profile: 'agent_delegation',
      audience: 'https://rs.example.com',
      agent_delegation_chain: [t0],
    });
    expect(child.status).toBe(200);
    const t1 = child.body.agent_delegation_token as string;
    expect(decode(t1, 1)).toMatchObject({ sub: 'alice', client_id: CHILD.did, del_depth: 1 });

    const verified = verifyAgentDelegationChain([t0, t1], { acceptedAlgs: ['EdDSA'], resolveKey, audience: 'https://rs.example.com' });
    expect(verified).toMatchObject({ ok: true, principal: 'alice', actingAgent: CHILD.did });
  });

  it('refuses a child when the presented chain is not the parent receipt\'s', async () => {
    const { app } = await setup();
    const a = await delegateRoot(app, { token_profile: 'agent_delegation' });
    const b = await delegateRoot(app, { token_profile: 'agent_delegation' });
    const child = await subdelegate(app, a.body.receipt, CHILD, {
      token_profile: 'agent_delegation',
      agent_delegation_chain: [b.body.agent_delegation_token],
    });
    expect(child.status).toBe(400);
    expect(child.body.error).toBe('invalid_parent_chain');
  });

  it('needs a did:key agent, so the token can carry cnf', async () => {
    const { app } = await setup();
    const res = await delegateRoot(app, { token_profile: 'agent_delegation', agent_did: 'did:web:agent.example.com' });
    expect(res.status).toBe(400);
  });
});

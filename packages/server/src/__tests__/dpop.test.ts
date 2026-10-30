/**
 * DPoP-bound handles (RFC 9449), with the server's default
 * CRED_REQUIRE_DPOP=true. A brokered handle is issued only to a did:key
 * agent, bound to that key, and usable only with a fresh DPoP proof by it:
 * the handle id and the deployment Bearer credential together are no longer
 * enough. Proofs come from the TypeScript client's createDpopProof(), so the
 * suite also checks that client and server agree on the wire format.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createActorToken, createDpopProof, generateAgentIdentity, type AgentIdentity } from '@credninja/sdk';
import { canonicalJson, didKeyConfirmation } from '@credninja/attenuation';
import { createServer } from '../server.js';
import { dpopAth, normalizeHtu, verifyDpopProof } from '../dpop.js';
import type { ServerConfig } from '../config.js';

const TEST_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const TEST_ADMIN_TOKEN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const USERINFO = 'https://www.googleapis.com/oauth2/v3/userinfo';

const tmpDirs: string[] = [];

function makeConfig(overrides?: Partial<ServerConfig>): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-dpop-'));
  tmpDirs.push(dir);
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'file',
    tofuPath: path.join(dir, 'tofu.json'),
    adminToken: TEST_ADMIN_TOKEN,
    agentToken: TEST_TOKEN,
    providers: [{
      slug: 'google',
      clientId: 'test-google-client-id',
      clientSecret: 'test-google-client-secret',
      defaultScopes: ['openid', 'email', 'profile'],
    }],
    redirectBaseUri: BASE,
    ...overrides,
  };
}

async function setup(overrides?: Partial<ServerConfig>, agents: AgentIdentity[] = []) {
  const { app, vault } = createServer(makeConfig(overrides));
  await vault.init();
  await vault.store({
    provider: 'google',
    userId: 'alice',
    accessToken: 'ya29.dpop',
    expiresAt: new Date(Date.now() + 3600 * 1000),
    scopes: ['openid', 'email', 'profile'],
  });
  for (const agent of agents) {
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
  return { app };
}

type App = Parameters<typeof request>[0];

function delegate(app: App, agentDid: string | undefined, proof?: string, body: Record<string, unknown> = {}) {
  const req = request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${TEST_TOKEN}`);
  if (proof !== undefined) req.set('DPoP', proof);
  return req.send({
    service: 'google',
    user_id: 'alice',
    scopes: ['openid', 'email'],
    token_format: 'handle',
    ...(agentDid ? { agent_did: agentDid } : {}),
    ...body,
  });
}

function delegateAs(app: App, agent: AgentIdentity, body: Record<string, unknown> = {}) {
  return delegate(app, agent.did, createDpopProof(agent, 'POST', `${BASE}/api/v1/delegate`), body);
}

function useBody(delegationId: string, extra: Record<string, unknown> = {}) {
  return { delegation_id: delegationId, url: USERINFO, method: 'GET', ...extra };
}

function use(app: App, delegationId: string, proof?: string, body: Record<string, unknown> = useBody(delegationId)) {
  const req = request(app).post('/api/v1/use').set('Authorization', `Bearer ${TEST_TOKEN}`);
  if (proof !== undefined) req.set('DPoP', proof);
  return req.send(body);
}

/** A proof for exactly this request body, as the SDK's use() makes it. */
function proofFor(agent: AgentIdentity, delegationId: string, body: Record<string, unknown> = useBody(delegationId)) {
  return createDpopProof(agent, 'POST', `${BASE}/api/v1/use`, delegationId, body);
}

function useAs(app: App, agent: AgentIdentity, delegationId: string) {
  return use(app, delegationId, proofFor(agent, delegationId));
}

function reqHash(body: unknown): string {
  return crypto.createHash('sha256').update(canonicalJson(body), 'utf8').digest('base64url');
}

/** A proof with chosen header and claims, signed by `agent`'s key (for malformed cases). */
function craftProof(agent: AgentIdentity, claims: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  const key = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(agent.privateKey)]),
    format: 'der',
    type: 'pkcs8',
  });
  const jwk = crypto.createPublicKey(key).export({ format: 'jwk' }) as Record<string, string>;
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode({ alg: 'EdDSA', typ: 'dpop+jwt', jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, ...header })}.${encode(claims)}`;
  return `${input}.${crypto.sign(null, Buffer.from(input), key).toString('base64url')}`;
}

function useClaims(delegationId: string, overrides: Record<string, unknown> = {}) {
  return {
    htm: 'POST',
    htu: `${BASE}/api/v1/use`,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    ath: crypto.createHash('sha256').update(delegationId, 'ascii').digest('base64url'),
    cred_req: reqHash(useBody(delegationId)),
    ...overrides,
  };
}

function mockUpstream() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ sub: 'alice' }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }));
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of tmpDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('DPoP at handle issuance (/api/v1/delegate)', () => {
  it('binds the handle to the key the agent proves', async () => {
    const agent = await generateAgentIdentity();
    const { app } = await setup();
    const res = await delegateAs(app, agent);
    expect(res.status).toBe(200);
    expect(res.body.cnf).toEqual({ jkt: didKeyConfirmation(agent.did)!.jkt });
    const receiptClaims = JSON.parse(Buffer.from(res.body.receipt.split('.')[1], 'base64url').toString('utf8'));
    expect(receiptClaims.cnf).toEqual(res.body.cnf);
  });

  it('refuses a handle request without a proof', async () => {
    const agent = await generateAgentIdentity();
    const { app } = await setup();
    const res = await delegate(app, agent.did);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_dpop_proof');
    expect(res.headers['www-authenticate']).toMatch(/^DPoP error="invalid_dpop_proof"/);
  });

  it('refuses a handle request that names no did:key agent', async () => {
    const { app } = await setup();
    expect((await delegate(app, undefined)).body.error).toBe('agent_key_required');
    expect((await delegate(app, 'did:web:agent.example')).body.error).toBe('agent_key_required');
  });

  it('refuses a proof by a key other than the agent named', async () => {
    const [agent, other] = [await generateAgentIdentity(), await generateAgentIdentity()];
    const { app } = await setup();
    const res = await delegate(app, agent.did, createDpopProof(other, 'POST', `${BASE}/api/v1/delegate`));
    expect(res.status).toBe(401);
    expect(res.body.message).toMatch(/not the key of/);
  });

  it('hands out no provider token by default', async () => {
    const { app } = await setup();
    const raw = await delegate(app, undefined, undefined, { token_format: 'raw' });
    expect(raw.status).toBe(403);
    expect(raw.body.error).toBe('raw_token_disabled');
    expect(JSON.stringify(raw.body)).not.toContain('ya29.dpop');
    const legacy = await request(app).get('/api/token/google').query({ user_id: 'alice' }).set('Authorization', `Bearer ${TEST_TOKEN}`);
    expect(legacy.status).toBe(403);
    expect(legacy.body.error).toBe('raw_token_disabled');
    expect(JSON.stringify(legacy.body)).not.toContain('ya29.dpop');
  });

  it('hands out the provider token only when CRED_ALLOW_RAW_TOKENS=true, and warns', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { app } = await setup({ allowRawTokens: true });
    expect(warn.mock.calls.some(([m]) => String(m).includes('CRED_ALLOW_RAW_TOKENS=true'))).toBe(true);
    const res = await delegate(app, undefined, undefined, { token_format: 'raw' });
    expect(res.status).toBe(200);
    expect(res.body.access_token).toBe('ya29.dpop');
  });
});

describe('DPoP at exercise (/api/v1/use)', () => {
  async function handleFor(agent: AgentIdentity) {
    const { app } = await setup();
    const res = await delegateAs(app, agent);
    expect(res.status).toBe(200);
    return { app, id: res.body.delegation_id as string };
  }

  it('brokers the call with a proof by the bound key', async () => {
    const agent = await generateAgentIdentity();
    const { app, id } = await handleFor(agent);
    const upstream = mockUpstream();
    const res = await useAs(app, agent, id);
    expect(res.status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('refuses the handle id and Bearer credential without a proof, before any upstream call', async () => {
    const agent = await generateAgentIdentity();
    const { app, id } = await handleFor(agent);
    const upstream = mockUpstream();
    const res = await use(app, id);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_dpop_proof');
    expect(upstream).not.toHaveBeenCalled();
  });

  it('does not reveal the bound agent to a caller without its key', async () => {
    const [agent, thief] = [await generateAgentIdentity(), await generateAgentIdentity()];
    const { app, id } = await handleFor(agent);
    const res = await useAs(app, thief, id);
    expect(res.status).toBe(401);
    expect(JSON.stringify(res.body)).not.toContain(agent.did);
  });

  it('keeps the bound agent out of the audit entry a Bearer caller can read', async () => {
    const [agent, thief] = [await generateAgentIdentity(), await generateAgentIdentity()];
    const { app, id } = await handleFor(agent);
    expect((await useAs(app, thief, id)).status).toBe(401);
    const audit = await request(app).get('/api/v1/audit').query({ user_id: 'alice' }).set('Authorization', `Bearer ${TEST_TOKEN}`);
    expect(audit.status).toBe(200);
    const text = JSON.stringify(audit.body);
    expect(text).toContain('invalid_dpop_proof');
    expect(text).not.toContain(agent.did);
  });

  it('refuses a valid proof by another agent', async () => {
    const [agent, thief] = [await generateAgentIdentity(), await generateAgentIdentity()];
    const { app, id } = await handleFor(agent);
    const upstream = mockUpstream();
    expect((await useAs(app, thief, id)).status).toBe(401);
    expect(upstream).not.toHaveBeenCalled();
  });

  it('refuses a proof made for another handle (ath)', async () => {
    const agent = await generateAgentIdentity();
    const { app } = await setup();
    const first = (await delegateAs(app, agent)).body.delegation_id;
    const second = (await delegateAs(app, agent)).body.delegation_id;
    const res = await use(app, first, createDpopProof(agent, 'POST', `${BASE}/api/v1/use`, second, useBody(first)));
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_dpop_proof');
  });

  it('refuses a replayed proof', async () => {
    const agent = await generateAgentIdentity();
    const { app, id } = await handleFor(agent);
    mockUpstream();
    const proof = proofFor(agent, id);
    expect((await use(app, id, proof)).status).toBe(200);
    const replay = await use(app, id, proof);
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe('invalid_dpop_proof');
  });

  it('refuses a proof for another method or URL', async () => {
    const agent = await generateAgentIdentity();
    const { app, id } = await handleFor(agent);
    expect((await use(app, id, createDpopProof(agent, 'GET', `${BASE}/api/v1/use`, id, useBody(id)))).status).toBe(401);
    expect((await use(app, id, createDpopProof(agent, 'POST', `${BASE}/api/v1/delegate`, id, useBody(id)))).status).toBe(401);
    expect((await use(app, id, createDpopProof(agent, 'POST', 'https://attacker.example/api/v1/use', id, useBody(id)))).status).toBe(401);
  });

  it('authorizes exactly the request the proof names (cred_req)', async () => {
    const agent = await generateAgentIdentity();
    const { app, id } = await handleFor(agent);
    const upstream = mockUpstream();
    const proof = proofFor(agent, id);
    // Same handle, same key, a different upstream call: refused before any upstream request.
    expect((await use(app, id, proof, useBody(id, { url: 'https://www.googleapis.com/oauth2/v3/tokeninfo' }))).status).toBe(401);
    expect((await use(app, id, proofFor(agent, id), useBody(id, { method: 'DELETE' }))).status).toBe(401);
    expect((await use(app, id, proofFor(agent, id), useBody(id, { extra_headers: { 'X-HTTP-Method-Override': 'DELETE' } }))).status).toBe(401);
    expect((await use(app, id, proofFor(agent, id), useBody(id, { quantities: { max_calls: 0 } }))).status).toBe(401);
    expect(upstream).not.toHaveBeenCalled();
    // A proof without cred_req is refused too.
    const { cred_req: _omit, ...unbound } = useClaims(id);
    expect((await use(app, id, craftProof(agent, unbound))).status).toBe(401);
    expect(upstream).not.toHaveBeenCalled();
    // The proof made for this exact request works.
    expect((await use(app, id, proofFor(agent, id))).status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('accepts a query or fragment on htu, which RFC 9449 excludes from the comparison', async () => {
    const agent = await generateAgentIdentity();
    const { app, id } = await handleFor(agent);
    mockUpstream();
    const res = await use(app, id, craftProof(agent, useClaims(id, { htu: `${BASE}/api/v1/use?x=1#y` })));
    expect(res.status).toBe(200);
  });

  it('refuses stale, future, and incomplete proofs', async () => {
    const agent = await generateAgentIdentity();
    const { app, id } = await handleFor(agent);
    const now = Math.floor(Date.now() / 1000);
    for (const claims of [{ iat: now - 600 }, { iat: now + 600 }, { jti: undefined }, { ath: undefined }]) {
      expect((await use(app, id, craftProof(agent, useClaims(id, claims)))).status).toBe(401);
    }
  });

  it('refuses malformed proof headers', async () => {
    const agent = await generateAgentIdentity();
    const { app, id } = await handleFor(agent);
    const claims = useClaims(id);
    const withPrivate = craftProof(agent, claims, {
      jwk: { ...(JSON.parse(Buffer.from(craftProof(agent, claims).split('.')[0]!, 'base64url').toString()).jwk), d: 'AAAA' },
    });
    const tampered = proofFor(agent, id).replace(/\.[^.]+$/, '.AAAA');
    for (const proof of [
      craftProof(agent, claims, { typ: 'JWT' }),
      craftProof(agent, claims, { alg: 'none' }),
      craftProof(agent, claims, { jwk: undefined }),
      withPrivate,
      tampered,
    ]) {
      expect((await use(app, id, proof)).status).toBe(401);
    }
  });

  it('refuses more than one DPoP header', async () => {
    const agent = await generateAgentIdentity();
    const { app, id } = await handleFor(agent);
    const proof = proofFor(agent, id);
    const res = await use(app, id, `${proof}, ${proof}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_dpop_proof');
  });
});

describe('DPoP across sub-delegation', () => {
  function subdelegate(app: App, parentReceipt: string, delegator: AgentIdentity, childDid: string, body: Record<string, unknown> = {}) {
    return request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
      parent_receipt: parentReceipt,
      actor_token: createActorToken(delegator, `${BASE}/api/v1/subdelegate`),
      agent_did: childDid,
      service: 'google',
      user_id: 'alice',
      scopes: ['openid'],
      ...body,
    });
  }

  it('binds a child handle to the receiving agent, not to the delegator who holds it', async () => {
    const [root, child] = [await generateAgentIdentity(), await generateAgentIdentity()];
    const { app } = await setup(undefined, [child]);
    const parent = await delegateAs(app, root);
    const sub = await subdelegate(app, parent.body.receipt, root, child.did);
    expect(sub.status).toBe(200);
    expect(sub.body.cnf).toEqual({ jkt: didKeyConfirmation(child.did)!.jkt });
    const upstream = mockUpstream();
    expect((await useAs(app, root, sub.body.delegation_id)).status).toBe(401);
    expect((await useAs(app, child, sub.body.delegation_id)).status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('requires the delegator\'s actor_token even when CRED_REQUIRE_AGENT_IDENTITY=false', async () => {
    const [root, thief] = [await generateAgentIdentity(), await generateAgentIdentity()];
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { app } = await setup({ requireAgentIdentity: false }, [thief]);
    const parent = await delegateAs(app, root);
    // A leaked receipt plus the Bearer credential, sub-delegating to the thief's own key.
    const res = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${TEST_TOKEN}`).send({
      parent_receipt: parent.body.receipt,
      agent_did: thief.did,
      service: 'google',
      user_id: 'alice',
      scopes: ['openid'],
    });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('agent_identity_required');
  });

  it('refuses to sub-delegate to an agent with no key to bind', async () => {
    const root = await generateAgentIdentity();
    const { app } = await setup();
    const parent = await delegateAs(app, root);
    const res = await subdelegate(app, parent.body.receipt, root, 'did:web:agent.example');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('agent_key_required');
  });

  it('binds the handle issued by token exchange to the agent that redeemed the grant', async () => {
    const [root, child] = [await generateAgentIdentity(), await generateAgentIdentity()];
    const { app } = await setup(undefined, [child]);
    const parent = await delegateAs(app, root);
    const grant = await subdelegate(app, parent.body.receipt, root, child.did, { exchange: 'grant' });
    expect(grant.status).toBe(200);
    const issued = await request(app).post('/api/v1/token').set('Authorization', `Bearer ${TEST_TOKEN}`).type('form').send({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: grant.body.delegation_grant,
      subject_token_type: 'urn:credninja:params:oauth:token-type:delegation-grant',
      actor_token: createActorToken(child, `${BASE}/api/v1/token`),
      actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    });
    expect(issued.status).toBe(200);
    const handle = issued.body.access_token as string;
    const upstream = mockUpstream();
    expect((await use(app, handle)).status).toBe(401);
    expect((await useAs(app, root, handle)).status).toBe(401);
    expect((await useAs(app, child, handle)).status).toBe(200);
    expect(upstream).toHaveBeenCalledTimes(1);
  });
});

describe('CRED_REQUIRE_DPOP=false (deprecated)', () => {
  it('keeps the legacy Bearer-bound handles and warns at startup', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const agent = await generateAgentIdentity();
    const { app } = await setup({ requireDpop: false });
    expect(warn.mock.calls.some(([m]) => String(m).includes('CRED_REQUIRE_DPOP=false'))).toBe(true);
    const res = await delegate(app, agent.did);
    expect(res.status).toBe(200);
    expect(res.body.cnf).toBeUndefined();
    mockUpstream();
    expect((await use(app, res.body.delegation_id)).status).toBe(200);
  });
});

describe('verifyDpopProof', () => {
  const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function base58(bytes: Uint8Array): string {
    let n = BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`);
    let out = '';
    while (n > 0n) { out = BASE58[Number(n % 58n)] + out; n /= 58n; }
    for (const b of bytes) { if (b !== 0) break; out = `1${out}`; }
    return out;
  }
  const htu = `${BASE}/api/v1/use`;
  const handle = 'del_example';
  function check(agentDid: string, proof: string, seen = new Set<string>()) {
    return verifyDpopProof(proof, {
      agentDid,
      htm: 'POST',
      htu,
      ath: dpopAth(handle),
      seenJti: (key) => (seen.has(key) ? true : (seen.add(key), false)),
    });
  }

  it('names the reason for each rejected proof', async () => {
    const agent = await generateAgentIdentity();
    const other = await generateAgentIdentity();
    const now = Math.floor(Date.now() / 1000);
    const claims = useClaims(handle);
    const cases: Array<[string, RegExp]> = [
      [craftProof(agent, { ...claims, htm: 'GET' }), /htm/],
      [craftProof(agent, { ...claims, htu: `${BASE}/api/v1/delegate` }), /htu/],
      [craftProof(agent, { ...claims, htu: 'ftp://localhost:3456/api/v1/use' }), /htu/],
      [craftProof(agent, { ...claims, iat: now - 600 }), /too old/],
      [craftProof(agent, { ...claims, iat: now + 600 }), /future/],
      [craftProof(agent, { ...claims, jti: undefined }), /jti/],
      [craftProof(agent, { ...claims, ath: undefined }), /ath/],
      [craftProof(agent, claims, { typ: 'JWT' }), /typ/],
      [craftProof(agent, claims, { alg: 'none' }), /signature/],
      [craftProof(agent, claims, { alg: 'ES256' }), /signature/],
      [craftProof(agent, claims, { jwk: undefined }), /jwk/],
      [createDpopProof(other, 'POST', htu, handle), /not the key of/],
      [createDpopProof(agent, 'POST', htu, handle).replace(/\.[^.]+$/, '.AAAA'), /signature/],
    ];
    for (const [proof, reason] of cases) {
      const result = check(agent.did, proof);
      expect(result.ok, String(reason)).toBe(false);
      if (!result.ok) expect(result.message).toMatch(reason);
    }
  });

  it('names a request mismatch (cred_req)', async () => {
    const agent = await generateAgentIdentity();
    const result = verifyDpopProof(craftProof(agent, useClaims(handle)), {
      agentDid: agent.did,
      htm: 'POST',
      htu,
      ath: dpopAth(handle),
      req: reqHash(useBody(handle, { method: 'DELETE' })),
      seenJti: () => false,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.message).toMatch(/cred_req/);
  });

  it('does not spend a jti on a proof that fails', async () => {
    const agent = await generateAgentIdentity();
    const seen = new Set<string>();
    const claims = useClaims(handle, { jti: 'fixed-jti' });
    expect(check(agent.did, craftProof(agent, claims).replace(/\.[^.]+$/, '.AAAA'), seen).ok).toBe(false);
    expect(check(agent.did, craftProof(agent, { ...claims, htm: 'GET' }), seen).ok).toBe(false);
    expect(check(agent.did, craftProof(agent, claims), seen).ok).toBe(true);
    expect(check(agent.did, craftProof(agent, claims), seen).ok).toBe(false);
  });

  it('compares htu by scheme, host, port and path, as RFC 9449 does', async () => {
    const agent = await generateAgentIdentity();
    expect(normalizeHtu('HTTP://LocalHost:3456/api/v1/use?x=1#y')).toBe(normalizeHtu(htu));
    expect(normalizeHtu('https://cred.example:443/api/v1/use')).toBe('https://cred.example/api/v1/use');
    expect(normalizeHtu('http://127.0.0.1:3456/api/v1/use')).not.toBe(normalizeHtu(htu));
    expect(check(agent.did, craftProof(agent, useClaims(handle, { htu: 'HTTP://LOCALHOST:3456/api/v1/use' }))).ok).toBe(true);
  });

  it('accepts an ES256 proof from a P-256 did:key agent', async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
    const x = Buffer.from(jwk.x!, 'base64url');
    const y = Buffer.from(jwk.y!, 'base64url');
    const compressed = Buffer.concat([Buffer.from([(y[y.length - 1]! & 1) === 1 ? 0x03 : 0x02]), x]);
    const did = `did:key:z${base58(Buffer.concat([Buffer.from([0x80, 0x24]), compressed]))}`;
    expect(didKeyConfirmation(did)).not.toBeNull();
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const input = `${encode({ alg: 'ES256', typ: 'dpop+jwt', jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } })}.${encode(useClaims(handle))}`;
    const signature = crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    expect(check(did, `${input}.${signature}`).ok).toBe(true);
    const wrongAlg = `${encode({ alg: 'EdDSA', typ: 'dpop+jwt', jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } })}.${encode(useClaims(handle))}`;
    expect(check(did, `${wrongAlg}.${signature}`).ok).toBe(false);
  });
});

// Guard policies that judge identity must see what the server verified, never
// what the request body claims.
import { describe, it, expect, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto, { generateKeyPairSync, sign } from 'node:crypto';
import { CredGuard, receiptClaimsPolicy, webBotAuthPolicy } from '@credninja/guard';
import { createDpopProof } from '@credninja/sdk';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { delegateAs, newAgent, type AgentIdentity, type App } from './token-helpers.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const SIGNATURE_AGENT = `${BASE}/.well-known/http-message-signatures-directory`;
const dirs: string[] = [];
afterAll(() => { for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true }); });

async function setup(overrides: Partial<ServerConfig>) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-guard-identity-'));
  dirs.push(dir);
  const server = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'sqlite', tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: ADMIN, agentToken: BEARER, redirectBaseUri: BASE,
    providers: [{ slug: 'github', clientId: 'id', clientSecret: 'secret', defaultScopes: [] }], ...overrides,
  });
  await server.vault.init();
  await server.tofu.init();
  await server.vault.store({ provider: 'github', userId: 'alice', accessToken: 'tok', expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
  const agent = await newAgent();
  await request(server.app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`)
    .send({ agentId: agent.did, connectionId: 'github', allowedScopes: ['repo'] });
  return { ...server, agent };
}

const ask = (app: App, agent: AgentIdentity, body: Record<string, unknown> = {}, headers: Record<string, string> = {}) =>
  delegateAs(app, agent, { service: 'github', user_id: 'alice', scopes: ['repo'], ...body }, { bearer: BEARER, headers });

function signedHeaders(keyId: string, privateKey: crypto.KeyObject): Record<string, string> {
  const created = Math.floor(Date.now() / 1000);
  const params = `("@authority" "signature-agent");created=${created};expires=${created + 60};nonce="${crypto.randomBytes(12).toString('base64url')}";alg="ed25519";keyid="${keyId}";tag="web-bot-auth"`;
  const base = [`"@authority": localhost:3456`, `"signature-agent": "${SIGNATURE_AGENT}"`, `"@signature-params": ${params}`].join('\n');
  return {
    Host: 'localhost:3456',
    'Signature-Agent': `"${SIGNATURE_AGENT}"`,
    'Signature-Input': `sig1=${params}`,
    Signature: `sig1=:${sign(null, Buffer.from(base, 'utf8'), privateKey).toString('base64')}:`,
  };
}

describe('a Guard that requires a Web Bot Auth identity', () => {
  const guard = () => new CredGuard({
    policies: [webBotAuthPolicy({ allowedIdentitySources: ['web-bot-auth'], requireKeyId: true, allowedSignatureAgentPrefixes: [`${BASE}/`] })],
  });

  for (const mode of ['off', 'optional'] as const) {
    it(`refuses an unsigned request that names a key id and Signature-Agent in its body (mode ${mode})`, async () => {
      const { app, agent } = await setup({ guard: guard(), webBotAuthMode: mode });
      const res = await ask(app, agent, { web_bot_auth_key_id: 'claimed-key', signature_agent: SIGNATURE_AGENT });
      expect(res.status).toBe(403);
      expect(res.body.policy).toBe('web-bot-auth');
      expect(res.body.access_token).toBeUndefined();
    });
  }

  it('refuses a bare key_id in the body too', async () => {
    const { app, agent } = await setup({ guard: new CredGuard({ policies: [webBotAuthPolicy({ requireKeyId: true })] }) });
    const res = await ask(app, agent, { key_id: 'claimed-key' });
    expect(res.status).toBe(403);
    expect(res.body.policy).toBe('web-bot-auth');
  });

  it('allows a verified signature, and shows Guard the verified values over any the body names', async () => {
    const seen: Array<{ keyId?: string; signatureAgent?: string; source?: string }> = [];
    const { app, agent } = await setup({
      webBotAuthMode: 'optional',
      guard: new CredGuard({
        policies: [
          webBotAuthPolicy({ allowedIdentitySources: ['web-bot-auth'], requireKeyId: true, allowedSignatureAgentPrefixes: [`${BASE}/`] }),
          { name: 'record', evaluate: (ctx) => { seen.push({ keyId: ctx.webBotAuthKeyId, signatureAgent: ctx.signatureAgent, source: ctx.identitySource }); return { decision: 'ALLOW', policy: 'record' }; } },
        ],
      }),
    });
    const keypair = generateKeyPairSync('ed25519');
    const spki = keypair.publicKey.export({ type: 'spki', format: 'der' });
    const key = await request(app).post('/api/v1/web-bot-auth/keys').set('Authorization', `Bearer ${BEARER}`)
      .send({ public_key: Buffer.from(spki.subarray(-32)).toString('base64') });
    expect(key.status).toBe(201);

    const res = await ask(app, agent, { web_bot_auth_key_id: 'another-key', signature_agent: 'https://elsewhere.example/' }, signedHeaders(key.body.key_id, keypair.privateKey));
    expect(res.status).toBe(200);
    expect(seen).toEqual([{ keyId: key.body.key_id, signatureAgent: SIGNATURE_AGENT, source: 'web-bot-auth' }]);
  });
});

describe('verified TOFU policy context', () => {
  it('permits a real verified root TOFU proof and refuses a tampered proof', async () => {
    const seen: Array<string | undefined> = [];
    const { app, agent, tofu } = await setup({ guard: new CredGuard({ policies: [
      webBotAuthPolicy({ allowedIdentitySources: ['tofu'] }),
      { name: 'fingerprint', evaluate: (ctx) => { seen.push(ctx.tofuFingerprint); return { decision: 'ALLOW', policy: 'fingerprint' }; } },
    ] }) });
    const pair = generateKeyPairSync('ed25519');
    const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    const registered = await tofu.registerAgent({ publicKey, initialScopes: ['repo'] });
    const payload = Buffer.from(JSON.stringify({ service: 'github', userId: 'alice', appClientId: 'local', scopes: ['repo'], timestamp: new Date().toISOString() }));
    const proof = { tofu_fingerprint: registered.fingerprint, tofu_payload: payload.toString('base64'), tofu_signature: sign(null, payload, pair.privateKey).toString('base64') };
    const accepted = await ask(app, agent, proof);
    expect(accepted.status).toBe(200);
    expect(seen).toEqual([registered.fingerprint]);
    const denied = await ask(app, agent, { ...proof, tofu_signature: Buffer.alloc(64).toString('base64') });
    expect(denied.status).toBe(403);
    expect(denied.body.policy).toBe('web-bot-auth');
    expect(seen).toEqual([registered.fingerprint]);
  });
  it('does not create a real approval request from a forged TOFU fingerprint', async () => {
    const { app, agent } = await setup({ guard: new CredGuard({ policies: [webBotAuthPolicy({ allowedIdentitySources: ['tofu'] })] }) });
    await request(app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`)
      .send({ agentId: agent.did, connectionId: 'github', allowedScopes: ['repo'], requiresApproval: true, approver: 'admin' });
    const res = await request(app).post('/bc-authorize').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/bc-authorize`))
      .send({ service: 'github', login_hint: 'alice', agent_did: agent.did, scopes: ['repo'], tofu_fingerprint: 'forged' });
    expect(res.status).toBe(403);
    expect(res.body.policy).toBe('web-bot-auth');
    expect(res.body.auth_req_id).toBeUndefined();
    const pending = await request(app).get('/admin/approvals').set('Authorization', `Bearer ${ADMIN}`);
    expect(pending.body.approvals).toEqual([]);
  });

  it.each([
    ['/api/v1/subdelegate', 'did'],
    ['/api/token/github', 'agent-token'],
  ] as const)('does not expose an unverified TOFU fingerprint to policies on %s', async (route, source) => {
    const seen: unknown[] = [];
    const { app, agent } = await setup({ guard: new CredGuard({ policies: [{ name: 'capture', evaluate: (ctx) => {
      seen.push({ source: ctx.identitySource, did: ctx.agentDid, tofu: ctx.tofuFingerprint });
      return { decision: 'DENY', policy: 'capture', reason: 'test boundary' };
    } }] }) });
    const req = route.startsWith('/api/token/') ? request(app).get(`${route}?user_id=alice`) : request(app).post(route);
    const res = await req.set('Authorization', `Bearer ${BEARER}`).send({ service: 'github', agent_did: agent.did, tofu_fingerprint: 'forged' });
    expect(res.status).toBe(403);
    // Sub-delegation names the receiving agent, and what it issues is bound to that key.
    expect(seen).toEqual([{ source, did: source === 'did' ? agent.did : undefined, tofu: undefined }]);
  });
});

describe('the agent DID a Guard judges', () => {
  type Seen = { source?: string; did?: string };
  const denyList = (banned: () => string, seen: Seen[] = []) => new CredGuard({ policies: [{
    name: 'deny-list',
    evaluate: (ctx) => {
      seen.push({ source: ctx.identitySource, did: ctx.agentDid });
      return ctx.agentDid === banned()
        ? { decision: 'DENY', policy: 'deny-list', reason: 'agent is banned' }
        : { decision: 'ALLOW', policy: 'deny-list' };
    },
  }] });

  it('a policy that denies one DID still denies that agent when it proves its key', async () => {
    const seen: Seen[] = [];
    let banned = '';
    const { app, agent } = await setup({ guard: denyList(() => banned, seen) });
    banned = agent.did;
    const res = await ask(app, agent);
    expect(res.status).toBe(403);
    expect(res.body.policy).toBe('deny-list');
    expect(res.body.access_token).toBeUndefined();
    expect(seen).toEqual([{ source: 'did', did: agent.did }]);
  });

  it('shows Guard no DID for a request that only names one, and the route then refuses it', async () => {
    const seen: Seen[] = [];
    const { app, agent } = await setup({ guard: denyList(() => 'did:key:none', seen) });
    const body = { service: 'github', user_id: 'alice', scopes: ['repo'], token_format: 'handle', agent_did: agent.did };
    const unproved = await request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`).send(body);
    const wrongKey = await request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(await newAgent(), 'POST', `${BASE}/api/v1/delegate`)).send(body);
    const wrongRoute = await request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(agent, 'POST', `${BASE}/bc-authorize`)).send(body);
    for (const res of [unproved, wrongKey, wrongRoute]) {
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_dpop_proof');
      expect(res.body.access_token).toBeUndefined();
    }
    expect(seen).toEqual(Array(3).fill({ source: 'agent-token', did: undefined }));
  });

  it('a policy that admits only DID identities admits a did:key agent that proves its key', async () => {
    const guard = () => new CredGuard({ policies: [webBotAuthPolicy({ allowedIdentitySources: ['did'] })] });
    const root = await setup({ guard: guard() });
    expect((await ask(root.app, root.agent)).status).toBe(200);
    const unproved = await request(root.app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .send({ service: 'github', user_id: 'alice', scopes: ['repo'], agent_did: root.agent.did });
    expect(unproved.status).toBe(403);
    expect(unproved.body.policy).toBe('web-bot-auth');

    const ciba = await setup({ guard: guard() });
    await request(ciba.app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`)
      .send({ agentId: ciba.agent.did, connectionId: 'github', allowedScopes: ['repo'], requiresApproval: true, approver: 'admin' });
    const pending = await request(ciba.app).post('/bc-authorize').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(ciba.agent, 'POST', `${BASE}/bc-authorize`))
      .send({ service: 'github', login_hint: 'alice', agent_did: ciba.agent.did, scopes: ['repo'] });
    expect(pending.status).toBe(200);
    expect(typeof pending.body.auth_req_id).toBe('string');
  });

  it('a policy that denies one DID denies a sub-delegation to it', async () => {
    let banned = '';
    const { app, agent } = await setup({ guard: denyList(() => banned) });
    banned = agent.did;
    const res = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`)
      .send({ service: 'github', agent_did: agent.did });
    expect(res.status).toBe(403);
    expect(res.body.policy).toBe('deny-list');
  });

  describe('with the raw-token opt-in', () => {
    async function registered(guard?: CredGuard) {
      const server = await setup({ allowRawTokens: true, ...(guard ? { guard } : {}) });
      const holder = await newAgent();
      const now = new Date().toISOString();
      await server.vault.registerAgent({ id: 'agt_holder', did: holder.did, name: 'holder', fingerprint: 'fp_holder', scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now });
      await server.vault.createPermission({ agentId: 'agt_holder', connectionId: 'github', allowedScopes: ['repo'], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
      const raw = (proof?: string) => {
        const req = request(server.app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`);
        if (proof) req.set('DPoP', proof);
        return req.send({ service: 'github', user_id: 'alice', token_format: 'raw', agent_did: 'agt_holder' });
      };
      return { ...server, holder, raw };
    }

    it('an agent named by its record id proves the key on its record before a raw token is issued', async () => {
      const { raw, holder } = await registered();
      for (const proof of [undefined, createDpopProof(await newAgent(), 'POST', `${BASE}/api/v1/delegate`)]) {
        const refused = await raw(proof);
        expect(refused.status).toBe(401);
        expect(refused.body.error).toBe('invalid_dpop_proof');
        expect(JSON.stringify(refused.body)).not.toContain('tok');
      }
      const issued = await raw(createDpopProof(holder, 'POST', `${BASE}/api/v1/delegate`));
      expect(issued.status).toBe(200);
    });

    it('shows Guard the DID the raw request proved, so a deny list holds for a record id too', async () => {
      const seen: Seen[] = [];
      let banned = '';
      const { raw, holder } = await registered(denyList(() => banned, seen));
      banned = holder.did;
      const res = await raw(createDpopProof(holder, 'POST', `${BASE}/api/v1/delegate`));
      expect(res.status).toBe(403);
      expect(res.body.policy).toBe('deny-list');
      expect(seen).toEqual([{ source: 'did', did: holder.did }]);
    });
  });
});

describe('a Guard that requires receipt claims', () => {
  const guard = () => new CredGuard({ policies: [receiptClaimsPolicy({ requiredClaims: ['staff-engineer:approved'] })] });

  it('refuses claims named in the request body', async () => {
    const { app, agent } = await setup({ guard: guard() });
    for (const body of [{ receipt_claims: ['staff-engineer:approved'] }, { metadata: { receiptClaims: ['staff-engineer:approved'] } }]) {
      const res = await ask(app, agent, body);
      expect(res.status, JSON.stringify(body)).toBe(403);
      expect(res.body.policy).toBe('receipt-claims');
    }
  });

  it('allows claims a request verifier attached to the caller', async () => {
    const { app, agent } = await setup({
      guard: guard(),
      agentRequestVerifier: async () => ({ ok: true, principal: { type: 'custom-verifier', principalId: 'svc', metadata: { receiptClaims: ['staff-engineer:approved'] } } }),
    } as Partial<ServerConfig>);
    expect((await ask(app, agent)).status).toBe(200);
  });
});

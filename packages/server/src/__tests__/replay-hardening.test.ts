/**
 * Replay stores record only what verified, and the caller does not choose
 * how long an entry is held: Web Bot Auth nonces and TOFU proofs.
 */
import { describe, it, expect, afterEach } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto, { generateKeyPairSync, sign } from 'node:crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { delegateAs, newAgent } from './token-helpers.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const SIGNATURE_AGENT = `${BASE}/.well-known/http-message-signatures-directory`;
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true }); });

async function setup(overrides: Partial<ServerConfig> = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-replay-'));
  dirs.push(dir);
  const server = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'sqlite', tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: ADMIN, agentToken: BEARER, redirectBaseUri: BASE,
    providers: [{ slug: 'github', clientId: 'id', clientSecret: 'secret', defaultScopes: [] }], ...overrides,
  });
  await server.vault.init();
  await server.tofu.init();
  return server;
}

function signed(keyId: string, privateKey: crypto.KeyObject, opts: { nonce?: string; lifetime?: number; corrupt?: boolean } = {}) {
  const created = Math.floor(Date.now() / 1000);
  const nonce = opts.nonce ?? crypto.randomBytes(12).toString('base64url');
  const params = `("@authority" "signature-agent");created=${created};expires=${created + (opts.lifetime ?? 60)};nonce="${nonce}";alg="ed25519";keyid="${keyId}";tag="web-bot-auth"`;
  const base = [`"@authority": localhost:3456`, `"signature-agent": "${SIGNATURE_AGENT}"`, `"@signature-params": ${params}`].join('\n');
  const sig = sign(null, Buffer.from(base, 'utf8'), privateKey);
  if (opts.corrupt) sig[0] ^= 0xff;
  return {
    Host: 'localhost:3456',
    'Signature-Agent': `"${SIGNATURE_AGENT}"`,
    'Signature-Input': `sig1=${params}`,
    Signature: `sig1=:${sig.toString('base64')}:`,
    Authorization: `Bearer ${BEARER}`,
  };
}

async function registeredKey(app: any) {
  const keypair = generateKeyPairSync('ed25519');
  const spki = keypair.publicKey.export({ type: 'spki', format: 'der' });
  const key = await request(app).post('/api/v1/web-bot-auth/keys').set('Authorization', `Bearer ${BEARER}`)
    .send({ public_key: Buffer.from(spki.subarray(-32)).toString('base64') });
  expect(key.status).toBe(201);
  return { keyId: key.body.key_id as string, privateKey: keypair.privateKey };
}

const providers = (app: any, headers: Record<string, string>) => {
  const req = request(app).get('/api/v1/providers');
  for (const [k, v] of Object.entries(headers)) req.set(k, v);
  return req;
};

describe('Web Bot Auth replay store', () => {
  it('does not record the nonce of a signature that fails, so the real signer can still use it', async () => {
    const { app } = await setup({ webBotAuthMode: 'require' });
    const { keyId, privateKey } = await registeredKey(app);
    const nonce = crypto.randomBytes(12).toString('base64url');
    expect((await providers(app, signed(keyId, privateKey, { nonce, corrupt: true }))).status).toBe(401);
    expect((await providers(app, signed(keyId, privateKey, { nonce }))).status).toBe(200);
    // A verified nonce is spent.
    expect((await providers(app, signed(keyId, privateKey, { nonce }))).status).toBe(401);
  });

  it('refuses a signature whose lifetime exceeds the cap', async () => {
    const { app } = await setup({ webBotAuthMode: 'require' });
    const { keyId, privateKey } = await registeredKey(app);
    expect((await providers(app, signed(keyId, privateKey, { lifetime: 301 }))).status).toBe(401);
    expect((await providers(app, signed(keyId, privateKey, { lifetime: 300 }))).status).toBe(200);
  });
});

describe('TOFU proof replay', () => {
  it('refuses a TOFU proof presented a second time', async () => {
    const { app, vault, tofu } = await setup({ allowAgentsWithoutPermission: true });
    await vault.store({ provider: 'github', userId: 'alice', accessToken: 'tok', expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
    const pair = generateKeyPairSync('ed25519');
    const registered = await tofu.registerAgent({ publicKey: pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), initialScopes: ['repo'] });
    await vault.createPermission({
      agentId: `tofu:${registered.agentId}`, connectionId: 'github', allowedScopes: ['repo'],
      delegatable: false, maxDelegationDepth: 0, requiresApproval: false, createdBy: 'admin',
    });
    const proof = (offsetMs: number) => {
      const payload = Buffer.from(JSON.stringify({ service: 'github', userId: 'alice', appClientId: 'local', scopes: ['repo'], timestamp: new Date(Date.now() + offsetMs).toISOString() }));
      return { tofu_fingerprint: registered.fingerprint, tofu_payload: payload.toString('base64'), tofu_signature: sign(null, payload, pair.privateKey).toString('base64') };
    };
    const send = async (p: Record<string, string>) => delegateAs(app, await newAgent(),
      { service: 'github', user_id: 'alice', appClientId: 'local', scopes: ['repo'], ...p }, { bearer: BEARER, base: BASE });
    const first = proof(0);
    expect((await send(first)).status).toBe(200);
    const again = await send(first);
    expect(again.status).toBe(403);
    expect(again.body.error).toContain('already been used');
    expect((await send(proof(1))).status).toBe(200);
  });
});

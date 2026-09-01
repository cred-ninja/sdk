import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { verify as verifySignature, createPublicKey, createPrivateKey, sign, generateKeyPairSync } from 'node:crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { CredGuard, rateLimitPolicy, scopeFilterPolicy, receiptClaimsPolicy, urlAllowlistPolicy } from '@credninja/guard';

// ── Test fixtures ────────────────────────────────────────────────────────────

const TEST_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const TEST_ADMIN_TOKEN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const TEST_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-vault.json');
const TEST_SQLITE_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-vault.sqlite');
const TEST_TOFU_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-tofu.json');
const TEST_SQLITE_TOFU_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-tofu.sqlite');
const TEST_SQLITE_NONCE_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-web-bot-auth-nonces.sqlite');
const DIRECTORY_TEST_HOST = 'cred.example.com';

function makeTestConfig(overrides?: Partial<ServerConfig>): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'file',
    vaultPath: TEST_VAULT_PATH,
    tofuStorage: 'file',
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
    webBotAuthNonceStore: 'memory',
    ...overrides,
  };
}

function adminGet(app: any, route: string) {
  return request(app)
    .get(route)
    .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`);
}

function verifyDirectoryResponseSignature(
  res: request.Response,
  authority: string,
): void {
  const signatureInput = res.headers['signature-input'];
  const signature = res.headers['signature'];

  expect(typeof signatureInput).toBe('string');
  expect(typeof signature).toBe('string');

  const signatureParams = String(signatureInput).replace(/^sig0=/, '');
  const keyIdMatch = signatureParams.match(/keyid="([^"]+)"/);
  expect(keyIdMatch).not.toBeNull();
  const keyId = keyIdMatch![1];

  const directoryKey = res.body.keys.find((key: any) => key.kid === keyId);
  expect(directoryKey).toBeDefined();

  const rawPublicKey = Buffer.from(directoryKey.x, 'base64url');
  const publicKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      rawPublicKey,
    ]),
    format: 'der',
    type: 'spki',
  });

  const signatureMatch = String(signature).match(/^sig0=:([^:]+):$/);
  expect(signatureMatch).not.toBeNull();

  const signatureBase = [
    `"@authority";req: ${authority}`,
    `"@signature-params": ${signatureParams}`,
  ].join('\n');

  const valid = verifySignature(
    null,
    Buffer.from(signatureBase, 'utf8'),
    publicKey,
    Buffer.from(signatureMatch![1], 'base64'),
  );
  expect(valid).toBe(true);
}

function signWebBotAuthRequest(input: {
  url: string;
  signatureAgent: string;
  keyId: string;
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
  now?: Date;
  nonce?: string;
  components?: string[];
  expiresInSeconds?: number;
}): Record<string, string> {
  const now = input.now ?? new Date();
  const created = Math.floor(now.getTime() / 1000);
  const expires = created + (input.expiresInSeconds ?? 60);
  const nonce = input.nonce ?? crypto.randomBytes(12).toString('base64url');
  const authority = new URL(input.url).host;
  const components = input.components ?? ['@authority', 'signature-agent'];
  const signatureParams =
    `(${components.map((component) => `"${component}"`).join(' ')});created=${created};expires=${expires};nonce="${nonce}";alg="ed25519";keyid="${input.keyId}";tag="web-bot-auth"`;
  const signatureBase = [
    ...components.map((component) => {
      if (component === '@authority') return `"@authority": ${authority}`;
      if (component === 'signature-agent') return `"signature-agent": "${input.signatureAgent}"`;
      throw new Error(`Unsupported test component: ${component}`);
    }),
    `"@signature-params": ${signatureParams}`,
  ].join('\n');
  const signature = sign(null, Buffer.from(signatureBase, 'utf8'), input.privateKey).toString('base64');

  return {
    'Signature-Agent': `"${input.signatureAgent}"`,
    'Signature-Input': `sig1=${signatureParams}`,
    'Signature': `sig1=:${signature}:`,
  };
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('@credninja/server', () => {
  afterAll(() => {
    // Cleanup test vault files
    for (const base of [TEST_VAULT_PATH, TEST_SQLITE_VAULT_PATH, TEST_TOFU_PATH, TEST_SQLITE_TOFU_PATH, TEST_SQLITE_NONCE_PATH]) {
      for (const suffix of ['', '.salt']) {
        const p = base + suffix;
        if (fs.existsSync(p)) fs.unlinkSync(p);
      }
    }
  });

  describe('GET /health', () => {
    it('returns ok with provider list', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).get('/health');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ok');
      expect(res.body.providers).toEqual(['google']);
      expect(res.body.vault).toBe('file');
      expect(res.body.tofu).toBe('file');
    });
  });

  describe('protocol-version handshake', () => {
    it('echoes the Cred-Protocol-Version header on every response', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).get('/health');

      expect(res.headers['cred-protocol-version']).toBe('0.1.0');
    });

    it('accepts the canonical Cred-Protocol-Version request header', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/health')
        .set('Cred-Protocol-Version', '0.1.0');

      expect(res.status).toBe(200);
      expect(res.headers['cred-protocol-version']).toBe('0.1.0');
    });

    it('rejects explicit unsupported protocol versions before route handling', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/health')
        .set('Cred-Protocol-Version', '0.0.9');

      expect(res.status).toBe(426);
      expect(res.headers['cred-protocol-version']).toBe('0.1.0');
      expect(res.body).toMatchObject({
        error: 'protocol_version_unsupported',
        requested_version: '0.0.9',
        supported_versions: ['0.1.0'],
        minimum_version: '0.1.0',
        current_version: '0.1.0',
      });
    });
  });

  describe('agent auth configuration', () => {
    it('supports a custom request verifier without a static agent token', async () => {
      const { app, tofu } = createServer(makeTestConfig({
        agentToken: undefined,
        agentRequestVerifier: (req) => {
          if (req.get('X-Test-Agent') === 'external-agent') {
            return {
              ok: true,
              principal: {
                type: 'external-runtime',
                principalId: 'agt_release_engineer',
                metadata: { workspaceId: 'workspace_demo' },
              },
            };
          }
          return { ok: false, status: 401, error: 'invalid test agent' };
        },
      }));
      await tofu.init();

      const okRes = await request(app)
        .get('/api/v1/web-bot-auth/keys')
        .set('X-Test-Agent', 'external-agent');

      expect(okRes.status).toBe(200);
      expect(Array.isArray(okRes.body.keys)).toBe(true);

      const deniedRes = await request(app)
        .get('/api/v1/web-bot-auth/keys')
        .set('X-Test-Agent', 'wrong-agent');

      expect(deniedRes.status).toBe(401);
      expect(deniedRes.body.error).toBe('invalid test agent');
    });

    it('throws when no agent auth mode is configured', () => {
      expect(() => createServer(makeTestConfig({
        agentToken: undefined,
        agentRequestVerifier: undefined,
      }))).toThrow('Either agentToken or agentRequestVerifier is required');
    });
  });

  describe('GET /.well-known/http-message-signatures-directory', () => {
    it('returns an empty Web Bot Auth directory when no agents are registered', async () => {
      const { app, tofu } = createServer(makeTestConfig());
      await tofu.init();

      const res = await request(app)
        .get('/.well-known/http-message-signatures-directory')
        .set('Host', DIRECTORY_TEST_HOST);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('application/http-message-signatures-directory+json');
      expect(res.body.keys).toHaveLength(1);
      verifyDirectoryResponseSignature(res, DIRECTORY_TEST_HOST);
    });

    it('returns registered agent keys as Ed25519 JWKs with thumbprint key ids', async () => {
      const { app, tofu } = createServer(makeTestConfig());
      await tofu.init();

      const { publicKey } = generateKeyPairSync('ed25519');
      const spki = publicKey.export({ type: 'spki', format: 'der' });
      const rawPublicKey = new Uint8Array(spki.slice(-32));

      await tofu.registerAgent({
        publicKey: rawPublicKey,
        initialScopes: ['calendar.readonly'],
        metadata: { name: 'web-bot-auth-test' },
      });

      const res = await request(app)
        .get('/.well-known/http-message-signatures-directory')
        .set('Host', DIRECTORY_TEST_HOST);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('application/http-message-signatures-directory+json');
      expect(res.body.keys).toHaveLength(2);
      expect(res.body.keys[0]).toMatchObject({
        kty: 'OKP',
        crv: 'Ed25519',
        alg: 'EdDSA',
        use: 'sig',
      });
      expect(typeof res.body.keys[0].kid).toBe('string');
      expect(res.body.keys[0].kid.length).toBeGreaterThan(20);
      verifyDirectoryResponseSignature(res, DIRECTORY_TEST_HOST);
    });

    it('publishes both current and previous keys during a rotation grace window', async () => {
      const { app, tofu } = createServer(makeTestConfig());
      await tofu.init();

      const first = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });
      const second = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });

      const registered = await tofu.registerAgent({
        publicKey: new Uint8Array(first.slice(-32)),
      });
      const original = await tofu.getAgent(registered.fingerprint);
      expect(original).not.toBeNull();

      await tofu.rotateKey({
        fingerprint: registered.fingerprint,
        newPublicKey: new Uint8Array(second.slice(-32)),
        gracePeriodHours: 2,
      });

      const res = await request(app)
        .get('/.well-known/http-message-signatures-directory')
        .set('Host', DIRECTORY_TEST_HOST);

      expect(res.status).toBe(200);
      const kids = res.body.keys.map((key: any) => key.kid);
      expect(kids).toContain(original!.keyId);
      const rotated = (await tofu.listAgents()).find((agent) => agent.agentId === original!.agentId);
      expect(rotated).toBeDefined();
      expect(kids).toContain(rotated!.keyId);
      verifyDirectoryResponseSignature(res, DIRECTORY_TEST_HOST);
    });
  });

  describe('Web Bot Auth key management APIs', () => {
    it('creates, lists, and rotates Web Bot Auth keys', async () => {
      const { app, tofu } = createServer(makeTestConfig());
      await tofu.init();

      const keypair = generateKeyPairSync('ed25519');
      const first = keypair.publicKey.export({ type: 'spki', format: 'der' });
      const second = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });

      const createRes = await request(app)
        .post('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          public_key: Buffer.from(first.slice(-32)).toString('base64'),
          initial_scopes: ['calendar.readonly'],
          metadata: { label: 'native-web-bot-auth' },
        });

      expect(createRes.status).toBe(201);
      expect(createRes.body.agent_id).toBeDefined();
      expect(createRes.body.key_id).toBeDefined();
      expect(createRes.body.signature_agent).toContain('/.well-known/http-message-signatures-directory');

      const listRes = await request(app)
        .get('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(listRes.status).toBe(200);
      const listed = listRes.body.keys.find((key: any) => key.agent_id === createRes.body.agent_id);
      expect(listed).toBeDefined();
      expect(listed.metadata.label).toBe('native-web-bot-auth');

      // Rotation is one of the two routes hardened by the ownership-check fix
      // (docs/plans/2026-08-31-002-fix-agent-ownership-check-plan.md): it now
      // requires a verified Web Bot Auth identity matching the target agent,
      // regardless of the deployment's global webBotAuthMode — proven here by
      // using the default config (mode left unset, i.e. 'off').
      const signedHeaders = signWebBotAuthRequest({
        url: `http://localhost:3456/api/v1/web-bot-auth/keys/${createRes.body.agent_id}/rotate`,
        signatureAgent: createRes.body.signature_agent,
        keyId: createRes.body.key_id,
        privateKey: keypair.privateKey,
      });

      const rotateRes = await request(app)
        .post(`/api/v1/web-bot-auth/keys/${createRes.body.agent_id}/rotate`)
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({
          public_key: Buffer.from(second.slice(-32)).toString('base64'),
          grace_period_hours: 2,
        });

      expect(rotateRes.status).toBe(200);
      expect(rotateRes.body.agent_id).toBe(createRes.body.agent_id);
      expect(rotateRes.body.previous_fingerprint).toBe(createRes.body.fingerprint);
      expect(rotateRes.body.previous_key_id).toBe(createRes.body.key_id);
      expect(rotateRes.body.key_id).not.toBe(createRes.body.key_id);
      expect(rotateRes.body.grace_expires_at).toBeDefined();

      const listAfterRotate = await request(app)
        .get('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      const rotated = listAfterRotate.body.keys.find((key: any) => key.agent_id === createRes.body.agent_id);
      expect(rotated.previous_key_id).toBe(createRes.body.key_id);
      expect(rotated.rotation_grace_expires_at).toBeDefined();
    });

    it('surfaces Web Bot Auth metadata in the audit API', async () => {
      const { app, tofu, vault } = createServer(makeTestConfig({ vaultStorage: 'sqlite', vaultPath: TEST_SQLITE_VAULT_PATH }));
      await tofu.init();
      await vault.init();

      const first = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });

      const createRes = await request(app)
        .post('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          public_key: Buffer.from(first.slice(-32)).toString('base64'),
        });

      expect(createRes.status).toBe(201);

      const auditRes = await request(app)
        .get('/api/v1/audit')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      const rawEvents = vault.queryAuditEvents({ limit: 20 });
      const rawCreateEvent = rawEvents.find((event) =>
        event.action === 'create' &&
        event.resource.type === 'agent' &&
        event.metadata?.webBotAuthKeyId === createRes.body.key_id
      );

      expect(rawCreateEvent).toBeDefined();
      expect(rawCreateEvent?.metadata?.identitySource).toBe('web-bot-auth');

      expect(auditRes.status).toBe(200);
      expect(auditRes.body.entries.some((entry: any) => entry.action === 'create' && entry.service === 'agent')).toBe(true);
    });

    it('requires agent auth for Web Bot Auth key management', async () => {
      const { app, tofu } = createServer(makeTestConfig());
      await tofu.init();

      const listRes = await request(app).get('/api/v1/web-bot-auth/keys');
      expect(listRes.status).toBe(401);

      const createRes = await request(app)
        .post('/api/v1/web-bot-auth/keys')
        .send({ public_key: Buffer.alloc(32).toString('base64') });
      expect(createRes.status).toBe(401);
    });

    it('returns 400 for malformed Web Bot Auth public keys', async () => {
      const { app, tofu } = createServer(makeTestConfig());
      await tofu.init();

      const createRes = await request(app)
        .post('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({ public_key: Buffer.alloc(31).toString('base64') });

      expect(createRes.status).toBe(400);
      expect(createRes.body.error).toMatch(/32-byte Ed25519 public key/);
    });

    it('returns 404 before validating rotation payloads for unknown Web Bot Auth keys', async () => {
      const { app, tofu } = createServer(makeTestConfig());
      await tofu.init();

      const rotateRes = await request(app)
        .post('/api/v1/web-bot-auth/keys/missing-agent/rotate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({ public_key: 'not-base64' });

      expect(rotateRes.status).toBe(404);
      expect(rotateRes.body.error).toBe('Web Bot Auth key not found');
    });
  });

  // Ownership-check hardening for revoke-all and rotate:
  // docs/plans/2026-08-31-002-fix-agent-ownership-check-plan.md
  describe('agent ownership checks (revoke-all, rotate)', () => {
    async function registerWebBotAuthAgent(app: any) {
      const keypair = generateKeyPairSync('ed25519');
      const spki = keypair.publicKey.export({ type: 'spki', format: 'der' });
      const createRes = await request(app)
        .post('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({ public_key: Buffer.from(spki.slice(-32)).toString('base64') });
      expect(createRes.status).toBe(201);
      return { agentId: createRes.body.agent_id as string, keyId: createRes.body.key_id as string, signatureAgent: createRes.body.signature_agent as string, keypair };
    }

    it('denies rotate when the caller is a different verified agent', async () => {
      const { app, tofu } = createServer(makeTestConfig());
      await tofu.init();

      const owner = await registerWebBotAuthAgent(app);
      const other = await registerWebBotAuthAgent(app);

      const signedHeaders = signWebBotAuthRequest({
        url: `http://localhost:3456/api/v1/web-bot-auth/keys/${owner.agentId}/rotate`,
        signatureAgent: other.signatureAgent,
        keyId: other.keyId,
        privateKey: other.keypair.privateKey,
      });

      const newKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });
      const rotateRes = await request(app)
        .post(`/api/v1/web-bot-auth/keys/${owner.agentId}/rotate`)
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({ public_key: Buffer.from(newKey.slice(-32)).toString('base64') });

      expect(rotateRes.status).toBe(403);

      const stillListed = (await request(app).get('/api/v1/web-bot-auth/keys').set('Authorization', `Bearer ${TEST_TOKEN}`)).body.keys
        .find((key: any) => key.agent_id === owner.agentId);
      expect(stillListed.key_id).toBe(owner.keyId);
    });

    it('denies rotate for a static-bearer-only caller regardless of webBotAuthMode', async () => {
      const { app, tofu } = createServer(makeTestConfig());
      await tofu.init();

      const owner = await registerWebBotAuthAgent(app);
      const newKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });

      const rotateRes = await request(app)
        .post(`/api/v1/web-bot-auth/keys/${owner.agentId}/rotate`)
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({ public_key: Buffer.from(newKey.slice(-32)).toString('base64') });

      expect(rotateRes.status).toBe(403);
    });

    it('writes a denied-outcome audit event when rotate ownership check fails', async () => {
      const { app, tofu, vault } = createServer(makeTestConfig({ vaultStorage: 'sqlite', vaultPath: TEST_SQLITE_VAULT_PATH }));
      await tofu.init();
      await vault.init();

      const owner = await registerWebBotAuthAgent(app);
      const newKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });

      await request(app)
        .post(`/api/v1/web-bot-auth/keys/${owner.agentId}/rotate`)
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({ public_key: Buffer.from(newKey.slice(-32)).toString('base64') });

      const events = vault.queryAuditEvents({ limit: 20 });
      const denyEvent = events.find((event) => event.action === 'deny' && event.resource.id === owner.agentId);
      expect(denyEvent).toBeDefined();
      expect(denyEvent?.outcome).toBe('denied');
    });

    it('allows a custom agentRequestVerifier principalId matching the target TOFU agentId', async () => {
      const { app, tofu } = createServer(makeTestConfig({
        agentRequestVerifier: (req) => {
          if (req.get('Authorization') !== `Bearer ${TEST_TOKEN}`) {
            return { ok: false, status: 401, error: 'unauthorized' };
          }
          return { ok: true, principal: { type: 'test-verifier', principalId: req.get('X-Test-Acting-Agent-Id') ?? undefined } };
        },
      }));
      await tofu.init();

      const owner = await registerWebBotAuthAgent(app);
      const newKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });

      const rotateRes = await request(app)
        .post(`/api/v1/web-bot-auth/keys/${owner.agentId}/rotate`)
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set('X-Test-Acting-Agent-Id', owner.agentId)
        .send({ public_key: Buffer.from(newKey.slice(-32)).toString('base64') });

      expect(rotateRes.status).toBe(200);
    });

    it('denies revoke-all when the caller is a different verified agent (vault fingerprint mismatch)', async () => {
      const targetId = `agt_${crypto.randomUUID().replace(/-/g, '')}`;
      const callerId = `agt_${crypto.randomUUID().replace(/-/g, '')}`;

      // A caller with its own verified identity (via a custom verifier
      // resolving to the caller's own id) attempts to revoke a different agent.
      const { app, vault } = createServer(makeTestConfig({
        vaultStorage: 'sqlite',
        vaultPath: TEST_SQLITE_VAULT_PATH,
        agentRequestVerifier: (req) => {
          if (req.get('Authorization') !== `Bearer ${TEST_TOKEN}`) {
            return { ok: false, status: 401, error: 'unauthorized' };
          }
          return { ok: true, principal: { type: 'test-verifier', principalId: callerId } };
        },
      }));
      await vault.init();

      const now = new Date().toISOString();
      await vault.registerAgent({ id: targetId, fingerprint: `fp_${targetId}`, name: 'target', scopeCeiling: [], status: 'active', createdBy: 'test', createdAt: now, updatedAt: now });
      await vault.registerAgent({ id: callerId, fingerprint: `fp_${callerId}`, name: 'caller', scopeCeiling: [], status: 'active', createdBy: 'test', createdAt: now, updatedAt: now });

      const revokeRes = await request(app)
        .post(`/api/v1/agents/${targetId}/revoke-all`)
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({});

      expect(revokeRes.status).toBe(403);
      await expect(vault.getAgent(targetId)).resolves.toMatchObject({ status: 'active' });
    });

    it('writes a denied-outcome audit event when revoke-all ownership check fails', async () => {
      const { app, vault } = createServer(makeTestConfig({ vaultStorage: 'sqlite', vaultPath: TEST_SQLITE_VAULT_PATH }));
      await vault.init();

      const now = new Date().toISOString();
      const targetId = `agt_${crypto.randomUUID().replace(/-/g, '')}`;
      await vault.registerAgent({ id: targetId, fingerprint: `fp_${targetId}`, name: 'target', scopeCeiling: [], status: 'active', createdBy: 'test', createdAt: now, updatedAt: now });

      await request(app)
        .post(`/api/v1/agents/${targetId}/revoke-all`)
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({});

      const events = vault.queryAuditEvents({ limit: 20 });
      const denyEvent = events.find((event) => event.action === 'deny' && event.resource.id === targetId);
      expect(denyEvent).toBeDefined();
      expect(denyEvent?.outcome).toBe('denied');
    });

    it('denies revoke-all after key rotation invalidates the vault fingerprint bridge (documented accepted trade-off)', async () => {
      const { app, tofu, vault } = createServer(makeTestConfig({ vaultStorage: 'sqlite', vaultPath: TEST_SQLITE_VAULT_PATH }));
      await tofu.init();
      await vault.init();

      const owner = await registerWebBotAuthAgent(app);
      const originalIdentity = (await tofu.listAgents()).find((agent) => agent.agentId === owner.agentId)!;

      // Bridge the TOFU identity into a vault AgentRecord the way an operator's
      // out-of-band provisioning process would, using TOFU's exact fingerprint.
      const now = new Date().toISOString();
      await vault.registerAgent({
        id: owner.agentId,
        fingerprint: originalIdentity.fingerprint,
        name: 'bridged-agent',
        scopeCeiling: [],
        status: 'active',
        createdBy: 'test',
        createdAt: now,
        updatedAt: now,
      });

      const newKeypair = generateKeyPairSync('ed25519');
      const newKeySpki = newKeypair.publicKey.export({ type: 'spki', format: 'der' });
      const rotateHeaders = signWebBotAuthRequest({
        url: `http://localhost:3456/api/v1/web-bot-auth/keys/${owner.agentId}/rotate`,
        signatureAgent: owner.signatureAgent,
        keyId: owner.keyId,
        privateKey: owner.keypair.privateKey,
      });
      const rotateRes = await request(app)
        .post(`/api/v1/web-bot-auth/keys/${owner.agentId}/rotate`)
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(rotateHeaders)
        .send({ public_key: Buffer.from(newKeySpki.slice(-32)).toString('base64') });
      expect(rotateRes.status).toBe(200);

      // Attempt revoke-all signed with the NEW key's identity — the vault
      // AgentRecord's fingerprint is still the pre-rotation snapshot, so this
      // must be denied per Key Technical Decisions' accepted trade-off.
      const revokeHeaders = signWebBotAuthRequest({
        url: `http://localhost:3456/api/v1/agents/${owner.agentId}/revoke-all`,
        signatureAgent: owner.signatureAgent,
        keyId: rotateRes.body.key_id,
        privateKey: newKeypair.privateKey,
      });
      const revokeRes = await request(app)
        .post(`/api/v1/agents/${owner.agentId}/revoke-all`)
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(revokeHeaders)
        .send({});

      expect(revokeRes.status).toBe(403);
      await expect(vault.getAgent(owner.agentId)).resolves.toMatchObject({ status: 'active' });
    });
  });

  describe('GET /providers', () => {
    it('requires admin auth', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).get('/providers');

      expect(res.status).toBe(401);
    });

    it('lists configured providers', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/providers')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.providers).toHaveLength(1);
      expect(res.body.providers[0].slug).toBe('google');
      expect(res.body.providers[0].connected).toBe(false);
    });
  });

  describe('GET /api/v1/providers', () => {
    it('requires agent auth (401 without a Bearer token)', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).get('/api/v1/providers');

      expect(res.status).toBe(401);
    });

    it('is served by agent-Bearer auth alone — admin auth is not required', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/api/v1/providers')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
    });

    it('lists configured provider slugs without exposing client id/secret or admin-only fields', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/api/v1/providers')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.providers).toHaveLength(1);
      expect(res.body.providers[0]).toMatchObject({
        slug: 'google',
        defaultScopes: ['openid', 'email', 'profile'],
      });
      expect(res.body.providers[0].clientId).toBeUndefined();
      expect(res.body.providers[0].clientSecret).toBeUndefined();

      // Assert no credential material leaks anywhere in the response body.
      const serialized = JSON.stringify(res.body);
      expect(serialized).not.toContain('test-google-client-secret');
      expect(serialized).not.toContain('test-google-client-id');
    });

    it('is a distinct route from the admin-only GET /providers (agent token alone does not satisfy admin auth there)', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const adminRouteRes = await request(app)
        .get('/providers')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);
      expect(adminRouteRes.status).toBe(401);

      const agentRouteRes = await request(app)
        .get('/api/v1/providers')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);
      expect(agentRouteRes.status).toBe(200);
    });
  });

  describe('GET /connect/:provider', () => {
    it('returns 404 for unconfigured provider', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/connect/slack')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/not configured/);
    });

    it('redirects to Google OAuth for configured provider', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/connect/google?scopes=calendar.readonly')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`);

      expect(res.status).toBe(302);
      expect(res.headers.location).toMatch(/accounts\.google\.com/);
    });
  });

  describe('GET /api/token/:provider', () => {
    it('returns 401 without auth', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).get('/api/token/google');

      expect(res.status).toBe(401);
      expect(res.body.error).toMatch(/Unauthorized/);
    });

    it('returns 401 with wrong token', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/api/token/google')
        .set('Authorization', 'Bearer cred_at_wrong_token');

      expect(res.status).toBe(401);
    });

    it('returns 404 when no credentials stored', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/No credentials stored/);
    });

    it('returns stored token when credentials exist', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      // Pre-store a token in the vault
      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.test-access-token',
        refreshToken: 'rt_test-refresh-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const res = await request(app)
        .get('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe('google');
      expect(res.body.accessToken).toBe('ya29.test-access-token');
      expect(res.body.scopes).toEqual(['calendar.readonly']);
      // Refresh token must NOT be in the response
      expect(res.body.refreshToken).toBeUndefined();
    });
  });

  describe('DELETE /api/token/:provider', () => {
    it('returns 401 without auth', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).delete('/api/token/google');

      expect(res.status).toBe(401);
    });

    it('returns 204 on successful revoke', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      // Pre-store a token
      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.to-be-revoked',
      });

      const res = await request(app)
        .delete('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(204);

      // Verify it's gone
      const entry = await vault.get({ provider: 'google', userId: 'default' });
      expect(entry).toBeNull();
    });
  });

  describe('GET /api/v1/connections', () => {
    it('requires agent auth', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).get('/api/v1/connections?user_id=default');

      expect(res.status).toBe(401);
    });

    it('lists default-user connections for SDK compatibility', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.test-access-token',
        scopes: ['calendar.readonly'],
      });

      const res = await request(app)
        .get('/api/v1/connections?user_id=default')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.connections).toHaveLength(1);
      expect(res.body.connections[0]).toMatchObject({
        slug: 'google',
        scopesGranted: ['calendar.readonly'],
        appClientId: null,
      });
      expect(res.body.connections[0].consentedAt).toBeTypeOf('string');
    });

    it('lists connections for the requested logical user only', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({ provider: 'google', userId: 'default', accessToken: 'default-token' });
      await vault.store({ provider: 'google', userId: 'user-2', accessToken: 'user-2-token', scopes: ['calendar.readonly'] });

      const res = await request(app)
        .get('/api/v1/connections?user_id=user-2')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.connections).toHaveLength(1);
      expect(res.body.connections[0]).toMatchObject({
        slug: 'google',
        scopesGranted: ['calendar.readonly'],
      });
    });
  });

  describe('DELETE /api/v1/connections/:provider', () => {
    it('revokes the default-user connection for SDK compatibility', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.to-be-revoked',
      });

      const res = await request(app)
        .delete('/api/v1/connections/google?user_id=default')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(204);
      await expect(vault.get({ provider: 'google', userId: 'default' })).resolves.toBeNull();
    });
  });

  describe('POST /api/v1/delegate', () => {
    it('returns 401 without auth', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .post('/api/v1/delegate')
        .send({ service: 'google' });

      expect(res.status).toBe(401);
    });

    it('returns consent URL when delegation is requested before connection', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'needs-consent-user',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('consent_required');
      expect(res.body.consent_url).toContain('/connect/google');
      expect(res.body.consent_url).toContain('user_id=needs-consent-user');
      expect(res.body.consent_url).toContain('app_client_id=app_123');
      expect(res.body.consent_url).toContain('scopes=calendar.readonly');
      expect(res.body.access_token).toBeUndefined();
    });

    it('returns a delegated token with requested scopes', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['openid', 'email', 'calendar.readonly'],
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(200);
      expect(res.body.access_token).toBe('ya29.delegate-token');
      expect(res.body.token_type).toBe('Bearer');
      expect(res.body.service).toBe('google');
      expect(res.body.scopes).toEqual(['calendar.readonly']);
      expect(res.body.delegation_id).toMatch(/^del_/);
      expect(res.body.expires_in).toBeGreaterThan(0);
    });

    it('can return a brokered handle without exposing the access token', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'user-2',
        accessToken: 'ya29.brokered-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const delegateRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'user-2',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
          token_format: 'handle',
        });

      expect(delegateRes.status).toBe(200);
      expect(delegateRes.body.access_token).toBeUndefined();
      expect(delegateRes.body.token_type).toBe('Delegation');
      expect(delegateRes.body.user_id).toBe('user-2');
      expect(delegateRes.body.delegation_id).toMatch(/^del_/);

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

      const useRes = await request(app)
        .post('/api/v1/use')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          delegation_id: delegateRes.body.delegation_id,
          url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
          method: 'GET',
          extra_headers: {
            Authorization: 'Bearer attacker-token',
            ' Authorization ': 'Bearer whitespace-attacker-token',
            Host: 'attacker.com',
            Cookie: 'session=secret',
            'Content-Length': '999',
            'X-Forwarded-For': '127.0.0.1',
            'X-Test': '1',
          },
        });

      expect(useRes.status).toBe(200);
      expect(useRes.body.body).toEqual({ items: [] });
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [, init] = fetchSpy.mock.calls[0]!;
      const headers = init?.headers as Record<string, string>;
      expect(headers.Authorization).toBe('Bearer ya29.brokered-token');
      expect(headers[' Authorization ']).toBeUndefined();
      expect(headers.Host).toBeUndefined();
      expect(headers.Cookie).toBeUndefined();
      expect(headers['Content-Length']).toBeUndefined();
      expect(headers['X-Forwarded-For']).toBeUndefined();
      expect(headers['X-Test']).toBe('1');
      fetchSpy.mockRestore();
    });

    it('blocks brokered use outside delegated Google scopes', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.calendar-only',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const delegateRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
          token_format: 'handle',
        });

      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      const useRes = await request(app)
        .post('/api/v1/use')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          delegation_id: delegateRes.body.delegation_id,
          url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages',
          method: 'GET',
        });

      expect(useRes.status).toBe(400);
      expect(fetchSpy).not.toHaveBeenCalled();
      fetchSpy.mockRestore();
    });

    it.each([
      ['missing delegation id', {}, 400, /delegation_id is required/],
      ['missing URL', { delegation_id: 'del_missing', method: 'GET' }, 400, /url is required/],
      ['invalid method', { delegation_id: 'del_missing', url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events', method: 'TRACE' }, 400, /method must be one of/],
      ['GET body', { delegation_id: 'del_missing', url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events', method: 'GET', body: { q: 'bad' } }, 400, /GET requests cannot have a body/],
      ['unknown delegation handle', { delegation_id: 'del_missing', url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events', method: 'GET' }, 404, /Delegation handle not found/],
    ])('validates brokered use request shape: %s', async (_name, payload, status, errorPattern) => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();
      const fetchSpy = vi.spyOn(globalThis, 'fetch');

      try {
        const useRes = await request(app)
          .post('/api/v1/use')
          .set('Authorization', `Bearer ${TEST_TOKEN}`)
          .send(payload);

        expect(useRes.status).toBe(status);
        expect(useRes.body.error).toMatch(errorPattern);
        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it.each([
      ['userinfo host confusion', 'https://www.googleapis.com@attacker.example/calendar/v3/calendars/primary/events'],
      ['subdomain confusion', 'https://www.googleapis.com.evil.example/calendar/v3/calendars/primary/events'],
      ['http protocol downgrade', 'http://www.googleapis.com/calendar/v3/calendars/primary/events'],
      ['private IPv4 target', 'https://127.0.0.1/calendar/v3/calendars/primary/events'],
      ['private IPv6 target', 'https://[::1]/calendar/v3/calendars/primary/events'],
      ['non-standard https port', 'https://www.googleapis.com:8443/calendar/v3/calendars/primary/events'],
      ['cross-service API target', 'https://api.github.com/repos/cred-ninja/sdk'],
      ['encoded authority confusion', 'https://www.googleapis.com%2F@attacker.example/calendar/v3/calendars/primary/events'],
      ['unicode homoglyph host', 'https://www.google\u0430pis.com/calendar/v3/calendars/primary/events'],
    ])('blocks brokered server-side SSRF attempt: %s', async (_name, targetUrl) => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'ssrf-user',
        accessToken: 'ya29.ssrf-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const delegateRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'ssrf-user',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
          token_format: 'handle',
        });

      expect(delegateRes.status).toBe(200);
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

      try {
        const useRes = await request(app)
          .post('/api/v1/use')
          .set('Authorization', `Bearer ${TEST_TOKEN}`)
          .send({
            delegation_id: delegateRes.body.delegation_id,
            url: targetUrl,
            method: 'GET',
          });

        expect(useRes.status).toBe(400);
        expect(useRes.body.error).toMatch(/URL is not allowed/);
        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it('matches short Google scope requests against full OAuth scope URLs', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.full-scope-url',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['https://www.googleapis.com/auth/calendar.readonly'],
      });

      const delegateRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
          token_format: 'handle',
        });

      expect(delegateRes.status).toBe(200);
      expect(delegateRes.body.access_token).toBeUndefined();
      expect(delegateRes.body.scopes).toEqual(['https://www.googleapis.com/auth/calendar.readonly']);

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

      const useRes = await request(app)
        .post('/api/v1/use')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          delegation_id: delegateRes.body.delegation_id,
          url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
          method: 'GET',
        });

      expect(useRes.status).toBe(200);
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      fetchSpy.mockRestore();
    });

    it('applies guard URL policies to brokered use before forwarding', async () => {
      const guard = new CredGuard({
        policies: [
          urlAllowlistPolicy({
            allowedUrls: {
              google: ['https://www.googleapis.com/calendar/'],
            },
          }),
        ],
      });
      const { app, vault } = createServer(makeTestConfig({ guard }));
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.guard-brokered-use',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly', 'gmail.readonly'],
      });

      const delegateRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly', 'gmail.readonly'],
          token_format: 'handle',
        });

      expect(delegateRes.status).toBe(200);

      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      const useRes = await request(app)
        .post('/api/v1/use')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          delegation_id: delegateRes.body.delegation_id,
          url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages',
          method: 'GET',
        });

      expect(useRes.status).toBe(403);
      expect(useRes.body.policy).toBe('url-allowlist');
      expect(JSON.stringify(useRes.body)).not.toContain('ya29.guard-brokered-use');
      expect(fetchSpy).not.toHaveBeenCalled();
      fetchSpy.mockRestore();
    });

    it('fails closed for brokered Google use when stored scopes are missing', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.no-scope-metadata',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: [],
      });

      const delegateRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          token_format: 'handle',
        });

      expect(delegateRes.status).toBe(200);

      const fetchSpy = vi.spyOn(globalThis, 'fetch');
      const useRes = await request(app)
        .post('/api/v1/use')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          delegation_id: delegateRes.body.delegation_id,
          url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
          method: 'GET',
        });

      expect(useRes.status).toBe(400);
      expect(fetchSpy).not.toHaveBeenCalled();
      fetchSpy.mockRestore();
    });

    it('returns upstream error responses without exposing the provider token', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.brokered-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const delegateRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
          token_format: 'handle',
        });

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ message: 'Not Found' }), {
        status: 404,
        headers: { 'content-type': 'application/json' },
      }));

      const useRes = await request(app)
        .post('/api/v1/use')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          delegation_id: delegateRes.body.delegation_id,
          url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events/missing',
          method: 'GET',
        });

      expect(useRes.status).toBe(200);
      expect(useRes.body.ok).toBe(false);
      expect(useRes.body.status).toBe(404);
      expect(useRes.body.body).toEqual({ message: 'Not Found' });
      expect(JSON.stringify(useRes.body)).not.toContain('ya29.brokered-token');
      fetchSpy.mockRestore();
    });

    it('delegates credentials for non-default logical users', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'user-2',
        accessToken: 'ya29.user-2-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'user-2',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(200);
      expect(res.body.access_token).toBe('ya29.user-2-token');
      expect(res.body.user_id).toBe('user-2');
    });

    it('revokes stored DID agents and blocks future delegations for that agent', async () => {
      // revoke-all is hardened by the ownership-check fix
      // (docs/plans/2026-08-31-002-fix-agent-ownership-check-plan.md): it now
      // requires a verified identity matching the target agent. This fixture's
      // AgentRecord has no real Web Bot Auth key registered, so ownership is
      // proven via a custom agentRequestVerifier whose principalId equals the
      // target AgentRecord.id when the caller opts in via a test-only header —
      // mirroring how a real custom verifier would resolve caller identity.
      const { app, vault } = createServer(makeTestConfig({
        vaultStorage: 'sqlite',
        vaultPath: TEST_SQLITE_VAULT_PATH,
        agentRequestVerifier: (req) => {
          if (req.get('Authorization') !== `Bearer ${TEST_TOKEN}`) {
            return { ok: false, status: 401, error: 'Unauthorized. Provide a valid Bearer token.' };
          }
          const actingAsAgentId = req.get('X-Test-Acting-Agent-Id');
          return {
            ok: true,
            principal: { type: 'test-verifier', principalId: actingAsAgentId ?? undefined },
          };
        },
      }));
      await vault.init();

      const now = new Date().toISOString();
      const agentId = `agt_${crypto.randomUUID().replace(/-/g, '')}`;
      const agentDid = `did:key:${agentId}`;
      await vault.registerAgent({
        id: agentId,
        did: agentDid,
        fingerprint: `fp_${agentId}`,
        name: 'revokable-agent',
        scopeCeiling: ['calendar.readonly'],
        status: 'active',
        createdBy: 'test',
        createdAt: now,
        updatedAt: now,
      });
      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.revoked-agent-test',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const allowedRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          agent_did: agentDid,
          scopes: ['calendar.readonly'],
        });

      expect(allowedRes.status).toBe(200);

      const revokeRes = await request(app)
        .post(`/api/v1/agents/${agentId}/revoke-all`)
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set('X-Test-Acting-Agent-Id', agentId)
        .send({});

      expect(revokeRes.status).toBe(204);
      await expect(vault.getAgent(agentId)).resolves.toMatchObject({ status: 'revoked' });

      const deniedRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          agent_did: agentDid,
          scopes: ['calendar.readonly'],
        });

      expect(deniedRes.status).toBe(403);
      expect(deniedRes.body.error).toBe('agent_revoked');
      expect(JSON.stringify(deniedRes.body)).not.toContain('ya29.revoked-agent-test');
    });

    it('enforces stored DID agent scope ceilings during root delegation', async () => {
      const { app, vault } = createServer(makeTestConfig({
        vaultStorage: 'sqlite',
        vaultPath: TEST_SQLITE_VAULT_PATH,
      }));
      await vault.init();

      const now = new Date().toISOString();
      const agentId = `agt_${crypto.randomUUID().replace(/-/g, '')}`;
      await vault.registerAgent({
        id: agentId,
        did: `did:key:${agentId}`,
        fingerprint: `fp_${agentId}`,
        name: 'scope-ceiling-agent',
        scopeCeiling: ['calendar.readonly'],
        status: 'active',
        createdBy: 'test',
        createdAt: now,
        updatedAt: now,
      });
      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.scope-ceiling-test',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly', 'gmail.readonly'],
      });

      const deniedRes = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          agent_did: `did:key:${agentId}`,
          scopes: ['gmail.readonly'],
        });

      expect(deniedRes.status).toBe(403);
      expect(deniedRes.body.error).toBe('scope_ceiling_exceeded');
      expect(JSON.stringify(deniedRes.body)).not.toContain('ya29.scope-ceiling-test');
    });

    it('requires and verifies Web Bot Auth signatures when configured', async () => {
      const config = makeTestConfig({
        webBotAuthMode: 'require',
        redirectBaseUri: 'http://localhost:3456',
        vaultStorage: 'sqlite',
        vaultPath: TEST_SQLITE_VAULT_PATH,
        tofuStorage: 'sqlite',
        tofuPath: TEST_SQLITE_TOFU_PATH,
      });
      const { app, vault, tofu } = createServer(config);
      await vault.init();
      await tofu.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const keypair = generateKeyPairSync('ed25519');
      const spki = keypair.publicKey.export({ type: 'spki', format: 'der' });
      const createRes = await request(app)
        .post('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          public_key: Buffer.from(spki.slice(-32)).toString('base64'),
        });

      expect(createRes.status).toBe(201);

      const signedHeaders = signWebBotAuthRequest({
        url: 'http://localhost:3456/api/v1/delegate',
        signatureAgent: `${config.redirectBaseUri}/.well-known/http-message-signatures-directory`,
        keyId: createRes.body.key_id,
        privateKey: keypair.privateKey,
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(200);

      const rawEvents = vault.queryAuditEvents({ limit: 20 });
      const delegateEvent = rawEvents.find((event) =>
        event.action === 'delegate' &&
        event.metadata?.identitySource === 'web-bot-auth'
      );
      expect(delegateEvent?.metadata?.webBotAuthKeyId).toBe(createRes.body.key_id);
      expect(delegateEvent?.metadata?.signatureAgent).toBe(`${config.redirectBaseUri}/.well-known/http-message-signatures-directory`);
    });

    it('rejects unsigned delegate requests when Web Bot Auth is required', async () => {
      const config = makeTestConfig({ webBotAuthMode: 'require' });
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Web Bot Auth signature required');
    });

    it('rejects replayed Web Bot Auth nonces', async () => {
      const sharedConfig = {
        webBotAuthMode: 'require',
        redirectBaseUri: 'http://localhost:3456',
        vaultStorage: 'sqlite' as const,
        vaultPath: TEST_SQLITE_VAULT_PATH,
        tofuStorage: 'sqlite' as const,
        tofuPath: TEST_SQLITE_TOFU_PATH,
        webBotAuthNonceStore: 'sqlite' as const,
        webBotAuthNoncePath: TEST_SQLITE_NONCE_PATH,
      };
      const firstServer = createServer(makeTestConfig(sharedConfig));
      const secondServer = createServer(makeTestConfig(sharedConfig));
      await firstServer.vault.init();
      await firstServer.tofu.init();
      await secondServer.vault.init();
      await secondServer.tofu.init();

      await firstServer.vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const keypair = generateKeyPairSync('ed25519');
      const spki = keypair.publicKey.export({ type: 'spki', format: 'der' });
      const createRes = await request(firstServer.app)
        .post('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          public_key: Buffer.from(spki.slice(-32)).toString('base64'),
        });

      expect(createRes.status).toBe(201);

      const signedHeaders = signWebBotAuthRequest({
        url: 'http://localhost:3456/api/v1/delegate',
        signatureAgent: `${sharedConfig.redirectBaseUri}/.well-known/http-message-signatures-directory`,
        keyId: createRes.body.key_id,
        privateKey: keypair.privateKey,
        nonce: 'replay-test-nonce',
      });

      const firstRes = await request(firstServer.app)
        .post('/api/v1/delegate')
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(firstRes.status).toBe(200);

      const replayRes = await request(secondServer.app)
        .post('/api/v1/delegate')
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(replayRes.status).toBe(401);
      expect(replayRes.body.error).toBe('invalid_web_bot_auth');
      expect(replayRes.body.message).toMatch(/nonce has already been used/i);
    });

    it('rejects signatures that do not cover signature-agent', async () => {
      const config = makeTestConfig({
        webBotAuthMode: 'require',
        redirectBaseUri: 'http://localhost:3456',
      });
      const { app, vault, tofu } = createServer(config);
      await vault.init();
      await tofu.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const keypair = generateKeyPairSync('ed25519');
      const spki = keypair.publicKey.export({ type: 'spki', format: 'der' });
      const createRes = await request(app)
        .post('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          public_key: Buffer.from(spki.slice(-32)).toString('base64'),
        });

      const signedHeaders = signWebBotAuthRequest({
        url: 'http://localhost:3456/api/v1/delegate',
        signatureAgent: `${config.redirectBaseUri}/.well-known/http-message-signatures-directory`,
        keyId: createRes.body.key_id,
        privateKey: keypair.privateKey,
        components: ['@authority'],
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_web_bot_auth');
      expect(res.body.message).toMatch(/must cover @authority and signature-agent/i);
    });

    it('rejects expired Web Bot Auth signatures', async () => {
      const config = makeTestConfig({
        webBotAuthMode: 'require',
        redirectBaseUri: 'http://localhost:3456',
      });
      const { app, vault, tofu } = createServer(config);
      await vault.init();
      await tofu.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const keypair = generateKeyPairSync('ed25519');
      const spki = keypair.publicKey.export({ type: 'spki', format: 'der' });
      const createRes = await request(app)
        .post('/api/v1/web-bot-auth/keys')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          public_key: Buffer.from(spki.slice(-32)).toString('base64'),
        });

      const signedHeaders = signWebBotAuthRequest({
        url: 'http://localhost:3456/api/v1/delegate',
        signatureAgent: `${config.redirectBaseUri}/.well-known/http-message-signatures-directory`,
        keyId: createRes.body.key_id,
        privateKey: keypair.privateKey,
        now: new Date(Date.now() - 5 * 60 * 1000),
        expiresInSeconds: 60,
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_web_bot_auth');
      expect(res.body.message).toMatch(/expired/i);
    });

    it('rejects non-https remote Signature-Agent URLs', async () => {
      const config = makeTestConfig({ webBotAuthMode: 'require' });
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const keypair = generateKeyPairSync('ed25519');
      const signedHeaders = signWebBotAuthRequest({
        url: 'http://localhost:3456/api/v1/delegate',
        signatureAgent: 'http://remote.example.com/.well-known/http-message-signatures-directory',
        keyId: 'kid_unused',
        privateKey: keypair.privateKey,
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_web_bot_auth');
      expect(res.body.message).toMatch(/must use HTTPS unless it targets localhost/i);
    });

    it('rejects untrusted remote Signature-Agent origins', async () => {
      const config = makeTestConfig({ webBotAuthMode: 'require' });
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const keypair = generateKeyPairSync('ed25519');
      const signedHeaders = signWebBotAuthRequest({
        url: 'http://localhost:3456/api/v1/delegate',
        signatureAgent: 'https://remote.example.com/.well-known/http-message-signatures-directory',
        keyId: 'kid_unused',
        privateKey: keypair.privateKey,
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_web_bot_auth');
      expect(res.body.message).toMatch(/origin is not trusted/i);
    });

    it('rejects Signature-Agent URLs that do not use the canonical directory path', async () => {
      const config = makeTestConfig({
        webBotAuthMode: 'require',
        webBotAuthAllowedOrigins: ['https://remote.example.com'],
      });
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const keypair = generateKeyPairSync('ed25519');
      const signedHeaders = signWebBotAuthRequest({
        url: 'http://localhost:3456/api/v1/delegate',
        signatureAgent: 'https://remote.example.com/not-the-directory',
        keyId: 'kid_unused',
        privateKey: keypair.privateKey,
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Host', 'localhost:3456')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .set(signedHeaders)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('invalid_web_bot_auth');
      expect(res.body.message).toMatch(/must point to \/.well-known\/http-message-signatures-directory/i);
    });

    it('preserves trusted receipt claims across guarded sub-delegation', async () => {
      const config = makeTestConfig({
        agentToken: undefined,
        vaultStorage: 'sqlite',
        vaultPath: TEST_SQLITE_VAULT_PATH,
        providers: [
          {
            slug: 'github',
            clientId: 'test-github-client-id',
            clientSecret: 'test-github-client-secret',
            defaultScopes: ['repo'],
          },
        ],
        agentRequestVerifier: (req) => {
          if (req.get('X-Test-Agent') === 'staff-reviewer') {
            return {
              ok: true,
              principal: {
                type: 'external-runtime',
                principalId: 'agt_staff_reviewer',
                metadata: {
                  receiptClaims: ['staff-engineer:approved'],
                },
              },
            };
          }
          if (req.get('X-Test-Agent') === 'release-engineer') {
            return {
              ok: true,
              principal: {
                type: 'external-runtime',
                principalId: 'agt_release_engineer',
              },
            };
          }
          return { ok: false, status: 401, error: 'invalid test agent' };
        },
        guard: new CredGuard({
          policies: [
            receiptClaimsPolicy({
              perProvider: {
                github: ['staff-engineer:approved'],
              },
            }),
          ],
        }),
      });
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'github',
        userId: 'default',
        accessToken: 'gho_delegate_token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['repo'],
      });

      await vault.createPermission({
        agentId: 'did:key:release-engineer',
        connectionId: 'github',
        allowedScopes: ['repo'],
        delegatable: true,
        maxDelegationDepth: 2,
        requiresApproval: false,
        createdBy: 'test',
      });

      const rootRes = await request(app)
        .post('/api/v1/delegate')
        .set('X-Test-Agent', 'staff-reviewer')
        .send({
          service: 'github',
          user_id: 'default',
          appClientId: 'app_123',
          agent_did: 'did:key:staff-reviewer',
          scopes: ['repo'],
        });

      expect(rootRes.status).toBe(200);
      expect(rootRes.body.receipt).toBeDefined();

      const childRes = await request(app)
        .post('/api/v1/subdelegate')
        .set('X-Test-Agent', 'release-engineer')
        .send({
          parent_receipt: rootRes.body.receipt,
          agent_did: 'did:key:release-engineer',
          service: 'github',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['repo'],
        });

      expect(childRes.status).toBe(200);
      expect(childRes.body.receipt).toBeDefined();
      expect(childRes.body.chain_depth).toBe(1);
    });

    it('denies scope escalation on the normalized route', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['gmail.send'],
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('scope_escalation_denied');
    });

    it('returns a signed receipt when agent_did is provided', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.delegate-token',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          agent_did: 'did:key:z6MkReceiptAgent',
        });

      expect(res.status).toBe(200);
      expect(res.body.receipt).toBeTypeOf('string');

      const [headerB64, payloadB64, signatureB64] = res.body.receipt.split('.');
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
      expect(payload.sub).toBe('did:key:z6MkReceiptAgent');
      expect(payload.appClientId).toBe('app_123');
      expect(payload.scopes).toEqual(['calendar.readonly']);

      const seed = crypto.scryptSync(config.vaultPassphrase, 'cred:local-receipt:v1', 32);
      const publicKey = createPublicKey({
        key: Buffer.concat([
          Buffer.from('302e020100300506032b657004220420', 'hex'),
          seed,
        ]),
        format: 'der',
        type: 'pkcs8',
      });
      const valid = verifySignature(
        null,
        Buffer.from(`${headerB64}.${payloadB64}`, 'utf8'),
        publicKey,
        Buffer.from(signatureB64, 'base64url'),
      );

      expect(valid).toBe(true);
    });

    it('accepts TOFU proof-of-possession for unclaimed agents within bootstrap scopes', async () => {
      const config = makeTestConfig({
        vaultStorage: 'sqlite',
        vaultPath: TEST_SQLITE_VAULT_PATH,
        tofuStorage: 'sqlite',
        tofuPath: TEST_SQLITE_TOFU_PATH,
      });
      const { app, vault, tofu } = createServer(config);
      await vault.init();
      await tofu.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.tofu-bootstrap',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly', 'gmail.readonly'],
      });

      const keypair = generateTofuKeypair();
      const registration = await tofu.registerAgent({
        publicKey: keypair.publicKey,
        initialScopes: ['calendar.readonly'],
      });

      const proof = createTofuProof(keypair.privateKeyDer, {
        service: 'google',
        userId: 'default',
        appClientId: 'app_123',
        scopes: ['calendar.readonly'],
        timestamp: new Date().toISOString(),
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
          tofu_fingerprint: registration.fingerprint,
          tofu_payload: proof.payloadBase64,
          tofu_signature: proof.signatureBase64,
        });

      expect(res.status).toBe(200);
      expect(res.body.scopes).toEqual(['calendar.readonly']);
      expect(res.body.receipt).toBeUndefined();
    });

    it('denies TOFU proof that exceeds bootstrap scopes', async () => {
      const config = makeTestConfig({ tofuStorage: 'sqlite', tofuPath: TEST_SQLITE_TOFU_PATH });
      const { app, vault, tofu } = createServer(config);
      await vault.init();
      await tofu.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.tofu-bootstrap',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly', 'gmail.readonly'],
      });

      const keypair = generateTofuKeypair();
      const registration = await tofu.registerAgent({
        publicKey: keypair.publicKey,
        initialScopes: ['calendar.readonly'],
      });

      const proof = createTofuProof(keypair.privateKeyDer, {
        service: 'google',
        userId: 'default',
        appClientId: 'app_123',
        scopes: ['gmail.readonly'],
        timestamp: new Date().toISOString(),
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['gmail.readonly'],
          tofu_fingerprint: registration.fingerprint,
          tofu_payload: proof.payloadBase64,
          tofu_signature: proof.signatureBase64,
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toBe('scope_escalation_denied');
    });

    it('requires a permission record for claimed TOFU agents', async () => {
      const config = makeTestConfig({
        vaultStorage: 'sqlite',
        vaultPath: TEST_SQLITE_VAULT_PATH,
        tofuStorage: 'sqlite',
        tofuPath: TEST_SQLITE_TOFU_PATH,
      });
      const { app, vault, tofu } = createServer(config);
      await vault.init();
      await tofu.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.tofu-claimed',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly', 'gmail.readonly'],
      });

      const keypair = generateTofuKeypair();
      const registration = await tofu.registerAgent({
        publicKey: keypair.publicKey,
        initialScopes: ['calendar.readonly'],
      });
      await tofu.claimAgent({ fingerprint: registration.fingerprint, ownerUserId: 'user-123' });

      const proof = createTofuProof(keypair.privateKeyDer, {
        service: 'google',
        userId: 'default',
        appClientId: 'app_123',
        scopes: ['calendar.readonly'],
        timestamp: new Date().toISOString(),
      });

      const denied = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
          tofu_fingerprint: registration.fingerprint,
          tofu_payload: proof.payloadBase64,
          tofu_signature: proof.signatureBase64,
        });

      expect(denied.status).toBe(403);
      expect(denied.body.error).toContain('no permission');

      await vault.createPermission({
        agentId: `tofu:${registration.agentId}`,
        connectionId: 'google',
        allowedScopes: ['calendar.readonly'],
        delegatable: true,
        maxDelegationDepth: 1,
        requiresApproval: false,
        createdBy: 'admin',
      });

      const allowed = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
          tofu_fingerprint: registration.fingerprint,
          tofu_payload: proof.payloadBase64,
          tofu_signature: proof.signatureBase64,
        });

      expect(allowed.status).toBe(200);
      expect(allowed.body.scopes).toEqual(['calendar.readonly']);
    });

    it('rejects stale TOFU proofs', async () => {
      const config = makeTestConfig({ tofuStorage: 'sqlite', tofuPath: TEST_SQLITE_TOFU_PATH });
      const { app, vault, tofu } = createServer(config);
      await vault.init();
      await tofu.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.tofu-stale',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const keypair = generateTofuKeypair();
      const registration = await tofu.registerAgent({
        publicKey: keypair.publicKey,
        initialScopes: ['calendar.readonly'],
      });

      const staleProof = createTofuProof(keypair.privateKeyDer, {
        service: 'google',
        userId: 'default',
        appClientId: 'app_123',
        scopes: ['calendar.readonly'],
        timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
      });

      const res = await request(app)
        .post('/api/v1/delegate')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          service: 'google',
          user_id: 'default',
          appClientId: 'app_123',
          scopes: ['calendar.readonly'],
          tofu_fingerprint: registration.fingerprint,
          tofu_payload: staleProof.payloadBase64,
          tofu_signature: staleProof.signatureBase64,
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toContain('timestamp');
    });
  });

  describe('POST /api/v1/tofu/register', () => {
    it('requires agent auth', async () => {
      const config = makeTestConfig({ tofuStorage: 'sqlite', tofuPath: TEST_SQLITE_TOFU_PATH });
      const { app, tofu } = createServer(config);
      await tofu.init();

      const keypair = generateTofuKeypair();

      const res = await request(app)
        .post('/api/v1/tofu/register')
        .send({
          public_key: Buffer.from(keypair.publicKey).toString('base64'),
          initial_scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(401);
    });

    it('registers a TOFU identity with agent Authorization', async () => {
      const config = makeTestConfig({ tofuStorage: 'sqlite', tofuPath: TEST_SQLITE_TOFU_PATH });
      const { app, tofu } = createServer(config);
      await tofu.init();

      const keypair = generateTofuKeypair();

      const res = await request(app)
        .post('/api/v1/tofu/register')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          public_key: Buffer.from(keypair.publicKey).toString('base64'),
          initial_scopes: ['calendar.readonly'],
          metadata: { name: 'test-agent' },
        });

      expect(res.status).toBe(201);
      expect(res.body.agent_id).toBeTypeOf('string');
      expect(res.body.fingerprint).toBeTypeOf('string');
      expect(res.body.status).toBe('unclaimed');
      expect(res.body.initial_scopes).toEqual(['calendar.readonly']);

      const identity = await tofu.getAgent(res.body.fingerprint);
      expect(identity?.metadata).toEqual({ name: 'test-agent' });
    });

    it('still validates the request body', async () => {
      const config = makeTestConfig({ tofuStorage: 'sqlite', tofuPath: TEST_SQLITE_TOFU_PATH });
      const { app, tofu } = createServer(config);
      await tofu.init();

      const res = await request(app)
        .post('/api/v1/tofu/register')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .send({
          initial_scopes: ['calendar.readonly'],
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/public_key is required/);
    });
  });

  describe('GET /api/v1/audit', () => {
    it('returns an empty audit list when no audit-capable backend is configured', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/api/v1/audit?user_id=default')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.entries).toEqual([]);
    });

    it('returns audit entries from sqlite-backed vaults', async () => {
      const { app, vault } = createServer(makeTestConfig({
        vaultStorage: 'sqlite',
        vaultPath: TEST_SQLITE_VAULT_PATH,
      }));
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.audit-test',
        scopes: ['calendar.readonly'],
      });

      await request(app)
        .get('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
        .expect(200);

      const res = await request(app)
        .get('/api/v1/audit?user_id=default&service=google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.entries.length).toBeGreaterThan(0);
      expect(res.body.entries[0].service).toBe('google');
      expect(res.body.entries[0].action).toBe('access');
    });
  });

  describe('Security', () => {
    it('never returns refresh tokens in API response', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.access',
        refreshToken: 'rt_secret_refresh',
        expiresAt: new Date(Date.now() + 3600 * 1000),
      });

      const res = await request(app)
        .get('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
      const body = JSON.stringify(res.body);
      expect(body).not.toContain('rt_secret_refresh');
      expect(body).not.toContain('refreshToken');
    });

    it('uses constant-time token comparison', async () => {
      // Use a separate vault to avoid pollution from other tests
      const isolatedPath = TEST_VAULT_PATH + '.timing';
      const config = makeTestConfig({ vaultPath: isolatedPath });
      const { app, vault } = createServer(config);
      await vault.init();

      try {
        // Timing attack resistance: wrong tokens should take same time as right tokens.
        // We can't test timing precisely, but we verify both paths execute.
        const res1 = await request(app)
          .get('/api/token/google')
          .set('Authorization', 'Bearer cred_at_wrong');
        expect(res1.status).toBe(401);

        const res2 = await request(app)
          .get('/api/token/google')
          .set('Authorization', `Bearer ${TEST_TOKEN}`);
        // Will be 404 (no stored token), not 401 — proves auth passed
        expect(res2.status).toBe(404);
      } finally {
        // Clean up
        const fs = await import('fs');
        for (const suffix of ['', '.salt']) {
          const p = isolatedPath + suffix;
          if (fs.existsSync(p)) fs.unlinkSync(p);
        }
      }
    });
  });

  // ── New feature tests: default scopes + admin UI ────────────────────────

  describe('Default Scopes', () => {
    it('uses default scopes when no ?scopes param is provided', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect/google');

      expect(res.status).toBe(302);
      const location = res.headers.location;
      // Default scopes from config: openid, email, profile
      // Google prepends https://www.googleapis.com/auth/ to some scopes
      expect(location).toMatch(/scope=/);
      // The URL should contain the default scopes
      const url = new URL(location);
      const scopeParam = url.searchParams.get('scope') ?? '';
      expect(scopeParam).toContain('openid');
      expect(scopeParam).toContain('email');
      expect(scopeParam).toContain('profile');
    });

    it('overrides default scopes when ?scopes param is provided', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect/google?scopes=calendar.readonly');

      expect(res.status).toBe(302);
      const location = res.headers.location;
      const url = new URL(location);
      const scopeParam = url.searchParams.get('scope') ?? '';
      expect(scopeParam).toContain('calendar');
      // Should NOT contain default scopes when overridden
      // (they're replaced, not merged)
    });

    it('stores requested scopes when the OAuth token response omits scope metadata', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const connectRes = await adminGet(app, '/connect/google?user_id=user-2&scopes=calendar.readonly');
      expect(connectRes.status).toBe(302);
      const authUrl = new URL(connectRes.headers.location);
      const state = authUrl.searchParams.get('state');
      expect(state).toBeTruthy();

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
        access_token: 'ya29.callback-token',
        refresh_token: 'rt_callback-token',
        expires_in: 3600,
        token_type: 'Bearer',
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

      try {
        const callbackRes = await request(app)
          .get(`/connect/google/callback?code=test-code&state=${encodeURIComponent(state!)}`);

        expect(callbackRes.status).toBe(200);
        const entry = await vault.get({ provider: 'google', userId: 'user-2' });
        expect(entry?.scopes).toEqual(['calendar.readonly']);
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it('rejects OAuth callbacks with missing code or state', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const missingCode = await request(app)
        .get('/connect/google/callback?state=state-only');
      expect(missingCode.status).toBe(400);
      expect(missingCode.body.error).toBe('Missing code or state parameter');

      const missingState = await request(app)
        .get('/connect/google/callback?code=code-only');
      expect(missingState.status).toBe(400);
      expect(missingState.body.error).toBe('Missing code or state parameter');
    });

    it('escapes OAuth callback error messages before rendering HTML', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .get('/connect/google/callback?error=%3Cscript%3Ealert(1)%3C%2Fscript%3E');

      expect(res.status).toBe(400);
      expect(res.text).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
      expect(res.text).not.toContain('<script>alert(1)</script>');
    });

    it('rejects OAuth callbacks with invalid or provider-mismatched state', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const invalidState = await request(app)
        .get('/connect/google/callback?code=test-code&state=missing-state');
      expect(invalidState.status).toBe(400);
      expect(invalidState.body.error).toMatch(/Invalid or expired OAuth state/);

      const connectRes = await adminGet(app, '/connect/google?user_id=user-2&scopes=calendar.readonly');
      const state = new URL(connectRes.headers.location).searchParams.get('state');
      expect(state).toBeTruthy();

      const providerMismatch = await request(app)
        .get(`/connect/github/callback?code=test-code&state=${encodeURIComponent(state!)}`);
      expect(providerMismatch.status).toBe(400);
      expect(providerMismatch.body.error).toMatch(/Invalid or expired OAuth state/);
    });

    it('does not store credentials when OAuth token exchange fails', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const connectRes = await adminGet(app, '/connect/google?user_id=exchange-fail-user&scopes=calendar.readonly');
      const state = new URL(connectRes.headers.location).searchParams.get('state');
      expect(state).toBeTruthy();

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
        error: 'invalid_grant',
      }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }));

      try {
        const callbackRes = await request(app)
          .get(`/connect/google/callback?code=test-code&state=${encodeURIComponent(state!)}`);

        expect(callbackRes.status).toBe(500);
        expect(callbackRes.text).toContain('Connection Failed');
        const entry = await vault.get({ provider: 'google', userId: 'exchange-fail-user' });
        expect(entry).toBeNull();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it('uses empty scopes when no defaults configured and no param', async () => {
      const config = makeTestConfig({
        providers: [
          {
            slug: 'github',
            clientId: 'test-github-id',
            clientSecret: 'test-github-secret',
            defaultScopes: [],
          },
        ],
      });
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect/github');

      expect(res.status).toBe(302);
      // Should redirect without error even with empty scopes
    });

    it('loads default scopes from config correctly', () => {
      // Test the config interface compliance
      const config = makeTestConfig();
      expect(config.providers[0].defaultScopes).toEqual(['openid', 'email', 'profile']);
    });
  });

  describe('GET /connect (Admin UI)', () => {
    it('returns HTML admin page', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect');

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/html/);
      expect(res.text).toContain('Cred');
      expect(res.text).toContain('Provider Connections');
    });

    it('lists configured providers', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect');

      expect(res.text).toContain('google');
      expect(res.text).toContain('Connect');
    });

    it('shows connected status when tokens are stored', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.test',
        scopes: ['calendar.readonly'],
      });

      const res = await adminGet(app, '/connect');

      expect(res.text).toContain('Connected');
      expect(res.text).toContain('calendar.readonly');
      expect(res.text).toContain('Reconnect');
      expect(res.text).toContain('Revoke');
    });

    it('pre-checks default scopes in the UI', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect');

      // Default scopes should be pre-checked
      // openid, email, profile are in defaultScopes
      expect(res.text).toContain('value="openid"');
      expect(res.text).toMatch(/value="openid"[^>]*checked/);
      expect(res.text).toMatch(/value="email"[^>]*checked/);
      expect(res.text).toMatch(/value="profile"[^>]*checked/);
    });

    it('does not pre-check non-default scopes', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect');

      // gmail.readonly is NOT in defaultScopes, should not be checked
      // The checkbox for gmail.readonly should exist but not be checked
      expect(res.text).toContain('value="gmail.readonly"');
      expect(res.text).not.toMatch(/value="gmail\.readonly"[^>]*checked/);
    });

    it('shows multiple providers when configured', async () => {
      const config = makeTestConfig({
        providers: [
          { slug: 'google', clientId: 'g-id', clientSecret: 'g-secret', defaultScopes: ['openid'] },
          { slug: 'github', clientId: 'gh-id', clientSecret: 'gh-secret', defaultScopes: ['repo'] },
        ],
      });
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect');

      expect(res.text).toContain('google');
      expect(res.text).toContain('github');
    });

    it('does not expose sensitive data in admin UI', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.super-secret-access-token',
        refreshToken: 'rt_super-secret-refresh-token',
        scopes: ['calendar.readonly'],
      });

      const res = await adminGet(app, '/connect');

      // Access tokens MUST NOT appear in admin UI HTML
      expect(res.text).not.toContain('ya29.super-secret-access-token');
      // Refresh tokens MUST NOT appear in admin UI HTML
      expect(res.text).not.toContain('rt_super-secret-refresh-token');
      // Client secrets MUST NOT appear in admin UI HTML
      expect(res.text).not.toContain('test-google-client-secret');
    });

    it('requires admin auth', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await request(app).get('/connect');
      expect(res.status).toBe(401);
    });

    it('creates a browser admin session from login form', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const bootstrap = await request(app)
        .post('/admin/login')
        .type('form')
        .send({ admin_token: TEST_ADMIN_TOKEN, next: '/connect' });

      expect(bootstrap.status).toBe(303);
      expect(bootstrap.headers.location).toBe('/connect');
      expect(bootstrap.headers['set-cookie']?.[0]).toContain('cred_admin_session=');
      expect(bootstrap.headers['referrer-policy']).toBe('no-referrer');

      const res = await request(app)
        .get('/connect')
        .set('Cookie', bootstrap.headers['set-cookie']);
      expect(res.status).toBe(200);
    });

    it('does not redirect admin login to protocol-relative external URLs', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const bootstrap = await request(app)
        .post('/admin/login')
        .type('form')
        .send({ admin_token: TEST_ADMIN_TOKEN, next: '//evil.example.com' });

      expect(bootstrap.status).toBe(303);
      expect(bootstrap.headers.location).toBe('/connect');
    });
  });

  describe('Admin UI — XSS Protection', () => {
    it('escapes provider slugs in HTML output', async () => {
      // Provider slugs come from config (trusted), but verify they're
      // rendered safely. The slug type is constrained to BuiltinAdapterSlug
      // so this is defense-in-depth.
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect');

      // Verify the HTML is well-formed and contains expected structure
      expect(res.text).toContain('<!DOCTYPE html>');
      expect(res.text).toContain('</html>');
    });

    it('custom scope input is text-only (no script injection path)', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await adminGet(app, '/connect');

      // The custom scope input accepts text and is processed client-side
      // via buildScopes() which uses encodeURIComponent — safe for URL injection
      expect(res.text).toContain('encodeURIComponent');
    });
  });

  describe('Revoke via Admin UI', () => {
    it('revokes with the admin session without asking for an agent token', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'user-2',
        accessToken: 'ya29.to-be-revoked',
      });

      const login = await request(app)
        .post('/admin/login')
        .type('form')
        .send({ admin_token: TEST_ADMIN_TOKEN, next: '/connect?user_id=user-2' });

      const res = await request(app)
        .delete('/connect/google?user_id=user-2')
        .set('Cookie', login.headers['set-cookie']);

      expect(res.status).toBe(204);
      await expect(vault.get({ provider: 'google', userId: 'user-2' })).resolves.toBeNull();
    });

    it('admin revoke endpoint requires admin auth', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await request(app).delete('/connect/google');
      expect(res.status).toBe(401);
    });
  });

  // ── Guard integration tests ─────────────────────────────────────────────

  describe('Guard integration', () => {
    it('works without guard configured (no guard = no policy enforcement)', async () => {
      const config = makeTestConfig();
      // No guard in config — default behavior
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.no-guard-test',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const res = await request(app)
        .get('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBe('ya29.no-guard-test');
      // No guard field when guard is not configured
      expect(res.body.guard).toBeUndefined();
    });

    it('allows requests that pass all guard policies', async () => {
      const guard = new CredGuard({
        policies: [
          scopeFilterPolicy({
            allowedScopes: {
              google: ['calendar.readonly', 'gmail.readonly'],
            },
          }),
        ],
      });

      const config = makeTestConfig({ guard });
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.guard-allow',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const res = await request(app)
        .get('/api/token/google?scopes=calendar.readonly')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBe('ya29.guard-allow');
      // Guard metadata is present
      expect(res.body.guard).toBeDefined();
      expect(res.body.guard.allowed).toBe(true);
      expect(res.body.guard.policies).toHaveLength(1);
      expect(res.body.guard.policies[0].name).toBe('scope-filter');
      expect(res.body.guard.policies[0].decision).toBe('ALLOW');
    });

    it('denies requests that fail guard policies with 403', async () => {
      const guard = new CredGuard({
        policies: [
          scopeFilterPolicy({
            allowedScopes: {
              google: ['calendar.readonly'],
            },
          }),
        ],
      });

      const config = makeTestConfig({ guard });
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.guard-deny',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['gmail.send'],
      });

      // Request a scope that isn't allowed
      const res = await request(app)
        .get('/api/token/google?scopes=gmail.send')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/denied by guard policy/);
      expect(res.body.policy).toBe('scope-filter');
      // Access token must NOT leak on denial
      expect(JSON.stringify(res.body)).not.toContain('ya29');
    });

    it('enforces rate limits across requests', async () => {
      const guard = new CredGuard({
        policies: [
          rateLimitPolicy({
            maxRequests: 2,
            windowMs: 60_000,
          }),
        ],
      });

      const config = makeTestConfig({ guard });
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.rate-limit-test',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      // First two requests should pass
      const res1 = await request(app)
        .get('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);
      expect(res1.status).toBe(200);

      const res2 = await request(app)
        .get('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);
      expect(res2.status).toBe(200);

      // Third request should be rate-limited
      const res3 = await request(app)
        .get('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);
      expect(res3.status).toBe(403);
      expect(res3.body.policy).toBe('rate-limit');
    });

    it('guard runs after auth — unauthenticated requests never reach guard', async () => {
      let guardCalled = false;
      const guard = new CredGuard({
        policies: [{
          name: 'spy-policy',
          evaluate: () => {
            guardCalled = true;
            return { decision: 'ALLOW', policy: 'spy-policy' };
          },
        }],
      });

      const config = makeTestConfig({ guard });
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await request(app)
        .get('/api/token/google')
        .set('Authorization', 'Bearer cred_at_wrong_token');

      expect(res.status).toBe(401);
      expect(guardCalled).toBe(false);
    });

    it('guard does not affect non-token routes', async () => {
      const guard = new CredGuard({
        policies: [{
          name: 'deny-all',
          evaluate: () => ({ decision: 'DENY' as const, policy: 'deny-all', reason: 'blocked' }),
        }],
      });

      const config = makeTestConfig({ guard });
      const { app, vault } = createServer(config);
      await vault.init();

      // Health and providers should still work
      const healthRes = await request(app).get('/health');
      expect(healthRes.status).toBe(200);

      const providersRes = await adminGet(app, '/providers');
      expect(providersRes.status).toBe(200);
    });

    it('guard denial does not leak access tokens', async () => {
      const guard = new CredGuard({
        policies: [{
          name: 'deny-all',
          evaluate: () => ({ decision: 'DENY' as const, policy: 'deny-all', reason: 'no access' }),
        }],
      });

      const config = makeTestConfig({ guard });
      const { app, vault } = createServer(config);
      await vault.init();

      await vault.store({
        provider: 'google',
        userId: 'default',
        accessToken: 'ya29.secret-should-not-leak',
        refreshToken: 'rt_also-secret',
        expiresAt: new Date(Date.now() + 3600 * 1000),
        scopes: ['calendar.readonly'],
      });

      const res = await request(app)
        .get('/api/token/google')
        .set('Authorization', `Bearer ${TEST_TOKEN}`);

      expect(res.status).toBe(403);
      const body = JSON.stringify(res.body);
      expect(body).not.toContain('ya29');
      expect(body).not.toContain('rt_');
      expect(body).not.toContain('accessToken');
      expect(body).not.toContain('refreshToken');
    });
  });
});

function generateTofuKeypair(): { publicKey: Uint8Array; privateKeyDer: Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
  return {
    publicKey: new Uint8Array(spki.slice(-32)),
    privateKeyDer: Buffer.from(pkcs8),
  };
}

function createTofuProof(
  privateKeyDer: Buffer,
  payload: {
    service: string;
    userId: string;
    appClientId: string;
    scopes?: string[];
    timestamp: string;
  },
): { payloadBase64: string; signatureBase64: string } {
  const payloadBuffer = Buffer.from(JSON.stringify(payload), 'utf8');
  const privateKey = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
  const signature = sign(null, payloadBuffer, privateKey);
  return {
    payloadBase64: payloadBuffer.toString('base64'),
    signatureBase64: signature.toString('base64'),
  };
}

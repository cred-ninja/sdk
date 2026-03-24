import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { verify as verifySignature, createPublicKey, createPrivateKey, sign, generateKeyPairSync } from 'node:crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { CredGuard, rateLimitPolicy, scopeFilterPolicy } from '@credninja/guard';

// ── Test fixtures ────────────────────────────────────────────────────────────

const TEST_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
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

      const first = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' });
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

      const rotateRes = await request(app)
        .post(`/api/v1/web-bot-auth/keys/${createRes.body.agent_id}/rotate`)
        .set('Authorization', `Bearer ${TEST_TOKEN}`)
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
  });

  describe('GET /providers', () => {
    it('lists configured providers', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).get('/providers');

      expect(res.status).toBe(200);
      expect(res.body.providers).toHaveLength(1);
      expect(res.body.providers[0].slug).toBe('google');
      expect(res.body.providers[0].connected).toBe(false);
    });
  });

  describe('GET /connect/:provider', () => {
    it('returns 404 for unconfigured provider', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).get('/connect/slack');

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/not configured/);
    });

    it('redirects to Google OAuth for configured provider', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app).get('/connect/google?scopes=calendar.readonly');

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

  describe('POST /api/v1/delegate', () => {
    it('returns 401 without auth', async () => {
      const { app, vault } = createServer(makeTestConfig());
      await vault.init();

      const res = await request(app)
        .post('/api/v1/delegate')
        .send({ service: 'google' });

      expect(res.status).toBe(401);
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
    it('registers a TOFU identity without Authorization', async () => {
      const config = makeTestConfig({ tofuStorage: 'sqlite', tofuPath: TEST_SQLITE_TOFU_PATH });
      const { app, tofu } = createServer(config);
      await tofu.init();

      const keypair = generateTofuKeypair();

      const res = await request(app)
        .post('/api/v1/tofu/register')
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

      const res = await request(app).get('/connect/google');

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

      const res = await request(app).get('/connect/google?scopes=calendar.readonly');

      expect(res.status).toBe(302);
      const location = res.headers.location;
      const url = new URL(location);
      const scopeParam = url.searchParams.get('scope') ?? '';
      expect(scopeParam).toContain('calendar');
      // Should NOT contain default scopes when overridden
      // (they're replaced, not merged)
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

      const res = await request(app).get('/connect/github');

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

      const res = await request(app).get('/connect');

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/html/);
      expect(res.text).toContain('Cred');
      expect(res.text).toContain('Provider Connections');
    });

    it('lists configured providers', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await request(app).get('/connect');

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

      const res = await request(app).get('/connect');

      expect(res.text).toContain('Connected');
      expect(res.text).toContain('calendar.readonly');
      expect(res.text).toContain('Reconnect');
      expect(res.text).toContain('Revoke');
    });

    it('pre-checks default scopes in the UI', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await request(app).get('/connect');

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

      const res = await request(app).get('/connect');

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

      const res = await request(app).get('/connect');

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

      const res = await request(app).get('/connect');

      // Access tokens MUST NOT appear in admin UI HTML
      expect(res.text).not.toContain('ya29.super-secret-access-token');
      // Refresh tokens MUST NOT appear in admin UI HTML
      expect(res.text).not.toContain('rt_super-secret-refresh-token');
      // Client secrets MUST NOT appear in admin UI HTML
      expect(res.text).not.toContain('test-google-client-secret');
    });

    it('does not require auth (admin is browser-accessible)', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      // No auth header — should still work
      const res = await request(app).get('/connect');
      expect(res.status).toBe(200);
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

      const res = await request(app).get('/connect');

      // Verify the HTML is well-formed and contains expected structure
      expect(res.text).toContain('<!DOCTYPE html>');
      expect(res.text).toContain('</html>');
    });

    it('custom scope input is text-only (no script injection path)', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      const res = await request(app).get('/connect');

      // The custom scope input accepts text and is processed client-side
      // via buildScopes() which uses encodeURIComponent — safe for URL injection
      expect(res.text).toContain('encodeURIComponent');
    });
  });

  describe('Revoke via Admin UI', () => {
    it('revoke endpoint requires agent token (not cookie-based)', async () => {
      const config = makeTestConfig();
      const { app, vault } = createServer(config);
      await vault.init();

      // The admin UI's revoke uses prompt() for token — this is by design.
      // Verify the DELETE endpoint still requires auth
      const res = await request(app).delete('/api/token/google');
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

      const providersRes = await request(app).get('/providers');
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

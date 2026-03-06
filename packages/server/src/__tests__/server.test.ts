import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

// ── Test fixtures ────────────────────────────────────────────────────────────

const TEST_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const TEST_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-vault.json');

function makeTestConfig(overrides?: Partial<ServerConfig>): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'file',
    vaultPath: TEST_VAULT_PATH,
    agentToken: TEST_TOKEN,
    providers: [
      {
        slug: 'google',
        clientId: 'test-google-client-id',
        clientSecret: 'test-google-client-secret',
      },
    ],
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('@credninja/server', () => {
  afterAll(() => {
    // Cleanup test vault files
    for (const suffix of ['', '.salt']) {
      const p = TEST_VAULT_PATH + suffix;
      if (fs.existsSync(p)) fs.unlinkSync(p);
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
});

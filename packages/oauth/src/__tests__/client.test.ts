import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { OAuthClient } from '../client.js';
import { GoogleAdapter } from '../adapters/google.js';
import { SlackAdapter } from '../adapters/slack.js';
import { NotionAdapter } from '../adapters/notion.js';

const mockTokenResponse = {
  access_token: 'access-123',
  refresh_token: 'refresh-456',
  expires_in: 3600,
  scope: 'test:scope',
  token_type: 'Bearer',
};

function mockFetch(data: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: 'OK',
    json: async () => data,
  });
}

function makeClient(adapter = new GoogleAdapter()) {
  return new OAuthClient({
    adapter,
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    redirectUri: 'http://localhost:3000/callback',
  });
}

describe('OAuthClient', () => {
  afterEach(() => vi.unstubAllGlobals());

  describe('getAuthorizationUrl', () => {
    it('returns url, state, and codeVerifier for PKCE-enabled adapter', async () => {
      const client = makeClient();
      const result = await client.getAuthorizationUrl({ scopes: ['drive'] });
      expect(result.url).toBeTruthy();
      expect(result.state).toBeTruthy();
      expect(result.codeVerifier).toBeTruthy();
    });

    it('state is a 64-char hex string (32 bytes)', async () => {
      const client = makeClient();
      const { state } = await client.getAuthorizationUrl({ scopes: [] });
      expect(state).toMatch(/^[0-9a-f]{64}$/);
    });

    it('state is different on each call', async () => {
      const client = makeClient();
      const a = await client.getAuthorizationUrl({ scopes: [] });
      const b = await client.getAuthorizationUrl({ scopes: [] });
      expect(a.state).not.toBe(b.state);
    });

    it('returns no codeVerifier for non-PKCE adapters (Slack)', async () => {
      const client = makeClient(new SlackAdapter());
      const result = await client.getAuthorizationUrl({ scopes: ['channels:read'] });
      expect(result.codeVerifier).toBeUndefined();
    });

    it('URL includes the state parameter', async () => {
      const client = makeClient();
      const { url, state } = await client.getAuthorizationUrl({ scopes: ['drive'] });
      expect(new URL(url).searchParams.get('state')).toBe(state);
    });

    it('URL includes scopes', async () => {
      const client = makeClient();
      const { url } = await client.getAuthorizationUrl({ scopes: ['calendar.readonly', 'drive'] });
      const scope = new URL(url).searchParams.get('scope');
      expect(scope).toBeTruthy();
    });
  });

  describe('exchangeCode', () => {
    beforeEach(() => vi.stubGlobal('fetch', mockFetch(mockTokenResponse)));

    it('returns token response', async () => {
      const client = makeClient();
      const tokens = await client.exchangeCode({ code: 'auth-code-123' });
      expect(tokens.access_token).toBe('access-123');
      expect(tokens.refresh_token).toBe('refresh-456');
    });

    it('passes codeVerifier when provided', async () => {
      const client = makeClient();
      await client.exchangeCode({ code: 'auth-code-123', codeVerifier: 'my-verifier' });
      const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(init.body.toString()).toContain('code_verifier=my-verifier');
    });
  });

  describe('refreshToken', () => {
    it('calls adapter refreshAccessToken and returns result', async () => {
      vi.stubGlobal('fetch', mockFetch({ access_token: 'new-access', expires_in: 3600, token_type: 'Bearer' }));
      const client = makeClient();
      const result = await client.refreshToken('refresh-tok');
      expect(result.access_token).toBe('new-access');
    });

    it('throws for adapters that do not support refresh (Notion)', async () => {
      const client = makeClient(new NotionAdapter());
      await expect(client.refreshToken('tok')).rejects.toThrow('cannot be refreshed');
    });
  });

  describe('revokeToken', () => {
    it('calls revokeToken on adapter', async () => {
      vi.stubGlobal('fetch', mockFetch({}, 200));
      const client = makeClient();
      await expect(client.revokeToken('access-tok')).resolves.toBeUndefined();
    });

    it('no-op for Notion (no revocation endpoint)', async () => {
      const client = makeClient(new NotionAdapter());
      await expect(client.revokeToken('tok')).resolves.toBeUndefined();
    });
  });

  describe('adapterSlug', () => {
    it('returns the adapter slug', () => {
      const client = makeClient(new GoogleAdapter('google'));
      expect(client.adapterSlug).toBe('google');
    });
  });
});

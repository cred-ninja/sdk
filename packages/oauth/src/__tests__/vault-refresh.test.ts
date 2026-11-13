import { afterEach, describe, expect, it, vi } from 'vitest';
import { GitHubAdapter, GoogleAdapter, createAdapter, toVaultRefreshAdapter } from '../index.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

function tokenEndpoint(reply: Record<string, unknown>) {
  const forms: URLSearchParams[] = [];
  vi.stubGlobal('fetch', vi.fn(async (_url: string | URL, init?: RequestInit) => {
    forms.push(new URLSearchParams(String(init?.body ?? '')));
    return new Response(JSON.stringify(reply), { status: 200, headers: { 'content-type': 'application/json' } });
  }));
  return forms;
}

describe('toVaultRefreshAdapter', () => {
  it('calls the native adapter with the positional arguments the vault passes', async () => {
    const forms = tokenEndpoint({ access_token: 'synthetic-new', expires_in: 60, refresh_token: 'synthetic-rotated' });

    const result = await toVaultRefreshAdapter(new GoogleAdapter()).refreshAccessToken('synthetic-rt', 'cid', 'csecret');

    expect(forms[0].get('refresh_token')).toBe('synthetic-rt');
    expect(forms[0].get('client_id')).toBe('cid');
    expect(forms[0].get('client_secret')).toBe('csecret');
    expect(result).toEqual({ accessToken: 'synthetic-new', refreshToken: 'synthetic-rotated', expiresIn: 60 });
  });

  it('splits a stated scope on spaces, and on GitHub commas', async () => {
    tokenEndpoint({ access_token: 'synthetic-new', scope: 'openid email' });
    expect((await toVaultRefreshAdapter(new GoogleAdapter()).refreshAccessToken('rt', 'c', 's')).scopes)
      .toEqual(['openid', 'email']);

    tokenEndpoint({ access_token: 'synthetic-new', scope: 'public_repo,read:user' });
    expect((await toVaultRefreshAdapter(new GitHubAdapter()).refreshAccessToken('rt', 'c', 's')).scopes)
      .toEqual(['public_repo', 'read:user']);
  });

  it('carries the stated scope through an adapter that overrides refresh (Zoom)', async () => {
    tokenEndpoint({ access_token: 'synthetic-new', scope: 'meeting:read' });
    expect((await toVaultRefreshAdapter(createAdapter('zoom')).refreshAccessToken('rt', 'c', 's')).scopes)
      .toEqual(['meeting:read']);
  });

  it('leaves scopes unstated when the provider omits scope or sends it empty', async () => {
    tokenEndpoint({ access_token: 'synthetic-new' });
    expect(await toVaultRefreshAdapter(new GoogleAdapter()).refreshAccessToken('rt', 'c', 's')).not.toHaveProperty('scopes');

    tokenEndpoint({ access_token: 'synthetic-new', scope: '' });
    expect(await toVaultRefreshAdapter(new GoogleAdapter()).refreshAccessToken('rt', 'c', 's')).not.toHaveProperty('scopes');
  });

  it('refuses a refresh that returns no access token', async () => {
    tokenEndpoint({ token_type: 'Bearer' });
    await expect(toVaultRefreshAdapter(new GoogleAdapter()).refreshAccessToken('rt', 'c', 's'))
      .rejects.toThrow('no access token');
  });
});

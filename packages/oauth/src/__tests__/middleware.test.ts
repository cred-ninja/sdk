import { describe, it, expect, vi } from 'vitest';
import { credOAuth } from '../middleware/express.js';
import { GoogleAdapter } from '../adapters/google.js';

const mockFetch = (data: unknown, status = 200) =>
  vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: 'OK',
    json: async () => data,
  });

const providerConfig = {
  google: {
    adapter: new GoogleAdapter(),
    clientId: 'test-cid',
    clientSecret: 'test-secret',
    scopes: ['drive'],
  },
};

function makeReqRes(url: string, session: Record<string, unknown> = {}) {
  const req = { url, session } as Parameters<ReturnType<typeof credOAuth>>[0];
  const res = {
    _status: 0,
    _location: '',
    _body: '',
    writeHead(status: number, headers?: Record<string, string>) {
      this._status = status;
      this._location = headers?.Location ?? '';
    },
    end(body?: string) { this._body = body ?? ''; },
  } as unknown as Parameters<ReturnType<typeof credOAuth>>[1];
  return { req, res };
}

describe('credOAuth middleware', () => {
  it('redirects to provider auth URL for initiation route', async () => {
    const middleware = credOAuth(providerConfig, {
      redirectUri: 'http://localhost:3000/auth/callback',
      onSuccess: () => {},
    });
    const { req, res } = makeReqRes('/google');
    const next = vi.fn();
    await middleware(req, res, next);
    const r = res as { _status: number; _location: string };
    expect(r._status).toBe(302);
    expect(r._location).toContain('accounts.google.com');
  });

  it('stores state in session during initiation', async () => {
    const middleware = credOAuth(providerConfig, {
      redirectUri: 'http://localhost:3000/auth/callback',
      onSuccess: () => {},
    });
    const session: Record<string, unknown> = {};
    const { req, res } = makeReqRes('/google', session);
    await middleware(req, res, vi.fn());
    expect(session['oauthState:google']).toBeTruthy();
  });

  it('calls next() for unknown provider on initiation', async () => {
    const middleware = credOAuth(providerConfig, {
      redirectUri: 'http://localhost:3000/auth/callback',
      onSuccess: () => {},
    });
    const { req, res } = makeReqRes('/unknown-provider');
    const next = vi.fn();
    await middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('calls onSuccess with tokens on valid callback', async () => {
    vi.stubGlobal('fetch', mockFetch({ access_token: 'tok', token_type: 'Bearer' }));
    const state = 'test-state-xyz';
    const onSuccess = vi.fn();
    const middleware = credOAuth(providerConfig, {
      redirectUri: 'http://localhost:3000/auth/callback',
      onSuccess,
    });
    const session = { 'oauthState:google': state };
    const { req, res } = makeReqRes(`/google/callback?code=test-code&state=${state}`, session);
    await middleware(req, res, vi.fn());
    expect(onSuccess).toHaveBeenCalled();
    expect(onSuccess.mock.calls[0][2].provider).toBe('google');
    expect(onSuccess.mock.calls[0][2].tokens.access_token).toBe('tok');
    vi.unstubAllGlobals();
  });

  it('calls onError on state mismatch (CSRF protection)', async () => {
    const onError = vi.fn();
    const middleware = credOAuth(providerConfig, {
      redirectUri: 'http://localhost:3000/auth/callback',
      onSuccess: () => {},
      onError,
    });
    const session = { 'oauthState:google': 'saved-state' };
    const { req, res } = makeReqRes('/google/callback?code=code&state=WRONG', session);
    await middleware(req, res, vi.fn());
    expect(onError).toHaveBeenCalled();
    expect(onError.mock.calls[0][2].message).toContain('State mismatch');
  });

  it('handles OAuth error param in callback', async () => {
    const onError = vi.fn();
    const middleware = credOAuth(providerConfig, {
      redirectUri: 'http://localhost:3000/auth/callback',
      onSuccess: () => {},
      onError,
    });
    const { req, res } = makeReqRes('/google/callback?error=access_denied', {});
    await middleware(req, res, vi.fn());
    expect(onError).toHaveBeenCalled();
    expect(onError.mock.calls[0][2].message).toContain('access_denied');
  });
});

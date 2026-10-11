import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  GoogleAdapter,
  GitHubAdapter,
  NotionAdapter,
  SlackAdapter,
  OAuthTokenError,
  getRawTokenResponse,
  isOAuthTokenError,
} from '../index.js';

function mockFetch(data: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: async () => data,
  });
}

const EXCHANGE = { code: 'c', clientId: 'id', clientSecret: 'secret', redirectUri: 'http://localhost/cb' };
const REFRESH = { refreshToken: 'rt', clientId: 'id', clientSecret: 'secret' };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('OAuthTokenError', () => {
  it('is thrown by refresh with the status and the OAuth error code, keeping the message', async () => {
    vi.stubGlobal('fetch', mockFetch({ error: 'invalid_grant', error_description: 'Token has been expired or revoked.' }, 400));
    const error = await new GoogleAdapter().refreshAccessToken(REFRESH).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(OAuthTokenError);
    expect(isOAuthTokenError(error)).toBe(true);
    expect(error).toMatchObject({ status: 400, error: 'invalid_grant', operation: 'refresh' });
    expect((error as Error).message).toBe('Token refresh failed: 400 Error');
    expect(JSON.stringify(error)).not.toContain('expired or revoked');
  });

  it('is thrown by exchange; a body without a valid error code leaves error unset', async () => {
    vi.stubGlobal('fetch', mockFetch({ error: 'bad code with spaces "quoted"' }, 401));
    const error = await new GoogleAdapter().exchangeCodeForTokens(EXCHANGE).catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 401, operation: 'exchange' });
    expect((error as OAuthTokenError).error).toBeUndefined();
  });

  it('treats a 200 body carrying an OAuth error and no token as a failure (GitHub)', async () => {
    vi.stubGlobal('fetch', mockFetch({ error: 'bad_verification_code' }));
    const error = await new GitHubAdapter().exchangeCodeForTokens(EXCHANGE).catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 200, error: 'bad_verification_code', operation: 'exchange' });
    vi.stubGlobal('fetch', mockFetch({ error: 'bad_refresh_token' }));
    const refresh = await new GitHubAdapter().refreshAccessToken(REFRESH).catch((e: unknown) => e);
    expect(refresh).toMatchObject({ error: 'bad_refresh_token', operation: 'refresh' });
  });

  it('treats Slack ok:false as a failure', async () => {
    vi.stubGlobal('fetch', mockFetch({ ok: false, error: 'invalid_code' }));
    const error = await new SlackAdapter().exchangeCodeForTokens(EXCHANGE).catch((e: unknown) => e);
    expect(error).toMatchObject({ error: 'invalid_code' });
  });
});

describe('getRawTokenResponse', () => {
  it('exposes provider fields the normalized shape drops, without changing that shape', async () => {
    vi.stubGlobal('fetch', mockFetch({ ok: true, access_token: 'xoxb', scope: 'chat:write', team: { id: 'T1', name: 'Acme' }, bot_user_id: 'U1' }));
    const tokens = await new SlackAdapter().exchangeCodeForTokens(EXCHANGE);
    expect(Object.keys(tokens).sort()).toEqual(['access_token', 'expires_in', 'refresh_token', 'scope', 'token_type']);
    expect(getRawTokenResponse(tokens)).toMatchObject({ team: { id: 'T1', name: 'Acme' }, bot_user_id: 'U1' });
    expect(JSON.stringify(tokens)).not.toContain('T1');
  });

  it('works for adapters that override the exchange (Notion)', async () => {
    vi.stubGlobal('fetch', mockFetch({ access_token: 'secret_x', workspace_id: 'W1', bot_id: 'B1', workspace_name: 'Docs' }));
    const tokens = await new NotionAdapter().exchangeCodeForTokens(EXCHANGE);
    expect(getRawTokenResponse(tokens)).toMatchObject({ workspace_id: 'W1', bot_id: 'B1' });
    expect(getRawTokenResponse({ access_token: 'x' })).toBeUndefined();
  });

  it('works for refresh responses through the shared refresh path (refresh scope)', async () => {
    vi.stubGlobal('fetch', mockFetch({ access_token: 'ya29.new', expires_in: 3600, scope: 'openid https://www.googleapis.com/auth/calendar.readonly' }));
    const refreshed = await new GoogleAdapter().refreshAccessToken(REFRESH);
    expect(Object.keys(refreshed).sort()).toEqual(['access_token', 'expires_in', 'refresh_token']);
    expect(getRawTokenResponse(refreshed)).toMatchObject({ scope: 'openid https://www.googleapis.com/auth/calendar.readonly' });
  });
});

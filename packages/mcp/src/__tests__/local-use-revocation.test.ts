import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CredError, type Cred } from '@credninja/sdk';
import { TokenCache } from '../token-cache';
import { handleUse } from '../tools/use';
import { handleRevoke } from '../tools/revoke';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

const URL = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';

describe('local mode cred_use revocation and audit', () => {
  let tokenCache: TokenCache;
  let delegationId: string;

  beforeEach(() => {
    vi.resetAllMocks();
    tokenCache = new TokenCache();
    delegationId = tokenCache.store({
      accessToken: 'ya29.local-token',
      service: 'google',
      userId: 'default',
      scopes: ['calendar.readonly'],
      expiresAt: Date.now() + 60_000,
    });
    mockFetch.mockResolvedValue(new Response(JSON.stringify({ items: [] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
  });

  afterEach(() => {
    tokenCache.destroy();
  });

  it('checks and audits the connection before every local call', async () => {
    const authorizeLocalUse = vi.fn().mockResolvedValue(undefined);
    const cred = { authorizeLocalUse } as unknown as Cred;

    const result = await handleUse(
      { delegation_id: delegationId, url: URL, method: 'GET' },
      { tokenCache, cred, useServerBroker: false, agentDid: 'did:key:agent' },
    );

    expect(result.isError).toBe(false);
    expect(authorizeLocalUse).toHaveBeenCalledWith({
      service: 'google',
      userId: 'default',
      accessToken: 'ya29.local-token',
      agentId: 'did:key:agent',
    });
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('refuses the call and drops the handle when the connection was revoked elsewhere', async () => {
    const authorizeLocalUse = vi.fn().mockRejectedValue(
      new CredError('The google connection has been revoked', 'connection_revoked', 401),
    );
    const cred = { authorizeLocalUse } as unknown as Cred;

    const result = await handleUse(
      { delegation_id: delegationId, url: URL, method: 'GET' },
      { tokenCache, cred, useServerBroker: false },
    );

    expect(result.isError).toBe(true);
    expect(mockFetch).not.toHaveBeenCalled();
    expect(tokenCache.get(delegationId)).toBeUndefined();
  });

  it('drops cached handles for the connection on cred_revoke', async () => {
    const other = tokenCache.store({
      accessToken: 'gho_other',
      service: 'github',
      userId: 'default',
      expiresAt: Date.now() + 60_000,
    });
    const cred = { revoke: vi.fn().mockResolvedValue(undefined) } as unknown as Cred;

    const result = await handleRevoke(
      { user_id: 'default', service: 'google' },
      { cred, appClientId: 'local', tokenCache },
    );

    expect(result.isError).toBeFalsy();
    expect(tokenCache.get(delegationId)).toBeUndefined();
    expect(tokenCache.get(other)).toBeDefined();
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Cred, CredError } from '../index';

/**
 * Local mode tests — mock @credninja/vault and @credninja/oauth
 * to test the SDK's local delegation path without real vault I/O.
 */

// Shared mock state — must be declared before vi.mock (hoisted)
const mockVault = {
  init: vi.fn().mockResolvedValue(undefined),
  get: vi.fn(),
  store: vi.fn(),
  list: vi.fn(),
  delete: vi.fn(),
};

const mockCreateAdapter = vi.fn().mockReturnValue({
  refreshAccessToken: vi.fn(),
});

// Track constructor calls
const vaultConstructorCalls: unknown[] = [];

vi.mock('@credninja/vault', () => {
  // This class uses the shared mockVault object from outer scope
  // (vi.mock is hoisted but has access to outer-scope vars declared before it)
  return {
    CredVault: class MockCredVault {
      constructor(opts: unknown) {
        vaultConstructorCalls.push(opts);
        Object.assign(this, mockVault);
      }
    },
  };
});

vi.mock('@credninja/oauth', () => ({
  createAdapter: (...args: unknown[]) => mockCreateAdapter(...args),
}));

function makeLocalCred(providers: Record<string, { clientId: string; clientSecret: string }> = {}) {
  return new Cred({
    mode: 'local',
    vault: { passphrase: 'test-pass', path: '/tmp/test-vault.json', storage: 'file' },
    providers,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockVault.init.mockResolvedValue(undefined);
  vaultConstructorCalls.length = 0;
});

describe('Local mode delegate()', () => {
  it('returns credentials from vault', async () => {
    const local = makeLocalCred({ google: { clientId: 'cid', clientSecret: 'csec' } });

    mockVault.get.mockResolvedValue({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'ya29.fresh-token',
      refreshToken: 'rt_123',
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: ['calendar.readonly'],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await local.delegate({ service: 'google', userId: 'user-1' });

    expect(result.accessToken).toBe('ya29.fresh-token');
    expect(result.tokenType).toBe('Bearer');
    expect(result.service).toBe('google');
    expect(result.scopes).toContain('calendar.readonly');
    expect(result.delegationId).toBe('local_google_user-1');
    expect(result.expiresIn).toBeGreaterThan(0);
  });

  it('throws not_found when vault has no entry', async () => {
    const local = makeLocalCred({ google: { clientId: 'cid', clientSecret: 'csec' } });
    mockVault.get.mockResolvedValue(null);

    await expect(
      local.delegate({ service: 'google', userId: 'user-1' }),
    ).rejects.toThrow('No credentials found');
  });

  it('passes adapter + client creds to vault.get for auto-refresh', async () => {
    const local = makeLocalCred({ google: { clientId: 'gid', clientSecret: 'gsec' } });

    mockVault.get.mockResolvedValue({
      provider: 'google',
      userId: 'u1',
      accessToken: 'refreshed-token',
      scopes: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await local.delegate({ service: 'google', userId: 'u1' });

    // Verify vault.get was called with adapter and credentials
    expect(mockVault.get).toHaveBeenCalledWith(expect.objectContaining({
      provider: 'google',
      userId: 'u1',
      clientId: 'gid',
      clientSecret: 'gsec',
    }));
    // adapter should be defined (from createAdapter)
    expect(mockVault.get.mock.calls[0][0].adapter).toBeDefined();
    expect(mockCreateAdapter).toHaveBeenCalledWith('google');
  });

  it('works without provider config (no auto-refresh)', async () => {
    const local = makeLocalCred({}); // no providers configured

    mockVault.get.mockResolvedValue({
      provider: 'custom-api',
      userId: 'u1',
      accessToken: 'static-token',
      scopes: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await local.delegate({ service: 'custom-api', userId: 'u1' });
    expect(result.accessToken).toBe('static-token');

    // Adapter should NOT have been requested since no provider config
    expect(mockCreateAdapter).not.toHaveBeenCalled();
    expect(mockVault.get).toHaveBeenCalledWith(expect.objectContaining({
      adapter: undefined,
      clientId: undefined,
      clientSecret: undefined,
    }));
  });

  it('initializes vault only once across multiple calls', async () => {
    const local = makeLocalCred({ google: { clientId: 'cid', clientSecret: 'csec' } });

    mockVault.get.mockResolvedValue({
      provider: 'google',
      userId: 'u1',
      accessToken: 'token',
      scopes: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await local.delegate({ service: 'google', userId: 'u1' });
    await local.delegate({ service: 'google', userId: 'u1' });

    expect(vaultConstructorCalls).toHaveLength(1);
    expect(mockVault.init).toHaveBeenCalledTimes(1);
  });

  it('passes vault config to CredVault constructor', async () => {
    const local = new Cred({
      mode: 'local',
      vault: { passphrase: 'my-pass', path: '/data/vault.db', storage: 'sqlite' },
      providers: { google: { clientId: 'c', clientSecret: 's' } },
    });

    mockVault.get.mockResolvedValue({
      provider: 'google', userId: 'u1', accessToken: 'tok',
      scopes: [], createdAt: new Date(), updatedAt: new Date(),
    });

    await local.delegate({ service: 'google', userId: 'u1' });

    expect(vaultConstructorCalls[0]).toEqual({
      passphrase: 'my-pass',
      storage: 'sqlite',
      path: '/data/vault.db',
    });
  });

  it('defaults storage to file when not specified', async () => {
    const local = new Cred({
      mode: 'local',
      vault: { passphrase: 'pass', path: '/tmp/v.json' },
      providers: { google: { clientId: 'c', clientSecret: 's' } },
    });

    mockVault.get.mockResolvedValue({
      provider: 'google', userId: 'u1', accessToken: 'tok',
      scopes: [], createdAt: new Date(), updatedAt: new Date(),
    });

    await local.delegate({ service: 'google', userId: 'u1' });

    expect(vaultConstructorCalls[0]).toEqual(expect.objectContaining({
      storage: 'file',
    }));
  });
});

describe('Local mode getUserConnections()', () => {
  it('returns connections from vault list', async () => {
    const local = makeLocalCred();

    mockVault.list.mockResolvedValue([
      { provider: 'google', userId: 'u1', accessToken: 'at1', scopes: ['cal'], createdAt: new Date(), updatedAt: new Date() },
      { provider: 'github', userId: 'u1', accessToken: 'at2', scopes: ['repo'], createdAt: new Date(), updatedAt: new Date() },
    ]);

    const conns = await local.getUserConnections('u1');
    expect(conns).toHaveLength(2);
    expect(conns[0].slug).toBe('google');
    expect(conns[0].scopesGranted).toContain('cal');
    expect(conns[1].slug).toBe('github');
    expect(conns[1].scopesGranted).toContain('repo');
  });

  it('returns empty array when no connections', async () => {
    const local = makeLocalCred();
    mockVault.list.mockResolvedValue([]);

    const conns = await local.getUserConnections('u1');
    expect(conns).toHaveLength(0);
  });
});

describe('Local mode revoke()', () => {
  it('deletes from vault', async () => {
    const local = makeLocalCred();
    mockVault.delete.mockResolvedValue(undefined);

    await local.revoke({ service: 'google', userId: 'u1' });

    expect(mockVault.delete).toHaveBeenCalledWith({
      provider: 'google',
      userId: 'u1',
    });
  });
});

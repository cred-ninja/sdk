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
  getAgentByDid: undefined as undefined | ReturnType<typeof vi.fn>,
  store: vi.fn(),
  list: vi.fn(),
  delete: vi.fn(),
  writeAuditEvent: undefined as undefined | ReturnType<typeof vi.fn>,
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

function makeLocalCred(
  providers: Record<string, { clientId: string; clientSecret: string }> = {},
  options: { requireAudit?: boolean } = {},
) {
  return new Cred({
    mode: 'local',
    vault: { passphrase: 'test-pass', path: '/tmp/test-vault.json', storage: 'file' },
    providers,
    requireAudit: options.requireAudit,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockVault.init.mockResolvedValue(undefined);
  mockVault.getAgentByDid = undefined;
  mockVault.writeAuditEvent = undefined;
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

  it('looks up agent policy by DID when agentDid is provided', async () => {
    const local = makeLocalCred({ github: { clientId: 'gid', clientSecret: 'gsec' } });
    mockVault.getAgentByDid = vi.fn().mockResolvedValue({
      status: 'active',
      scopeCeiling: ['repo'],
    });
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'u1',
      accessToken: 'token',
      scopes: ['repo'],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await local.delegate({
      service: 'github',
      userId: 'u1',
      agentDid: 'did:key:z6MkTestAgent',
      scopes: ['repo'],
    });

    expect(mockVault.getAgentByDid).toHaveBeenCalledWith('did:key:z6MkTestAgent');
  });

  it('writes the pending audit event before reading from the vault', async () => {
    const local = makeLocalCred({ google: { clientId: 'gid', clientSecret: 'gsec' } });
    mockVault.writeAuditEvent = vi.fn();
    mockVault.get.mockResolvedValue({
      provider: 'google',
      userId: 'u1',
      accessToken: 'token',
      scopes: ['calendar.readonly'],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await local.delegate({ service: 'google', userId: 'u1' });

    expect(mockVault.writeAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      outcome: 'pending',
    }));
    expect(mockVault.writeAuditEvent!.mock.invocationCallOrder[0]).toBeLessThan(
      mockVault.get.mock.invocationCallOrder[0],
    );
  });

  it('attenuates returned scopes to the agent ceiling when scopes are omitted', async () => {
    const local = makeLocalCred({ github: { clientId: 'gid', clientSecret: 'gsec' } });
    mockVault.getAgentByDid = vi.fn().mockResolvedValue({
      status: 'active',
      scopeCeiling: ['repo'],
    });
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'u1',
      accessToken: 'token',
      scopes: ['repo', 'admin:org'],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await local.delegate({
      service: 'github',
      userId: 'u1',
      agentDid: 'did:key:z6MkTestAgent',
    });

    expect(result.scopes).toEqual(['repo']);
  });

  it('records the pending audit event even when vault.get throws', async () => {
    const local = makeLocalCred({ google: { clientId: 'gid', clientSecret: 'gsec' } });
    mockVault.writeAuditEvent = vi.fn();
    mockVault.get.mockRejectedValue(new Error('vault unavailable'));

    await expect(
      local.delegate({ service: 'google', userId: 'u1' }),
    ).rejects.toThrow('vault unavailable');

    expect(mockVault.writeAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      outcome: 'pending',
    }));
    expect(mockVault.writeAuditEvent!.mock.invocationCallOrder[0]).toBeLessThan(
      mockVault.get.mock.invocationCallOrder[0],
    );
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

describe('Local mode TTL enforcement', () => {
  it('DelegationResult.expiresIn is always a number', async () => {
    const local = makeLocalCred({ google: { clientId: 'cid', clientSecret: 'csec' } });

    mockVault.get.mockResolvedValue({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'ya29.token',
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await local.delegate({ service: 'google', userId: 'user-1' });
    expect(typeof result.expiresIn).toBe('number');
    expect(result.expiresIn).toBeGreaterThan(0);
  });

  it('DelegationResult.expiresAt is always a Date', async () => {
    const local = makeLocalCred({ google: { clientId: 'cid', clientSecret: 'csec' } });

    mockVault.get.mockResolvedValue({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'ya29.token',
      expiresAt: new Date(Date.now() + 3600_000),
      scopes: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await local.delegate({ service: 'google', userId: 'user-1' });
    expect(result.expiresAt).toBeInstanceOf(Date);
    expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('defaults expiresIn to 900 when no expiry info from vault', async () => {
    const local = makeLocalCred({});

    mockVault.get.mockResolvedValue({
      provider: 'custom',
      userId: 'u1',
      accessToken: 'static-token',
      // No expiresAt
      scopes: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await local.delegate({ service: 'custom', userId: 'u1' });
    expect(result.expiresIn).toBe(900);
    expect(result.expiresAt).toBeInstanceOf(Date);
    // Should be approximately 15 minutes from now
    const expectedMs = Date.now() + 900 * 1000;
    expect(Math.abs(result.expiresAt.getTime() - expectedMs)).toBeLessThan(1000);
  });

  it('throws token_expired when vault returns null (expired) and no refresh possible', async () => {
    const local = makeLocalCred({}); // no providers = no refresh

    // Vault returns null for expired entries
    mockVault.get.mockResolvedValue(null);

    await expect(
      local.delegate({ service: 'google', userId: 'user-1' }),
    ).rejects.toThrow(CredError);
  });
});

describe('Local mode audit enforcement', () => {
  it('throws audit_not_supported when requireAudit is true and backend lacks audit support', async () => {
    const local = makeLocalCred({}, { requireAudit: true });

    mockVault.get.mockResolvedValue({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'ya29.token',
      scopes: ['calendar.readonly'],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      local.delegate({ service: 'google', userId: 'user-1' }),
    ).rejects.toMatchObject({ code: 'audit_not_supported' });
  });

  it('delegates when requireAudit is true and audit support is available', async () => {
    const local = makeLocalCred({}, { requireAudit: true });
    mockVault.writeAuditEvent = vi.fn();

    mockVault.get.mockResolvedValue({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'ya29.token',
      scopes: ['calendar.readonly'],
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await local.delegate({ service: 'google', userId: 'user-1' });

    expect(result.accessToken).toBe('ya29.token');
    expect(mockVault.writeAuditEvent).toHaveBeenCalledTimes(2);
    expect(mockVault.writeAuditEvent.mock.calls[0][0]).toEqual(expect.objectContaining({
      outcome: 'pending',
    }));
    expect(mockVault.writeAuditEvent.mock.calls[1][0]).toEqual(expect.objectContaining({
      outcome: 'success',
    }));
  });
});

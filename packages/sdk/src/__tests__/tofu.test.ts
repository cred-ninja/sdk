import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Cred, CredError } from '../index';
import type { TofuDelegateParams, TofuDelegationResult } from '../index';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function mockResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  };
}

const TOKEN = 'cred_at_test_token';

let cred: Cred;

beforeEach(() => {
  vi.resetAllMocks();
  cred = new Cred({ agentToken: TOKEN });
});

describe('Cred.tofuDelegate()', () => {
  it('POSTs to /api/v1/tofu/delegate with base64-encoded payload and signature', async () => {
    const payload = Buffer.from('request-payload');
    const signature = Buffer.from('fake-signature');

    mockFetch.mockResolvedValue(mockResponse(200, {
      agent_id: 'agent-uuid',
      fingerprint: 'abc123',
      status: 'unclaimed',
      owner_user_id: null,
      token: 'tofu-token-xyz',
      token_expires_at: '2026-03-18T01:00:00.000Z',
      granted_scopes: ['read'],
    }));

    const result = await cred.tofuDelegate({
      fingerprint: 'abc123',
      payload,
      signature,
      requestedScopes: ['read'],
    });

    expect(result.agentId).toBe('agent-uuid');
    expect(result.fingerprint).toBe('abc123');
    expect(result.status).toBe('unclaimed');
    expect(result.ownerUserId).toBeNull();
    expect(result.token).toBe('tofu-token-xyz');
    expect(result.tokenExpiresAt).toBe('2026-03-18T01:00:00.000Z');
    expect(result.grantedScopes).toEqual(['read']);

    // Verify the request was correct
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/api/v1/tofu/delegate');
    expect(init.method).toBe('POST');

    const body = JSON.parse(init.body);
    expect(body.fingerprint).toBe('abc123');
    expect(body.payload).toBe(payload.toString('base64'));
    expect(body.signature).toBe(signature.toString('base64'));
    expect(body.requestedScopes).toEqual(['read']);
  });

  it('defaults requestedScopes to empty array', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      agent_id: 'agent-uuid',
      fingerprint: 'abc123',
      status: 'unclaimed',
      owner_user_id: null,
      token: 'token',
      token_expires_at: '2026-03-18T01:00:00.000Z',
      granted_scopes: [],
    }));

    await cred.tofuDelegate({
      fingerprint: 'abc123',
      payload: Buffer.from('test'),
      signature: Buffer.from('sig'),
    });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.requestedScopes).toEqual([]);
  });

  it('throws CredError in local mode', async () => {
    const local = new Cred({
      mode: 'local',
      vault: { passphrase: 'test', path: '/tmp/test-vault.json' },
      providers: {},
    });

    await expect(
      local.tofuDelegate({
        fingerprint: 'abc',
        payload: Buffer.from('p'),
        signature: Buffer.from('s'),
      }),
    ).rejects.toThrow(CredError);

    try {
      await local.tofuDelegate({
        fingerprint: 'abc',
        payload: Buffer.from('p'),
        signature: Buffer.from('s'),
      });
    } catch (err) {
      expect((err as CredError).code).toBe('not_supported');
      expect((err as CredError).message).toContain('not available in local mode');
    }
  });

  it('throws CredError on server error', async () => {
    mockFetch.mockResolvedValue(mockResponse(401, { error: 'unauthorized', message: 'Invalid token' }));

    await expect(
      cred.tofuDelegate({
        fingerprint: 'abc',
        payload: Buffer.from('p'),
        signature: Buffer.from('s'),
      }),
    ).rejects.toThrow(CredError);
  });
});

describe('TOFU type exports', () => {
  it('TofuDelegateParams type is usable', () => {
    const params: TofuDelegateParams = {
      fingerprint: 'test',
      payload: Buffer.from('test'),
      signature: Buffer.from('test'),
      requestedScopes: ['read'],
    };
    expect(params.fingerprint).toBe('test');
  });

  it('TofuDelegationResult type is usable', () => {
    const result: TofuDelegationResult = {
      agentId: 'id',
      fingerprint: 'fp',
      status: 'unclaimed',
      ownerUserId: null,
      token: 'tok',
      tokenExpiresAt: '2026-01-01T00:00:00Z',
      grantedScopes: [],
    };
    expect(result.status).toBe('unclaimed');
  });
});

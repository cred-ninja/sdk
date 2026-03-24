import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createHash, generateKeyPairSync, verify as verifySignature } from 'node:crypto';
import { Cred, CredError, ConsentRequiredError } from '../index';

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
const BASE_URL = 'https://cred.example.com';

let cred: Cred;

beforeEach(() => {
  vi.resetAllMocks();
  cred = new Cred({ agentToken: TOKEN, baseUrl: BASE_URL });
});

afterEach(() => {
  vi.useRealTimers();
});

function generateTofuKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  const publicKeyBytes = spki.slice(-32);

  return {
    fingerprint: createHash('sha256').update(publicKeyBytes.toString('hex')).digest('hex'),
    privateKeyBytes: new Uint8Array(pkcs8.slice(-32)),
    publicKey,
  };
}

// ── constructor ───────────────────────────────────────────────────────────────

describe('Cred constructor', () => {
  it('throws CredError when agentToken is missing', () => {
    expect(() => new Cred({ agentToken: '', baseUrl: BASE_URL })).toThrow(CredError);
  });

  it('throws CredError when baseUrl is missing', () => {
    expect(() => new Cred({ agentToken: TOKEN } as any)).toThrow('baseUrl is required');
  });

  it('allows HTTP for localhost', () => {
    const local = new Cred({ agentToken: TOKEN, baseUrl: 'http://localhost:3456' });
    expect(local).toBeInstanceOf(Cred);
  });

  it('rejects HTTP for non-localhost', () => {
    expect(() => new Cred({ agentToken: TOKEN, baseUrl: 'http://remote.example.com' })).toThrow('HTTPS');
  });

  it('accepts custom baseUrl and strips trailing slash', async () => {
    const custom = new Cred({ agentToken: TOKEN, baseUrl: 'https://custom.cred.ninja:3001/' });
    mockFetch.mockResolvedValue(mockResponse(200, {
      access_token: 'at', token_type: 'Bearer', service: 'google',
      scopes: [], delegation_id: 'del_1',
    }));
    await custom.delegate({ service: 'google', userId: 'u1', appClientId: 'app1' });
    expect(mockFetch).toHaveBeenCalledWith(
      'https://custom.cred.ninja:3001/api/v1/delegate',
      expect.any(Object),
    );
  });
});

// ── delegate() ────────────────────────────────────────────────────────────────

describe('Cred.delegate()', () => {
  it('returns DelegationResult on 200', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      access_token: 'ya29.mock',
      token_type: 'Bearer',
      expires_in: 3600,
      service: 'google',
      scopes: ['calendar.readonly'],
      delegation_id: 'del_abc',
    }));

    const result = await cred.delegate({
      service: 'google',
      userId: 'user_1',
      appClientId: 'app_1',
      scopes: ['calendar.readonly'],
    });

    expect(result.accessToken).toBe('ya29.mock');
    expect(result.tokenType).toBe('Bearer');
    expect(result.expiresIn).toBe(3600);
    expect(result.expiresAt).toBeInstanceOf(Date);
    expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
    expect(result.delegationId).toBe('del_abc');
    expect(result.scopes).toContain('calendar.readonly');
  });

  it('sends Authorization header with agent token', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      access_token: 'at', token_type: 'Bearer', service: 'google',
      scopes: [], delegation_id: 'del_1',
    }));
    await cred.delegate({ service: 'google', userId: 'u1', appClientId: 'app1' });
    const [, init] = mockFetch.mock.calls[0];
    expect(init.headers['Authorization']).toBe(`Bearer ${TOKEN}`);
  });

  it('throws ConsentRequiredError on 403 consent_required', async () => {
    mockFetch.mockResolvedValue(mockResponse(403, {
      error: 'consent_required',
      message: 'User has not consented',
      consent_url: 'https://cred.example.com/api/connect/google/authorize?app_client_id=app1',
    }));

    await expect(
      cred.delegate({ service: 'google', userId: 'u1', appClientId: 'app1' }),
    ).rejects.toThrow(ConsentRequiredError);

    try {
      await cred.delegate({ service: 'google', userId: 'u1', appClientId: 'app1' });
    } catch (err) {
      expect(err).toBeInstanceOf(ConsentRequiredError);
      expect((err as ConsentRequiredError).consentUrl).toContain('/api/connect/google/authorize');
    }
  });

  it('throws CredError on 403 scope_escalation_denied', async () => {
    mockFetch.mockResolvedValue(mockResponse(403, {
      error: 'scope_escalation_denied',
      message: 'Requested scopes exceed user consent',
    }));

    await expect(
      cred.delegate({ service: 'google', userId: 'u1', appClientId: 'app1', scopes: ['gmail.send'] }),
    ).rejects.toThrow(CredError);
  });

  it('throws CredError on 401 unauthorized', async () => {
    mockFetch.mockResolvedValue(mockResponse(401, { error: 'Invalid or expired agent token' }));
    await expect(
      cred.delegate({ service: 'google', userId: 'u1', appClientId: 'app1' }),
    ).rejects.toThrow(CredError);
  });

  it('defaults expiresIn to 900 when API omits expires_in', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      access_token: 'at', token_type: 'Bearer', service: 'google',
      scopes: [], delegation_id: 'del_1',
      // no expires_in
    }));
    const result = await cred.delegate({ service: 'google', userId: 'u1', appClientId: 'app1' });
    expect(result.expiresIn).toBe(900);
    expect(result.expiresAt).toBeInstanceOf(Date);
  });

  it('omits scopes from body when not provided', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      access_token: 'at', token_type: 'Bearer', service: 'google',
      scopes: ['calendar.readonly'], delegation_id: 'del_1',
    }));
    await cred.delegate({ service: 'google', userId: 'u1', appClientId: 'app1' });
    const [, init] = mockFetch.mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body).not.toHaveProperty('scopes');
  });
});

describe('Cred Web Bot Auth discovery', () => {
  it('returns the configured directory URL', () => {
    expect(cred.getWebBotAuthDirectoryUrl()).toBe(
      'https://cred.example.com/.well-known/http-message-signatures-directory',
    );
  });

  it('fetches the Web Bot Auth directory document', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      keys: [{
        kty: 'OKP',
        crv: 'Ed25519',
        x: 'test-x',
        kid: 'test-kid',
        alg: 'EdDSA',
        use: 'sig',
      }],
    }));

    const directory = await cred.getWebBotAuthDirectory();

    expect(directory.keys).toHaveLength(1);
    expect(directory.keys[0]?.kid).toBe('test-kid');
    expect(mockFetch).toHaveBeenCalledWith(
      'https://cred.example.com/.well-known/http-message-signatures-directory',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          Authorization: `Bearer ${TOKEN}`,
        }),
      }),
    );
  });
});

describe('Cred.tofuDelegate()', () => {
  it('constructs and posts a signed TOFU proof payload', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-03-22T12:34:56.789Z'));
    const keypair = generateTofuKeypair();

    mockFetch.mockResolvedValue(mockResponse(200, {
      access_token: 'ya29.tofu',
      token_type: 'Bearer',
      expires_in: 1200,
      service: 'google',
      scopes: ['calendar.readonly', 'gmail.readonly'],
      delegation_id: 'del_tofu_1',
    }));

    const result = await cred.tofuDelegate({
      fingerprint: keypair.fingerprint,
      privateKeyBytes: keypair.privateKeyBytes,
      service: 'google',
      userId: 'default',
      scopes: ['gmail.readonly', 'calendar.readonly'],
    });

    expect(result.accessToken).toBe('ya29.tofu');
    expect(result.expiresIn).toBe(1200);
    expect(result.delegationId).toBe('del_tofu_1');

    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe(`${BASE_URL}/api/v1/delegate`);
    expect(init.method).toBe('POST');

    const body = JSON.parse(init.body);
    expect(body).toMatchObject({
      service: 'google',
      user_id: 'default',
      appClientId: 'local',
      scopes: ['calendar.readonly', 'gmail.readonly'],
      tofu_fingerprint: keypair.fingerprint,
    });

    const payloadBytes = Buffer.from(body.tofu_payload, 'base64');
    const payload = JSON.parse(payloadBytes.toString('utf8'));
    expect(payload).toEqual({
      service: 'google',
      userId: 'default',
      appClientId: 'local',
      scopes: ['calendar.readonly', 'gmail.readonly'],
      timestamp: '2026-03-22T12:34:56.789Z',
    });

    expect(
      verifySignature(null, payloadBytes, keypair.publicKey, Buffer.from(body.tofu_signature, 'base64')),
    ).toBe(true);
  });

  it('throws CredError when the server rejects the TOFU proof', async () => {
    const keypair = generateTofuKeypair();
    mockFetch.mockResolvedValue(mockResponse(403, {
      error: 'invalid_tofu_proof',
      message: 'Invalid TOFU proof',
    }));

    await expect(
      cred.tofuDelegate({
        fingerprint: keypair.fingerprint,
        privateKeyBytes: keypair.privateKeyBytes,
        service: 'google',
        userId: 'default',
      }),
    ).rejects.toThrow(CredError);
  });

  it('throws local_mode_unsupported in local mode', async () => {
    const local = new Cred({
      mode: 'local',
      vault: { passphrase: 'test-pass', path: '/tmp/test-vault.json' },
      providers: {},
    });
    const keypair = generateTofuKeypair();

    await expect(
      local.tofuDelegate({
        fingerprint: keypair.fingerprint,
        privateKeyBytes: keypair.privateKeyBytes,
        service: 'google',
        userId: 'default',
      }),
    ).rejects.toMatchObject({ code: 'local_mode_unsupported' });
  });
});

// ── getUserConnections() ──────────────────────────────────────────────────────

describe('Cred.getUserConnections()', () => {
  it('returns array of Connection objects', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      connections: [
        { slug: 'google', scopesGranted: ['calendar.readonly'], consentedAt: '2026-03-01T00:00:00Z', appClientId: 'app1' },
        { slug: 'github', scopesGranted: ['repo'], consentedAt: '2026-03-01T00:00:00Z', appClientId: 'app1' },
      ],
    }));

    const conns = await cred.getUserConnections('user_1');
    expect(conns).toHaveLength(2);
    expect(conns[0].slug).toBe('google');
    expect(conns[1].slug).toBe('github');
  });

  it('passes user_id and app_client_id as query params', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, { connections: [] }));
    await cred.getUserConnections('user_1', 'app1');
    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain('user_id=user_1');
    expect(url).toContain('app_client_id=app1');
  });
});

// ── getConsentUrl() ───────────────────────────────────────────────────────────

describe('Cred.getConsentUrl()', () => {
  it('builds correct URL with all required params', () => {
    const url = cred.getConsentUrl({
      service: 'google',
      userId: 'user_1',
      appClientId: 'app_1',
      scopes: ['calendar.readonly', 'calendar.events'],
      redirectUri: 'https://myapp.com/callback',
    });

    expect(url).toContain(`${BASE_URL}/api/connect/google/authorize`);
    expect(url).toContain('app_client_id=app_1');
    expect(url).toContain('scopes=calendar.readonly%2Ccalendar.events');
    expect(url).toContain('redirect_uri=');
  });

  it('does not make an HTTP call', () => {
    cred.getConsentUrl({
      service: 'google', userId: 'u1', appClientId: 'app1',
      scopes: ['calendar.readonly'], redirectUri: 'https://example.com/cb',
    });
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

// ── revoke() ─────────────────────────────────────────────────────────────────

describe('Cred.revoke()', () => {
  it('calls DELETE and resolves on 204', async () => {
    mockFetch.mockResolvedValue({ ok: true, status: 204, json: vi.fn() });
    await expect(
      cred.revoke({ service: 'google', userId: 'user_1' }),
    ).resolves.toBeUndefined();

    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/api/v1/connections/google');
    expect(url).toContain('user_id=user_1');
    expect(init.method).toBe('DELETE');
  });

  it('includes app_client_id when provided', async () => {
    mockFetch.mockResolvedValue({ ok: true, status: 204, json: vi.fn() });
    await cred.revoke({ service: 'google', userId: 'user_1', appClientId: 'app1' });
    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain('app_client_id=app1');
  });

  it('throws CredError on 404', async () => {
    mockFetch.mockResolvedValue(mockResponse(404, { error: 'No active connection found' }));
    await expect(
      cred.revoke({ service: 'google', userId: 'user_1' }),
    ).rejects.toThrow(CredError);
  });
});

// ── getAuditLog() ────────────────────────────────────────────────────────────

describe('Cred.getAuditLog()', () => {
  it('returns audit entries on 200', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      entries: [
        {
          id: 'evt_1',
          action: 'access',
          service: 'google',
          userId: 'default',
          timestamp: '2026-03-21T00:00:00.000Z',
          metadata: { source: 'server' },
        },
      ],
    }));

    const entries = await cred.getAuditLog({ userId: 'default', service: 'google', limit: 10 });
    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe('access');
    expect(entries[0].service).toBe('google');
  });

  it('passes user_id, service, and limit as query params', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, { entries: [] }));
    await cred.getAuditLog({ userId: 'default', service: 'google', limit: 25 });
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/api/v1/audit?');
    expect(url).toContain('user_id=default');
    expect(url).toContain('service=google');
    expect(url).toContain('limit=25');
    expect(init.method).toBe('GET');
  });
});

// ── Web Bot Auth key management ───────────────────────────────────────────────

describe('Cred.listWebBotAuthKeys()', () => {
  it('returns registered identities', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      keys: [
        {
          agent_id: 'agent_123',
          fingerprint: 'fp_123',
          key_id: 'kid_123',
          previous_fingerprint: 'fp_prev',
          previous_key_id: 'kid_prev',
          rotation_grace_expires_at: '2026-03-24T00:00:00.000Z',
          status: 'active',
          initial_scopes: ['calendar.readonly'],
          metadata: { source: 'import' },
          signature_agent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
          created_at: '2026-03-23T00:00:00.000Z',
          updated_at: '2026-03-23T00:00:00.000Z',
          claimed_at: null,
          revoked_at: null,
        },
      ],
    }));

    const keys = await cred.listWebBotAuthKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0].agentId).toBe('agent_123');
    expect(keys[0].keyId).toBe('kid_123');
    expect(keys[0].previousKeyId).toBe('kid_prev');
    expect(keys[0].signatureAgent).toContain('/.well-known/http-message-signatures-directory');
  });
});

describe('Cred.registerWebBotAuthKey()', () => {
  it('posts a base64-encoded public key and returns the created identity', async () => {
    const publicKey = new Uint8Array([1, 2, 3, 4]);
    mockFetch.mockResolvedValue(mockResponse(201, {
      agent_id: 'agent_123',
      fingerprint: 'fp_123',
      key_id: 'kid_123',
      status: 'active',
      initial_scopes: ['calendar.readonly'],
      metadata: { importedBy: 'sdk-test' },
      signature_agent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
      created_at: '2026-03-23T00:00:00.000Z',
      updated_at: '2026-03-23T00:00:00.000Z',
      claimed_at: null,
      revoked_at: null,
    }));

    const key = await cred.registerWebBotAuthKey({
      publicKey,
      initialScopes: ['calendar.readonly'],
      metadata: { importedBy: 'sdk-test' },
    });

    expect(key.agentId).toBe('agent_123');
    const [, init] = mockFetch.mock.calls[0];
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body).public_key).toBe(Buffer.from(publicKey).toString('base64'));
    expect(JSON.parse(init.body).initial_scopes).toEqual(['calendar.readonly']);
  });
});

describe('Cred.rotateWebBotAuthKey()', () => {
  it('posts a rotation request and returns rotation metadata', async () => {
    mockFetch.mockResolvedValue(mockResponse(200, {
      agent_id: 'agent_123',
      fingerprint: 'fp_new',
      key_id: 'kid_new',
      previous_key_id: 'kid_old',
      status: 'active',
      initial_scopes: ['calendar.readonly'],
      metadata: {},
      signature_agent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
      created_at: '2026-03-23T00:00:00.000Z',
      updated_at: '2026-03-23T01:00:00.000Z',
      claimed_at: null,
      revoked_at: null,
      previous_fingerprint: 'fp_old',
      grace_expires_at: '2026-03-24T01:00:00.000Z',
    }));

    const rotated = await cred.rotateWebBotAuthKey({
      agentId: 'agent_123',
      publicKey: 'AQIDBA==',
      gracePeriodHours: 24,
    });

    expect(rotated.previousFingerprint).toBe('fp_old');
    expect(rotated.previousKeyId).toBe('kid_old');
    expect(rotated.graceExpiresAt).toBe('2026-03-24T01:00:00.000Z');
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain('/api/v1/web-bot-auth/keys/agent_123/rotate');
    expect(JSON.parse(init.body).grace_period_hours).toBe(24);
  });
});

// ── error hierarchy ───────────────────────────────────────────────────────────

describe('Error hierarchy', () => {
  it('ConsentRequiredError is instanceof CredError', () => {
    const err = new ConsentRequiredError('test', 'https://example.com');
    expect(err).toBeInstanceOf(CredError);
    expect(err).toBeInstanceOf(ConsentRequiredError);
    expect(err.code).toBe('consent_required');
    expect(err.statusCode).toBe(403);
  });

  it('CredError has correct name', () => {
    const err = new CredError('test', 'some_code', 400);
    expect(err.name).toBe('CredError');
    expect(err.message).toBe('test');
  });
});

// ── Local mode ────────────────────────────────────────────────────────────────

describe('Cred local mode', () => {
  it('throws when vault.passphrase is missing', () => {
    expect(() => new Cred({
      mode: 'local',
      vault: { passphrase: '', path: '/tmp/test-vault.json' },
      providers: {},
    })).toThrow('vault.passphrase is required');
  });

  it('throws when vault.path is missing', () => {
    expect(() => new Cred({
      mode: 'local',
      vault: { passphrase: 'test', path: '' },
      providers: {},
    })).toThrow('vault.path is required');
  });

  it('constructs without error when config is valid', () => {
    const local = new Cred({
      mode: 'local',
      vault: { passphrase: 'test-pass', path: '/tmp/test-vault.json' },
      providers: { google: { clientId: 'cid', clientSecret: 'csec' } },
    });
    expect(local).toBeInstanceOf(Cred);
  });

  it('getConsentUrl throws in local mode', () => {
    const local = new Cred({
      mode: 'local',
      vault: { passphrase: 'test-pass', path: '/tmp/test-vault.json' },
      providers: {},
    });
    expect(() => local.getConsentUrl({
      service: 'google',
      userId: 'u1',
      appClientId: 'app1',
      scopes: ['cal'],
      redirectUri: 'https://example.com/cb',
    })).toThrow('not available in local mode');
  });
});

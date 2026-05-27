import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { TokenCache } from '../token-cache';
import { handleUse } from '../tools/use';
import { createWebBotAuthSigner } from '../web-bot-auth';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('handleUse Web Bot Auth integration', () => {
  let tokenCache: TokenCache;
  let delegationId: string;

  beforeEach(() => {
    vi.resetAllMocks();
    tokenCache = new TokenCache();
    delegationId = tokenCache.store({
      accessToken: 'ya29.test-token',
      service: 'google',
      userId: 'default',
      scopes: ['calendar.readonly'],
      expiresAt: Date.now() + 60_000,
    });

    mockFetch.mockResolvedValue(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
  });

  afterEach(() => {
    tokenCache.destroy();
  });

  it('makes an unsigned upstream request when no signer is configured', async () => {
    await handleUse({
      delegation_id: delegationId,
      url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      method: 'GET',
      extra_headers: {
        'X-Test': '1',
      },
    }, {
      tokenCache,
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [, init] = mockFetch.mock.calls[0]!;
    const headers = init.headers as Record<string, string>;

    expect(headers.Authorization).toBe('Bearer ya29.test-token');
    expect(headers.Accept).toBe('application/json');
    expect(headers['X-Test']).toBe('1');
    expect(headers.Signature).toBeUndefined();
    expect(headers['Signature-Input']).toBeUndefined();
    expect(headers['Signature-Agent']).toBeUndefined();
  });

  it('signs the upstream request when a signer is configured', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
    const signer = createWebBotAuthSigner({
      privateKeyHex: pkcs8.slice(-32).toString('hex'),
      signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
      ttlSeconds: 60,
    });

    await handleUse({
      delegation_id: delegationId,
      url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      method: 'POST',
      body: { summary: 'test' },
      extra_headers: {
        'X-Test': '1',
      },
    }, {
      tokenCache,
      webBotAuthSigner: signer,
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [, init] = mockFetch.mock.calls[0]!;
    const headers = init.headers as Record<string, string>;

    expect(headers.Authorization).toBe('Bearer ya29.test-token');
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['X-Test']).toBe('1');
    expect(headers['Signature-Agent']).toBe('"https://cred.example.com/.well-known/http-message-signatures-directory"');
    expect(headers['Signature-Input']).toContain('tag="web-bot-auth"');
    expect(headers.Signature).toMatch(/^sig1=:[^:]+:$/);
  });

  it('strips caller-controlled auth and signature headers before signing', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
    const signer = createWebBotAuthSigner({
      privateKeyHex: pkcs8.slice(-32).toString('hex'),
      signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
      ttlSeconds: 60,
    });

    await handleUse({
      delegation_id: delegationId,
      url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      method: 'GET',
      extra_headers: {
        Authorization: 'Bearer attacker-token',
        Signature: 'sig1=:forged:',
        'Signature-Input': 'sig1=(\"@authority\")',
        'Signature-Agent': '"https://evil.example.com/.well-known/http-message-signatures-directory"',
        Host: 'attacker.com',
        Cookie: 'session=secret',
        'Content-Length': '999',
        'X-Forwarded-For': '127.0.0.1',
        'X-Test': '1',
      },
    }, {
      tokenCache,
      webBotAuthSigner: signer,
    });

    const [, init] = mockFetch.mock.calls[0]!;
    const headers = init.headers as Record<string, string>;

    expect(headers.Authorization).toBe('Bearer ya29.test-token');
    expect(headers['Signature-Agent']).toBe('"https://cred.example.com/.well-known/http-message-signatures-directory"');
    expect(headers.Signature).not.toBe('sig1=:forged:');
    expect(headers['Signature-Input']).not.toBe('sig1=("@authority")');
    expect(headers.Host).toBeUndefined();
    expect(headers.Cookie).toBeUndefined();
    expect(headers['Content-Length']).toBeUndefined();
    expect(headers['X-Forwarded-For']).toBeUndefined();
    expect(headers['X-Test']).toBe('1');
  });

  it('routes brokered handles through the Cred server without local fetch', async () => {
    const brokeredId = tokenCache.store({
      brokered: true,
      serverDelegationId: 'del_server',
      service: 'google',
      userId: 'default',
      scopes: ['calendar.readonly'],
      expiresAt: Date.now() + 60_000,
    });
    const use = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      contentType: 'application/json',
      body: { items: [] },
    });

    const result = await handleUse({
      delegation_id: brokeredId,
      url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      method: 'GET',
    }, {
      tokenCache,
      cred: { use } as any,
    });

    expect(result.isError).toBe(false);
    expect(use).toHaveBeenCalledWith({
      delegationId: 'del_server',
      url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      method: 'GET',
      body: undefined,
      extraHeaders: undefined,
    });
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

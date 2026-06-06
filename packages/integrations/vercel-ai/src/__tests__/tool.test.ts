/**
 * Cred Vercel AI SDK integration tests.
 *
 * Tests focus on: tool shape, execution, output format,
 * and error propagation. The Cred SDK is mocked -- no real HTTP.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the @credninja/sdk module
const mockDelegate = vi.fn();
const mockDelegateHandle = vi.fn();
const mockUse = vi.fn();

vi.mock('@credninja/sdk', () => {
  class MockCred {
    constructor(public config: any) {}
    delegate = mockDelegate;
    delegateHandle = mockDelegateHandle;
    use = mockUse;
  }

  class CredError extends Error {
    code: string;
    statusCode: number;
    constructor(message: string, code: string, statusCode: number) {
      super(message);
      this.code = code;
      this.statusCode = statusCode;
    }
  }

  class ConsentRequiredError extends Error {
    consentUrl: string;
    constructor(message: string, consentUrl: string) {
      super(message);
      this.consentUrl = consentUrl;
    }
  }

  return {
    Cred: MockCred,
    CredError,
    ConsentRequiredError,
  };
});

const { ConsentRequiredError, CredError } = await import('@credninja/sdk');
import { credDelegateTool } from '../tool';
import { credUseTool } from '../tool';

const TOKEN = 'cred_at_test';
const USER_ID = 'user_123';
const APP_CLIENT_ID = 'app_1';
const BASE_URL = 'https://cred.example.com';

beforeEach(() => {
  vi.clearAllMocks();
});

// -- factory function ---------------------------------------------------------

describe('credDelegateTool factory', () => {
  it('returns a tool with description', () => {
    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    expect(t.description).toBeDefined();
    expect(t.description!.toLowerCase()).toContain('access token');
    expect(t.description!.toLowerCase()).toContain('service');
  });

  it('returns a brokered-handle tool description when configured', () => {
    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'handle',
    });

    expect(t.description!.toLowerCase()).toContain('delegation handle');
    expect(t.description!.toLowerCase()).not.toContain('access_token');
  });

  it('defaults to brokered handle mode (keeps tokens out of the model)', async () => {
    mockDelegateHandle.mockResolvedValue({
      tokenType: 'Delegation',
      expiresIn: 900,
      expiresAt: new Date(Date.now() + 900_000),
      service: 'google',
      userId: USER_ID,
      scopes: ['calendar.readonly'],
      delegationId: 'del_default',
    });

    // No tokenFormat → secure default.
    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
    });

    expect(t.description!.toLowerCase()).toContain('delegation handle');

    const result: any = await t.execute!(
      { service: 'google', scopes: ['calendar.readonly'] },
      { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
    );

    expect(result.accessToken).toBeUndefined();
    expect(result.delegationId).toBe('del_default');
    expect(mockDelegateHandle).toHaveBeenCalled();
    expect(mockDelegate).not.toHaveBeenCalled();
  });

  it('returns a tool with input schema', () => {
    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    expect(t.inputSchema).toBeDefined();
  });

  it('returns a tool with execute function', () => {
    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    expect(t.execute).toBeDefined();
    expect(typeof t.execute).toBe('function');
  });
});

// -- execute ------------------------------------------------------------------

describe('credDelegateTool execute', () => {
  it('returns delegation result with all fields', async () => {
    mockDelegate.mockResolvedValue({
      accessToken: 'ya29.mock',
      tokenType: 'Bearer',
      expiresIn: 3600,
      service: 'google',
      scopes: ['calendar.readonly'],
      delegationId: 'del_abc',
    });

    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    const result = await t.execute!(
      { service: 'google', scopes: ['calendar.readonly'] },
      { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
    );

    expect(result).toEqual({
      accessToken: 'ya29.mock',
      tokenType: 'Bearer',
      expiresIn: 3600,
      service: 'google',
      scopes: ['calendar.readonly'],
      delegationId: 'del_abc',
    });
  });

  it('passes service, userId, appClientId, and scopes to Cred', async () => {
    mockDelegate.mockResolvedValue({
      accessToken: 'at',
      tokenType: 'Bearer',
      service: 'github',
      scopes: ['repo'],
      delegationId: 'del_1',
    });

    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    await t.execute!(
      { service: 'github', scopes: ['repo'] },
      { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
    );

    expect(mockDelegate).toHaveBeenCalledWith({
      service: 'github',
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      scopes: ['repo'],
    });
  });

  it('can return brokered handles without exposing access tokens', async () => {
    mockDelegateHandle.mockResolvedValue({
      tokenType: 'Delegation',
      expiresIn: 900,
      expiresAt: new Date(Date.now() + 900_000),
      service: 'google',
      userId: USER_ID,
      scopes: ['calendar.readonly'],
      delegationId: 'del_handle',
    });

    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'handle',
    });

    const result = await t.execute!(
      { service: 'google', scopes: ['calendar.readonly'] },
      { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
    );

    expect(result).toEqual({
      tokenType: 'Delegation',
      expiresIn: 900,
      service: 'google',
      userId: USER_ID,
      scopes: ['calendar.readonly'],
      delegationId: 'del_handle',
      note: 'Pass delegationId to cred_use to make authenticated API calls.',
    });
    expect(mockDelegateHandle).toHaveBeenCalledWith({
      service: 'google',
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      scopes: ['calendar.readonly'],
    });
    expect(mockDelegate).not.toHaveBeenCalled();
  });

  it('passes undefined scopes when empty array', async () => {
    mockDelegate.mockResolvedValue({
      accessToken: 'at',
      tokenType: 'Bearer',
      service: 'google',
      scopes: [],
      delegationId: 'del_1',
    });

    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    await t.execute!(
      { service: 'google', scopes: [] },
      { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
    );

    expect(mockDelegate).toHaveBeenCalledWith({
      service: 'google',
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      scopes: undefined,
    });
  });

  it('reuses a cached token until it is within the refresh window', async () => {
    mockDelegate.mockResolvedValueOnce({
      accessToken: 'cached-token',
      tokenType: 'Bearer',
      expiresIn: 3600,
      expiresAt: new Date(Date.now() + 3600_000),
      service: 'google',
      scopes: ['calendar.readonly'],
      delegationId: 'del_cached',
    });

    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    const first = await t.execute!(
      { service: 'google', scopes: ['calendar.readonly'] },
      { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
    );
    const second = await t.execute!(
      { service: 'google', scopes: ['calendar.readonly'] },
      { toolCallId: 'tc_2', messages: [], abortSignal: new AbortController().signal },
    );

    expect(first.accessToken).toBe('cached-token');
    expect(second.accessToken).toBe('cached-token');
    expect(mockDelegate).toHaveBeenCalledTimes(1);
  });

  it('refreshes when the cached token is near expiry', async () => {
    mockDelegate
      .mockResolvedValueOnce({
        accessToken: 'stale-token',
        tokenType: 'Bearer',
        expiresIn: 30,
        expiresAt: new Date(Date.now() + 30_000),
        service: 'google',
        scopes: ['calendar.readonly'],
        delegationId: 'del_stale',
      })
      .mockResolvedValueOnce({
        accessToken: 'fresh-token',
        tokenType: 'Bearer',
        expiresIn: 3600,
        expiresAt: new Date(Date.now() + 3600_000),
        service: 'google',
        scopes: ['calendar.readonly'],
        delegationId: 'del_fresh',
      });

    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    await t.execute!(
      { service: 'google', scopes: ['calendar.readonly'] },
      { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
    );
    const refreshed = await t.execute!(
      { service: 'google', scopes: ['calendar.readonly'] },
      { toolCallId: 'tc_2', messages: [], abortSignal: new AbortController().signal },
    );

    expect(refreshed.accessToken).toBe('fresh-token');
    expect(mockDelegate).toHaveBeenCalledTimes(2);
  });

  it('propagates ConsentRequiredError', async () => {
    const err = new (ConsentRequiredError as any)(
      'User has not consented',
      'https://cred.example.com/connect/google?user_id=user_123&app_client_id=app_1',
    );
    mockDelegate.mockRejectedValue(err);

    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    await expect(
      t.execute!(
        { service: 'google', scopes: ['calendar.readonly'] },
        { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
      ),
    ).rejects.toThrow('User has not consented');
  });

  it('propagates CredError on 401', async () => {
    const err = new (CredError as any)('Invalid agent token', 'unauthorized', 401);
    mockDelegate.mockRejectedValue(err);

    const t = credDelegateTool({
      agentToken: TOKEN,
      baseUrl: BASE_URL,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
      tokenFormat: 'raw',
    });

    await expect(
      t.execute!(
        { service: 'google', scopes: [] },
        { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
      ),
    ).rejects.toThrow('Invalid agent token');
  });
});

describe('credUseTool execute', () => {
  it('brokers an upstream request through Cred.use', async () => {
    mockUse.mockResolvedValue({
      status: 200,
      ok: true,
      contentType: 'application/json',
      body: { items: [] },
    });

    const t = credUseTool({
      agentToken: TOKEN,
      baseUrl: 'https://cred.example.com',
    });

    const result = await t.execute!(
      {
        delegationId: 'del_handle',
        url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
        method: 'GET',
        extraHeaders: { 'X-Test': '1' },
      },
      { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
    );

    expect(result).toEqual({
      status: 200,
      ok: true,
      contentType: 'application/json',
      body: { items: [] },
    });
    expect(mockUse).toHaveBeenCalledWith({
      delegationId: 'del_handle',
      url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      method: 'GET',
      body: undefined,
      extraHeaders: { 'X-Test': '1' },
    });
  });
});

/**
 * Cred Vercel AI SDK integration tests.
 *
 * Tests focus on: tool shape, execution, output format,
 * and error propagation. The Cred SDK is mocked -- no real HTTP.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the @credninja/sdk module
const mockDelegate = vi.fn();

vi.mock('@credninja/sdk', () => {
  class MockCred {
    constructor(public config: any) {}
    delegate = mockDelegate;
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

const TOKEN = 'cred_at_test';
const USER_ID = 'user_123';
const APP_CLIENT_ID = 'app_1';

beforeEach(() => {
  vi.clearAllMocks();
});

// -- factory function ---------------------------------------------------------

describe('credDelegateTool factory', () => {
  it('returns a tool with description', () => {
    const t = credDelegateTool({
      agentToken: TOKEN,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
    });

    expect(t.description).toBeDefined();
    expect(t.description!.toLowerCase()).toContain('access token');
    expect(t.description!.toLowerCase()).toContain('service');
  });

  it('returns a tool with parameters schema', () => {
    const t = credDelegateTool({
      agentToken: TOKEN,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
    });

    expect(t.parameters).toBeDefined();
  });

  it('returns a tool with execute function', () => {
    const t = credDelegateTool({
      agentToken: TOKEN,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
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
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
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
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
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
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
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

  it('propagates ConsentRequiredError', async () => {
    const err = new (ConsentRequiredError as any)(
      'User has not consented',
      'https://api.cred.ninja/api/connect/google/authorize?app_client_id=app_1',
    );
    mockDelegate.mockRejectedValue(err);

    const t = credDelegateTool({
      agentToken: TOKEN,
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
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
      userId: USER_ID,
      appClientId: APP_CLIENT_ID,
    });

    await expect(
      t.execute!(
        { service: 'google', scopes: [] },
        { toolCallId: 'tc_1', messages: [], abortSignal: new AbortController().signal },
      ),
    ).rejects.toThrow('Invalid agent token');
  });
});

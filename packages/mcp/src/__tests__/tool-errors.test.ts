import { describe, it, expect } from 'vitest';
import { CredError, ConsentRequiredError } from '@credninja/sdk';
import { toolErrorResult } from '../tool-errors.js';
import { handleDelegate } from '../tools/delegate.js';
import { TokenCache } from '../token-cache.js';

// U3 (docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md):
// CredError.code/statusCode must survive the MCP tool boundary instead of
// being flattened to prose.
describe('toolErrorResult', () => {
  it('surfaces code and statusCode for a CredError, not just prose', () => {
    const result = toolErrorResult(new CredError('Too many requests', 'rate_limited', 429));

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String((result.content as any[])[0].text));
    expect(payload).toEqual({ error: 'rate_limited', message: 'Too many requests', statusCode: 429 });
  });

  it('produces a readable message with no code field for a plain Error', () => {
    const result = toolErrorResult(new Error('boom'));

    expect(result.isError).toBe(true);
    expect(String((result.content as any[])[0].text)).toBe('Error: boom');
  });

  it('produces a readable message for a non-Error thrown value', () => {
    const result = toolErrorResult('a string was thrown');

    expect(result.isError).toBe(true);
    expect(String((result.content as any[])[0].text)).toBe('Error: a string was thrown');
  });

  it('uses a caller-supplied fallback message for a non-Error thrown value, instead of a raw String(error)', () => {
    const result = toolErrorResult({ some: 'non-error-object' }, 'Brokered upstream request failed');

    expect(result.isError).toBe(true);
    expect(String((result.content as any[])[0].text)).toBe('Error: Brokered upstream request failed');
  });

  it('ignores the fallback message when the thrown value is a real Error', () => {
    const result = toolErrorResult(new Error('boom'), 'should not appear');

    expect(String((result.content as any[])[0].text)).toBe('Error: boom');
  });
});

describe('cred_delegate error handling (U3)', () => {
  it('still surfaces ConsentRequiredError.consentUrl as a non-error response (existing behavior, unchanged)', async () => {
    const tokenCache = new TokenCache();
    const result = await handleDelegate(
      { user_id: 'default', service: 'google' },
      {
        cred: {
          delegate: async () => {
            throw new ConsentRequiredError('Consent required', 'https://cred.example.com/consent/abc');
          },
        } as any,
        appClientId: 'app_123',
        tokenCache,
      },
    );

    expect(result.isError).toBeUndefined();
    expect(String((result.content as any[])[0].text)).toContain('https://cred.example.com/consent/abc');
    tokenCache.destroy();
  });

  it('surfaces a non-consent CredError with structured code via toolErrorResult', async () => {
    const tokenCache = new TokenCache();
    const result = await handleDelegate(
      { user_id: 'default', service: 'google' },
      {
        cred: {
          delegate: async () => {
            throw new CredError('Scope ceiling exceeded', 'scope_ceiling_exceeded', 403);
          },
        } as any,
        appClientId: 'app_123',
        tokenCache,
      },
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String((result.content as any[])[0].text));
    expect(payload).toMatchObject({ error: 'scope_ceiling_exceeded', statusCode: 403 });
    tokenCache.destroy();
  });
});

import { describe, it, expect } from 'vitest';
import { handleCapabilities } from '../tools/capabilities.js';
import { CredError } from '@credninja/sdk';

describe('cred_capabilities tool', () => {
  it('returns the configured providers from Cred.listProviders()', async () => {
    const providers = [
      { slug: 'google', defaultScopes: ['openid', 'email'] },
      { slug: 'github', defaultScopes: ['repo'] },
    ];

    const result = await handleCapabilities(
      {},
      {
        cred: {
          listProviders: async () => providers,
        } as any,
      },
    );

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.providers).toEqual(providers);
  });

  it('returns an empty list, not an error, when no providers are configured', async () => {
    const result = await handleCapabilities(
      {},
      {
        cred: {
          listProviders: async () => [],
        } as any,
      },
    );

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.providers).toEqual([]);
  });

  it('includes a summarized guard decision under `guard` when the context carries one (this tool IS guard-wrapped)', async () => {
    const result = await handleCapabilities(
      {},
      {
        cred: {
          listProviders: async () => [{ slug: 'google', defaultScopes: [] }],
        } as any,
        guardDecision: {
          results: [
            { policy: 'rate-limit', decision: 'ALLOW', limit: 100, windowMs: 60_000, remaining: 99 },
          ],
        },
      },
    );

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.guard).toMatchObject({ rateLimit: { limit: 100, windowMs: 60_000, remaining: 99 } });
  });

  it('surfaces a thrown CredError as a structured error, matching U3\'s pattern', async () => {
    const result = await handleCapabilities(
      {},
      {
        cred: {
          listProviders: async () => {
            throw new CredError('Upstream unavailable', 'upstream_error', 502);
          },
        } as any,
      },
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload).toMatchObject({ error: 'upstream_error', statusCode: 502 });
  });
});

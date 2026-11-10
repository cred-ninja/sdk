import { afterEach, expect, it, vi } from 'vitest';
import { Cred, generateAgentIdentity } from '../index.js';

afterEach(() => vi.restoreAllMocks());

it.each(['delegate', 'delegateHandle', 'subDelegate', 'subDelegateHandle', 'tofuDelegate'] as const)(
  '%s rejects lossy constraints before transport or signing', async (method) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      access_token: 'fixture-token', token_type: 'Delegation', service: 'github', scopes: ['repo'], delegation_id: 'fixture',
    })));
    const cred = new Cred({ agentToken: 'cred_at_fixture', baseUrl: 'https://cred.example.com' });
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    class LossyArray extends Array<number> {
      override map<U>(): U[] { return []; }
    }
    for (const value of [{ mandatory: undefined }, [undefined], [, 1], new LossyArray(1, 2), NaN, Infinity, 1n, cycle]) {
      await expect(cred[method]({
        service: 'github', userId: 'owner', appClientId: 'local', agentDid: 'did:key:child', parentReceipt: 'fixture',
        constraints: [{ key: 'x', future: value }], fingerprint: 'fixture',
        // Invalid signing material ensures validation must precede either signing path.
        privateKeyBytes: new Uint8Array(0), delegatorIdentity: { did: 'did:key:root', privateKey: new Uint8Array(0) },
      })).rejects.toMatchObject({ code: 'invalid_constraints' });
    }
    expect(fetch).not.toHaveBeenCalled();
  },
);

it('transports a validated detached constraint list rather than invoking custom list serialization', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
    token_type: 'Delegation', service: 'github', scopes: ['repo'], delegation_id: 'fixture',
  })));
  const cred = new Cred({ agentToken: 'cred_at_fixture', baseUrl: 'https://cred.example.com' });
  class LossyList extends Array<{ key: string; future: unknown }> {
    toJSON() { return []; }
  }
  const constraint = { key: 'x', future: { a: [true, null, 1] } };
  await cred.delegateHandle({
    service: 'github', userId: 'owner', appClientId: 'local', constraints: new LossyList(constraint),
    agentIdentity: await generateAgentIdentity(),
  }).catch(() => {});
  expect(JSON.parse(String(fetch.mock.calls[0]![1]!.body)).constraints).toEqual([constraint]);
});

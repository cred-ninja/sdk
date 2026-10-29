import { afterEach, describe, expect, it, vi } from 'vitest';
import { Cred, CredError, type DelegateParams } from '@credninja/sdk';
import { TokenCache } from '../token-cache.js';
import { handleUse } from '../tools/use.js';
import { handleDelegate, DELEGATE_TOOL_DEFINITION } from '../tools/delegate.js';
import { handleSubdelegate, SUBDELEGATE_TOOL_DEFINITION } from '../tools/subdelegate.js';

const cache = new TokenCache();
afterEach(() => { cache.destroy(); vi.restoreAllMocks(); });
const constraints = [{ key: 'destination', future: { nested: [1, true] } }];

describe('MCP opaque constraints', () => {
  it.each([
    { key: 'max_calls', max_lifetime: 0 }, { key: 'max_calls', max_subtree: 0 },
    { key: 'destination', prefix: 'https://blocked.invalid/' }, { key: 'x', max: 1 },
    { key: 'x', min: 1 }, { key: 'x', one_of: ['allowed'] },
    { key: 'x', not_one_of: ['blocked'] }, { key: 'x', rank: 0 },
  ])('denies unsupported cached constraint %j even without a Cred context', async (constraint) => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}'));
    const id = cache.store({ accessToken: 'test-token', service: 'github', userId: 'user-test', scopes: ['repo'], constraints: [constraint], expiresAt: Date.now() + 60_000 });
    const result = await handleUse({ delegation_id: id, url: 'https://api.github.com/user', method: 'GET' }, { tokenCache: cache });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain('unsupported_constraint');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('leaves brokered exercise to the server without requiring local vault support', async () => {
    const use = vi.fn().mockRejectedValue(new CredError('Opaque constraint refused by broker', 'unknown_constraint', 403));
    const id = cache.store({ brokered: true, serverDelegationId: 'server-id', service: 'github', userId: 'user-test', constraints, expiresAt: Date.now() + 60_000 });
    const result = await handleUse({ delegation_id: id, url: 'https://api.github.com/user', method: 'GET' }, { tokenCache: cache, cred: { use } as unknown as Cred });
    expect(use).toHaveBeenCalledTimes(1);
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain('unknown_constraint');
  });
  it('denies a cached opaque constraint before any upstream request, even without a client', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}'));
    const id = cache.store({ accessToken: 'test-token', service: 'github', userId: 'user-test', scopes: ['repo'], constraints, expiresAt: Date.now() + 60_000 });
    const result = await handleUse({ delegation_id: id, url: 'https://api.github.com/user', method: 'GET' }, { tokenCache: cache });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain('unknown_constraint');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('forwards opaque constraints from both delegation tools instead of dropping them', async () => {
    const requests: DelegateParams[] = [];
    const delegate = async (request: DelegateParams) => {
      requests.push(request);
      return { tokenType: 'Delegation' as const, expiresIn: 60, expiresAt: new Date(Date.now() + 60_000), service: 'github', scopes: ['repo'], delegationId: 'server-handle', receipt: 'test-receipt', chainDepth: 1, parentDelegationId: 'parent' };
    };
    const cred = { delegateHandle: delegate, subDelegateHandle: delegate } as unknown as Cred;
    const context = { cred, tokenCache: cache, appClientId: 'local', useServerBroker: true };
    const root = await handleDelegate({ service: 'github', user_id: 'user-test', constraints }, context);
    const child = await handleSubdelegate({ service: 'github', user_id: 'user-test', agent_did: 'did:key:child', parent_receipt: 'parent', constraints }, context);
    expect(requests.map((request) => request.constraints)).toEqual([constraints, constraints]);
    expect(DELEGATE_TOOL_DEFINITION.inputSchema.properties).toHaveProperty('constraints');
    expect(SUBDELEGATE_TOOL_DEFINITION.inputSchema.properties).toHaveProperty('constraints');
    for (const result of [root, child]) {
      const content = result.content[0]!;
      if (content.type !== 'text') throw new Error('Expected tool text');
      expect(cache.get(JSON.parse(content.text).delegationId)?.constraints).toEqual(constraints);
    }
  });

  it('cannot erase cached opaque restrictions by mutating store input or returned copies', () => {
    const input = structuredClone(constraints);
    const id = cache.store({ accessToken: 'test-token', service: 'github', userId: 'user-test', constraints: input, expiresAt: Date.now() + 60_000 });
    input.splice(0);
    expect(cache.get(id)?.constraints).toEqual(constraints);
    cache.get(id)!.constraints!.splice(0);
    expect(cache.get(id)?.constraints).toEqual(constraints);
  });
});

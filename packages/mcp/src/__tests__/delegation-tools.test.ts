import { describe, it, expect } from 'vitest';
import { handleDelegate } from '../tools/delegate.js';
import { handleSubdelegate } from '../tools/subdelegate.js';
import { TokenCache } from '../token-cache.js';

describe('delegation tools', () => {
  it('returns a receipt from cred_delegate when present', async () => {
    const tokenCache = new TokenCache();
    const result = await handleDelegate(
      {
        user_id: 'default',
        service: 'github',
        scopes: ['repo'],
      },
      {
        cred: {
          delegate: async () => ({
            accessToken: 'gho_root',
            tokenType: 'Bearer',
            expiresIn: 900,
            expiresAt: new Date(Date.now() + 900_000),
            service: 'github',
            scopes: ['repo'],
            delegationId: 'del_root',
            receipt: 'receipt_root',
          }),
        } as any,
        appClientId: 'external-runtime',
        agentDid: 'agent:staff-engineer',
        tokenCache,
      },
    );

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.receipt).toBe('receipt_root');
    expect(payload.delegationId).toMatch(/^del_/);
    expect(tokenCache.get(payload.delegationId)?.scopes).toEqual(['repo']);
    tokenCache.destroy();
  });

  it('uses server-brokered handles in cloud mode without caching raw tokens', async () => {
    const tokenCache = new TokenCache();
    const result = await handleDelegate(
      {
        user_id: 'default',
        service: 'google',
        scopes: ['calendar.readonly'],
      },
      {
        cred: {
          delegateHandle: async () => ({
            tokenType: 'Delegation',
            expiresIn: 900,
            expiresAt: new Date(Date.now() + 900_000),
            service: 'google',
            userId: 'default',
            scopes: ['calendar.readonly'],
            delegationId: 'del_server',
          }),
        } as any,
        appClientId: 'external-runtime',
        tokenCache,
        useServerBroker: true,
      },
    );

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    const cached = tokenCache.get(payload.delegationId);
    expect(cached?.brokered).toBe(true);
    expect(cached?.serverDelegationId).toBe('del_server');
    expect(cached?.accessToken).toBeUndefined();
    tokenCache.destroy();
  });

  it('returns a child receipt from cred_subdelegate', async () => {
    const tokenCache = new TokenCache();
    const result = await handleSubdelegate(
      {
        parent_receipt: 'receipt_root',
        agent_did: 'agent:release-engineer',
        user_id: 'default',
        service: 'github',
        scopes: ['repo'],
      },
      {
        cred: {
          subDelegate: async () => ({
            accessToken: 'gho_child',
            tokenType: 'Bearer',
            expiresIn: 600,
            expiresAt: new Date(Date.now() + 600_000),
            service: 'github',
            scopes: ['repo'],
            delegationId: 'del_child',
            receipt: 'receipt_child',
            chainDepth: 1,
            parentDelegationId: 'del_root',
          }),
        } as any,
        appClientId: 'external-runtime',
        tokenCache,
      },
    );

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.receipt).toBe('receipt_child');
    expect(payload.chainDepth).toBe(1);
    expect(payload.parentDelegationId).toBe('del_root');
    expect(payload.delegationId).toMatch(/^del_/);
    expect(tokenCache.get(payload.delegationId)?.scopes).toEqual(['repo']);
    tokenCache.destroy();
  });
});

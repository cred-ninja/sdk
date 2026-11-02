import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Cred } from '@credninja/sdk';
import { TokenCache } from '../token-cache';
import { handleUse } from '../tools/use';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

const GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me';

describe('local mode cred_use classification', () => {
  let tokenCache: TokenCache;

  beforeEach(() => {
    vi.resetAllMocks();
    tokenCache = new TokenCache();
    mockFetch.mockImplementation(async () => new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }));
  });
  afterEach(() => tokenCache.destroy());

  const handle = (service: string, scopes: string[]) => tokenCache.store({ accessToken: 'tok', service, userId: 'default', scopes, expiresAt: Date.now() + 60_000 });
  const text = (result: Awaited<ReturnType<typeof handleUse>>) => (result.content[0] as { text: string }).text;

  function context(extra: Record<string, unknown> = {}) {
    const authorizeLocalUse = vi.fn().mockResolvedValue(undefined);
    const recordLocalRefusal = vi.fn().mockResolvedValue(undefined);
    return { ctx: { tokenCache, cred: { authorizeLocalUse, recordLocalRefusal } as unknown as Cred, useServerBroker: false, agentDid: 'did:key:agent', ...extra }, authorizeLocalUse, recordLocalRefusal };
  }

  it('gmail.readonly reads and cannot send, and the refusal is audited', async () => {
    const { ctx, recordLocalRefusal } = context();
    const id = handle('google', ['gmail.readonly']);
    expect((await handleUse({ delegation_id: id, url: `${GMAIL}/messages`, method: 'GET' }, ctx)).isError).toBe(false);
    mockFetch.mockClear();
    const sent = await handleUse({ delegation_id: id, url: `${GMAIL}/messages/send`, method: 'POST', body: { raw: 'eA' } }, ctx);
    expect(sent.isError).toBe(true);
    expect(text(sent)).toContain('scope_insufficient');
    expect(mockFetch).not.toHaveBeenCalled();
    expect(recordLocalRefusal).toHaveBeenCalledWith(expect.objectContaining({ error: 'scope_insufficient', service: 'google', agentId: 'did:key:agent' }));
  });

  it('an unmapped call is refused as not mapped', async () => {
    const { ctx } = context();
    const result = await handleUse({ delegation_id: handle('github', ['repo']), url: 'https://api.github.com/enterprises/acme', method: 'GET' }, ctx);
    expect(text(result)).toContain('operation_not_mapped');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('forwards the canonical URL, and refuses what is not canonical', async () => {
    const { ctx } = context();
    const id = handle('google', ['gmail.readonly']);
    expect((await handleUse({ delegation_id: id, url: 'https://gmail.googleapis.com/gmail/v1/users/me/labels/../messages', method: 'GET' }, ctx)).isError).toBe(false);
    expect(String(mockFetch.mock.calls[0]![0])).toBe(`${GMAIL}/messages`);
    mockFetch.mockClear();
    for (const url of [`${GMAIL}/messages%2Fsend`, 'https://gmail.googleapis.com./gmail/v1/users/me/messages', 'https://gmail.googleapis.com//gmail/v1/users/me/messages']) {
      expect((await handleUse({ delegation_id: id, url, method: 'POST', body: {} }, ctx)).isError, url).toBe(true);
    }
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('refuses every override channel and a Content-Type mismatch', async () => {
    const { ctx } = context();
    const id = handle('google', ['gmail.readonly', 'gmail.send']);
    const url = `${GMAIL}/messages/1`;
    for (const input of [
      { url: `${url}?_method=DELETE`, method: 'GET' as const },
      { url, method: 'GET' as const, extra_headers: { 'X-HTTP-Method-Override': 'DELETE' } },
      { url: `${GMAIL}/messages/send`, method: 'POST' as const, body: { _method: 'DELETE' } },
    ]) {
      const result = await handleUse({ delegation_id: id, ...input }, ctx);
      expect(result.isError).toBe(true);
      expect(text(result)).toContain('method override');
    }
    const typed = await handleUse({ delegation_id: id, url: `${GMAIL}/messages/send`, method: 'POST', body: {}, extra_headers: { 'Content-Type': 'multipart/mixed' } }, ctx);
    expect(text(typed)).toContain('operation_not_mapped');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('does not follow a redirect, even to an allowed host', async () => {
    const { ctx } = context();
    mockFetch.mockResolvedValue(new Response(null, { status: 302, headers: { location: `${GMAIL}/profile` } }));
    const result = await handleUse({ delegation_id: handle('google', ['gmail.readonly']), url: `${GMAIL}/messages`, method: 'GET' }, ctx);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(JSON.parse(text(result)).status).toBe(302);
  });

  it('a Notion connection with no named scope is write-capable', async () => {
    const { ctx } = context();
    expect((await handleUse({ delegation_id: handle('notion', []), url: 'https://api.notion.com/v1/pages', method: 'POST', body: {} }, ctx)).isError).toBe(false);
  });

  it('the opt-out restores the old behavior and marks the audit event', async () => {
    const { ctx, authorizeLocalUse } = context({ allowUnclassifiedCalls: true });
    const result = await handleUse({ delegation_id: handle('google', ['gmail.readonly']), url: `${GMAIL}/messages/send`, method: 'POST', body: { raw: 'eA' } }, ctx);
    expect(result.isError).toBe(false);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(authorizeLocalUse).toHaveBeenCalledWith(expect.objectContaining({ auditMetadata: { enforcementOptOuts: ['unclassified_broker_calls'] } }));
  });
});

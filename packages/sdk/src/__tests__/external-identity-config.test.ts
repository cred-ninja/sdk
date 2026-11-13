import { describe, it, expect, vi, afterEach } from 'vitest';
import { Cred } from '../cred.js';

afterEach(() => { vi.restoreAllMocks(); });

describe('cloud mode authenticated by an external identity', () => {
  it('sends the headers authenticateRequest returns, and no agent token', async () => {
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ providers: [] }), {
      status: 200, headers: { 'content-type': 'application/json' },
    }));
    const seen: Array<{ method: string; url: string }> = [];
    const cred = new Cred({
      baseUrl: 'https://cred.example.com',
      authenticateRequest: (r) => { seen.push(r); return { 'Workload-Identity-Token': 'wit', Authorization: 'WPT wpt' }; },
    });
    await cred.listProviders();
    const headers = fetch.mock.calls[0]![1]!.headers as Record<string, string>;
    expect(headers['Authorization']).toBe('WPT wpt');
    expect(headers['Workload-Identity-Token']).toBe('wit');
    expect(seen).toEqual([{ method: 'GET', url: 'https://cred.example.com/api/v1/providers' }]);
  });

  it('refuses a config with both an agent token and authenticateRequest, or with neither', () => {
    expect(() => new Cred({ baseUrl: 'https://cred.example.com', agentToken: 'cred_at_x', authenticateRequest: () => ({}) } as any)).toThrow(/not both/);
    expect(() => new Cred({ baseUrl: 'https://cred.example.com' } as any)).toThrow(/agentToken is required/);
    // Control: the agent token alone still works as before.
    expect(() => new Cred({ baseUrl: 'https://cred.example.com', agentToken: 'cred_at_x' })).not.toThrow();
  });
});

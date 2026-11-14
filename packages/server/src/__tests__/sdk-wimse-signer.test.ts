/**
 * The SDK as a WIMSE workload: `createWimseHttpSigner` on the `signRequest`
 * hook signs the exact requests the SDK sends (final headers and body), so a
 * delegation and a brokered call with a bound Txn-Token pass the real server.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import http from 'node:http';
import { Cred, createWimseHttpSigner } from '@credninja/sdk';
import { CALENDAR, cleanupDirs, trustDomain, txnIssuer, wimseServer } from './wimse-fixture.js';

const servers: http.Server[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const s of servers.splice(0)) {
    s.closeAllConnections();
    await new Promise((r) => s.close(r));
  }
  cleanupDirs();
});

async function freePort(): Promise<number> {
  const s = http.createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()));
  const { port } = s.address() as { port: number };
  await new Promise((r) => s.close(r));
  return port;
}

async function listening(opts: { txn?: boolean } = {}) {
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const b = trustDomain('domain-b.example');
  const w = b.workload();
  const tts = txnIssuer('domain-b.example');
  const s = await wimseServer({
    domains: [b], mapSubject: () => w.subject,
    config: { redirectBaseUri: baseUrl },
    ...(opts.txn ? { txnTokens: { 'domain-b.example': tts.trust() } } : {}),
  });
  const server = http.createServer(s.app);
  servers.push(server);
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', () => r()));
  return { ...s, baseUrl, w, tts };
}

function providerOnly() {
  const real = globalThis.fetch;
  const seen: Array<Record<string, string>> = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: any, init: any) => {
    const url = String(input instanceof Request ? input.url : input);
    if (!url.startsWith('https://www.googleapis.com/')) return real(input, init);
    seen.push(Object.fromEntries(Object.entries(init?.headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)])));
    return new Response('{"items":[]}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
  return seen;
}

describe('SDK signRequest with createWimseHttpSigner', () => {
  it('delegates and makes a brokered call with a bound Txn-Token, end to end', async () => {
    const s = await listening({ txn: true });
    const seen = providerOnly();
    let txn = s.tts.mint();
    const cred = new Cred({
      baseUrl: s.baseUrl,
      signRequest: createWimseHttpSigner({ wit: s.w.wit, privateKey: s.w.key.privateKey, alg: 'ES256', txnToken: () => txn }),
    });
    const agentIdentity = s.agent;
    const minted = await cred.delegateHandle({ service: 'google', userId: 'default', appClientId: 'local', scopes: ['calendar.readonly'], agentIdentity });
    txn = s.tts.mint();
    const used = await cred.use({ token: minted.token, url: CALENDAR, method: 'GET', agentIdentity });
    expect(used.status).toBe(200);
    expect(seen).toHaveLength(1);
    expect(Object.keys(seen[0])).not.toContain('txn-token');
  });

  it('without the hook the same agent is refused (the Txn-Token requirement holds)', async () => {
    const s = await listening({ txn: true });
    const cred = new Cred({ baseUrl: s.baseUrl, authenticateRequest: () => ({ 'workload-identity-token': s.w.wit }) });
    await expect(cred.delegateHandle({ service: 'google', userId: 'default', appClientId: 'local', scopes: ['calendar.readonly'], agentIdentity: s.agent }))
      .rejects.toThrow();
  });

  it('surfaces a refused signature as CredError code wimse-signature-invalid (RFC 9457 problem type)', async () => {
    const s = await listening();
    const cred = new Cred({
      baseUrl: s.baseUrl,
      signRequest: createWimseHttpSigner({ wit: s.w.wit, privateKey: s.w.key.privateKey, alg: 'ES256', audience: () => 'https://other.example/api' }),
    });
    await expect(cred.delegateHandle({ service: 'google', userId: 'default', appClientId: 'local', scopes: ['calendar.readonly'], agentIdentity: s.agent }))
      .rejects.toMatchObject({ code: 'wimse-signature-invalid', statusCode: 400 });
  });

  it('refuses a config that combines signRequest with webBotAuth or the agent token', async () => {
    const signRequest = createWimseHttpSigner({ wit: 'a.b.c', privateKey: (await import('node:crypto')).generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey, alg: 'ES256' });
    expect(() => new Cred({ baseUrl: 'http://127.0.0.1:1', agentToken: 'x', signRequest } as any)).toThrow(/not both/);
    expect(() => createWimseHttpSigner({ wit: 'a.b.c', privateKey: undefined as any, alg: 'ES256', lifetimeSec: 301 })).toThrow(/1 to 300/);
    expect(() => new Cred({ baseUrl: 'http://127.0.0.1:1', signRequest, webBotAuth: { privateKey: 'k', keyId: 'k', signatureAgent: 'https://a', ttlSeconds: 60 } } as any)).toThrow(/webBotAuth/);
  });
});

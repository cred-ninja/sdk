/**
 * Transaction Tokens on the final hop, through the real WIMSE source and
 * server: bound to the workload's proof, verified against the trust domain's
 * configuration, narrowing the authority of brokered calls, recorded in the
 * audit trail, and never sent to the provider.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import { createDpopProof } from '@credninja/sdk';
import { CredGuard, type CredPolicy } from '@credninja/guard';
import {
  ADMIN, BASE, BEARER, CALENDAR, cleanupDirs, delegateWithHttpSig, httpSigHeaders, send, sha256b64url, trustDomain, txnIssuer, useWithHttpSig, wimseServer, wptHeaders,
} from './wimse-fixture.js';
import { actorTokenFor, newAgent } from './token-helpers.js';

afterEach(() => {
  vi.restoreAllMocks();
  cleanupDirs();
});

const TD = 'domain-b.example';

async function setup(opts: { scopes?: string[]; required?: boolean; config?: Record<string, unknown>; userSubject?: null } = {}) {
  const b = trustDomain(TD);
  const w = b.workload();
  const tts = txnIssuer(TD);
  const trust = tts.trust({
    ...(opts.required === false ? { required: false } : {}),
    ...(opts.userSubject === null ? { userSubject: undefined } : {}),
  });
  const s = await wimseServer({ domains: [b], mapSubject: () => w.subject, txnTokens: { [TD]: trust }, scopes: opts.scopes, config: opts.config });
  return { b, w, tts, ...s };
}

function provider() {
  const seen: Array<{ method: string; url: string; headers: Record<string, string> }> = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any, init: any) => {
    seen.push({ method: init?.method ?? 'GET', url: String(url), headers: Object.fromEntries(Object.entries(init?.headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)])) });
    return new Response('{"items":[]}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
  return seen;
}

/** Audit events as GET /admin/audit returns them: outcome and details under metadata. */
async function auditFor(app: any) {
  const res = await request(app).get('/admin/audit?limit=200').set('Authorization', `Bearer ${ADMIN}`);
  return (res.body.entries as Array<{ action: string; metadata?: { outcome?: string; details?: Record<string, unknown> } }>)
    .map((e) => ({ action: e.action, outcome: e.metadata?.outcome, metadata: e.metadata?.details }));
}

/** Delegate with WIT + HTTP-sig and a bound Txn-Token, then return the Delegation Token. */
async function delegated(s: Awaited<ReturnType<typeof setup>>, txnClaims: Record<string, unknown> = {}, scopes = ['calendar.readonly']) {
  const txn = s.tts.mint(txnClaims);
  const minted = await delegateWithHttpSig(s.app, s.agent, s.w, { scopes }, { 'txn-token': txn });
  expect(minted.status, JSON.stringify(minted.body)).toBe(200);
  return minted.body.access_token as string;
}

describe('binding: a Txn-Token rides only on the proof that covers it', () => {
  it('WPT with a matching tth is accepted on an agent route', async () => {
    const s = await setup();
    const txn = s.tts.mint();
    const json = JSON.stringify({ token_format: 'handle', agent_did: s.agent.did, service: 'google', user_id: 'default', scopes: ['calendar.readonly'] });
    const res = await send(s.app, 'post', '/api/v1/delegate', {
      ...wptHeaders(s.w, '/api/v1/delegate', { tth: sha256b64url(txn) }), 'txn-token': txn,
      dpop: createDpopProof(s.agent, 'POST', `${BASE}/api/v1/delegate`),
    }, json);
    expect(res.status).toBe(200);
  });

  it('WPT: a Txn-Token swapped after the WPT was made is refused', async () => {
    const s = await setup();
    const res = await send(s.app, 'get', '/api/v1/connections?user_id=default', {
      ...wptHeaders(s.w, '/api/v1/connections', { tth: sha256b64url(s.tts.mint()) }), 'txn-token': s.tts.mint(),
    });
    expect(res.status).toBe(401);
  });

  it('HTTP signature: a Txn-Token swapped after signing is refused, and the provider is never called', async () => {
    const s = await setup();
    const token = await delegated(s);
    const seen = provider();
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'GET' }, {
      extraHeaders: { 'txn-token': s.tts.mint() },
      tamper: (h) => { h['txn-token'] = s.tts.mint(); },
    });
    expect(res.status).toBe(400);
    expect(seen).toHaveLength(0);
  });

  it('a Txn-Token with the agent token (no workload proof) is refused as unbound', async () => {
    const s = await setup();
    const res = await request(s.app).get('/api/v1/connections?user_id=default').set('Authorization', `Bearer ${BEARER}`).set('Txn-Token', s.tts.mint());
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('txn_token_unbound');
  });

  it('with no Txn-Token configuration the header is ignored, so existing deployments are unchanged', async () => {
    const b = trustDomain(TD);
    const w = b.workload();
    const s = await wimseServer({ domains: [b], mapSubject: () => w.subject });
    const res = await request(s.app).get('/api/v1/connections?user_id=default').set('Authorization', `Bearer ${BEARER}`).set('Txn-Token', 'x.y.z');
    expect(res.status).toBe(200);
  });

  it('a workload from a domain that requires Txn-Tokens is refused without one on a credential route, and accepted with required: false', async () => {
    const json = (agentDid: string) => JSON.stringify({ token_format: 'handle', agent_did: agentDid, service: 'google', user_id: 'default', scopes: ['calendar.readonly'] });
    const strict = await setup();
    const del = (s: Awaited<ReturnType<typeof setup>>) => send(s.app, 'post', '/api/v1/delegate', {
      ...wptHeaders(s.w, '/api/v1/delegate'), dpop: createDpopProof(s.agent, 'POST', `${BASE}/api/v1/delegate`),
    }, json(s.agent.did));
    expect((await del(strict)).status).toBe(401);
    const lax = await setup({ required: false });
    expect((await del(lax)).status).toBe(200);
  });

  it('revocation and audit reads do not depend on the Txn-Token Service, even where Txn-Tokens are required', async () => {
    const s = await setup();
    expect((await send(s.app, 'get', '/api/v1/audit?user_id=default', wptHeaders(s.w, '/api/v1/audit'))).status).toBe(200);
    expect((await send(s.app, 'get', '/api/v1/connections?user_id=default', wptHeaders(s.w, '/api/v1/connections'))).status).toBe(200);
  });

  it('an anonymous request carrying only a Txn-Token writes no audit row', async () => {
    const s = await setup();
    const before = (await auditFor(s.app)).length;
    const res = await request(s.app).get('/api/v1/connections?user_id=default').set('Txn-Token', s.tts.mint());
    expect(res.status).toBe(401);
    expect((await auditFor(s.app)).length).toBe(before);
  });

  it('two Txn-Token values on one request are refused', async () => {
    const s = await setup();
    const t1 = s.tts.mint();
    const res = await send(s.app, 'get', '/api/v1/connections?user_id=default', {
      ...wptHeaders(s.w, '/api/v1/connections', { tth: sha256b64url(t1) }), 'txn-token': `${t1}, ${s.tts.mint()}`,
    });
    expect(res.status).toBe(401);
  });

  it('an agent mapped from two trust domains keeps the strictest requirement: the laxer domain cannot shed the Txn-Token', async () => {
    const b = trustDomain(TD);
    const c = trustDomain('domain-c.example');
    const wb = b.workload();
    const wc = c.workload();
    const tts = txnIssuer(TD);
    const s = await wimseServer({
      domains: [b, c],
      mapSubject: (agent) => [
        { kind: 'wimse', subject: wb.subject, agentDid: agent.did },
        { kind: 'wimse', subject: wc.subject, agentDid: agent.did },
      ],
      txnTokens: { [TD]: tts.trust() },
    });
    const minted = await delegateWithHttpSig(s.app, s.agent, wb, {}, { 'txn-token': tts.mint() });
    expect(minted.status).toBe(200);
    const seen = provider();
    // Through domain C (no Txn-Token trust), with no Txn-Token: refused.
    const viaC = await useWithHttpSig(s.app, s.agent, minted.body.access_token, wc, { url: CALENDAR, method: 'GET' });
    expect(viaC.status).toBe(400);
    const delViaC = await delegateWithHttpSig(s.app, s.agent, wc);
    expect(delViaC.status).toBe(400);
    expect(seen).toHaveLength(0);
  });

  it('a Txn-Token issued for another trust domain is refused', async () => {
    const s = await setup();
    const txn = s.tts.mint({ aud: 'domain-a.example' });
    const res = await delegateWithHttpSig(s.app, s.agent, s.w, {}, { 'txn-token': txn });
    expect(res.status).toBe(400);
  });

  it('an agent whose domain requires Txn-Tokens cannot drop its workload proof on /use', async () => {
    const s = await setup();
    const token = await delegated(s);
    const seen = provider();
    const res = await useWithHttpSig(s.app, s.agent, token, null, { url: CALENDAR, method: 'GET' });
    expect(res.status).toBe(400);
    expect(seen).toHaveLength(0);
  });
});

describe('authority only narrows', () => {
  it('a bound Txn-Token for the delegation user allows a read, and the audit line carries its txn', async () => {
    const s = await setup();
    const token = await delegated(s);
    provider();
    const txn = s.tts.mint({ txn: 'txn-read-1' });
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'GET' }, { extraHeaders: { 'txn-token': txn } });
    expect(res.status).toBe(200);
    const access = (await auditFor(s.app)).filter((e) => e.action === 'access' && e.outcome === 'success');
    expect(access.map((e) => e.metadata?.txn)).toContain('txn-read-1');
  });

  it('a write is refused when the transaction maps only to read, though the Permission and grant allow write', async () => {
    const s = await setup({ scopes: ['calendar.readonly', 'calendar.events'] });
    const token = await delegated(s, { scope: 'calendar.read calendar.write' }, ['calendar.readonly', 'calendar.events']);
    const seen = provider();
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'POST', body: { summary: 'x' } }, {
      extraHeaders: { 'txn-token': s.tts.mint({ txn: 'txn-write-1', scope: 'calendar.read' }) },
    });
    expect(res.status).toBe(403);
    expect(seen).toHaveLength(0);
    // The refusal is recorded under the same transaction id.
    const denied = (await auditFor(s.app)).filter((e) => e.outcome === 'denied');
    expect(denied.map((e) => e.metadata?.txn)).toContain('txn-write-1');
  });

  it('a Txn-Token scope with no mapping is refused', async () => {
    const s = await setup();
    const token = await delegated(s);
    provider();
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'GET' }, { extraHeaders: { 'txn-token': s.tts.mint({ scope: 'payments.send' }) } });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_scope_unmapped');
  });

  it('an autonomous transaction (no user subject) cannot use a user-delegated credential', async () => {
    const s = await setup();
    const token = await delegated(s);
    const seen = provider();
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'GET' }, { extraHeaders: { 'txn-token': s.tts.mint({ sub: 'workload:nightly-batch' }) } });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_autonomous');
    expect(seen).toHaveLength(0);
    // Nor obtain one.
    const del = await delegateWithHttpSig(s.app, s.agent, s.w, {}, { 'txn-token': s.tts.mint({ sub: 'workload:nightly-batch' }) });
    expect(del.status).toBe(403);
  });

  it("a transaction for another user than the delegation's is refused", async () => {
    const s = await setup();
    const token = await delegated(s);
    provider();
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'GET' }, { extraHeaders: { 'txn-token': s.tts.mint({ sub: 'user:mallory' }) } });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_user_mismatch');
  });

  it('an agent whose domain requires Txn-Tokens cannot obtain a delegation with the agent token instead', async () => {
    const s = await setup();
    const res = await request(s.app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(s.agent, 'POST', `${BASE}/api/v1/delegate`))
      .send({ token_format: 'handle', agent_did: s.agent.did, service: 'google', user_id: 'default', scopes: ['calendar.readonly'] });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_token_required');
  });

  it('naming the agent by its record id does not get around the Txn-Token requirement', async () => {
    const s = await setup({ config: { allowRawTokens: true } });
    const record = await s.vault.getAgentByDid!(s.agent.did);
    const res = await request(s.app).post('/api/v1/delegate').set('Authorization', `Bearer ${BEARER}`)
      .set('DPoP', createDpopProof(s.agent, 'POST', `${BASE}/api/v1/delegate`))
      .send({ token_format: 'raw', agent_did: record!.id, service: 'google', user_id: 'default', scopes: ['calendar.readonly'] });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_token_required');
  });

  it('the compatibility raw-token route refuses a workload whose domain requires Txn-Tokens, and any verified Txn-Token', async () => {
    const s = await setup({ config: { allowRawTokens: true, allowAgentsWithoutPermission: true } });
    const txn = s.tts.mint();
    const seen = provider();
    const res = await send(s.app, 'get', '/api/token/google?user_id=default', {
      ...wptHeaders(s.w, '/api/token/google', { tth: sha256b64url(txn) }), 'txn-token': txn,
    });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_handle_required');
    expect(seen).toHaveLength(0);
  });

  it('an agent whose domain requires Txn-Tokens cannot sub-delegate', async () => {
    const s = await setup();
    const { createPrivateKey, sign } = await import('node:crypto');
    const seed = (await import('node:crypto')).scryptSync('test-passphrase-not-for-production', 'cred:local-receipt:v1', 32);
    const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
    const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
    const input = `${b64({ alg: 'EdDSA', typ: 'JWT' })}.${b64({ iss: BASE, iat: Math.floor(Date.now() / 1000), sub: s.agent.did, service: 'google', scopes: ['calendar.readonly'], userId: 'default', appClientId: 'local', delegationId: 'del_parent', chainDepth: 0 })}`;
    const receipt = `${input}.${sign(null, Buffer.from(input), key).toString('base64url')}`;
    const child = await newAgent();
    const res = await request(s.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${BEARER}`)
      .send({ parent_receipt: receipt, actor_token: actorTokenFor(s.agent, '/api/v1/subdelegate'), agent_did: child.did, service: 'google', user_id: 'default', scopes: ['calendar.readonly'] });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_subdelegation_refused');
  });

  it('inside a transaction only a handle is issued, never a raw provider token', async () => {
    const s = await setup({ config: { allowRawTokens: true } });
    const res = await delegateWithHttpSig(s.app, s.agent, s.w, { token_format: 'raw' }, { 'txn-token': s.tts.mint() });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_handle_required');
  });

  it('delegation in a transaction may not ask for scopes beyond what the transaction maps to', async () => {
    const s = await setup({ scopes: ['calendar.readonly', 'calendar.events'] });
    const res = await delegateWithHttpSig(s.app, s.agent, s.w, { scopes: ['calendar.events'] }, { 'txn-token': s.tts.mint({ scope: 'calendar.read' }) });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('txn_scope_exceeded');
  });
});

describe('audit context stays with its request', () => {
  it('a later request on the same keep-alive connection does not inherit the previous txn or workload', async () => {
    const http = await import('node:http');
    const s = await setup();
    const server = http.createServer(s.app);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const port = (server.address() as { port: number }).port;
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    const call = (method: string, p: string, headers: Record<string, string>, body?: string) => new Promise<number>((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, method, path: p, headers, agent }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode!)); });
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
    try {
      // Request 1: a delegation inside transaction txn-keepalive-1 (writes audit with txn and workload).
      const json = JSON.stringify({ token_format: 'handle', agent_did: s.agent.did, service: 'google', user_id: 'default', scopes: ['calendar.readonly'] });
      const { httpSigHeaders } = await import('./wimse-fixture.js');
      const txn = s.tts.mint({ txn: 'txn-keepalive-1' });
      const h1 = httpSigHeaders(s.w, 'POST', '/api/v1/delegate', { body: json, headers: { 'content-type': 'application/json', 'txn-token': txn } });
      // The fixture signs for BASE; this server listens elsewhere, so sign for its real audience.
      const real = (await import('../identity/http-signature.js')).signWimseRequest({
        method: 'POST', path: '/api/v1/delegate', headers: { 'content-type': 'application/json', 'txn-token': txn }, body: Buffer.from(json),
        wit: s.w.wit, privateKey: s.w.key.privateKey, alg: 'ES256', audience: `${BASE}/api/v1/delegate`,
      });
      void h1;
      const status1 = await call('POST', '/api/v1/delegate', { ...real, dpop: createDpopProof(s.agent, 'POST', `${BASE}/api/v1/delegate`), 'content-length': String(Buffer.byteLength(json)) }, json);
      expect(status1).toBe(200);
      // Request 2, same socket: a refused, unauthenticated request (writes a deny event).
      const status2 = await call('GET', '/api/v1/connections?user_id=default', { 'workload-identity-token': 'not.a.wit' });
      expect(status2).toBeGreaterThanOrEqual(400);
      const events = await auditFor(s.app);
      const deny = events.filter((e) => e.action === 'deny');
      expect(events.some((e) => e.metadata?.txn === 'txn-keepalive-1')).toBe(true);
      expect(deny.length).toBeGreaterThan(0);
      for (const e of deny) {
        expect(e.metadata?.txn).toBeUndefined();
        expect(e.metadata?.workload).toBeUndefined();
      }
    } finally {
      agent.destroy();
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    }
  });

  it('a refusal summary written later keeps the transaction of the requests it summarises', async () => {
    const s = await setup();
    const token = await delegated(s);
    provider();
    for (let i = 0; i < 3; i++) {
      const r = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'GET' }, { extraHeaders: { 'txn-token': s.tts.mint({ txn: 'txn-agg-1', scope: 'payments.send' }) } });
      expect(r.status).toBe(403);
    }
    // Flushed outside any request: the summary must not lose (or borrow) a txn.
    s.flushAuditAggregates();
    const rows = (await auditFor(s.app)).filter((e) => e.metadata?.aggregated);
    expect(rows.length).toBeGreaterThan(0);
    for (const e of rows) expect(e.metadata?.txn).toBe('txn-agg-1');
  });

  it('a receipt minted inside a transaction carries its txn, and one minted outside carries none', async () => {
    const s = await setup({ required: false });
    const inside = await delegateWithHttpSig(s.app, s.agent, s.w, {}, { 'txn-token': s.tts.mint({ txn: 'txn-receipt-1' }) });
    const outside = await delegateWithHttpSig(s.app, s.agent, s.w);
    const claims = (r: { body: Record<string, unknown> }) => {
      const receipt = (r.body.receipt ?? r.body.delegation_receipt) as string;
      return JSON.parse(Buffer.from(receipt.split('.')[1], 'base64url').toString());
    };
    expect(inside.status).toBe(200);
    expect(claims(inside).txn).toBe('txn-receipt-1');
    // The SDK's receipt verifier still accepts it (it reads named claims only).
    const { verifyDelegationReceipt } = await import('@credninja/sdk');
    const crypto = await import('node:crypto');
    const seed = crypto.scryptSync('test-passphrase-not-for-production', 'cred:local-receipt:v1', 32);
    const key = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
    const pubHex = (crypto.createPublicKey(key).export({ format: 'der', type: 'spki' }) as Buffer).subarray(-32).toString('hex');
    const receipt = (inside.body.receipt ?? inside.body.delegation_receipt) as string;
    expect(await verifyDelegationReceipt(receipt, { expectedDid: s.agent.did, credPublicKey: pubHex })).toBe(true);
    expect(outside.status).toBe(200);
    expect(claims(outside).txn).toBeUndefined();
  });

  it('audit lines of a WIMSE-authenticated request name the workload subject', async () => {
    const s = await setup();
    await delegated(s);
    const events = await auditFor(s.app);
    const del = events.find((e) => e.action === 'delegate' && e.outcome === 'success');
    expect(del?.metadata?.workload).toMatchObject({ subject: s.w.subject, trustDomain: TD, proof: 'http-sig' });
  });
});

describe('proof and body handling on /use and form posts', () => {
  it('a WIT with a WPT on /use is refused (Authorization carries the Delegation Token, so only an HTTP signature can bind it)', async () => {
    const s = await setup();
    const token = await delegated(s);
    const seen = provider();
    const res = await useWithHttpSig(s.app, s.agent, token, null, { url: CALENDAR, method: 'GET' }, {
      extraHeaders: { 'workload-identity-token': s.w.wit, 'txn-token': s.tts.mint() },
    });
    // The WPT path refuses an Authorization that is not the WPT scheme.
    expect(res.status).toBe(401);
    expect(seen).toHaveLength(0);
  });

  it('a WIMSE-signed form-encoded request keeps its parameters and its Content-Digest is checked', async () => {
    const s = await setup({ required: false });
    const form = 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=x';
    const h = httpSigHeaders(s.w, 'POST', '/api/v1/token', { body: form, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    const ok = await send(s.app, 'post', '/api/v1/token', h, form);
    // Authenticated, and the route saw the form fields (it refuses the exchange on its own terms).
    expect(ok.body?.type).not.toBe('https://iana.org/assignments/http-problem-types#wimse-signature-invalid');
    expect(JSON.stringify(ok.body)).not.toMatch(/grant_type.*required|unsupported_grant_type/);
    const h2 = httpSigHeaders(s.w, 'POST', '/api/v1/token', { body: form, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    const bad = await send(s.app, 'post', '/api/v1/token', h2, form.replace('=x', '=y'));
    expect(bad.status).toBe(400);
    expect(bad.body.type).toBe('https://iana.org/assignments/http-problem-types#wimse-signature-invalid');
  });
});

describe('never forwarded, and checked fresh before the provider call', () => {
  it('Txn-Token, WIT, signature, DPoP and Content-Digest headers never reach the provider, even as extra_headers', async () => {
    const s = await setup();
    const token = await delegated(s);
    const seen = provider();
    const txn = s.tts.mint();
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, {
      url: CALENDAR, method: 'GET',
      extra_headers: { 'Txn-Token': txn, 'Workload-Identity-Token': s.w.wit, Signature: 'x', 'Signature-Input': 'x', DPoP: 'x', 'Content-Digest': 'x', 'X-Request-Id': 'kept' },
    }, { extraHeaders: { 'txn-token': txn } });
    expect(res.status).toBe(200);
    const names = Object.keys(seen[0].headers);
    for (const h of ['txn-token', 'workload-identity-token', 'signature', 'signature-input', 'dpop', 'content-digest']) expect(names).not.toContain(h);
    expect(names).toContain('x-request-id');
    expect(seen[0].headers.authorization).toBe('Bearer ya29.wimse');
  });

  it('an agent revoked between authorization and the provider call is refused at the fresh check', async () => {
    let revoke: (() => Promise<void>) | undefined;
    const probe: CredPolicy = {
      name: 'revoke-mid-call',
      async evaluate(ctx) {
        if (ctx.metadata?.brokered && revoke) await revoke();
        return { decision: 'ALLOW', policy: 'revoke-mid-call' };
      },
    };
    const s = await setup({ config: { guard: new CredGuard({ policies: [probe] }) } });
    const token = await delegated(s);
    const record = await s.vault.getAgentByDid!(s.agent.did);
    revoke = () => s.vault.revokeAgent(record!.id);
    const seen = provider();
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'GET' }, { extraHeaders: { 'txn-token': s.tts.mint() } });
    expect(res.status).toBe(403);
    expect(seen).toHaveLength(0);
  });

  it('an agent record that disappears between authorization and the provider call is refused at the fresh check', async () => {
    let drop: (() => void) | undefined;
    const probe: CredPolicy = {
      name: 'drop-record-mid-call',
      evaluate(ctx) {
        if (ctx.metadata?.brokered && drop) drop();
        return { decision: 'ALLOW', policy: 'drop-record-mid-call' };
      },
    };
    const s = await setup({ config: { guard: new CredGuard({ policies: [probe] }) } });
    const token = await delegated(s);
    // Storage can lose a record outside Cred's API; simulate that mid-call.
    drop = () => { (s.vault as any).getAgentByDid = async () => null; };
    const seen = provider();
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'GET' }, { extraHeaders: { 'txn-token': s.tts.mint() } });
    expect(res.status).toBe(403);
    expect(seen).toHaveLength(0);
  });

  it('a Permission narrowed between authorization and the provider call is refused at the fresh check', async () => {
    let narrow: (() => Promise<unknown>) | undefined;
    const probe: CredPolicy = {
      name: 'narrow-mid-call',
      async evaluate(ctx) {
        if (ctx.metadata?.brokered && narrow) await narrow();
        return { decision: 'ALLOW', policy: 'narrow-mid-call' };
      },
    };
    const s = await setup({ scopes: ['calendar.readonly', 'calendar.events'], config: { guard: new CredGuard({ policies: [probe] }) } });
    const token = await delegated(s, { scope: 'calendar.read calendar.write' }, ['calendar.readonly', 'calendar.events']);
    narrow = () => request(s.app).patch(`/admin/permissions/${s.permissionId}`).set('Authorization', `Bearer ${ADMIN}`).send({ allowedScopes: ['calendar.events'] });
    const seen = provider();
    const res = await useWithHttpSig(s.app, s.agent, token, s.w, { url: CALENDAR, method: 'GET' }, { extraHeaders: { 'txn-token': s.tts.mint({ scope: 'calendar.read' }) } });
    expect(res.status).toBe(403);
    expect(seen).toHaveLength(0);
  });
});

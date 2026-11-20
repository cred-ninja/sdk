/**
 * WIT + HTTP signature (draft-ietf-wimse-http-signature-08) through the real
 * WIMSE source and server: accepted wherever WIT + WPT is, refused with one
 * undifferentiated 400 problem, and on /api/v1/use bound to the Delegation
 * Token through the covered Authorization header.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import crypto from 'node:crypto';
import { WIMSE_PROBLEM_TYPES } from '../identity/http-signature.js';
import {
  BASE, BEARER, CALENDAR, cleanupDirs, delegateWithHttpSig, httpSigHeaders, send, trustDomain, useWithHttpSig, wimseServer, wptHeaders,
} from './wimse-fixture.js';
import { newAgent } from './token-helpers.js';

afterEach(() => {
  vi.restoreAllMocks();
  cleanupDirs();
});

const CONN = '/api/v1/connections?user_id=default';
const PROBLEM = { type: WIMSE_PROBLEM_TYPES.signatureInvalid, title: 'Workload authentication failed', status: 400 };

async function domainB(config = {}) {
  const b = trustDomain('domain-b.example');
  const w = b.workload();
  const s = await wimseServer({ domains: [b], mapSubject: () => w.subject, config });
  return { b, w, ...s };
}

function mockProvider() {
  const seen: Array<{ url: string; headers: Record<string, string> }> = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any, init: any) => {
    seen.push({ url: String(url), headers: Object.fromEntries(Object.entries(init?.headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)])) });
    return new Response('{"items":[]}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
  return seen;
}

describe('WIT + HTTP signature on agent routes', () => {
  it('a mapped workload reaches an agent route with no agent token', async () => {
    const { app, w } = await domainB();
    const res = await send(app, 'get', CONN, httpSigHeaders(w, 'GET', CONN));
    expect(res.status).toBe(200);
  });

  it('a WIT with no proof of possession is refused', async () => {
    const { app, w } = await domainB();
    const res = await send(app, 'get', CONN, { 'workload-identity-token': w.wit });
    expect(res.status).toBe(401);
  });

  it('a WIT with both a WPT and an HTTP signature is refused', async () => {
    const { app, w } = await domainB();
    const sig = httpSigHeaders(w, 'GET', CONN);
    const res = await send(app, 'get', CONN, { ...sig, authorization: wptHeaders(w, '/api/v1/connections').authorization });
    expect(res.status).not.toBe(200);
  });

  it('a replayed signed request is refused the second time', async () => {
    const { app, w } = await domainB();
    const h = httpSigHeaders(w, 'GET', CONN);
    expect((await send(app, 'get', CONN, h)).status).toBe(200);
    const again = await send(app, 'get', CONN, h);
    expect(again.status).toBe(400);
    expect(again.body).toEqual(PROBLEM);
  });

  it('an audience other than this route is refused, and Host is never used', async () => {
    const { app, w } = await domainB();
    const wrong = await send(app, 'get', CONN, httpSigHeaders(w, 'GET', CONN, { audience: 'https://other.example/api/v1/connections' }));
    expect(wrong.status).toBe(400);
    const viaHost = await send(app, 'get', CONN, { ...httpSigHeaders(w, 'GET', CONN, { audience: 'http://evil.example/api/v1/connections' }), host: 'evil.example' });
    expect(viaHost.status).toBe(400);
  });

  it('a workload from a trust domain Cred does not trust is refused', async () => {
    const { app } = await domainB();
    const stranger = trustDomain('domain-c.example').workload();
    expect((await send(app, 'get', CONN, httpSigHeaders(stranger, 'GET', CONN))).status).toBe(400);
  });

  it('every failure gives the same 400 problem: bad WIT, bad signature and unmapped subject are indistinguishable (#419 N-17)', async () => {
    const { app, b, w } = await domainB();
    const badWit = httpSigHeaders(w, 'GET', CONN);
    badWit['workload-identity-token'] = `${w.wit.slice(0, -4)}AAAA`;
    const badSig = httpSigHeaders(w, 'GET', CONN);
    badSig.signature = badSig.signature.replace(/=:[A-Za-z0-9+/]{4}/, '=:AAAA');
    const unmapped = httpSigHeaders(b.workload('/agent/other'), 'GET', CONN);
    const bodies = [];
    for (const h of [badWit, badSig, unmapped]) {
      const res = await send(app, 'get', CONN, h);
      expect(res.status).toBe(400);
      expect(res.headers['content-type']).toMatch(/^application\/problem\+json/);
      expect(res.headers['www-authenticate']).toBeUndefined();
      bodies.push(res.text);
    }
    expect(new Set(bodies).size).toBe(1);
  });

  it('a request that requires a signed response gets 501 wimse-signed-response-unsupported, never a successful unsigned answer', async () => {
    const { app, w } = await domainB();
    const res = await send(app, 'get', CONN, httpSigHeaders(w, 'GET', CONN, { signResponse: true }));
    expect(res.status).toBe(501);
    expect(res.body.type).toBe(WIMSE_PROBLEM_TYPES.signedResponseUnsupported);
  });

  it('a signed JSON body is accepted, and one whose bytes differ from Content-Digest is refused', async () => {
    const { app, agent, w } = await domainB();
    expect((await delegateWithHttpSig(app, agent, w)).status).toBe(200);
    const json = JSON.stringify({ token_format: 'handle', agent_did: agent.did, service: 'google', user_id: 'default', scopes: ['calendar.readonly'] });
    const h = httpSigHeaders(w, 'POST', '/api/v1/delegate', { body: json, headers: { 'content-type': 'application/json' } });
    const res = await send(app, 'post', '/api/v1/delegate', h, json.replace('readonly', 'readonlx'));
    expect(res.status).toBe(400);
  });

  it('a non-JSON body is digested too: a text/plain body that does not match is refused, a matching one passes authentication', async () => {
    const { app, w } = await domainB();
    const DELEGATE = '/api/v1/delegate';
    const ok = httpSigHeaders(w, 'POST', DELEGATE, { body: 'hello', headers: { 'content-type': 'text/plain' } });
    // Authentication passes; the route then refuses the non-JSON body on its own terms.
    const passed = await send(app, 'post', DELEGATE, ok, 'hello');
    expect(passed.body.type).not.toBe(PROBLEM.type);
    const bad = httpSigHeaders(w, 'POST', DELEGATE, { body: 'hello', headers: { 'content-type': 'text/plain' } });
    const refused = await send(app, 'post', DELEGATE, bad, 'hellO');
    expect(refused.status).toBe(400);
    expect(refused.body).toEqual(PROBLEM);
  });

  it('a body with a Content-Encoding is refused (the digest would cover decoded bytes)', async () => {
    const { app, w } = await domainB();
    const h = httpSigHeaders(w, 'POST', CONN, { body: 'hello', headers: { 'content-type': 'text/plain', 'content-encoding': 'gzip' } });
    expect((await send(app, 'post', CONN, h, 'hello')).status).toBeGreaterThanOrEqual(400);
  });

  it('with Web Bot Auth optional, a WIMSE signature is not parsed as Web Bot Auth', async () => {
    const { app, w } = await domainB({ webBotAuthMode: 'optional' });
    expect((await send(app, 'get', CONN, httpSigHeaders(w, 'GET', CONN))).status).toBe(200);
  });

  it('with Web Bot Auth required, a WIMSE signature does not count as a Web Bot Auth signature (same as WPT)', async () => {
    const { app, w } = await domainB({ webBotAuthMode: 'require' });
    const sig = await send(app, 'get', CONN, httpSigHeaders(w, 'GET', CONN));
    const wpt = await send(app, 'get', CONN, wptHeaders(w, '/api/v1/connections'));
    expect(sig.status).toBe(401);
    expect(sig.body).toEqual(wpt.body);
  });

  it('warns once at startup when external identity runs with Web Bot Auth required, and not otherwise', async () => {
    const warns = (spy: ReturnType<typeof vi.spyOn>) => spy.mock.calls.filter((c) => String(c[0]).includes("webBotAuthMode is 'require' and externalIdentity")).length;
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await domainB({ webBotAuthMode: 'require' });
    expect(warns(spy)).toBe(1);
    spy.mockClear();
    await domainB({ webBotAuthMode: 'optional' });
    await domainB();
    expect(warns(spy)).toBe(0);
    spy.mockRestore();
  });

  it('a WIMSE signature mixed with another signature is refused where Web Bot Auth runs', async () => {
    const { app, w } = await domainB({ webBotAuthMode: 'optional' });
    const h = httpSigHeaders(w, 'GET', CONN);
    h['signature-input'] = `other=("@method");created=1;keyid="k";tag="web-bot-auth", ${h['signature-input']}`;
    h.signature = `other=:AAAA:, ${h.signature}`;
    expect((await send(app, 'get', CONN, h)).status).not.toBe(200);
  });
});

describe('signed responses (§3.5) when Cred has its own WIT', () => {
  async function signingServer() {
    const b = trustDomain('domain-b.example');
    const w = b.workload();
    const credWorkload = b.workload('/cred/final-hop');
    const s = await wimseServer({
      domains: [b], mapSubject: () => w.subject,
      responseSigning: { wit: credWorkload.wit, privateKey: credWorkload.key.privateKey, alg: 'ES256' },
    });
    const { verifyWimseResponseSignature } = await import('../identity/http-signature.js');
    const verify = (res: request.Response, reqHeaders: Record<string, string>, pathAndQuery: string, opts: { body?: string } = {}) => {
      const [p, q] = pathAndQuery.split('?');
      const nonce = /nonce="([^"]+)"/.exec(reqHeaders['signature-input'])![1];
      return verifyWimseResponseSignature(
        { method: 'GET', status: res.status, headers: res.headers as Record<string, string>, body: Buffer.from(opts.body ?? res.text) },
        { method: 'GET', path: p, query: q, headers: {} },
        nonce, true, { trustDomains: { [b.name]: b.anchors } },
      );
    };
    return { ...s, b, w, credWorkload, verify };
  }

  it('signs the response with its own WIT, echoing the request nonce, and the client verifies it', async () => {
    const s = await signingServer();
    const h = httpSigHeaders(s.w, 'GET', CONN, { signResponse: true });
    const res = await send(s.app, 'get', CONN, h);
    expect(res.status).toBe(200);
    expect(res.headers['workload-identity-token']).toBe(s.credWorkload.wit);
    const v = s.verify(res, h, CONN);
    expect(v?.wit.subject).toBe(s.credWorkload.subject);
    expect([...v!.covered]).toEqual(expect.arrayContaining(['@status', 'workload-identity-token', 'content-type', 'content-digest', '@method;req', '@path;req', '@query;req']));
  });

  it('a response body altered in transit fails the client check', async () => {
    const s = await signingServer();
    const h = httpSigHeaders(s.w, 'GET', CONN, { signResponse: true });
    const res = await send(s.app, 'get', CONN, h);
    const { IdentityRefusal } = await import('../identity/types.js');
    expect(() => s.verify(res, h, CONN, { body: res.text.replace('google', 'g00gle') })).toThrow(IdentityRefusal);
  });

  it('signs refusals too, so a required signed response is never an unsigned error from a route', async () => {
    const s = await signingServer();
    const p = '/api/v1/connections';
    const h = httpSigHeaders(s.w, 'GET', p, { signResponse: true });
    const res = await send(s.app, 'get', p, h);
    expect(res.status).toBe(400);
    expect(s.verify(res, h, p)).not.toBeNull();
  });

  it('adds no signature when the request did not ask for one', async () => {
    const s = await signingServer();
    const res = await send(s.app, 'get', CONN, httpSigHeaders(s.w, 'GET', CONN));
    expect(res.status).toBe(200);
    expect(res.headers.signature).toBeUndefined();
  });

  it('the event stream cannot be signed: 400 wimse-signed-response-unavailable', async () => {
    const s = await signingServer();
    const p = '/api/v1/audit/stream?user_id=default';
    const res = await send(s.app, 'get', p, httpSigHeaders(s.w, 'GET', p, { signResponse: true }));
    expect(res.status).toBe(400);
    expect(res.body.type).toBe(WIMSE_PROBLEM_TYPES.signedResponseUnavailable);
  });
});

describe('WIT + HTTP signature on /api/v1/use', () => {
  async function delegated() {
    const s = await domainB();
    const minted = await delegateWithHttpSig(s.app, s.agent, s.w);
    expect(minted.status).toBe(200);
    return { ...s, token: minted.body.access_token as string };
  }

  it('a delegated read with Delegation Token, DPoP, WIT and HTTP signature succeeds', async () => {
    const { app, agent, w, token } = await delegated();
    mockProvider();
    const res = await useWithHttpSig(app, agent, token, w, { url: CALENDAR, method: 'GET' });
    expect(res.status).toBe(200);
  });

  it('a Delegation Token swapped in after signing is refused (the signature covers Authorization)', async () => {
    const { app, agent, w, token } = await delegated();
    const other = await delegateWithHttpSig(app, agent, w);
    const fetchSpy = mockProvider();
    const res = await useWithHttpSig(app, agent, token, w, { url: CALENDAR, method: 'GET' }, {
      tamper: (h) => { h.authorization = `DPoP ${other.body.access_token}`; },
    });
    expect(res.status).toBe(400);
    expect(fetchSpy).toHaveLength(0);
  });

  it('a signature made before Authorization was added does not cover it and is refused', async () => {
    const { app, agent, w, token } = await delegated();
    const body = { url: CALENDAR, method: 'GET' };
    const json = JSON.stringify(body);
    const { createDpopProof } = await import('@credninja/sdk');
    const h = httpSigHeaders(w, 'POST', '/api/v1/use', { body: json, headers: { 'content-type': 'application/json' } });
    const res = await send(app, 'post', '/api/v1/use', {
      ...h, authorization: `DPoP ${token}`, dpop: createDpopProof(agent, 'POST', `${BASE}/api/v1/use`, token, body),
    }, json);
    expect(res.status).toBe(400);
  });

  it('a workload mapped to another agent than the Delegation Token is refused', async () => {
    const b = trustDomain('domain-b.example');
    const mine = b.workload('/agent/planner');
    const theirs = b.workload('/agent/other');
    const otherAgent = await newAgent();
    const s = await wimseServer({
      domains: [b],
      mapSubject: (agent) => [
        { kind: 'wimse', subject: mine.subject, agentDid: agent.did },
        { kind: 'wimse', subject: theirs.subject, agentDid: otherAgent.did },
      ],
    });
    const now = new Date().toISOString();
    await s.vault.registerAgent({ id: 'agt_other', did: otherAgent.did, fingerprint: crypto.randomBytes(16).toString('hex'), name: 'other', scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now });
    const minted = await delegateWithHttpSig(s.app, s.agent, mine);
    mockProvider();
    const res = await useWithHttpSig(s.app, s.agent, minted.body.access_token, theirs, { url: CALENDAR, method: 'GET' });
    expect(res.status).toBe(400);
  });

  it('without WIMSE headers /use keeps working as before (Delegation Token and DPoP only)', async () => {
    const { app, agent, token } = await delegated();
    mockProvider();
    expect((await useWithHttpSig(app, agent, token, null, { url: CALENDAR, method: 'GET' })).status).toBe(200);
  });

  it('the agent-token path is unchanged next to WIMSE configuration', async () => {
    const { app } = await domainB();
    expect((await request(app).get(CONN).set('Authorization', `Bearer ${BEARER}`)).status).toBe(200);
  });
});

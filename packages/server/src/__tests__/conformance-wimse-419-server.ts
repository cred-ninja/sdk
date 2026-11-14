/**
 * #419 behaviour cases where Cred plays the server (N-17 to N-20), probed
 * against the real server with a real WIMSE source. Each returns
 * 'conformant' only when Cred behaves as the vector's MUST clause requires.
 */
import { vi } from 'vitest';
import { WIMSE_PROBLEM_TYPES } from '../identity/http-signature.js';
import {
  CALENDAR, cleanupDirs, delegateWithHttpSig, httpSigHeaders, send, trustDomain, useWithHttpSig, wimseServer,
} from './wimse-fixture.js';

const CONN = '/api/v1/connections?user_id=default';
type Verdict = { outcome: 'conformant' | 'not conformant'; detail: string };
const verdict = (ok: boolean, detail: string): Verdict => ({ outcome: ok ? 'conformant' : 'not conformant', detail });

async function domainB() {
  const b = trustDomain('domain-b.example');
  const w = b.workload();
  const s = await wimseServer({ domains: [b], mapSubject: () => w.subject });
  return { b, w, ...s };
}

export async function serverBehaviour(id: string, _vectors: unknown): Promise<Verdict> {
  try {
    switch (id) {
      case 'N-17': {
        // §3.6: 400, one problem type, no distinction between a WIT and a signature failure.
        const { app, w } = await domainB();
        const badWit = httpSigHeaders(w, 'GET', CONN);
        badWit['workload-identity-token'] = `${w.wit.slice(0, -4)}AAAA`;
        const badSig = httpSigHeaders(w, 'GET', CONN);
        badSig.signature = badSig.signature.replace(/=:[A-Za-z0-9+/]{4}/, '=:AAAA');
        const a = await send(app, 'get', CONN, badWit);
        const b = await send(app, 'get', CONN, badSig);
        const ok = a.status === 400 && b.status === 400 && a.text === b.text
          && a.body.type === WIMSE_PROBLEM_TYPES.signatureInvalid && a.headers['www-authenticate'] === undefined;
        return verdict(ok, `WIT failure ${a.status}, signature failure ${b.status}, bodies ${a.text === b.text ? 'identical' : 'differ'}`);
      }
      case 'N-18': {
        // §3.5/§3.6: a server without response signing answers 501, never a successful unsigned response.
        const { app, w } = await domainB();
        const r = await send(app, 'get', CONN, httpSigHeaders(w, 'GET', CONN, { signResponse: true }));
        const ok = r.status === 501 && r.body.type === WIMSE_PROBLEM_TYPES.signedResponseUnsupported && !r.headers.signature;
        return verdict(ok, `wimse-sign-response gave ${r.status} ${r.body.type ?? ''}`);
      }
      case 'N-19': {
        // §3.5: Accept-Signature asking for weaker coverage never lowers what Cred does:
        // with wimse-sign-response it still refuses (501); without it no response is signed weakly.
        const { app, w } = await domainB();
        const weak = 'sig1=("@status");tag="wimse-workload-to-workload"';
        const mandated = await send(app, 'get', CONN, { ...httpSigHeaders(w, 'GET', CONN, { signResponse: true }), 'accept-signature': weak });
        const preference = await send(app, 'get', CONN, { ...httpSigHeaders(w, 'GET', CONN), 'accept-signature': weak });
        const ok = mandated.status === 501 && !mandated.headers.signature && preference.status === 200 && !preference.headers.signature;
        return verdict(ok, `with mandate ${mandated.status}; preference only ${preference.status}, unsigned (no weaker signature produced)`);
      }
      case 'N-20': {
        // §3: nothing is processed before the WIT and signature are validated. Probe: an
        // expired WIT with a valid signature on a brokered call must cause no provider call.
        const s = await domainB();
        const minted = await delegateWithHttpSig(s.app, s.agent, s.w);
        const now = Math.floor(Date.now() / 1000);
        const expired = { ...s.b.workload('/agent/planner', { iat: now - 7200, exp: now - 3600 }) };
        // Same subject and a key of its own: the signature is valid for that WIT.
        const calls: string[] = [];
        const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
          calls.push(String(url));
          return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
        });
        const r = await useWithHttpSig(s.app, s.agent, minted.body.access_token, expired, { url: CALENDAR, method: 'GET' });
        spy.mockRestore();
        const ok = r.status === 400 && calls.length === 0;
        return verdict(ok, `expired WIT with valid signature: ${r.status}, provider calls ${calls.length}`);
      }
      default:
        return verdict(false, `unknown behaviour case ${id}`);
    }
  } finally {
    cleanupDirs();
  }
}

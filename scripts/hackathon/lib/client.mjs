// An agent client in trust domain B: authenticates to Cred with its WIT plus
// a WPT (draft-ietf-wimse-wpt-02) or an HTTP signature
// (draft-ietf-wimse-http-signature-08), carrying a Txn-Token bound to that
// proof, and uses a Delegation Token with a DPoP proof on brokered calls.
import crypto from 'node:crypto';
import { sha256b64url } from './issuers.mjs';

const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');

/** The JOSE alg for a workload key: ES256 (P-256) or EdDSA (Ed25519). */
function algFor(key) {
  return key.asymmetricKeyType === 'ed25519' ? 'EdDSA' : 'ES256';
}

function signJws(header, claims, key) {
  const input = `${b64(header)}.${b64(claims)}`;
  const sig = algFor(key) === 'EdDSA'
    ? crypto.sign(null, Buffer.from(input), key)
    : crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' });
  return `${input}.${sig.toString('base64url')}`;
}

export function agentClient({ baseUrl, workload, agent, sdk, cred }) {
  const alg = algFor(workload.privateKey);
  const wpt = (pathOnly, txnToken) => {
    const now = Math.floor(Date.now() / 1000);
    return signJws({ alg, typ: 'wpt+jwt' }, {
      aud: `${baseUrl}${pathOnly}`, exp: now + 60, jti: crypto.randomBytes(16).toString('base64url'),
      wth: sha256b64url(workload.wit), ...(txnToken ? { tth: sha256b64url(txnToken) } : {}),
    }, workload.privateKey);
  };

  async function send(method, pathAndQuery, headers, body) {
    const res = await fetch(`${baseUrl}${pathAndQuery}`, { method, headers, body });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, body: json ?? text, headers: Object.fromEntries(res.headers) };
  }

  return {
    /** WIT + WPT (+ bound Txn-Token) on POST /api/v1/delegate: returns the Delegation Token response. */
    async delegateWithWpt(body, txnToken) {
      const p = '/api/v1/delegate';
      const json = JSON.stringify({ token_format: 'handle', agent_did: agent.did, service: 'google', ...body });
      return send('POST', p, {
        'content-type': 'application/json',
        'workload-identity-token': workload.wit,
        authorization: `WPT ${wpt(p, txnToken)}`,
        ...(txnToken ? { 'txn-token': txnToken } : {}),
        dpop: sdk.createDpopProof(agent.identity, 'POST', `${baseUrl}${p}`),
      }, json);
    },

    /**
     * Build a brokered call: Delegation Token + DPoP, WIT, bound Txn-Token,
     * HTTP signature over all of it (Authorization and Txn-Token covered).
     * Returns { headers, body } so a case can tamper before sending.
     */
    buildUse(token, call, txnToken, opts = {}) {
      const p = '/api/v1/use';
      const json = JSON.stringify(call);
      const headers = {
        'content-type': 'application/json',
        ...(token ? { authorization: `DPoP ${token}`, dpop: sdk.createDpopProof(agent.identity, 'POST', `${baseUrl}${p}`, token, call) } : {}),
        ...(txnToken ? { 'txn-token': txnToken } : {}),
      };
      const signed = cred.signWimseRequest({
        method: 'POST', path: p, headers, body: Buffer.from(json), wit: workload.wit,
        privateKey: workload.privateKey, alg, audience: opts.audience ?? `${baseUrl}${p}`,
      });
      return { headers: signed, body: json };
    },

    sendUse(built) {
      return send('POST', '/api/v1/use', built.headers, built.body);
    },

    /** A WIT alone, with no proof of possession, on an agent route. */
    witOnly(pathAndQuery) {
      return send('GET', pathAndQuery, { 'workload-identity-token': workload.wit });
    },
  };
}

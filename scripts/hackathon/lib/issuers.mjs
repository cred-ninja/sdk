// Local issuers for the hackathon demo: a WIT issuer per trust domain
// (draft-ietf-wimse-workload-creds-03) and a Txn-Token Service per trust
// domain (draft-ietf-oauth-transaction-tokens-11). Keys are generated at
// start; public keys are written to files that Cred then loads, the way a
// trust anchor is exchanged out of band.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');

export function es256Jws(header, claims, privateKey) {
  const input = `${b64(header)}.${b64(claims)}`;
  const sig = crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${sig.toString('base64url')}`;
}

export const sha256b64url = (s) => crypto.createHash('sha256').update(s, 'ascii').digest('base64url');

/** A WIMSE trust domain's WIT issuer. Writes `<dir>/<name>.wit-bundle.json` (a SPIFFE-style JWKS, use "wit-svid"). */
export function witIssuer(name, dir) {
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kid = `${name}-wit-1`;
  const bundlePath = path.join(dir, `${name}.wit-bundle.json`);
  fs.writeFileSync(bundlePath, JSON.stringify({
    keys: [{ ...key.publicKey.export({ format: 'jwk' }), kid, use: 'wit-svid', alg: 'ES256' }],
    spiffe_sequence: 1,
  }, null, 2));
  return {
    name,
    bundlePath,
    /** A workload with its own key pair and a WIT for `spiffe://<name><path>`. */
    workload(subPath, lifetimeSec = 3600) {
      const wkey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const now = Math.floor(Date.now() / 1000);
      const subject = `spiffe://${name}${subPath}`;
      const wit = es256Jws({ alg: 'ES256', kid, typ: 'wit+jwt' }, {
        sub: subject, iat: now, exp: now + lifetimeSec, jti: crypto.randomUUID(),
        cnf: { jwk: { ...wkey.publicKey.export({ format: 'jwk' }), alg: 'ES256' } },
      }, key.privateKey);
      return { subject, wit, privateKey: wkey.privateKey };
    },
  };
}

/** A Txn-Token Service for trust domain `aud`. Writes `<dir>/<aud>.txn-jwks.json`. */
export function txnService(aud, dir) {
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kid = `${aud}-tts-1`;
  const jwksPath = path.join(dir, `${aud}.txn-jwks.json`);
  fs.writeFileSync(jwksPath, JSON.stringify({ keys: [{ ...key.publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'ES256' }] }, null, 2));
  return {
    aud,
    jwksPath,
    mint(claims = {}) {
      const now = Math.floor(Date.now() / 1000);
      return es256Jws({ alg: 'ES256', kid, typ: 'txntoken+jwt' }, {
        iat: now, exp: now + 300, aud, txn: crypto.randomUUID(), sub: 'user:alice',
        scope: 'calendar.read', req_wl: `gateway.${aud}`, ...claims,
      }, key.privateKey);
    },
  };
}

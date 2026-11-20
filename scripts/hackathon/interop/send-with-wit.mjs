#!/usr/bin/env node
// Send one request to Cred with a WIT and private key issued by ANOTHER
// implementation, using Cred's http-signature-08 signer or a WPT.
//
//   node send-with-wit.mjs <svid.json> <url> <httpsig|wpt>
//
// svid.json: { "wit": "<compact JWS>", "key": "<base64 PKCS#8 DER>" | <JWK> }
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const { signWimseRequest } = await import(path.join(root, 'packages/server/dist/index.js'));
const [svidPath, url, mode = 'httpsig'] = process.argv.slice(2);
const svid = JSON.parse(fs.readFileSync(svidPath, 'utf8'));
const privateKey = typeof svid.key === 'string'
  ? crypto.createPrivateKey({ key: Buffer.from(svid.key, 'base64'), format: 'der', type: 'pkcs8' })
  : crypto.createPrivateKey({ key: svid.key, format: 'jwk' });
const alg = privateKey.asymmetricKeyType === 'ed25519' ? 'EdDSA' : 'ES256';
const u = new URL(url);
const audience = `${u.origin}${u.pathname}`;
let headers;
if (mode === 'wpt') {
  const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const input = `${b64({ alg, typ: 'wpt+jwt' })}.${b64({ aud: audience, exp: now + 60, jti: crypto.randomBytes(16).toString('base64url'), wth: crypto.createHash('sha256').update(svid.wit, 'ascii').digest('base64url') })}`;
  const sig = alg === 'ES256' ? crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }) : crypto.sign(null, Buffer.from(input), privateKey);
  headers = { 'workload-identity-token': svid.wit, authorization: `WPT ${input}.${sig.toString('base64url')}` };
} else {
  headers = signWimseRequest({ method: 'GET', path: u.pathname, query: u.search ? u.search.slice(1) : undefined, headers: {}, wit: svid.wit, privateKey, alg, audience });
}
const res = await fetch(url, { headers });
console.log(`request: GET ${u.pathname}${u.search} (${mode})`);
for (const [k, v] of Object.entries(headers)) console.log(`  ${k}: ${k === 'workload-identity-token' || k === 'authorization' ? `${v.slice(0, 48)}…` : v}`);
console.log(`response: ${res.status} ${await res.text()}`);

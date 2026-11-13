// Cred -> wimsey: a WIT from Cred's demo issuer and a request signed with
// Cred's http-signature-08 signer (and a WPT), printed as shell assignments
// for `wimsey httpsig verify` / `wimsey wpt verify`.
//   node cred-signed.mjs <dir> <authority> <path> <query> <aud>
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const { witIssuer, es256Jws, sha256b64url } = await import(path.join(root, 'scripts/hackathon/lib/issuers.mjs'));
const { signWimseRequest } = await import(path.join(root, 'packages/server/dist/index.js'));
const [dir, authority, p, query, aud] = process.argv.slice(2);
const issuer = witIssuer('domain-b.example', dir);
const w = issuer.workload('/ns/agents/sa/planner');
const issuerJwk = JSON.parse(fs.readFileSync(issuer.bundlePath, 'utf8')).keys[0];
fs.writeFileSync(path.join(dir, 'cred-issuer.pub.jwk'), JSON.stringify(issuerJwk));
const h = signWimseRequest({ method: 'GET', path: p, query, headers: {}, wit: w.wit, privateKey: w.privateKey, alg: 'ES256', audience: aud });
const now = Math.floor(Date.now() / 1000);
const wpt = es256Jws({ alg: 'ES256', typ: 'wpt+jwt' }, { aud, exp: now + 60, jti: crypto.randomBytes(16).toString('base64url'), wth: sha256b64url(w.wit) }, w.privateKey);
const q = (s) => `'${s.replace(/'/g, "'\\''")}'`;
console.log(`CRED_WIT=${q(w.wit)}`);
console.log(`CRED_SI=${q(h['signature-input'])}`);
console.log(`CRED_SIG=${q(h.signature)}`);
console.log(`CRED_WPT=${q(wpt)}`);

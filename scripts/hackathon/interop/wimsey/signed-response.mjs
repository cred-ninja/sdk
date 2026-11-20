// Cred signs a response (http-signature-08 §3.5) with its own WIT; this
// writes the exchange for wimsey's response-profile verifier.
//   node signed-response.mjs <outdir>
// Writes <outdir>/exchange.json, <outdir>/cred-issuer.pub.jwk and <outdir>/cred-wit.txt.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const { witIssuer } = await import(path.join(here, '../../lib/issuers.mjs'));
const { startCred } = await import(path.join(here, '../../lib/cred.mjs'));
const out = process.argv[2];
fs.mkdirSync(out, { recursive: true });
const TD = 'domain-b.example';
const issuer = witIssuer(TD, out);
const agent = issuer.workload('/ns/agents/sa/planner');
const credSelf = issuer.workload('/cred/final-hop');
const cred = await startCred({
  trustDomains: { [TD]: { witBundle: issuer.bundlePath } },
  user: 'alice',
  agents: [{ name: 'planner', workload: agent.subject, allowedScopes: ['calendar.readonly'] }],
}, { stateDir: path.join(out, 'cred'), responseSigning: { wit: credSelf.wit, privateKey: credSelf.privateKey, alg: 'ES256' } });
const p = '/api/v1/connections';
const query = 'user_id=alice';
const headers = cred.cred.signWimseRequest({
  method: 'GET', path: p, query, headers: {}, wit: agent.wit, privateKey: agent.privateKey, alg: 'ES256',
  audience: `${cred.baseUrl}${p}`, signResponse: true,
});
const res = await fetch(`${cred.baseUrl}${p}?${query}`, { headers });
const body = Buffer.from(await res.arrayBuffer());
const reqNonce = /nonce="([^"]+)"/.exec(headers['signature-input'])[1];
fs.writeFileSync(path.join(out, 'exchange.json'), JSON.stringify({
  status: res.status,
  headers: [...res.headers.entries()],
  body_b64: body.toString('base64'),
  request: { method: 'GET', path: p, query },
  req_nonce: reqNonce,
}, null, 2));
fs.writeFileSync(path.join(out, 'cred-issuer.pub.jwk'), JSON.stringify(JSON.parse(fs.readFileSync(issuer.bundlePath, 'utf8')).keys[0]));
fs.writeFileSync(path.join(out, 'cred-wit.txt'), res.headers.get('workload-identity-token') ?? '');
console.log(`request: GET ${p}?${query} with wimse-sign-response (nonce ${reqNonce})`);
console.log(`response: ${res.status}; Signature-Input: ${res.headers.get('signature-input')}`);
console.log(`response WIT is Cred's own (${credSelf.subject}): ${res.headers.get('workload-identity-token') === credSelf.wit}`);
await cred.close();

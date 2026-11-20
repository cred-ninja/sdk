#!/usr/bin/env node
// The final hop with a WIT issued by ANOTHER implementation: Cred trusts that
// issuer's bundle file, maps the WIT's subject to an agent, and the agent
// (proving its workload with that WIT and key) obtains a delegation with
// WIT + WPT and makes a delegated read with WIT + HTTP signature. Prints each
// request's outcome and the audit lines. No Txn-Tokens (the other
// implementations do not mint domain Txn-Tokens).
//
//   node final-hop.mjs <bundle.json> <trust-domain> <svid.json>
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const { startCred } = await import(path.join(here, '../lib/cred.mjs'));
const { startMockProvider } = await import(path.join(here, '../lib/mock-provider.mjs'));
const { agentClient } = await import(path.join(here, '../lib/client.mjs'));

const [bundle, td, svidPath] = process.argv.slice(2);
const svid = JSON.parse(fs.readFileSync(svidPath, 'utf8'));
const privateKey = typeof svid.key === 'string'
  ? crypto.createPrivateKey({ key: Buffer.from(svid.key, 'base64'), format: 'der', type: 'pkcs8' })
  : crypto.createPrivateKey({ key: svid.key, format: 'jwk' });
const subject = JSON.parse(Buffer.from(svid.wit.split('.')[1], 'base64url').toString()).sub;
const CALENDAR = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';

const state = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-interop-'));
const provider = await startMockProvider();
const cred = await startCred({
  trustDomains: { [td]: { witBundle: path.resolve(bundle), keyUse: 'wit-svid' } },
  user: 'alice',
  agents: [{ name: 'external-workload', workload: subject, allowedScopes: ['calendar.readonly'] }],
}, { stateDir: state });
const client = agentClient({ baseUrl: cred.baseUrl, workload: { wit: svid.wit, privateKey }, agent: cred.agents['external-workload'], sdk: cred.sdk, cred: cred.cred });

console.log(`Cred ${cred.baseUrl}; trusted ${td} from ${bundle}; ${subject} -> ${cred.agents['external-workload'].did}`);
const d = await client.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'] });
console.log(`POST /api/v1/delegate (WIT + WPT): ${d.status} ${d.body?.token_type ?? d.body?.error ?? ''}`);
let ok = d.status === 200;
if (ok) {
  const u = await client.sendUse(client.buildUse(d.body.access_token, { url: CALENDAR, method: 'GET' }));
  console.log(`POST /api/v1/use (WIT + HTTP signature + Delegation Token): ${u.status}, provider ${u.body?.status}`);
  ok = u.status === 200 && u.body?.status === 200;
}
const leaked = provider.received.flatMap((c) => Object.keys(c.headers).filter((h) => ['workload-identity-token', 'signature', 'signature-input', 'txn-token', 'dpop'].includes(h)));
console.log(`provider calls ${provider.received.length}; WIMSE headers at provider: ${leaked.length ? leaked.join(',') : 'none'}`);
const audit = await cred.admin('GET', '/admin/audit?limit=50');
console.log('audit:');
for (const e of (audit.body?.entries ?? []).slice().reverse()) {
  console.log(`  ${e.timestamp} ${e.action} ${e.metadata?.outcome} actor=${e.actor?.id} ${JSON.stringify(e.metadata?.details ?? {})}`);
}
console.log(ok && !leaked.length ? 'RESULT: PASS' : 'RESULT: FAIL');
await cred.close();
await provider.close();
fs.rmSync(state, { recursive: true, force: true });
process.exit(ok ? 0 : 1);

#!/usr/bin/env node
// The final hop with Txn-Tokens minted by ANOTHER implementation's Txn-Token
// Service. Cred trusts that service's JWKS (a file fetched out of band) for
// trust domain domain-b.example; the WIT comes from Cred's demo issuer. The
// agent binds each Txn-Token to its proof (WPT tth, HTTP signature coverage).
//
//   node txn-final-hop.mjs <tts-jwks.json> <tokens.json> <user-claim-path> <other-user-token>
//   tokens.json: [token for /delegate, token for /use, token for the swap case]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const { witIssuer } = await import(path.join(here, '../lib/issuers.mjs'));
const { startCred } = await import(path.join(here, '../lib/cred.mjs'));
const { startMockProvider } = await import(path.join(here, '../lib/mock-provider.mjs'));
const { agentClient } = await import(path.join(here, '../lib/client.mjs'));

const [jwksPath, tokensPath, userClaim, otherUserToken] = process.argv.slice(2);
const tokens = JSON.parse(fs.readFileSync(tokensPath, 'utf8'));
const txnOf = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()).txn;
const TD = 'domain-b.example';
const CALENDAR = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
const state = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-txn-interop-'));
const issuer = witIssuer(TD, state);
const w = issuer.workload('/ns/agents/sa/planner');
const provider = await startMockProvider();
const cred = await startCred({
  trustDomains: { [TD]: { witBundle: issuer.bundlePath } },
  txnTokens: { [TD]: { aud: TD, jwks: path.resolve(jwksPath), keyUse: 'sig', userSubject: { claim: userClaim }, scopeMap: { google: { 'calendar.read': ['calendar.readonly'] } } } },
  user: 'alice',
  agents: [{ name: 'planner', workload: w.subject, allowedScopes: ['calendar.readonly'] }],
}, { stateDir: path.join(state, 'cred') });
const c = agentClient({ baseUrl: cred.baseUrl, workload: w, agent: cred.agents.planner, sdk: cred.sdk, cred: cred.cred });
const results = [];
const report = (name, ok, detail) => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}: ${detail}`); };

const d = await c.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'] }, tokens[0]);
report('WIT + WPT with the external Txn-Token (tth) obtains a delegation', d.status === 200, `HTTP ${d.status} ${d.body?.error ?? d.body?.token_type ?? ''}`);
const u = await c.sendUse(c.buildUse(d.body.access_token, { url: CALENDAR, method: 'GET' }, tokens[1]));
report('WIT + HTTP signature covering the external Txn-Token makes the delegated read', u.status === 200 && u.body?.status === 200, `HTTP ${u.status}, provider ${u.body?.status}`);
const swapped = c.buildUse(d.body.access_token, { url: CALENDAR, method: 'GET' }, tokens[1]);
swapped.headers['txn-token'] = tokens[2];
const s = await c.sendUse(swapped);
report('An external Txn-Token swapped after signing is refused', s.status === 400, `HTTP ${s.status}`);
if (otherUserToken) {
  const o = await c.sendUse(c.buildUse(d.body.access_token, { url: CALENDAR, method: 'GET' }, fs.readFileSync(otherUserToken, 'utf8').trim()));
  report("An external Txn-Token for another user than the delegation's is refused", o.status === 403 && o.body?.error === 'txn_user_mismatch', `HTTP ${o.status} ${o.body?.error ?? ''}`);
}
const leaked = provider.received.flatMap((r) => Object.keys(r.headers).filter((h) => ['txn-token', 'workload-identity-token', 'signature', 'signature-input', 'dpop'].includes(h)));
report('The provider never received the Txn-Token or other WIMSE headers', provider.received.length === 1 && leaked.length === 0, `${provider.received.length} call(s), leaked: ${leaked.join(',') || 'none'}`);
const audit = await cred.admin('GET', '/admin/audit?limit=50');
const lines = (audit.body?.entries ?? []).filter((e) => e.metadata?.details?.txn).reverse();
for (const e of lines) console.log(`  audit ${e.action} ${e.metadata.outcome} txn=${e.metadata.details.txn} workload=${e.metadata.details.workload?.subject ?? '-'}`);
report('Audit lines carry the transaction ids the external service minted', [txnOf(tokens[0]), txnOf(tokens[1])].every((t) => lines.some((e) => e.metadata.details.txn === t)), `minted ${txnOf(tokens[0])}, ${txnOf(tokens[1])}`);
console.log(results.every(Boolean) ? 'RESULT: PASS' : 'RESULT: FAIL');
await cred.close();
await provider.close();
fs.rmSync(state, { recursive: true, force: true });
process.exit(results.every(Boolean) ? 0 : 1);

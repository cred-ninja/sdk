#!/usr/bin/env node
// IETF 127 hackathon, WIMSE table: Cred as the final hop in trust domain B.
//
// One command, no Docker: starts Cred configured for trust domain B, a mock
// third-party provider (not WIMSE-aware), a WIT issuer and a Txn-Token
// Service for domain B (keys generated now, trust material written to files
// and loaded by Cred from those files), plus a second trust domain A and an
// untrusted domain C for the negative cases. An agent in domain B then
// authenticates with WIT + WPT, and with WIT + HTTP signature, each carrying
// a bound Txn-Token, and every case below prints PASS or FAIL.
//
//   node scripts/hackathon/demo.mjs        (builds first if needed)
//   node scripts/hackathon/demo.mjs --keep (keep the state directory)
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
if (!fs.existsSync(path.join(root, 'packages/server/dist/index.js'))) {
  console.log('Building Cred (first run)...');
  const b = spawnSync('npm', ['run', 'build'], { cwd: root, stdio: 'inherit' });
  if (b.status !== 0) process.exit(b.status ?? 1);
}

const { witIssuer, txnService } = await import('./lib/issuers.mjs');
const { startMockProvider } = await import('./lib/mock-provider.mjs');
const { startCred } = await import('./lib/cred.mjs');
const { agentClient } = await import('./lib/client.mjs');

const TD_B = 'domain-b.example';
const TD_A = 'domain-a.example';
const TD_C = 'domain-c.example';
const CALENDAR = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
// One transaction id for the whole run: every hop logs the same txn.
const TXN = `txn-${crypto.randomUUID()}`;
const WIMSE_HEADERS = ['workload-identity-token', 'txn-token', 'signature', 'signature-input', 'content-digest', 'dpop'];

const state = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-hackathon-'));
const trustDir = path.join(state, 'trust');
fs.mkdirSync(trustDir);

const issuerB = witIssuer(TD_B, trustDir);
const ttsB = txnService(TD_B, trustDir);
const ttsA = txnService(TD_A, trustDir);
const issuerC = witIssuer(TD_C, trustDir); // never configured in Cred

const provider = await startMockProvider();
const planner = issuerB.workload('/ns/agents/sa/planner');
const stranger = issuerB.workload('/ns/agents/sa/no-delegation');

const config = {
  trustDomains: { [TD_B]: { witBundle: issuerB.bundlePath, keyUse: 'wit-svid' } },
  txnTokens: {
    [TD_B]: {
      aud: TD_B, jwks: ttsB.jwksPath, keyUse: 'sig',
      userSubject: { claim: 'sub', pattern: '^user:([a-z0-9._-]{1,64})$' },
      scopeMap: { google: { 'calendar.read': ['calendar.readonly'], 'calendar.write': ['calendar.events'] } },
    },
  },
  user: 'alice',
  connectionScopes: ['calendar.readonly', 'calendar.events'],
  agents: [
    // A read-only grant: the Permission allows calendar.readonly only.
    { name: 'planner', workload: planner.subject, allowedScopes: ['calendar.readonly'] },
    // Mapped and authenticated, but holds no delegation.
    { name: 'no-delegation', workload: stranger.subject },
  ],
};

const cred = await startCred(config, { stateDir: path.join(state, 'cred') });
const plannerClient = agentClient({ baseUrl: cred.baseUrl, workload: planner, agent: cred.agents.planner, sdk: cred.sdk, cred: cred.cred });
const strangerClient = agentClient({ baseUrl: cred.baseUrl, workload: stranger, agent: cred.agents['no-delegation'], sdk: cred.sdk, cred: cred.cred });
const txn = (claims = {}) => ttsB.mint({ txn: TXN, ...claims });

const results = [];
async function check(name, fn) {
  const before = provider.received.length;
  let ok = false;
  let detail = '';
  try {
    const r = await fn();
    ok = r.ok;
    detail = r.detail;
  } catch (err) {
    detail = `error: ${err.message}`;
  }
  const providerCalls = provider.received.length - before;
  results.push({ name, ok, detail, providerCalls });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}\n      ${detail}${providerCalls ? `  [provider called ${providerCalls}x]` : ''}`);
}
const refused = (r, status, noProvider = true) => ({ ok: r.status === status, detail: `HTTP ${r.status} ${typeof r.body === 'object' ? (r.body?.error ?? r.body?.type ?? '') : ''}`.trim(), noProvider });
// A refusal must never reach the provider.
async function refusal(name, fn) {
  await check(name, async () => {
    const before = provider.received.length;
    const r = await fn();
    if (provider.received.length !== before) return { ok: false, detail: `${r.detail} but the provider was called` };
    return r;
  });
}

console.log(`\nCred ${cred.baseUrl}  trust domain ${TD_B}  transaction ${TXN}`);
console.log(`Trust bundle (out of band): ${issuerB.bundlePath}`);
console.log(`Txn-Token keys (out of band): ${ttsB.jwksPath}\n`);

// ── 1. The normal delegated read ────────────────────────────────────────────
let token;
await check('WIT + WPT with a bound Txn-Token obtains a delegation (read, user alice)', async () => {
  const r = await plannerClient.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'] }, txn());
  token = r.body?.access_token;
  return { ok: r.status === 200 && typeof token === 'string', detail: `HTTP ${r.status} token_type ${r.body?.token_type ?? '-'}` };
});
let readRequest;
await check('WIT + HTTP signature with a bound Txn-Token makes the delegated read at the provider', async () => {
  readRequest = plannerClient.buildUse(token, { url: CALENDAR, method: 'GET' }, txn());
  const r = await plannerClient.sendUse(readRequest);
  return { ok: r.status === 200 && r.body?.status === 200, detail: `HTTP ${r.status}, provider ${r.body?.status}: ${JSON.stringify(r.body?.body?.items ?? [])}` };
});

// ── 2. Refusals ─────────────────────────────────────────────────────────────
await refusal('Refused: WIT without proof of possession', async () => refused(await plannerClient.witOnly('/api/v1/connections?user_id=alice'), 401));
await refusal('Refused: replayed request (same signed request sent again)', async () => refused(await plannerClient.sendUse(readRequest), 400));
await refusal('Refused: wrong audience (wimse-aud for another server)', async () => {
  const b = plannerClient.buildUse(token, { url: CALENDAR, method: 'GET' }, txn(), { audience: 'https://other-rs.domain-b.example/api/v1/use' });
  return refused(await plannerClient.sendUse(b), 400);
});
await refusal('Refused: Txn-Token swapped after signing', async () => {
  const b = plannerClient.buildUse(token, { url: CALENDAR, method: 'GET' }, txn());
  b.headers['txn-token'] = txn({ scope: 'calendar.read calendar.write' });
  return refused(await plannerClient.sendUse(b), 400);
});
await refusal('Refused: Txn-Token from another trust domain (aud domain-a)', async () => {
  const b = plannerClient.buildUse(token, { url: CALENDAR, method: 'GET' }, ttsA.mint({ txn: TXN }));
  return refused(await plannerClient.sendUse(b), 400);
});
await refusal('Refused: workload from an untrusted trust domain (domain-c)', async () => {
  const outsider = agentClient({ baseUrl: cred.baseUrl, workload: issuerC.workload('/ns/agents/sa/planner'), agent: cred.agents.planner, sdk: cred.sdk, cred: cred.cred });
  return refused(await outsider.sendUse(outsider.buildUse(token, { url: CALENDAR, method: 'GET' }, txn())), 400);
});
await refusal('Refused: autonomous identity (Txn-Token with no user) attempting a delegated action', async () => {
  const b = plannerClient.buildUse(token, { url: CALENDAR, method: 'GET' }, txn({ sub: 'workload:nightly-batch' }));
  return refused(await plannerClient.sendUse(b), 403);
});
await refusal('Refused: agent with no delegation attempting a call', async () => {
  const noToken = await strangerClient.sendUse(strangerClient.buildUse(null, { url: CALENDAR, method: 'GET' }, txn()));
  const asks = await strangerClient.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'] }, txn());
  return { ok: noToken.status === 401 && asks.status === 403, detail: `/use without a delegation: HTTP ${noToken.status} ${noToken.body?.error ?? ''}; asking for one: HTTP ${asks.status} ${asks.body?.error ?? ''}` };
});
await refusal('Refused: write under a read-only grant', async () => {
  const b = plannerClient.buildUse(token, { url: CALENDAR, method: 'POST', body: { summary: 'not allowed' } }, txn({ scope: 'calendar.read calendar.write' }));
  return refused(await plannerClient.sendUse(b), 403);
});
await refusal('Refused: revocation between authorization and use', async () => {
  const fresh = await plannerClient.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'] }, txn());
  const jti = JSON.parse(Buffer.from(fresh.body.access_token.split('.')[1], 'base64url').toString()).jti;
  const revoke = await fetch(`${cred.baseUrl}/api/v1/delegations/${jti}?user_id=alice`, { method: 'DELETE', headers: { authorization: `Bearer ${cred.agentToken}` } });
  const r = await plannerClient.sendUse(plannerClient.buildUse(fresh.body.access_token, { url: CALENDAR, method: 'GET' }, txn()));
  return { ok: fresh.status === 200 && revoke.status === 200 && r.status === 401, detail: `delegated ${fresh.status}, revoked ${revoke.status}, then use: HTTP ${r.status} ${r.body?.error ?? ''}` };
});

// ── 3. What the provider saw ────────────────────────────────────────────────
await check('The provider never received a WIMSE or Txn-Token header', async () => {
  const leaked = provider.received.flatMap((c) => Object.keys(c.headers).filter((h) => WIMSE_HEADERS.includes(h)));
  const names = [...new Set(provider.received.flatMap((c) => Object.keys(c.headers)))].sort();
  return { ok: provider.received.length > 0 && leaked.length === 0, detail: `${provider.received.length} provider call(s); headers received: ${names.join(', ')}` };
});

// ── 4. One audit trail, one transaction id ──────────────────────────────────
const audit = await cred.admin('GET', '/admin/audit?limit=200');
const entries = (audit.body?.entries ?? []).slice().reverse();
const withTxn = entries.filter((e) => e.metadata?.details?.txn === TXN);
const other = entries.filter((e) => e.metadata?.details?.txn !== TXN);
await check(`Audit trail: every line recorded after a Txn-Token verified carries txn ${TXN}`, async () => ({
  ok: withTxn.length > 0 && entries.filter((e) => e.metadata?.details?.txn && e.metadata.details.txn !== TXN).length === 0,
  detail: `${withTxn.length} line(s) with this txn; ${other.length} line(s) without one (refused before the Txn-Token was verified, or setup)`,
}));
console.log(`\nAudit trail for transaction ${TXN}:`);
for (const e of withTxn) {
  const d = e.metadata?.details ?? {};
  console.log(`  ${e.timestamp}  ${e.action.padEnd(8)} ${String(e.metadata?.outcome ?? '').padEnd(8)} ${e.actor?.id?.slice(0, 32) ?? ''}…  ${d.route ?? d.method ?? ''} ${d.reason ?? d.status ?? ''}  txn=${d.txn}`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} PASS${failed.length ? `, ${failed.length} FAIL` : ''}`);
await cred.close();
await provider.close();
if (process.argv.includes('--keep')) console.log(`State kept in ${state}`);
else fs.rmSync(state, { recursive: true, force: true });
process.exit(failed.length ? 1 : 0);

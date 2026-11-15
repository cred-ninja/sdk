#!/usr/bin/env node
// IETF 127 hackathon, scenario P8 ("Final hop to a bearer-only third-party
// API", format ietf127-wimse-scenario/1), run against Cred itself.
//
// Every decision below comes from a real Cred server built from this branch,
// reached over loopback HTTP by an agent in trust domain B that authenticates
// with WIT + WPT or WIT + HTTP signature. The provider is the local mock that
// stands in for the Google Calendar API (scripts/hackathon/lib/mock-provider.mjs).
//
// Two configurations:
//   A  the hackathon configuration: WIMSE + required Txn-Tokens, brokered
//      handles only. Cases 1-3, plus case 4 as Cred runs by default: the agent
//      asks for the bearer token itself and Cred refuses to release it.
//   B  the deprecated raw-token opt-out (allowRawTokens: true, no Txn-Tokens,
//      a read-only connection, since Cred refuses a raw token wider than the grant),
//      the only Cred path that releases a provider bearer token to the agent.
//      Case 4 as the scenario states it: release, then revoke, then use the
//      token at the provider directly.
//
//   node scripts/hackathon/interop/p8.mjs [--out <dir>]
// Writes <dir>/cred-P8.jsonl and <dir>/cred-P8.manifest.json (default
// conformance/interop/p8).
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
if (!fs.existsSync(path.join(root, 'packages/server/dist/index.js'))) {
  const b = spawnSync('npm', ['run', 'build'], { cwd: root, stdio: 'inherit' });
  if (b.status !== 0) process.exit(b.status ?? 1);
}
const outIdx = process.argv.indexOf('--out');
const outDir = path.resolve(outIdx > 0 ? process.argv[outIdx + 1] : path.join(root, 'conformance/interop/p8'));

const { witIssuer, txnService } = await import('../lib/issuers.mjs');
const { startMockProvider } = await import('../lib/mock-provider.mjs');
const { startCred } = await import('../lib/cred.mjs');
const { agentClient } = await import('../lib/client.mjs');

const TD_B = 'domain-b.example';
const PROVIDER = 'google';
const CALENDAR = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
const git = (...a) => spawnSync('git', a, { cwd: root, encoding: 'utf8' }).stdout.trim();
const commit = git('rev-parse', 'HEAD');
const branch = git('rev-parse', '--abbrev-ref', 'HEAD');
const dirty = git('status', '--porcelain', '--', 'packages').length > 0;

// Cred's own reason codes, mapped once to the scenario's names (P8 "reason_mapping").
const REASON_MAP = {
  invalid_token: 'no-delegation',
  permission_required: 'no-delegation',
  scope_insufficient: 'scope-exceeded',
  delegation_revoked: 'status-revoked',
};

const lines = [];
function log(cfgName, caseName, txnId, fields) {
  const line = {
    scenario: 'P8', case: caseName, impl: 'cred', hop: 'E', domain: 'B', txn_id: txnId,
    decision: fields.decision, reason: fields.reason, ts: Math.floor(Date.now() / 1000),
    provider: PROVIDER, scopes_requested: fields.scopes_requested, token_released: fields.token_released,
    effect: fields.effect,
    cred_config: cfgName, step: fields.step, http_status: fields.http_status, cred_reason: fields.cred_reason ?? null,
    provider_calls: fields.provider_calls, clock: 'wall', cred_commit: commit,
  };
  lines.push(line);
  console.log(`${line.case.padEnd(30)} ${cfgName} ${String(line.step).padEnd(22)} HTTP ${String(line.http_status).padEnd(4)} ${line.decision} ${line.reason} (cred: ${line.cred_reason ?? '-'}) released=${line.token_released} provider_calls=${line.provider_calls}`);
}
const err = (r) => (typeof r.body === 'object' && r.body ? (r.body.error ?? null) : null);
const jtiOf = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()).jti;

async function setup(cfgName, { txnRequired, serverOptions, connectionScopes = ['calendar.readonly', 'calendar.events'] }) {
  const state = fs.mkdtempSync(path.join(os.tmpdir(), `cred-p8-${cfgName}-`));
  const trustDir = path.join(state, 'trust');
  fs.mkdirSync(trustDir);
  const issuerB = witIssuer(TD_B, trustDir);
  const ttsB = txnService(TD_B, trustDir);
  const provider = await startMockProvider();
  const planner = issuerB.workload('/ns/agents/sa/planner');
  const stranger = issuerB.workload('/ns/agents/sa/no-delegation');
  const config = {
    trustDomains: { [TD_B]: { witBundle: issuerB.bundlePath, keyUse: 'wit-svid' } },
    ...(txnRequired ? {
      txnTokens: {
        [TD_B]: {
          aud: TD_B, jwks: ttsB.jwksPath, keyUse: 'sig',
          userSubject: { claim: 'sub', pattern: '^user:([a-z0-9._-]{1,64})$' },
          scopeMap: { google: { 'calendar.read': ['calendar.readonly'], 'calendar.write': ['calendar.events'] } },
        },
      },
    } : {}),
    user: 'alice',
    connectionScopes,
    agents: [
      { name: 'planner', workload: planner.subject, allowedScopes: ['calendar.readonly'] },
      { name: 'no-delegation', workload: stranger.subject },
    ],
  };
  const cred = await startCred(config, { stateDir: path.join(state, 'cred'), serverOptions });
  const mk = (w, a) => agentClient({ baseUrl: cred.baseUrl, workload: w, agent: cred.agents[a], sdk: cred.sdk, cred: cred.cred });
  return {
    cred, provider, state,
    planner: mk(planner, 'planner'), stranger: mk(stranger, 'no-delegation'),
    txn: (id, claims = {}) => (txnRequired ? ttsB.mint({ txn: id, ...claims }) : undefined),
    revoke: (jti) => fetch(`${cred.baseUrl}/api/v1/delegations/${jti}?user_id=alice`, { method: 'DELETE', headers: { authorization: `Bearer ${cred.agentToken}` } }),
    async close() { await cred.close(); await provider.close(); fs.rmSync(state, { recursive: true, force: true }); },
  };
}

// ── Configuration A: the hackathon configuration ───────────────────────────
{
  const A = await setup('A', { txnRequired: true });
  const calls = () => A.provider.received.length;

  // Case 1: no delegation.
  {
    const id = `txn-${crypto.randomUUID()}`;
    let before = calls();
    const use = await A.stranger.sendUse(A.stranger.buildUse(null, { url: CALENDAR, method: 'GET' }, A.txn(id)));
    log('A', 'no-delegation', id, { step: 'use-without-delegation', decision: use.status === 200 ? 'allow' : 'deny', reason: REASON_MAP[err(use)] ?? err(use), cred_reason: err(use), http_status: use.status, scopes_requested: ['calendar.readonly'], token_released: false, effect: calls() > before ? 'ran' : 'none', provider_calls: calls() - before });
    before = calls();
    const ask = await A.stranger.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'] }, A.txn(id));
    log('A', 'no-delegation', id, { step: 'ask-for-delegation', decision: ask.status === 200 ? 'allow' : 'deny', reason: REASON_MAP[err(ask)] ?? err(ask), cred_reason: err(ask), http_status: ask.status, scopes_requested: ['calendar.readonly'], token_released: false, effect: calls() > before ? 'ran' : 'none', provider_calls: calls() - before });
  }

  // Case 2: write under a read-only grant.
  {
    const id = `txn-${crypto.randomUUID()}`;
    const d = await A.planner.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'] }, A.txn(id));
    log('A', 'write-under-read', id, { step: 'delegate-read', decision: d.status === 200 ? 'allow' : 'deny', reason: d.status === 200 ? 'ok' : err(d), cred_reason: err(d), http_status: d.status, scopes_requested: ['calendar.readonly'], token_released: false, effect: 'none', provider_calls: 0 });
    const before = calls();
    const w = await A.planner.sendUse(A.planner.buildUse(d.body.access_token, { url: CALENDAR, method: 'POST', body: { summary: 'not allowed' } }, A.txn(id, { scope: 'calendar.read calendar.write' })));
    log('A', 'write-under-read', id, { step: 'write', decision: w.status === 200 ? 'allow' : 'deny', reason: REASON_MAP[err(w)] ?? err(w), cred_reason: err(w), http_status: w.status, scopes_requested: ['calendar.readonly', 'calendar.events'], token_released: false, effect: calls() > before ? 'ran' : 'none', provider_calls: calls() - before });
  }

  // Case 3: revoked between authorization and use.
  {
    const id = `txn-${crypto.randomUUID()}`;
    const d = await A.planner.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'] }, A.txn(id));
    log('A', 'revoked-between-authz-and-use', id, { step: 'delegate-read', decision: d.status === 200 ? 'allow' : 'deny', reason: d.status === 200 ? 'ok' : err(d), cred_reason: err(d), http_status: d.status, scopes_requested: ['calendar.readonly'], token_released: false, effect: 'none', provider_calls: 0 });
    const rv = await A.revoke(jtiOf(d.body.access_token));
    log('A', 'revoked-between-authz-and-use', id, { step: 'revoke', decision: rv.status === 200 ? 'revocation recorded' : 'revoke failed', reason: rv.status === 200 ? 'ok' : `revoke-${rv.status}`, http_status: rv.status, scopes_requested: ['calendar.readonly'], token_released: false, effect: 'none', provider_calls: 0 });
    const before = calls();
    const u = await A.planner.sendUse(A.planner.buildUse(d.body.access_token, { url: CALENDAR, method: 'GET' }, A.txn(id)));
    log('A', 'revoked-between-authz-and-use', id, { step: 'use-after-revoke', decision: u.status === 200 ? 'allow' : 'deny', reason: REASON_MAP[err(u)] ?? err(u), cred_reason: err(u), http_status: u.status, scopes_requested: ['calendar.readonly'], token_released: false, effect: calls() > before ? 'ran' : 'none', provider_calls: calls() - before });
  }

  // Case 4 under the default configuration: the agent asks for the bearer token itself.
  {
    const id = `txn-${crypto.randomUUID()}`;
    const before = calls();
    const raw = await A.planner.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'], token_format: 'raw' }, A.txn(id));
    const released = raw.status === 200 && typeof raw.body?.access_token === 'string';
    log('A', 'revoked-after-token-released', id, { step: 'ask-for-bearer-token', decision: released ? 'allow' : 'deny', reason: released ? 'token-released' : 'token-not-released', cred_reason: err(raw), http_status: raw.status, scopes_requested: ['calendar.readonly'], token_released: released, effect: calls() > before ? 'ran' : 'none', provider_calls: calls() - before });
  }
  await A.close();
}

// ── Configuration B: the deprecated raw-token opt-out ──────────────────────
{
  const B = await setup('B', { txnRequired: false, serverOptions: { allowRawTokens: true }, connectionScopes: ['calendar.readonly'] });
  const calls = () => B.provider.received.length;
  const id = `txn-${crypto.randomUUID()}`;
  const raw = await B.planner.delegateWithWpt({ user_id: 'alice', scopes: ['calendar.readonly'], token_format: 'raw' }, undefined);
  const bearer = raw.body?.access_token;
  const released = raw.status === 200 && typeof bearer === 'string';
  log('B', 'revoked-after-token-released', id, { step: 'release-bearer-token', decision: released ? 'allow' : 'deny', reason: released ? 'token-released' : (err(raw) ?? 'unexpected'), cred_reason: err(raw), http_status: raw.status, scopes_requested: ['calendar.readonly'], token_released: released, effect: 'none', provider_calls: 0 });
  if (released) {
    const delegationId = raw.body?.delegation_id ?? raw.body?.jti ?? null;
    let rvStatus = null;
    if (delegationId) rvStatus = (await B.revoke(delegationId)).status;
    log('B', 'revoked-after-token-released', id, { step: 'revoke', decision: rvStatus === 200 ? 'revocation recorded, token already released' : 'revoke failed', reason: rvStatus === 200 ? 'token-released' : `revoke-${rvStatus}`, http_status: rvStatus, scopes_requested: ['calendar.readonly'], token_released: true, effect: 'none', provider_calls: 0 });
    // The agent now goes to the provider directly with the bearer token it holds.
    const before = calls();
    const direct = await fetch(CALENDAR, { headers: { authorization: `Bearer ${bearer}` } });
    log('B', 'revoked-after-token-released', id, { step: 'direct-provider-call', decision: direct.status === 200 ? 'effect occurred at provider' : 'provider refused', reason: 'token-released', cred_reason: null, http_status: direct.status, scopes_requested: ['calendar.readonly'], token_released: true, effect: direct.status === 200 ? 'ran' : 'none', provider_calls: calls() - before });
  }
  await B.close();
}

// ── Output ─────────────────────────────────────────────────────────────────
fs.mkdirSync(outDir, { recursive: true });
const jsonl = path.join(outDir, 'cred-P8.jsonl');
fs.writeFileSync(jsonl, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const manifest = {
  scenario: 'P8', format: 'ietf127-wimse-scenario/1', impl: 'cred',
  repository: 'https://github.com/cred-ninja/sdk', branch, commit, packages_src_modified: dirty,
  packages_note: 'packages_src_modified checks git status of packages/ only; the runner builds dist only when it is missing, so run npm run build first to be sure dist matches the source.',
  node: process.version, run_at_utc: new Date().toISOString(), clock: 'wall',
  reproduce: `git clone -b ${branch} https://github.com/cred-ninja/sdk.git cred && cd cred && git checkout ${commit} && npm ci && npm run build && node scripts/hackathon/interop/p8.mjs`,
  provider_note: 'The provider is a local mock of the Google Calendar API that accepts any bearer token (scripts/hackathon/lib/mock-provider.mjs). It cannot introspect or revoke, which is the bearer-only property P8 is about.',
  configurations: {
    A: 'hackathon configuration: WIMSE (WIT + WPT / HTTP signature) with required Txn-Tokens for domain-b.example; brokered handles only (default)',
    B: 'deprecated opt-out allowRawTokens: true, WIMSE without Txn-Tokens, read-only connection (Cred refuses a raw token wider than the grant); the only Cred path that releases the provider bearer token to the agent',
  },
  txn_id_note: 'In A, txn_id is the txn claim of the Txn-Tokens Cred verified for that case. In B there is no Txn-Token; txn_id is a label from this runner only.',
  reason_mapping: REASON_MAP,
  reason_mapping_note: 'Partial: covers the Cred codes this run produced. Cred returns invalid_token also for a forged, expired or mismatched Delegation Token, and scope_insufficient also when the Permission behind a delegation was narrowed, revoked or expired. token-not-released is this runner\'s name for Cred\'s 403 raw_token_disabled; it is not a scenario reason.',
  checker_note: 'Not verified by observes_p1_p8.py. Cred answers with its own HTTP statuses and {error, message} bodies: 401 for no-delegation (use) and status-revoked, 403 for scope-exceeded and for no-delegation (ask), 403 raw_token_disabled for case 4 under configuration A.',
  files: { 'cred-P8.jsonl': { lines: lines.length, sha256: sha(jsonl) } },
};
fs.writeFileSync(path.join(outDir, 'cred-P8.manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`\nWrote ${lines.length} lines to ${jsonl}`);
process.exit(0);

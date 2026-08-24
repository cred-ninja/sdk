/**
 * End-to-end demo: scope, argument policy, mandatory proof-of-possession, and
 * the resulting audit trail.
 *
 * Runs in-process against a mock x64dbg upstream, so it needs no Windows host
 * and finishes in a few seconds. It doubles as a smoke test: every expectation
 * is asserted, and a failed assertion exits non-zero.
 *
 * Run: npx tsx demo/demo.ts     (from the example directory)
 */

import net from 'node:net';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateAgentIdentity } from '@credninja/sdk';
import { loadConfig } from '../src/config.js';
import { startProxy } from '../src/proxy.js';
import { createMockServer } from './mock-x64dbg.js';
import { generateIssuerKeypairHex, mintReceipt, signPop } from './mint-receipt.js';

const SCOPE_MAP = fileURLToPath(new URL('../config/scope-map.json', import.meta.url));
const AUDIT_FILE = join(tmpdir(), `x64dbg-proxy-audit-${process.pid}.log`);

let failures = 0;
function check(label: string, ok: boolean, detail = ''): void {
  const mark = ok ? 'PASS' : 'FAIL';
  if (!ok) failures++;
  console.log(`  [${mark}] ${label}${detail ? ` -- ${detail}` : ''}`);
}

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}

function listen(server: http.Server, port: number, host = '127.0.0.1'): Promise<void> {
  return new Promise((resolve) => server.listen(port, host, () => resolve()));
}

interface RpcResponse {
  status: number;
  body: any;
}

interface RpcOpts {
  receipt?: string;
  /** did:key private key hex to sign the PoP with (defaults to the credential holder). */
  signKey?: string;
  /** Send this exact PoP proof instead of signing a fresh one (for replay tests). */
  pop?: string;
  /** Send no PoP header at all. */
  omitPop?: boolean;
}

async function rpc(port: number, message: unknown, opts: RpcOpts = {}): Promise<RpcResponse & { pop?: string }> {
  const bodyStr = JSON.stringify(message);
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (opts.receipt) headers['authorization'] = `Bearer ${opts.receipt}`;
  let pop = opts.pop;
  if (!pop && !opts.omitPop && opts.receipt && opts.signKey) {
    pop = signPop({ privateKeyHex: opts.signKey, method: 'POST', path: '/', receipt: opts.receipt, body: bodyStr });
  }
  if (pop) headers['x64dbg-pop'] = pop;
  const res = await fetch(`http://127.0.0.1:${port}/`, { method: 'POST', headers, body: bodyStr });
  const text = await res.text();
  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, body, pop };
}

async function sseUntilClose(
  port: number,
  receipt: string,
  signKey: string,
  safetyMs: number,
): Promise<{ closedMs: number; timedOut: boolean }> {
  const controller = new AbortController();
  const started = Date.now();
  const pop = signPop({ privateKeyHex: signKey, method: 'GET', path: '/sse', receipt });
  const res = await fetch(`http://127.0.0.1:${port}/sse`, {
    headers: { authorization: `Bearer ${receipt}`, 'x64dbg-pop': pop },
    signal: controller.signal,
  });
  if (!res.body) return { closedMs: Date.now() - started, timedOut: false };
  const reader = res.body.getReader();
  const safety = setTimeout(() => controller.abort(), safetyMs);
  let timedOut = false;
  try {
    for (;;) {
      const { done } = await reader.read();
      if (done) break;
    }
  } catch {
    timedOut = true;
  } finally {
    clearTimeout(safety);
  }
  return { closedMs: Date.now() - started, timedOut };
}

function banner(title: string): void {
  console.log(`\n=== ${title} ===`);
}

const call = (name: string, args: Record<string, unknown> = {}, id = 1) => ({
  jsonrpc: '2.0',
  id,
  method: 'tools/call',
  params: { name, arguments: args },
});

async function main(): Promise<void> {
  const issuer = generateIssuerKeypairHex();
  // A read-only analyst and an incident responder (read + on-disk memory capture).
  const analyst = await generateAgentIdentity({ scopeCeiling: ['x64dbg:read'] });
  const responder = await generateAgentIdentity({ scopeCeiling: ['x64dbg:read', 'x64dbg:exfil'] });
  const attacker = await generateAgentIdentity();
  const analystKey = analyst.export().privateKeyHex;
  const responderKey = responder.export().privateKeyHex;
  const attackerKey = attacker.export().privateKeyHex;

  const mockPort = await getFreePort();
  const proxyPort = await getFreePort();
  const mock = createMockServer();
  await listen(mock, mockPort);

  const cfg = loadConfig({
    X64DBG_UPSTREAM_URL: `http://127.0.0.1:${mockPort}`,
    X64DBG_ISSUER_PUBLIC_KEY_HEX: issuer.publicKeyHex,
    X64DBG_LISTEN_HOST: '127.0.0.1',
    X64DBG_LISTEN_PORT: String(proxyPort),
    X64DBG_SCOPE_MAP: SCOPE_MAP,
    X64DBG_AUDIT_LOG: AUDIT_FILE,
    X64DBG_AUDIT_STDOUT: 'false',
    X64DBG_SSE_ON_EXPIRY: 'terminate',
  });
  const proxy = startProxy(cfg);
  await new Promise((r) => setTimeout(r, 150));

  const readReceipt = mintReceipt({ privateKeyHex: issuer.privateKeyHex, subject: analyst.did, scopes: ['x64dbg:read'], ttlSeconds: 300, delegationId: 'demo-analyst' });
  const exfilReceipt = mintReceipt({ privateKeyHex: issuer.privateKeyHex, subject: responder.did, scopes: ['x64dbg:read', 'x64dbg:exfil'], ttlSeconds: 300, delegationId: 'demo-responder' });
  const shortReceipt = mintReceipt({ privateKeyHex: issuer.privateKeyHex, subject: analyst.did, scopes: ['x64dbg:read'], ttlSeconds: 2, delegationId: 'demo-sse' });

  console.log(`Analyst DID (subject): ${analyst.did}`);
  console.log(`Granted: analyst=[x64dbg:read]  responder=[x64dbg:read, x64dbg:exfil]`);
  console.log(`Audit log: ${AUDIT_FILE}`);

  // --- ALLOW: a bounded read the analyst is entitled to ---
  banner('ALLOW  ReadMemory size=256 (analyst holds x64dbg:read, within arg policy)');
  {
    const r = await rpc(proxyPort, call('ReadMemory', { address: '0x7ff6a1b21044', size: 256 }), { receipt: readReceipt, signKey: analystKey });
    console.log(`  upstream said: ${r.body?.result?.content?.[0]?.text}`);
    check('forwarded and returned a result', r.status === 200 && !r.body.error && typeof r.body?.result?.content?.[0]?.text === 'string');
  }

  // --- DENY (scope): patch memory with a read-only credential ---
  banner('DENY   WriteMemToAddress (read-only credential cannot patch memory)');
  {
    const r = await rpc(proxyPort, call('WriteMemToAddress', { address: '0x7ff6a1b21044', data: '9090' }), { receipt: readReceipt, signKey: analystKey });
    console.log(`  ${r.body?.error?.message}`);
    check('scope-filter denied write', r.body?.error?.code === -32002 && r.body?.error?.data?.policy === 'scope-filter');
  }

  // --- DENY (catch-all) ---
  banner('DENY   ExecuteDebuggerCommand (catch-all, denied outright)');
  {
    const r = await rpc(proxyPort, call('ExecuteDebuggerCommand', { command: 'e rip 90' }), { receipt: readReceipt, signKey: analystKey });
    check('tool-disposition denied the catch-all', r.body?.error?.code === -32002 && r.body?.error?.data?.policy === 'tool-disposition');
  }

  // --- ARGUMENT POLICY: extent within a granted scope ---
  banner('ARG    ReadMemory size=1048576 (over the 4096-byte cap) denied by argument policy');
  {
    const r = await rpc(proxyPort, call('ReadMemory', { address: '0x0', size: 1048576 }), { receipt: readReceipt, signKey: analystKey });
    console.log(`  ${r.body?.error?.message}`);
    check('argument-policy denied oversized read', r.body?.error?.code === -32002 && r.body?.error?.data?.policy === 'argument-policy');
    check('reason names the size cap', String(r.body?.error?.message).includes('exceeds max 4096'));
  }

  banner('ARG    DumpMemory path confinement (responder holds x64dbg:exfil)');
  {
    const ok = await rpc(proxyPort, call('DumpMemory', { path: 'C:/cred-sandbox/heap.bin' }), { receipt: exfilReceipt, signKey: responderKey });
    check('dump to sandbox path allowed', ok.status === 200 && !ok.body.error);
    const bad = await rpc(proxyPort, call('DumpMemory', { path: 'C:/cred-sandbox/../../Windows/creds.bin' }), { receipt: exfilReceipt, signKey: responderKey });
    console.log(`  traversal: ${bad.body?.error?.message}`);
    check('dump with path traversal denied', bad.body?.error?.code === -32002 && bad.body?.error?.data?.policy === 'argument-policy');
    const outside = await rpc(proxyPort, call('DumpMemory', { path: '/etc/shadow' }), { receipt: exfilReceipt, signKey: responderKey });
    check('dump outside sandbox prefix denied', outside.body?.error?.code === -32002 && outside.body?.error?.data?.policy === 'argument-policy');
  }

  // --- PROOF OF POSSESSION (mandatory) ---
  banner('POP    a valid receipt with NO proof-of-possession is refused');
  {
    const r = await rpc(proxyPort, call('ReadMemory', { address: '0x0', size: 16 }), { receipt: readReceipt, omitPop: true });
    console.log(`  ${r.body?.error?.message}`);
    check('missing PoP refused', r.status === 401 && r.body?.error?.data?.reason === 'pop:missing_pop');
  }

  banner('POP    a stolen receipt signed with the wrong key is refused');
  {
    // Attacker holds the analyst receipt but signs the proof with their own key.
    const r = await rpc(proxyPort, call('ReadMemory', { address: '0x0', size: 16 }), { receipt: readReceipt, signKey: attackerKey });
    console.log(`  ${r.body?.error?.message}`);
    check('stolen-receipt PoP signature rejected', r.status === 401 && r.body?.error?.data?.reason === 'pop:pop_bad_signature');
  }

  banner('POP    replaying a captured proof is refused');
  {
    const msg = call('ReadMemory', { address: '0x10', size: 16 });
    const first = await rpc(proxyPort, msg, { receipt: readReceipt, signKey: analystKey });
    check('first use of the proof is allowed', first.status === 200 && !first.body.error);
    const replay = await rpc(proxyPort, msg, { receipt: readReceipt, pop: first.pop });
    console.log(`  ${replay.body?.error?.message}`);
    check('replayed proof (same jti) refused', replay.status === 401 && replay.body?.error?.data?.reason === 'pop:pop_replayed');
  }

  // --- least privilege visibility ---
  banner('FILTER tools/list is narrowed to the analyst credential');
  {
    const r = await rpc(proxyPort, { jsonrpc: '2.0', id: 2, method: 'tools/list' }, { receipt: readReceipt, signKey: analystKey });
    const names: string[] = (r.body?.result?.tools ?? []).map((t: any) => t.name);
    console.log(`  visible: ${names.join(', ')}`);
    check('read tools visible, write/exfil/catch-all hidden', names.includes('ReadMemory') && !names.includes('WriteMemToAddress') && !names.includes('DumpMemory') && !names.includes('ExecuteDebuggerCommand'));
  }

  // --- no credential at all ---
  banner('DENY   no credential presented');
  {
    const r = await rpc(proxyPort, call('ReadMemory', { address: '0x0' }), {});
    check('unauthenticated request rejected', r.status === 401 && r.body?.error?.data?.reason === 'missing_credential');
  }

  // --- SSE expiry ---
  banner('SSE    stream terminated when the delegated token expires (ttl=2s)');
  {
    const { closedMs, timedOut } = await sseUntilClose(proxyPort, shortReceipt, analystKey, 8000);
    console.log(`  stream closed after ${closedMs} ms (effective ~1-2s due to second-granular exp)`);
    check('proxy terminated the stream (did not hang)', !timedOut);
    check('termination near expiry', closedMs >= 900 && closedMs <= 4000);
  }

  // --- audit ---
  banner('AUDIT  one structured line per decision');
  const lines = readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const col = (s: string, n: number) => (s + ' '.repeat(n)).slice(0, n);
  console.log(`  ${col('decision', 8)} ${col('tool', 22)} ${col('policy', 18)} reason`);
  for (const l of lines) {
    console.log(`  ${col(l.decision, 8)} ${col(l.tool ?? '-', 22)} ${col(l.policy ?? '-', 18)} ${l.reason}`);
  }
  const denies = lines.filter((l) => l.decision === 'deny');
  console.log(`  ${lines.filter((l) => l.decision === 'allow').length} allow, ${denies.length} deny`);
  check('WriteMemToAddress scope deny recorded', denies.some((l) => l.tool === 'WriteMemToAddress' && l.requiredScope === 'x64dbg:write'));
  check('argument-policy deny recorded', denies.some((l) => l.policy === 'argument-policy'));
  check('PoP denies recorded', denies.some((l) => String(l.reason).startsWith('pop:')));
  check('SSE expiry termination recorded', denies.some((l) => l.reason === 'sse_terminated_token_expired'));

  proxy.close();
  mock.close();
  console.log(`\n${failures === 0 ? 'DEMO PASSED' : `DEMO FAILED (${failures} checks)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

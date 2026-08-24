/**
 * End-to-end demo: allow, deny, and the resulting audit trail.
 *
 * Runs entirely in-process against a mock x64dbg upstream, so it needs no
 * Windows host and finishes in a few seconds. It doubles as a smoke test:
 * every expectation is asserted, and a failed assertion exits non-zero.
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
import { generateIssuerKeypairHex, mintReceipt } from './mint-receipt.js';

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

async function rpc(port: number, message: unknown, receipt?: string): Promise<RpcResponse> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (receipt) headers['authorization'] = `Bearer ${receipt}`;
  const res = await fetch(`http://127.0.0.1:${port}/`, {
    method: 'POST',
    headers,
    body: JSON.stringify(message),
  });
  const text = await res.text();
  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, body };
}

/** Open an SSE stream through the proxy; resolve with ms until it closes. */
async function sseUntilClose(port: number, receipt: string, safetyMs: number): Promise<{ closedMs: number; timedOut: boolean }> {
  const controller = new AbortController();
  const started = Date.now();
  const res = await fetch(`http://127.0.0.1:${port}/sse`, {
    headers: { authorization: `Bearer ${receipt}` },
    signal: controller.signal,
  });
  if (!res.body) return { closedMs: Date.now() - started, timedOut: false };
  const reader = res.body.getReader();
  const safety = setTimeout(() => controller.abort(), safetyMs);
  let timedOut = false;
  try {
    // Read until the proxy terminates the stream (done) or safety fires.
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

async function main(): Promise<void> {
  // 1. Delegation issuer (throwaway) + a read-only analyst agent identity.
  const issuer = generateIssuerKeypairHex();
  const analyst = await generateAgentIdentity({ scopeCeiling: ['x64dbg:read'] });

  // 2. Mock upstream + proxy, on free ports.
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
  await new Promise<void>((resolve) => proxy.once('listening', resolve)).catch(() => undefined);
  // startProxy may already be listening; give the listen callback a tick.
  await new Promise((r) => setTimeout(r, 100));

  // 3. Receipts.
  const readOnly = mintReceipt({ privateKeyHex: issuer.privateKeyHex, subject: analyst.did, scopes: ['x64dbg:read'], ttlSeconds: 300, delegationId: 'demo-analyst-1' });
  const shortLived = mintReceipt({ privateKeyHex: issuer.privateKeyHex, subject: analyst.did, scopes: ['x64dbg:read'], ttlSeconds: 2, delegationId: 'demo-sse-1' });

  console.log(`Analyst DID (delegated subject): ${analyst.did}`);
  console.log(`Granted scopes: x64dbg:read`);
  console.log(`Audit log: ${AUDIT_FILE}`);

  const call = (name: string, args: Record<string, unknown> = {}, id = 1) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

  // --- ALLOW: a read the analyst is entitled to ---
  banner('ALLOW  ReadMemory (analyst holds x64dbg:read)');
  {
    const r = await rpc(proxyPort, call('ReadMemory', { address: '0x7ff6a1b21044', size: 10 }), readOnly);
    const text = r.body?.result?.content?.[0]?.text;
    console.log(`  upstream said: ${text}`);
    check('forwarded and returned a result', r.status === 200 && typeof text === 'string' && !r.body.error);
  }

  // --- DENY (headline): patch process memory with a read-only credential ---
  banner('DENY   WriteMemToAddress (read-only credential cannot patch memory)');
  {
    const r = await rpc(proxyPort, call('WriteMemToAddress', { address: '0x7ff6a1b21044', data: '9090' }), readOnly);
    console.log(`  jsonrpc error: ${r.body?.error?.message}`);
    check('rejected as a JSON-RPC error (not bare 403)', r.status === 200 && r.body?.error?.code === -32002);
    check('error names the required scope x64dbg:write', String(r.body?.error?.message).includes('x64dbg:write'));
    check('error data lists the granted scopes', Array.isArray(r.body?.error?.data?.grantedScopes) && r.body.error.data.grantedScopes.includes('x64dbg:read'));
    check('denied by the scope-filter policy', r.body?.error?.data?.policy === 'scope-filter');
  }

  // --- DENY: the catch-all tool, denied outright regardless of scope ---
  banner('DENY   ExecuteDebuggerCommand (catch-all, denied outright)');
  {
    const r = await rpc(proxyPort, call('ExecuteDebuggerCommand', { command: 'mov [rip], 0x90' }), readOnly);
    console.log(`  jsonrpc error: ${r.body?.error?.message}`);
    check('denied before any scope check, by tool-disposition', r.body?.error?.code === -32002 && r.body?.error?.data?.policy === 'tool-disposition');
  }

  // --- least privilege: tools/list only shows callable tools ---
  banner('FILTER tools/list is narrowed to the credential');
  {
    const r = await rpc(proxyPort, { jsonrpc: '2.0', id: 2, method: 'tools/list' }, readOnly);
    const names: string[] = (r.body?.result?.tools ?? []).map((t: any) => t.name);
    console.log(`  visible tools: ${names.join(', ')}`);
    check('read tools are visible', names.includes('ReadMemory') && names.includes('GetAllRegisters'));
    check('write/exfil/session/catch-all tools are hidden', !names.includes('WriteMemToAddress') && !names.includes('DumpMemory') && !names.includes('AttachProcess') && !names.includes('ExecuteDebuggerCommand'));
  }

  // --- DENY: no credential at all ---
  banner('DENY   no credential presented');
  {
    const r = await rpc(proxyPort, call('ReadMemory', { address: '0x0' }));
    console.log(`  jsonrpc error: ${r.body?.error?.message}`);
    check('unauthenticated request rejected', r.status === 401 && r.body?.error?.code === -32001);
  }

  // --- SSRF: a smuggled host in the request target cannot redirect upstream ---
  banner('SSRF   request target host is forced to the configured upstream');
  {
    // req.url arrives as "//evil.example.com/" (protocol-relative). The proxy
    // must take only the path and keep the upstream host from config, so this
    // still reaches the mock rather than evil.example.com.
    const res = await fetch(`http://127.0.0.1:${proxyPort}//evil.example.com/`, {
      method: 'POST',
      headers: { authorization: `Bearer ${readOnly}`, 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/list' }),
    });
    const body: any = await res.json().catch(() => ({}));
    console.log(`  smuggled "//evil.example.com/" -> status ${res.status}, tools returned: ${Array.isArray(body?.result?.tools)}`);
    check('smuggled host ignored; request still served by the configured upstream', res.status === 200 && Array.isArray(body?.result?.tools));
  }

  // --- SSE: the stream is terminated when its token expires ---
  banner('SSE    stream terminated when the delegated token expires (ttl=2s)');
  {
    const { closedMs, timedOut } = await sseUntilClose(proxyPort, shortLived, 8000);
    // Receipt `exp` is in whole seconds (Cred's format), so truncating `iat`
    // makes a nominal 2s ttl land anywhere in ~1.0-2.0s. The audit line below
    // is the authoritative proof that the proxy timer (not the client) closed it.
    console.log(`  stream closed after ${closedMs} ms (nominal ttl 2s; effective ~1-2s due to second-granular exp)`);
    check('proxy terminated the stream (did not hang)', !timedOut);
    check('termination happened around expiry, not immediately or never', closedMs >= 900 && closedMs <= 4000);
  }

  // --- audit trail ---
  banner('AUDIT  one structured line per decision');
  const lines = readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const col = (s: string, n: number) => (s + ' '.repeat(n)).slice(0, n);
  console.log(`  ${col('decision', 8)} ${col('tool', 24)} ${col('scope', 15)} ${col('up', 4)} reason`);
  for (const l of lines) {
    console.log(`  ${col(l.decision, 8)} ${col(l.tool ?? '-', 24)} ${col(l.requiredScope ?? '-', 15)} ${col(String(l.upstreamStatus ?? '-'), 4)} ${l.reason}`);
  }
  const denies = lines.filter((l) => l.decision === 'deny');
  const allows = lines.filter((l) => l.decision === 'allow');
  console.log(`  ${allows.length} allow, ${denies.length} deny`);
  check('every line has timestamp, subject, decision, upstreamStatus fields', lines.every((l) => l.ts && (l.subject || l.decision === 'deny') && l.decision && 'upstreamStatus' in l));
  check('a WriteMemToAddress deny was recorded', denies.some((l) => l.tool === 'WriteMemToAddress' && l.requiredScope === 'x64dbg:write'));
  check('the SSE expiry termination was recorded', denies.some((l) => l.reason === 'sse_terminated_token_expired'));

  // done
  proxy.close();
  mock.close();
  console.log(`\n${failures === 0 ? 'DEMO PASSED' : `DEMO FAILED (${failures} checks)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

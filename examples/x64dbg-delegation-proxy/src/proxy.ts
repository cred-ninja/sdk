/**
 * x64dbg delegation proxy.
 *
 * A reverse proxy in front of the unauthenticated x64dbg-mcp-server HTTP
 * interface. It enforces delegated, scope-limited access per MCP tool call:
 * verify the delegation receipt, resolve the tool -> required scope, check it
 * against the granted scopes, then forward or reject. Every decision is audited.
 *
 * Zero changes to the Zig plugin. This proxy controls *who asks*; it does not
 * shrink what x64dbg can do. See README for the deployment steps that close the
 * direct-connection bypass.
 *
 * Built on node:http (no runtime dependencies), reusing @credninja/guard for the
 * scope check and @credninja/sdk for receipt verification.
 */

import http from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { loadConfig, type ProxyConfig } from './config.js';
import { ScopeMap } from './scope-map.js';
import { verifyReceipt, type VerifiedToken } from './receipt.js';
import { evaluateToolCall, type ToolDecision } from './policy.js';
import { configureAudit, emitAudit, log } from './audit.js';
import { verifyPop, NonceStore, sha256Base64Url } from './pop.js';

/** JSON-RPC error codes (server-defined range). */
const ERR_UNAUTHORIZED = -32001; // credential missing/invalid/expired
const ERR_DENIED = -32002; // scope/tool disposition denied the call
const ERR_UPSTREAM = -32000; // upstream unreachable
const ERR_BAD_REQUEST = -32600;

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);
const MAX_BODY = 8 * 1024 * 1024;

function nowIso(): string {
  return new Date().toISOString();
}

function bearerFrom(req: IncomingMessage): string | undefined {
  const auth = req.headers['authorization'];
  if (!auth) return undefined;
  const value = (Array.isArray(auth) ? auth[0] : auth).trim();
  // Fixed-prefix check + slice, not a backtracking regex (avoids polynomial
  // ReDoS on an attacker-controlled Authorization header).
  if (!/^Bearer\b/i.test(value)) return undefined;
  const token = value.slice('Bearer'.length).trim();
  return token.length > 0 ? token : undefined;
}

function popFrom(req: IncomingMessage): string | undefined {
  const h = req.headers['x64dbg-pop'];
  if (!h) return undefined;
  const value = Array.isArray(h) ? h[0] : h;
  return value.trim() || undefined;
}

interface JsonRpcErrorObject {
  jsonrpc: '2.0';
  id: string | number | null;
  error: { code: number; message: string; data?: unknown };
}

function jsonRpcError(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcErrorObject {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data !== undefined ? { data } : {}) } };
}

function sendJson(res: ServerResponse, status: number, obj: unknown): void {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(body.length) });
  res.end(body);
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function tryParse(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString('utf8'));
  } catch {
    return undefined;
  }
}

interface RpcToolCall {
  id: string | number | null;
  name: string;
  args: Record<string, unknown>;
}

function extractToolCalls(parsed: unknown): RpcToolCall[] {
  const out: RpcToolCall[] = [];
  const items = Array.isArray(parsed) ? parsed : [parsed];
  for (const it of items) {
    if (it && typeof it === 'object' && (it as Record<string, unknown>).method === 'tools/call') {
      const rec = it as Record<string, unknown>;
      const params = (rec.params ?? {}) as Record<string, unknown>;
      const name = typeof params.name === 'string' ? params.name : '';
      const args = (params.arguments && typeof params.arguments === 'object')
        ? (params.arguments as Record<string, unknown>)
        : {};
      const id = (rec.id as string | number | null | undefined) ?? null;
      out.push({ id, name, args });
    }
  }
  return out;
}

function methodLabel(parsed: unknown): string {
  if (Array.isArray(parsed)) return 'batch';
  if (parsed && typeof parsed === 'object') {
    const m = (parsed as Record<string, unknown>).method;
    return typeof m === 'string' ? m : 'unknown';
  }
  return 'unparsed';
}

/**
 * Build the outbound request target. The host, port, and protocol come only
 * from cfg.upstreamUrl (operator-configured, constant). Only the path and query
 * are taken from the incoming request, and they are extracted via a throwaway
 * base so that an absolute-form, protocol-relative, or backslash-smuggled
 * request target cannot redirect the request off the configured upstream. This
 * keeps the proxy from becoming an open forwarder (SSRF).
 */
function upstreamTarget(cfg: ProxyConfig, reqUrl: string | undefined): { options: http.RequestOptions; hostHeader: string } {
  const base = new URL(cfg.upstreamUrl);
  const incoming = new URL(reqUrl || '/', 'http://proxy.invalid');
  const path = incoming.pathname + incoming.search;
  return {
    options: { protocol: base.protocol, hostname: base.hostname, port: base.port || undefined, path },
    hostHeader: base.host,
  };
}

function upstreamHeaders(req: IncomingMessage, hostHeader: string, bodyLength: number): http.OutgoingHttpHeaders {
  const h: http.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (lk === 'authorization') continue; // the delegation credential is for the proxy, not upstream
    if (lk === 'host') continue;
    if (lk === 'content-length') continue;
    if (v !== undefined) h[k] = v as string | string[];
  }
  h['host'] = hostHeader;
  if (bodyLength > 0) h['content-length'] = String(bodyLength);
  return h;
}

function copyResponseHeaders(upRes: IncomingMessage): http.OutgoingHttpHeaders {
  const h: http.OutgoingHttpHeaders = {};
  for (const [k, v] of Object.entries(upRes.headers)) {
    if (HOP_BY_HOP.has(k.toLowerCase())) continue;
    if (v !== undefined) h[k] = v as string | string[];
  }
  return h;
}

function collect(stream: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (c: Buffer) => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

function denyMessage(d: ToolDecision, token: VerifiedToken): string {
  if (d.policy === 'scope-filter' && d.requiredScope) {
    const granted = token.scopes.length ? token.scopes.join(', ') : 'none';
    return `Delegated access denied: tool "${d.tool}" requires scope "${d.requiredScope}", which this credential was not granted. Granted scopes: [${granted}].`;
  }
  // tool-disposition (catch-all/unmapped) or argument-policy: the deciding
  // reason is the specific violation, so surface it directly.
  return `Delegated access denied: tool "${d.tool}" -- ${d.reason}.`;
}

function denyData(d: ToolDecision, token: VerifiedToken): Record<string, unknown> {
  return {
    tool: d.tool,
    requiredScope: d.requiredScope ?? null,
    grantedScopes: token.scopes,
    policy: d.policy,
    reason: d.reason,
    subject: token.subject,
  };
}

// ── tools/list filtering ─────────────────────────────────────────────────────

function filterToolsListBody(buf: Buffer, token: VerifiedToken, service: string, map: ScopeMap): Buffer | null {
  try {
    const grant = new Set(token.scopes);
    const applyOne = (o: unknown): unknown => {
      if (o && typeof o === 'object') {
        const rec = o as Record<string, unknown>;
        const result = rec.result as Record<string, unknown> | undefined;
        if (result && Array.isArray(result.tools)) {
          result.tools = (result.tools as Array<Record<string, unknown>>).filter((t) => {
            const name = t?.name;
            if (typeof name !== 'string') return false;
            const disp = map.resolve(name);
            if (disp.kind !== 'scope') return false; // hide denied / unmapped tools
            return grant.has(disp.scope);
          });
        }
      }
      return o;
    };
    const parsed: unknown = JSON.parse(buf.toString('utf8'));
    const out = Array.isArray(parsed) ? parsed.map(applyOne) : applyOne(parsed);
    return Buffer.from(JSON.stringify(out));
  } catch {
    return null;
  }
}

// ── SSE helpers ──────────────────────────────────────────────────────────────

function sseMessage(obj: unknown): string {
  return `event: message\ndata: ${JSON.stringify(obj)}\n\n`;
}

/**
 * Pipe an SSE stream, rewriting any absolute upstream-origin URL the server
 * emits on a `data:` line to the proxy origin, so the client's follow-up POSTs
 * traverse the proxy (and get scope-checked) rather than hitting upstream
 * directly. Relative endpoint URLs already resolve to the proxy and pass through
 * unchanged.
 */
function pipeSseWithRewrite(src: IncomingMessage, dst: ServerResponse, fromOrigin: string, toOrigin: string): void {
  let buf = '';
  src.setEncoding('utf8');
  const flushLine = (line: string): void => {
    const rewritten = fromOrigin && line.startsWith('data:') ? line.split(fromOrigin).join(toOrigin) : line;
    dst.write(rewritten);
  };
  src.on('data', (chunk: string) => {
    buf += chunk;
    let idx: number;
    while ((idx = buf.indexOf('\n')) >= 0) {
      flushLine(buf.slice(0, idx + 1));
      buf = buf.slice(idx + 1);
    }
  });
  src.on('end', () => {
    if (buf) flushLine(buf);
    dst.end();
  });
  src.on('error', () => {
    try {
      dst.end();
    } catch {
      /* already closed */
    }
  });
}

// ── request handling ─────────────────────────────────────────────────────────

interface ForwardOptions {
  token: VerifiedToken;
  map: ScopeMap;
  /** JSON-RPC method label (for tools/list filtering). */
  rpcMethod?: string;
  /** Allowed tool-call decisions to audit once the upstream status is known. */
  decisions?: ToolDecision[];
}

function forward(
  req: IncomingMessage,
  res: ServerResponse,
  cfg: ProxyConfig,
  body: Buffer,
  opts: ForwardOptions,
): void {
  const { options, hostHeader } = upstreamTarget(cfg, req.url);
  const headers = upstreamHeaders(req, hostHeader, body.length);
  const upReq = http.request({ ...options, method: req.method, headers }, (upRes) => {
    const status = upRes.statusCode ?? 502;

    if (opts.decisions) {
      for (const d of opts.decisions) {
        emitAudit({
          ts: nowIso(),
          event: 'x64dbg.proxy.decision',
          transport: 'streamable-http',
          method: `POST ${req.url || '/'}`,
          subject: opts.token.subject,
          tokenHash: opts.token.tokenHash,
          tool: d.tool,
          requiredScope: d.requiredScope ?? null,
          decision: 'allow',
          reason: d.reason,
          policy: d.policy,
          upstreamStatus: status,
          guard: d.guardEvent,
        });
      }
    }

    const ct = String(upRes.headers['content-type'] ?? '');
    if (cfg.filterToolsList && opts.rpcMethod === 'tools/list' && ct.includes('application/json')) {
      collect(upRes)
        .then((buf) => {
          const filtered = filterToolsListBody(buf, opts.token, cfg.service, opts.map) ?? buf;
          const outHeaders = copyResponseHeaders(upRes);
          outHeaders['content-length'] = String(filtered.length);
          res.writeHead(status, outHeaders);
          res.end(filtered);
        })
        .catch(() => {
          if (!res.headersSent) sendJson(res, 502, jsonRpcError(null, ERR_UPSTREAM, 'failed reading upstream tools/list'));
        });
      return;
    }

    res.writeHead(status, copyResponseHeaders(upRes));
    upRes.pipe(res);
  });

  upReq.on('error', (err: Error) => {
    log(`upstream error: ${err.message}`);
    if (!res.headersSent) sendJson(res, 502, jsonRpcError(null, ERR_UPSTREAM, `upstream unreachable: ${err.message}`));
    else res.destroy();
  });
  req.on('close', () => upReq.destroy());
  if (body.length) upReq.write(body);
  upReq.end();
}

async function handlePost(
  req: IncomingMessage,
  res: ServerResponse,
  cfg: ProxyConfig,
  map: ScopeMap,
  nonce: NonceStore,
): Promise<void> {
  const receiptJws = bearerFrom(req);
  const token = await verifyReceipt(receiptJws, cfg);
  const method = `POST ${req.url || '/'}`;

  const denyAuth = (reason: string): void => {
    emitAudit({
      ts: nowIso(),
      event: 'x64dbg.proxy.decision',
      transport: 'streamable-http',
      method,
      subject: token.ok ? token.subject : (token.subject ?? null),
      tokenHash: token.ok ? token.tokenHash : (token.tokenHash ?? null),
      tool: null,
      requiredScope: null,
      decision: 'deny',
      reason,
      upstreamStatus: null,
    });
    sendJson(res, 401, jsonRpcError(null, ERR_UNAUTHORIZED, `Delegation rejected: ${reason}`, { reason }));
  };

  if (!token.ok) {
    denyAuth(token.reason);
    return;
  }

  let body: Buffer;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 413, jsonRpcError(null, ERR_BAD_REQUEST, 'request body too large'));
    return;
  }

  // Mandatory proof-of-possession: the caller must prove it holds the receipt
  // subject's key, bound to this method/path/body. A stolen receipt is inert.
  const pop = verifyPop(popFrom(req), {
    method: 'POST',
    path: req.url || '/',
    subjectDid: token.subject,
    receipt: receiptJws!,
    bodyHashB64: sha256Base64Url(body),
    windowSeconds: cfg.popWindowSeconds,
    nonceStore: nonce,
    nowMs: Date.now(),
  });
  if (!pop.ok) {
    denyAuth(`pop:${pop.reason}`);
    return;
  }

  const parsed = tryParse(body);
  const calls = extractToolCalls(parsed);
  const rpcMethod = methodLabel(parsed);

  if (calls.length === 0) {
    // Protocol traffic (initialize, tools/list, ping, notifications, ...).
    // Authenticated, but no per-tool scope decision.
    emitAudit({
      ts: nowIso(),
      event: 'x64dbg.proxy.decision',
      transport: 'streamable-http',
      method,
      subject: token.subject,
      tokenHash: token.tokenHash,
      tool: null,
      requiredScope: null,
      decision: 'allow',
      reason: `protocol:${rpcMethod}`,
      upstreamStatus: null,
    });
    forward(req, res, cfg, body, { token, map, rpcMethod });
    return;
  }

  const decisions = await Promise.all(calls.map((c) => evaluateToolCall(c.name, c.args, token, cfg.service, map)));
  const anyDenied = decisions.some((d) => !d.allowed);

  if (anyDenied) {
    for (const d of decisions) {
      emitAudit({
        ts: nowIso(),
        event: 'x64dbg.proxy.decision',
        transport: 'streamable-http',
        method,
        subject: token.subject,
        tokenHash: token.tokenHash,
        tool: d.tool,
        requiredScope: d.requiredScope ?? null,
        decision: d.allowed ? 'allow' : 'deny',
        reason: d.reason,
        policy: d.policy,
        upstreamStatus: null,
        guard: d.guardEvent,
      });
    }
    const firstDenied = decisions.find((d) => !d.allowed)!;
    const denyId = calls.length === 1 ? calls[0].id : null;
    sendJson(res, 200, jsonRpcError(denyId, ERR_DENIED, denyMessage(firstDenied, token), denyData(firstDenied, token)));
    return;
  }

  // All tool calls allowed: forward, audit each with the upstream status.
  forward(req, res, cfg, body, { token, map, rpcMethod, decisions });
}

async function handleGet(
  req: IncomingMessage,
  res: ServerResponse,
  cfg: ProxyConfig,
  nonce: NonceStore,
): Promise<void> {
  const receiptJws = bearerFrom(req);
  const token = await verifyReceipt(receiptJws, cfg);
  const method = `GET ${req.url || '/'}`;

  const denyAuth = (reason: string): void => {
    emitAudit({
      ts: nowIso(),
      event: 'x64dbg.proxy.decision',
      transport: 'sse',
      method,
      subject: token.ok ? token.subject : (token.subject ?? null),
      tokenHash: token.ok ? token.tokenHash : (token.tokenHash ?? null),
      tool: null,
      requiredScope: null,
      decision: 'deny',
      reason,
      upstreamStatus: null,
    });
    sendJson(res, 401, jsonRpcError(null, ERR_UNAUTHORIZED, `Delegation rejected: ${reason}`, { reason }));
  };

  if (!token.ok) {
    denyAuth(token.reason);
    return;
  }

  // Mandatory proof-of-possession for opening the stream (no body to bind).
  const pop = verifyPop(popFrom(req), {
    method: 'GET',
    path: req.url || '/',
    subjectDid: token.subject,
    receipt: receiptJws!,
    windowSeconds: cfg.popWindowSeconds,
    nonceStore: nonce,
    nowMs: Date.now(),
  });
  if (!pop.ok) {
    denyAuth(`pop:${pop.reason}`);
    return;
  }

  const { options, hostHeader } = upstreamTarget(cfg, req.url);
  const headers = upstreamHeaders(req, hostHeader, 0);
  const upReq = http.request({ ...options, method: 'GET', headers }, (upRes) => {
    const status = upRes.statusCode ?? 502;
    const ct = String(upRes.headers['content-type'] ?? '');
    const isStream = ct.includes('text/event-stream');

    res.writeHead(status, copyResponseHeaders(upRes));
    emitAudit({
      ts: nowIso(),
      event: 'x64dbg.proxy.decision',
      transport: 'sse',
      method,
      subject: token.subject,
      tokenHash: token.tokenHash,
      tool: null,
      requiredScope: null,
      decision: 'allow',
      reason: isStream ? 'sse_stream_opened' : 'get_forwarded',
      upstreamStatus: status,
    });

    if (isStream) {
      const proxyOrigin = `http://${req.headers.host ?? `${cfg.listenHost}:${cfg.listenPort}`}`;
      pipeSseWithRewrite(upRes, res, cfg.upstreamUrl, proxyOrigin);

      if (cfg.sseOnExpiry === 'terminate' && typeof token.exp === 'number') {
        // Terminate exactly at the receipt's stated expiry. The clock-skew
        // grace used when *validating* a presented token is a tolerance for
        // other parties' clocks; the proxy holds this stream against its own
        // clock, so it honors `exp` precisely. See ADR-0002.
        const ms = Math.max(0, token.exp * 1000 - Date.now());
        const timer = setTimeout(() => {
          emitAudit({
            ts: nowIso(),
            event: 'x64dbg.proxy.decision',
            transport: 'sse',
            method,
            subject: token.subject,
            tokenHash: token.tokenHash,
            tool: null,
            requiredScope: null,
            decision: 'deny',
            reason: 'sse_terminated_token_expired',
            upstreamStatus: status,
          });
          try {
            res.write(sseMessage(jsonRpcError(null, ERR_UNAUTHORIZED, 'Delegated credential expired; stream terminated by proxy.', { reason: 'token_expired' })));
          } catch {
            /* ignore */
          }
          try {
            res.end();
          } catch {
            /* ignore */
          }
          upReq.destroy();
        }, ms);
        const clear = (): void => clearTimeout(timer);
        res.on('close', clear);
        upRes.on('end', clear);
        upRes.on('error', clear);
      }
    } else {
      upRes.pipe(res);
    }
  });

  upReq.on('error', (err: Error) => {
    log(`sse upstream error: ${err.message}`);
    if (!res.headersSent) sendJson(res, 502, jsonRpcError(null, ERR_UPSTREAM, `upstream unreachable: ${err.message}`));
    else res.destroy();
  });
  req.on('close', () => upReq.destroy());
  upReq.end();
}

function passthrough(req: IncomingMessage, res: ServerResponse, cfg: ProxyConfig): void {
  // OPTIONS/HEAD: no credential (CORS preflight carries none). Forward verbatim.
  const { options, hostHeader } = upstreamTarget(cfg, req.url);
  const headers = upstreamHeaders(req, hostHeader, 0);
  const upReq = http.request({ ...options, method: req.method, headers }, (upRes) => {
    res.writeHead(upRes.statusCode ?? 502, copyResponseHeaders(upRes));
    upRes.pipe(res);
  });
  upReq.on('error', (err: Error) => {
    if (!res.headersSent) sendJson(res, 502, jsonRpcError(null, ERR_UPSTREAM, `upstream unreachable: ${err.message}`));
    else res.destroy();
  });
  req.on('close', () => upReq.destroy());
  upReq.end();
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  cfg: ProxyConfig,
  map: ScopeMap,
  nonce: NonceStore,
): Promise<void> {
  const method = req.method ?? 'GET';
  if (method === 'OPTIONS' || method === 'HEAD') return passthrough(req, res, cfg);
  if (method === 'POST') return handlePost(req, res, cfg, map, nonce);
  if (method === 'GET') return handleGet(req, res, cfg, nonce);
  sendJson(res, 405, jsonRpcError(null, ERR_BAD_REQUEST, `method ${method} not supported by proxy`));
}

export function createProxy(cfg: ProxyConfig, map: ScopeMap): http.Server {
  configureAudit(cfg.auditLogPath, { stdout: cfg.auditStdout });
  const nonce = new NonceStore(cfg.popWindowSeconds * 1000);
  return http.createServer((req, res) => {
    handle(req, res, cfg, map, nonce).catch((err: Error) => {
      log(`unhandled error: ${err.message}`);
      if (!res.headersSent) sendJson(res, 500, jsonRpcError(null, ERR_UPSTREAM, 'internal proxy error'));
      else res.destroy();
    });
  });
}

export function startProxy(cfg: ProxyConfig): http.Server {
  const map = ScopeMap.load(cfg.scopeMapPath);
  const server = createProxy(cfg, map);
  server.listen(cfg.listenPort, cfg.listenHost, () => {
    log(`listening on http://${cfg.listenHost}:${cfg.listenPort} -> upstream ${cfg.upstreamUrl}`);
    log(`service="${cfg.service}" scopeMap=${cfg.scopeMapPath} (${map.toolCount()} tools) unmapped=${map.unmappedPolicy}`);
    log(`sseOnExpiry=${cfg.sseOnExpiry} filterToolsList=${cfg.filterToolsList} PoP=required(window=${cfg.popWindowSeconds}s) subject=${cfg.expectedAgentDid ?? 'any-with-proof'}`);
    log('REMINDER: the proxy only controls who asks. Bind the plugin to 127.0.0.1 and add a host firewall rule, or this is advisory only. See README.');
  });
  return server;
}

// Run directly: `tsx src/proxy.ts`
const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  try {
    startProxy(loadConfig());
  } catch (err) {
    log(`fatal: ${(err as Error).message}`);
    process.exit(1);
  }
}

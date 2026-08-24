/**
 * Mock x64dbg-mcp-server for the demo.
 *
 * Stands in for duty1g/x64dbg-mcp-server so the example runs anywhere (the real
 * plugin is a Windows-only native x64dbg plugin). It speaks just enough of the
 * MCP HTTP surface to exercise the proxy: initialize, tools/list, tools/call
 * over POST /, and a long-lived SSE stream over GET /sse.
 *
 * It has NO auth, NO scoping, NO audit -- exactly like the real thing. The whole
 * point of the proxy is to put a boundary in front of a server like this.
 */

import http from 'node:http';

const PORT = Number(process.env.MOCK_PORT ?? '9099');
const HOST = process.env.MOCK_HOST ?? '127.0.0.1';

// A representative slice of the 71 tools, enough to show allow/deny/list-filter.
const TOOLS = [
  { name: 'ReadMemory', description: 'Read process memory at an address.' },
  { name: 'Disassemble', description: 'Disassemble instructions at an address.' },
  { name: 'GetAllRegisters', description: 'Read all CPU registers.' },
  { name: 'run', description: 'Resume execution.' },
  { name: 'SetBreakpoint', description: 'Set a software breakpoint.' },
  { name: 'WriteMemToAddress', description: 'Write bytes into process memory.' },
  { name: 'SetRegister', description: 'Set a CPU register value.' },
  { name: 'DumpMemory', description: 'Dump a memory region to disk.' },
  { name: 'AttachProcess', description: 'Attach the debugger to a process.' },
  { name: 'ExecuteDebuggerCommand', description: 'Run an arbitrary x64dbg command.' },
];

function fakeToolResult(name: string, args: Record<string, unknown>): string {
  switch (name) {
    case 'ReadMemory':
      return `bytes@${String(args.address ?? '0x0')}: 48 89 5c 24 08 57 48 83 ec 20`;
    case 'GetAllRegisters':
      return 'rax=0000000000000001 rbx=00007ff6a1b20000 rip=00007ff6a1b21044';
    case 'Disassemble':
      return `${String(args.address ?? '0x0')}: mov rax, qword ptr [rcx]`;
    case 'WriteMemToAddress':
      return `wrote ${String(args.data ?? '')} to ${String(args.address ?? '0x0')}`;
    case 'SetRegister':
      return `set ${String(args.register ?? 'rax')} = ${String(args.value ?? '0')}`;
    case 'DumpMemory':
      return `dumped region to ${String(args.path ?? 'C:/dump.bin')}`;
    default:
      return `ok: ${name}`;
  }
}

function reply(res: http.ServerResponse, obj: unknown, status = 200): void {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': String(body.length) });
  res.end(body);
}

function handleRpc(msg: Record<string, unknown>): unknown {
  const id = (msg.id as string | number | null | undefined) ?? null;
  switch (msg.method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'x64dbg-mcp-server (mock)', version: '0.0.0' },
          capabilities: { tools: {} },
        },
      };
    case 'tools/list':
      return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
    case 'tools/call': {
      const params = (msg.params ?? {}) as Record<string, unknown>;
      const name = String(params.name ?? '');
      const args = (params.arguments ?? {}) as Record<string, unknown>;
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: fakeToolResult(name, args) }] } };
    }
    case 'ping':
      return { jsonrpc: '2.0', id, result: {} };
    default:
      return { jsonrpc: '2.0', id, error: { code: -32601, message: `method not found: ${String(msg.method)}` } };
  }
}

export function createMockServer(): http.Server {
  return http.createServer((req, res) => {
  const url = req.url ?? '/';

  if (req.method === 'GET' && url.startsWith('/sse')) {
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    });
    // MCP HTTP+SSE: announce the client->server POST endpoint (relative, so it
    // resolves to whatever origin the client connected to -- the proxy).
    res.write(`event: endpoint\ndata: /message?sessionId=mock-session\n\n`);
    const keepalive = setInterval(() => {
      try {
        res.write(`: keepalive ${Date.now()}\n\n`);
      } catch {
        clearInterval(keepalive);
      }
    }, 300);
    req.on('close', () => clearInterval(keepalive));
    return;
  }

  if (req.method === 'POST') {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch {
        reply(res, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }, 400);
        return;
      }
      if (Array.isArray(parsed)) {
        reply(res, parsed.map((m) => handleRpc(m as Record<string, unknown>)));
      } else {
        reply(res, handleRpc(parsed as Record<string, unknown>));
      }
    });
    return;
  }

  reply(res, { error: 'not found' }, 404);
  });
}

// Run directly: `tsx demo/mock-x64dbg.ts`
const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  createMockServer().listen(PORT, HOST, () => {
    process.stderr.write(`[mock-x64dbg] listening on http://${HOST}:${PORT} (no auth, no scoping, no audit)\n`);
  });
}

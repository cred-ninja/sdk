/**
 * Tailscale node identity source. No tailnet here: a fake LocalAPI (an HTTP
 * server on a unix socket) returns canned WhoIsResponse JSON keyed by addr,
 * and requests reach the listener socket directly, standing in for
 * `tailscale serve`. Each refusal is paired with a passing control.
 */
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { spawnSync } from 'node:child_process';
import {
  startTailscaleListener,
  checkListenerSocket,
  checkLocalApiSocket,
  type TailscaleSourceConfig,
  type TailscaleListener,
} from '../identity/tailscale.js';
import { IdentityRefusal, type ExternalIdentitySource } from '../identity/types.js';

const UID = process.getuid!();
const TAILNET = 'example-tail.ts.net';
const PEER = '100.64.0.7';

type Canned = { status?: number; body?: unknown; raw?: string; hang?: boolean };

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
});

function tmpDir(mode = 0o700): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cts-'));
  fs.chmodSync(d, mode);
  cleanups.push(() => {
    fs.chmodSync(d, 0o700);
    fs.rmSync(d, { recursive: true, force: true });
  });
  return d;
}

function node(overrides: Record<string, unknown> = {}): unknown {
  return {
    Node: {
      ID: 12,
      StableID: 'nAbC123CNTRL',
      Name: `agent-1.${TAILNET}.`,
      Tags: ['tag:agent'],
      KeyExpiry: '0001-01-01T00:00:00Z',
      ...overrides,
    },
    UserProfile: { ID: 1, LoginName: 'tagged-devices' },
    CapMap: {},
  };
}

interface FakeLocalApi {
  socketPath: string;
  dir: string;
  table: Map<string, Canned>;
  seen: Array<{ url: string; headers: http.IncomingHttpHeaders }>;
}

async function fakeLocalApi(): Promise<FakeLocalApi> {
  const dir = tmpDir();
  const socketPath = path.join(dir, 'tailscaled.sock');
  const table = new Map<string, Canned>();
  const seen: FakeLocalApi['seen'] = [];
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url ?? '', headers: req.headers });
    const addr = new URL(req.url ?? '', 'http://x').searchParams.get('addr') ?? '';
    const c = table.get(addr);
    if (!c) {
      res.writeHead(404).end('no match for IP:port\n');
      return;
    }
    if (c.hang) return;
    res.writeHead(c.status ?? 200, { 'content-type': 'application/json' });
    res.end(c.raw ?? JSON.stringify(c.body));
  });
  await new Promise<void>((r) => server.listen(socketPath, r));
  cleanups.push(
    () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  );
  return { socketPath, dir, table, seen };
}

type Outcome = { identity?: unknown; refusal?: string; none?: true };

/** Handler that runs the source on each request and reports the result as JSON. */
function makeHandler(ref: { source?: ExternalIdentitySource }): http.RequestListener {
  return (req, res) => {
    ref
      .source!.authenticate({
        method: req.method ?? 'GET',
        targetUri: 'https://cred.example/v1/x',
        headers: req.headers,
        socket: req.socket,
      })
      .then(
        (identity): Outcome => (identity ? { identity } : { none: true }),
        (err): Outcome => {
          if (err instanceof IdentityRefusal) return { refusal: err.code };
          throw err;
        },
      )
      .then((o) => res.end(JSON.stringify(o)));
  };
}

async function start(
  over: Partial<TailscaleSourceConfig> & { dirMode?: number } = {},
  api?: FakeLocalApi,
): Promise<{ l: TailscaleListener; api: FakeLocalApi; cfg: TailscaleSourceConfig }> {
  const localApi = api ?? (await fakeLocalApi());
  if (!api) localApi.table.set(PEER, { body: node() });
  const dir = over.listenerSocketPath ? '' : tmpDir(over.dirMode ?? 0o700);
  const cfg: TailscaleSourceConfig = {
    listenerSocketPath: path.join(dir, 'ts.sock'),
    localApiSocketPath: localApi.socketPath,
    tailnet: TAILNET,
    localApiOwnerUid: UID,
    whoisTimeoutMs: 300,
    ...over,
  };
  const ref: { source?: ExternalIdentitySource } = {};
  const l = await startTailscaleListener(makeHandler(ref), cfg);
  ref.source = l.source;
  cleanups.push(() => l.close());
  return { l, api: localApi, cfg };
}

function send(
  target: { socketPath: string } | { port: number },
  headers: Record<string, string> = { 'x-forwarded-for': PEER },
): Promise<Outcome> {
  return new Promise((resolve, reject) => {
    const req = http.request({ ...target, host: 'localhost', path: '/v1/x', headers, agent: false }, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => resolve(JSON.parse(b) as Outcome));
    });
    req.on('error', reject);
    req.end();
  });
}

const via = (cfg: TailscaleSourceConfig) => ({ socketPath: cfg.listenerSocketPath });

describe('tailscale listener: happy path', () => {
  it('verifies a tagged node from WhoIs only', async () => {
    const { l, cfg } = await start({ requireTags: ['tag:agent'] });
    expect(l.enabled).toBe(true);
    expect(l.disabledReason).toBeUndefined();
    const before = Math.floor(Date.now() / 1000);
    const out = await send(via(cfg));
    expect(out.identity).toMatchObject({
      kind: 'tailscale',
      subject: 'tailscale:node:nAbC123CNTRL',
      trustDomain: TAILNET,
      attributes: { nodeName: `agent-1.${TAILNET}.`, tags: ['tag:agent'] },
      proof: 'channel',
    });
    const exp = (out.identity as { expiresAt: number }).expiresAt;
    expect(exp).toBeGreaterThanOrEqual(before + 60);
    expect(exp).toBeLessThanOrEqual(before + 61);
  });

  it('sends the LocalAPI Host and no Origin/Referer, with addr from X-Forwarded-For', async () => {
    const { cfg, api } = await start();
    await send(via(cfg));
    expect(api.seen).toHaveLength(1);
    expect(api.seen[0].url).toBe(`/localapi/v0/whois?addr=${PEER}`);
    expect(api.seen[0].headers.host).toBe('local-tailscaled.sock');
    expect(api.seen[0].headers.origin).toBeUndefined();
    expect(api.seen[0].headers.referer).toBeUndefined();
  });

  it('does not cache WhoIs: each request asks again', async () => {
    const { cfg, api } = await start();
    expect((await send(via(cfg))).identity).toBeDefined();
    api.table.set(PEER, { body: node({ Expired: true }) });
    expect((await send(via(cfg))).refusal).toBe('expired');
    expect(api.seen).toHaveLength(2);
  });

  it('creates the listener socket mode 0600 and replaces a stale Cred-owned socket', async () => {
    const dir = tmpDir();
    const p = path.join(dir, 'ts.sock');
    // A process killed while listening leaves its socket file behind.
    spawnSync(process.execPath, [
      '-e',
      `require('net').createServer().listen(${JSON.stringify(p)}, () => process.kill(process.pid, 'SIGKILL'))`,
    ]);
    expect(fs.lstatSync(p).isSocket()).toBe(true);
    const { l } = await start({ listenerSocketPath: p });
    expect(l.enabled).toBe(true);
    expect(fs.lstatSync(p).mode & 0o777).toBe(0o600);
  });
});

describe('tailscale listener: socket rule', () => {
  it('forged X-Forwarded-For through a listener whose directory is world-writable is refused', async () => {
    const bad = await start({ dirMode: 0o777 });
    expect(bad.l.enabled).toBe(false);
    expect(bad.l.disabledReason).toMatch(/listener directory .* writable by others/);
    expect(await send(via(bad.cfg))).toEqual({ refusal: 'source_disabled' });
    expect(bad.api.seen).toHaveLength(0);
    // Control: the same request through a passing socket succeeds.
    const good = await start({}, bad.api);
    expect((await send(via(good.cfg))).identity).toMatchObject({ subject: 'tailscale:node:nAbC123CNTRL' });
  });

  it('group-writable directory is refused without allowedGid and accepted with the matching gid', async () => {
    const bad = await start({ dirMode: 0o770 });
    expect(bad.l.disabledReason).toMatch(/group-writable and no allowedGid/);
    expect((await send(via(bad.cfg))).refusal).toBe('source_disabled');

    const dir = tmpDir(0o770);
    const gid = fs.statSync(dir).gid;
    const good = await start({ listenerSocketPath: path.join(dir, 'ts.sock'), allowedGid: gid }, bad.api);
    expect(good.l.enabled).toBe(true);
    expect(fs.lstatSync(good.cfg.listenerSocketPath).mode & 0o777).toBe(0o660);
    expect((await send(via(good.cfg))).identity).toBeDefined();
  });

  it('group-writable with a different allowedGid is refused', async () => {
    const dir = tmpDir(0o770);
    const gid = fs.statSync(dir).gid;
    const { l } = await start({ listenerSocketPath: path.join(dir, 'ts.sock'), allowedGid: gid + 1 });
    expect(l.enabled).toBe(false);
  });

  it('symlinked listener directory is refused', async () => {
    const real = tmpDir();
    const holder = tmpDir();
    const link = path.join(holder, 'link');
    fs.symlinkSync(real, link);
    const { l, cfg } = await start({ listenerSocketPath: path.join(link, 'ts.sock') });
    expect(l.enabled).toBe(false);
    expect(l.disabledReason).toMatch(/symlink/);
    expect((await send(via(cfg))).refusal).toBe('source_disabled');
  });

  it('listener directory owned by an unexpected uid is refused (credUid/tailscaledUid mismatch)', async () => {
    const { l } = await start({ credUid: UID + 1, tailscaledUid: UID + 2 });
    expect(l.enabled).toBe(false);
    expect(l.disabledReason).toMatch(/owned by uid/);
  });

  it('refuses to start over a non-socket file', async () => {
    const dir = tmpDir();
    const p = path.join(dir, 'ts.sock');
    fs.writeFileSync(p, 'x');
    await expect(start({ listenerSocketPath: p })).rejects.toThrow(/not a socket/);
    expect(fs.readFileSync(p, 'utf8')).toBe('x');
  });

  it('LocalAPI socket directory world-writable is refused', async () => {
    const api = await fakeLocalApi();
    api.table.set(PEER, { body: node() });
    fs.chmodSync(api.dir, 0o777);
    const { l, cfg } = await start({}, api);
    expect(l.enabled).toBe(false);
    expect(l.disabledReason).toMatch(/LocalAPI directory .* writable by others/);
    expect((await send(via(cfg))).refusal).toBe('source_disabled');
    // Control.
    fs.chmodSync(api.dir, 0o700);
    expect(checkLocalApiSocket(cfg)).toEqual({ ok: true });
  });

  it('LocalAPI socket with the wrong owner, or missing, is refused', async () => {
    const wrong = await start({ localApiOwnerUid: UID + 1 });
    expect(wrong.l.enabled).toBe(false);
    expect(checkLocalApiSocket({ ...wrong.cfg, localApiOwnerUid: UID })).toEqual({ ok: true });
    const missing = checkLocalApiSocket({ ...wrong.cfg, localApiSocketPath: path.join(wrong.api.dir, 'nope.sock') });
    expect(missing.ok).toBe(false);
  });

  it('checkListenerSocket is exported and agrees with startup', async () => {
    const { cfg } = await start();
    expect(checkListenerSocket(cfg)).toEqual({ ok: true });
    fs.chmodSync(cfg.listenerSocketPath, 0o602);
    const r = checkListenerSocket(cfg);
    expect(r.ok).toBe(false);
  });
});

describe('tailscale listener: not this source', () => {
  it('a plain TCP request with forged X-Forwarded-For and Tailscale-User-Login yields null', async () => {
    const ref: { source?: ExternalIdentitySource } = {};
    const { l, cfg, api } = await start();
    ref.source = l.source;
    const tcp = http.createServer(makeHandler(ref));
    await new Promise<void>((r) => tcp.listen(0, '127.0.0.1', r));
    cleanups.push(() => new Promise<void>((r) => { tcp.closeAllConnections(); tcp.close(() => r()); }));
    const forged = { 'x-forwarded-for': PEER, 'tailscale-user-login': 'admin@example.com' };
    expect(await send({ port: (tcp.address() as AddressInfo).port }, forged)).toEqual({ none: true });
    expect(api.seen).toHaveLength(0);
    // Control: the same headers on the listener socket resolve through WhoIs.
    expect((await send(via(cfg), forged)).identity).toBeDefined();
  });
});

describe('tailscale listener: request and node checks', () => {
  async function outcome(canned: Canned | undefined, headers?: Record<string, string>, over = {}) {
    const api = await fakeLocalApi();
    if (canned) api.table.set(PEER, canned);
    const { cfg } = await start(over, api);
    return send(via(cfg), headers);
  }

  it('forged Tailscale-User-Login is ignored: identity comes from WhoIs', async () => {
    const out = await outcome({ body: node() }, { 'x-forwarded-for': PEER, 'tailscale-user-login': 'root@evil' });
    expect(out.identity).toMatchObject({ subject: 'tailscale:node:nAbC123CNTRL' });
    expect(JSON.stringify(out.identity)).not.toContain('root@evil');
  });

  it('uses the last X-Forwarded-For entry', async () => {
    const api = await fakeLocalApi();
    api.table.set(PEER, { body: node() });
    api.table.set('100.64.0.99', { body: node({ StableID: 'nOTHER' }) });
    const { cfg } = await start({}, api);
    const out = await send(via(cfg), { 'x-forwarded-for': `100.64.0.99, ${PEER}` });
    expect(out.identity).toMatchObject({ subject: 'tailscale:node:nAbC123CNTRL' });
    expect(api.seen[0].url).toBe(`/localapi/v0/whois?addr=${PEER}`);
  });

  it('missing or non-IP X-Forwarded-For is refused as no_peer', async () => {
    expect(await outcome({ body: node() }, {})).toEqual({ refusal: 'no_peer' });
    expect(await outcome({ body: node() }, { 'x-forwarded-for': 'agent-1.example-tail.ts.net' })).toEqual({
      refusal: 'no_peer',
    });
    expect(await outcome({ body: node() }, { 'x-forwarded-for': 'fd7a:115c:a1e0::7' })).toMatchObject({
      refusal: 'unknown_node',
    });
  });

  it('Funnel request header is refused', async () => {
    expect(await outcome({ body: node() }, { 'x-forwarded-for': PEER, 'tailscale-funnel-request': '?1' })).toEqual({
      refusal: 'funnel',
    });
  });

  it('unmapped node (WhoIs 404) is refused', async () => {
    expect(await outcome(undefined)).toEqual({ refusal: 'unknown_node' });
  });

  it('WhoIs non-200, bad JSON, oversize body, no Node and timeout are refused', async () => {
    expect(await outcome({ status: 403, body: {} })).toEqual({ refusal: 'whois_failed' });
    expect(await outcome({ raw: '{not json' })).toEqual({ refusal: 'whois_failed' });
    expect(await outcome({ raw: `"${'a'.repeat(1024 * 1024 + 10)}"` })).toEqual({ refusal: 'whois_failed' });
    expect(await outcome({ body: { UserProfile: {} } })).toEqual({ refusal: 'no_node' });
    expect(await outcome({ hang: true })).toEqual({ refusal: 'whois_failed' });
  });

  it('expired node is refused (Expired flag or past KeyExpiry); future KeyExpiry passes', async () => {
    expect(await outcome({ body: node({ Expired: true }) })).toEqual({ refusal: 'expired' });
    expect(await outcome({ body: node({ KeyExpiry: '2001-01-01T00:00:00Z' }) })).toEqual({ refusal: 'expired' });
    expect((await outcome({ body: node({ KeyExpiry: '2999-01-01T00:00:00Z' }) })).identity).toBeDefined();
    expect((await outcome({ body: node({ KeyExpiry: undefined }) })).identity).toBeDefined();
  });

  it('shared-in node (Sharer set) is refused', async () => {
    expect(await outcome({ body: node({ Sharer: 4242 }) })).toEqual({ refusal: 'shared' });
    expect((await outcome({ body: node({ Sharer: 0 }) })).identity).toBeDefined();
  });

  it('WireGuard-only peer and missing StableID are refused', async () => {
    expect(await outcome({ body: node({ IsWireGuardOnly: true }) })).toEqual({ refusal: 'wireguard_only' });
    expect(await outcome({ body: node({ StableID: '' }) })).toEqual({ refusal: 'no_stable_id' });
  });

  it('missing required tag is refused; present tag passes', async () => {
    expect(await outcome({ body: node({ Tags: ['tag:other'] }) }, undefined, { requireTags: ['tag:agent'] })).toEqual(
      { refusal: 'missing_tag' },
    );
    expect(await outcome({ body: node({ Tags: undefined }) }, undefined, { requireTags: ['tag:agent'] })).toEqual({
      refusal: 'missing_tag',
    });
    expect(
      (await outcome({ body: node() }, undefined, { requireTags: ['tag:agent'] })).identity,
    ).toBeDefined();
  });

  it('node outside the tailnet is refused, including suffix look-alikes', async () => {
    expect(await outcome({ body: node({ Name: 'agent-1.other-tail.ts.net.' }) })).toEqual({ refusal: 'outside_tailnet' });
    expect(await outcome({ body: node({ Name: 'agent-1.evilexample-tail.ts.net.' }) })).toEqual({
      refusal: 'outside_tailnet',
    });
    expect(await outcome({ body: node({ Name: `${TAILNET}.` }) })).toEqual({ refusal: 'outside_tailnet' });
    expect((await outcome({ body: node({ Name: `agent-1.${TAILNET}` }) })).identity).toBeDefined();
  });
});

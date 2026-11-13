/**
 * Tailscale node identity as an external identity source.
 *
 * Deployment: the operator runs `tailscale serve` with a `unix:<path>` backend
 * pointing at `listenerSocketPath`; Cred listens on that unix socket. For each
 * request that arrived on that socket, Cred takes the WireGuard source address
 * tailscaled wrote into X-Forwarded-For and asks tailscaled itself, over its
 * LocalAPI socket, which node owns that address (WhoIs). The identity comes
 * only from that WhoIs answer, never from Tailscale-User-* request headers.
 *
 * The X-Forwarded-For value is trustworthy only because nothing but tailscaled
 * can write to the listener socket. So the socket and its directory must be
 * writable only by Cred and the tailscaled user; if that cannot be shown at
 * startup the source stays disabled and refuses every request on the listener.
 *
 * Behavior references are to tailscale/tailscale @ 59064619a0f4ea3293be038e08651c66c2886255.
 */
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import {
  IdentityRefusal,
  type ExternalIdentitySource,
  type IdentityRequest,
  type VerifiedExternalIdentity,
} from './types.js';

export interface TailscaleSourceConfig {
  /** Unix socket Cred listens on; `tailscale serve` proxies to `unix:<this>`. */
  listenerSocketPath: string;
  /** tailscaled LocalAPI socket. Default `/var/run/tailscale/tailscaled.sock`. */
  localApiSocketPath?: string;
  /**
   * MagicDNS suffix, e.g. `example-tail.ts.net`. Node.Name must be
   * `<host>.<tailnet>` with an optional trailing dot.
   */
  tailnet: string;
  /** Every listed tag must be on the node. */
  requireTags?: string[];
  /** Uid Cred runs as. Default `process.getuid()`. */
  credUid?: number;
  /** Uid tailscaled runs as. Default 0. */
  tailscaledUid?: number;
  /** Group-write on the listener socket and directory is allowed only for this gid. */
  allowedGid?: number;
  /** The LocalAPI socket and its directory must be owned by this uid. Default 0. */
  localApiOwnerUid?: number;
  /** WhoIs deadline for the whole request and response. Default 2000. */
  whoisTimeoutMs?: number;
}

export type SocketCheck = { ok: true } | { ok: false; reason: string };

export interface TailscaleListener {
  server: http.Server;
  source: ExternalIdentitySource;
  enabled: boolean;
  disabledReason?: string;
  close(): Promise<void>;
}

export const DEFAULT_LOCALAPI_SOCKET = '/var/run/tailscale/tailscaled.sock';
// client/tailscale/apitype/apitype.go:14 (LocalAPIHost). The LocalAPI handler
// rejects any other Host, and any request carrying Referer or Origin, unless a
// RequiredPassword is configured: ipn/localapi/localapi.go:250-253, 286-293.
const LOCALAPI_HOST = 'local-tailscaled.sock';
const WHOIS_MAX_BYTES = 1024 * 1024;
const IDENTITY_TTL_SECONDS = 60;

const S_IWOTH = 0o002;
const S_IWGRP = 0o020;

function defaultCredUid(): number | undefined {
  return typeof process.getuid === 'function' ? process.getuid() : undefined;
}

function refuse(code: string, detail: string): never {
  throw new IdentityRefusal('tailscale', code, detail);
}

/** lstat-based check of one filesystem entry against an ownership and write-bit policy. */
function checkEntry(
  label: string,
  p: string,
  expect: 'socket' | 'directory',
  allowedUids: readonly number[],
  allowedGid: number | undefined,
  checkWriteBits: boolean,
): SocketCheck {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(p);
  } catch (err) {
    return { ok: false, reason: `${label} ${p}: lstat failed (${(err as NodeJS.ErrnoException).code ?? 'error'})` };
  }
  if (st.isSymbolicLink()) return { ok: false, reason: `${label} ${p} is a symlink` };
  if (expect === 'socket' && !st.isSocket()) return { ok: false, reason: `${label} ${p} is not a socket` };
  if (expect === 'directory' && !st.isDirectory()) return { ok: false, reason: `${label} ${p} is not a directory` };
  if (!allowedUids.includes(st.uid)) {
    return { ok: false, reason: `${label} ${p} is owned by uid ${st.uid}, expected ${allowedUids.join(' or ')}` };
  }
  if (checkWriteBits) {
    if (st.mode & S_IWOTH) return { ok: false, reason: `${label} ${p} is writable by others` };
    if (st.mode & S_IWGRP) {
      if (allowedGid === undefined) {
        return { ok: false, reason: `${label} ${p} is group-writable and no allowedGid is configured` };
      }
      if (st.gid !== allowedGid) {
        return { ok: false, reason: `${label} ${p} is group-writable by gid ${st.gid}, allowed gid is ${allowedGid}` };
      }
    }
  }
  return { ok: true };
}

/**
 * The listener socket and its directory: not symlinks, owned by Cred or the
 * tailscaled user, no other-write, group-write only for `allowedGid`.
 */
export function checkListenerSocket(cfg: TailscaleSourceConfig): SocketCheck {
  const credUid = cfg.credUid ?? defaultCredUid();
  if (credUid === undefined) return { ok: false, reason: 'cannot determine Cred uid on this platform' };
  const uids = [credUid, cfg.tailscaledUid ?? 0];
  const sock = path.resolve(cfg.listenerSocketPath);
  const dir = checkEntry('listener directory', path.dirname(sock), 'directory', uids, cfg.allowedGid, true);
  if (!dir.ok) return dir;
  return checkEntry('listener socket', sock, 'socket', uids, cfg.allowedGid, true);
}

/**
 * The LocalAPI socket and its directory: not symlinks, owned by
 * `localApiOwnerUid`, and the directory has no other-write bit. The socket
 * itself is normally world-connectable, so its mode is not checked.
 */
export function checkLocalApiSocket(cfg: TailscaleSourceConfig): SocketCheck {
  const owner = [cfg.localApiOwnerUid ?? 0];
  const sock = path.resolve(cfg.localApiSocketPath ?? DEFAULT_LOCALAPI_SOCKET);
  const dirPath = path.dirname(sock);
  const dir = checkEntry('LocalAPI directory', dirPath, 'directory', owner, undefined, false);
  if (!dir.ok) return dir;
  try {
    if (fs.lstatSync(dirPath).mode & S_IWOTH) {
      return { ok: false, reason: `LocalAPI directory ${dirPath} is writable by others` };
    }
  } catch {
    return { ok: false, reason: `LocalAPI directory ${dirPath}: lstat failed` };
  }
  return checkEntry('LocalAPI socket', sock, 'socket', owner, undefined, false);
}

/** Removes a stale socket left at `p`, only if it is a socket owned by `credUid`. */
function prepareListenerPath(p: string, credUid: number | undefined): void {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(p);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw err;
  }
  if (!st.isSocket()) throw new Error(`tailscale listener path ${p} exists and is not a socket`);
  if (credUid === undefined || st.uid !== credUid) {
    throw new Error(`tailscale listener path ${p} is a socket owned by uid ${st.uid}, not Cred; refusing to remove it`);
  }
  fs.unlinkSync(p);
}

function headerValue(v: string | string[] | undefined): string | undefined {
  if (v === undefined) return undefined;
  return Array.isArray(v) ? v.join(',') : v;
}

/**
 * The peer address tailscaled forwarded. ipn/ipnlocal/serve.go:1149-1157 sets
 * X-Forwarded-For to the WireGuard source address only (Set, not append, and
 * httputil.ReverseProxy with Rewrite drops inbound X-Forwarded-* before
 * Rewrite runs: serve.go:989). The last entry is taken so that even an
 * appending proxy could not place a caller-chosen value last.
 */
function peerAddress(headers: IdentityRequest['headers']): string | undefined {
  const xff = headerValue(headers['x-forwarded-for']);
  if (xff === undefined) return undefined;
  const parts = xff.split(',');
  const last = parts[parts.length - 1].trim();
  return net.isIP(last) !== 0 ? last : undefined;
}

interface WhoIsNode {
  StableID?: unknown;
  Name?: unknown;
  Tags?: unknown;
  Expired?: unknown;
  KeyExpiry?: unknown;
  Sharer?: unknown;
  IsWireGuardOnly?: unknown;
}

/**
 * GET /localapi/v0/whois?addr=<ip> (ipn/localapi/localapi.go:557-631). A
 * unix-socket client gets PermitRead (ipn/ipnserver/server.go:351-352); no
 * match is a 404 (localapi.go:593-596). The response is
 * apitype.WhoIsResponse (client/tailscale/apitype/apitype.go:35-42).
 */
function whois(socketPath: string, addr: string, timeoutMs: number): Promise<WhoIsNode> {
  return new Promise<WhoIsNode>((resolve, reject) => {
    let settled = false;
    const fail = (code: string, detail: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.destroy();
      reject(new IdentityRefusal('tailscale', code, detail));
    };
    const req = http.request(
      {
        socketPath,
        method: 'GET',
        path: `/localapi/v0/whois?addr=${encodeURIComponent(addr)}`,
        headers: { Host: LOCALAPI_HOST, Accept: 'application/json' },
        agent: false,
      },
      (res) => {
        if (res.statusCode === 404) {
          res.resume();
          return fail('unknown_node', `WhoIs found no node for ${addr}`);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return fail('whois_failed', `WhoIs returned HTTP ${res.statusCode}`);
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (c: Buffer) => {
          size += c.length;
          if (size > WHOIS_MAX_BYTES) return fail('whois_failed', 'WhoIs response exceeds size limit');
          chunks.push(c);
        });
        res.on('error', (err) => fail('whois_failed', `WhoIs response error: ${err.message}`));
        res.on('end', () => {
          if (settled) return;
          let body: unknown;
          try {
            body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch {
            return fail('whois_failed', 'WhoIs response is not JSON');
          }
          const node =
            body !== null && typeof body === 'object' ? (body as { Node?: unknown }).Node : undefined;
          if (node === null || typeof node !== 'object' || Array.isArray(node)) {
            return fail('no_node', 'WhoIs response has no Node');
          }
          settled = true;
          clearTimeout(timer);
          resolve(node as WhoIsNode);
        });
      },
    );
    const timer = setTimeout(() => fail('whois_failed', `WhoIs timed out after ${timeoutMs}ms`), timeoutMs);
    req.on('error', (err) => fail('whois_failed', `WhoIs request failed: ${err.message}`));
    req.end();
  });
}

function normalizeDomain(s: string): string {
  return s.trim().replace(/^\.+/, '').replace(/\.+$/, '').toLowerCase();
}

/** Node checks; field meanings from tailcfg/tailcfg.go:372-549. */
function verifyNode(node: WhoIsNode, cfg: TailscaleSourceConfig, nowMs: number): VerifiedExternalIdentity {
  const stableId = node.StableID;
  if (typeof stableId !== 'string' || stableId === '') refuse('no_stable_id', 'WhoIs Node has no StableID');

  // tailcfg.go:514: computed client-side by tailscaled from control's timestamp.
  if (node.Expired === true) refuse('expired', `node ${stableId} key is expired`);
  // tailcfg.go:391: zero value (omitted, or Go's zero time) means no expiry.
  if (node.KeyExpiry !== undefined && node.KeyExpiry !== null) {
    if (typeof node.KeyExpiry !== 'string') refuse('expired', `node ${stableId} has malformed KeyExpiry`);
    if (!node.KeyExpiry.startsWith('0001-01-01T00:00:00')) {
      const t = Date.parse(node.KeyExpiry);
      if (Number.isNaN(t)) refuse('expired', `node ${stableId} has malformed KeyExpiry`);
      if (t <= nowMs) refuse('expired', `node ${stableId} key expired at ${node.KeyExpiry}`);
    }
  }
  // tailcfg.go:388: non-zero Sharer means the node was shared in from another tailnet.
  if (node.Sharer !== undefined && node.Sharer !== null && node.Sharer !== 0 && node.Sharer !== '') {
    refuse('shared', `node ${stableId} is shared in`);
  }
  // tailcfg.go:549: a plain WireGuard peer, not a Tailscale node.
  if (node.IsWireGuardOnly === true) refuse('wireguard_only', `node ${stableId} is WireGuard-only`);

  // tailcfg.go:376-380: Name is the MagicDNS FQDN with a trailing dot.
  if (typeof node.Name !== 'string' || node.Name === '') refuse('outside_tailnet', `node ${stableId} has no Name`);
  const name = normalizeDomain(node.Name);
  const tailnet = normalizeDomain(cfg.tailnet);
  if (tailnet === '' || !name.endsWith(`.${tailnet}`) || name.length <= tailnet.length + 1) {
    refuse('outside_tailnet', `node ${stableId} name ${node.Name} is not under ${cfg.tailnet}`);
  }

  let tags: string[] = [];
  if (node.Tags !== undefined && node.Tags !== null) {
    if (!Array.isArray(node.Tags) || !node.Tags.every((t) => typeof t === 'string')) {
      refuse('bad_tags', `node ${stableId} has malformed Tags`);
    }
    tags = [...(node.Tags as string[])];
  }
  for (const required of cfg.requireTags ?? []) {
    if (!tags.includes(required)) refuse('missing_tag', `node ${stableId} lacks required tag ${required}`);
  }

  return {
    kind: 'tailscale',
    subject: `tailscale:node:${stableId}`,
    trustDomain: tailnet,
    attributes: { nodeName: node.Name, tags },
    proof: 'channel',
    expiresAt: Math.floor(nowMs / 1000) + IDENTITY_TTL_SECONDS,
  };
}

/**
 * Starts the HTTP server on the listener unix socket, then runs the socket
 * checks. Requests are refused until the checks pass, and for the life of the
 * listener if they fail. The caller logs `disabledReason`.
 */
export async function startTailscaleListener(
  handler: http.RequestListener,
  cfg: TailscaleSourceConfig,
): Promise<TailscaleListener> {
  const socketPath = path.resolve(cfg.listenerSocketPath);
  const localApiSocketPath = cfg.localApiSocketPath ?? DEFAULT_LOCALAPI_SOCKET;
  const credUid = cfg.credUid ?? defaultCredUid();
  const timeoutMs = cfg.whoisTimeoutMs ?? 2000;

  prepareListenerPath(socketPath, credUid);

  const accepted = new WeakSet<object>();
  const state: { enabled: boolean; disabledReason?: string } = {
    enabled: false,
    disabledReason: 'startup checks have not completed',
  };

  const server = http.createServer(handler);
  server.on('connection', (s) => accepted.add(s));

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    server.once('error', onError);
    server.listen(socketPath, () => {
      server.off('error', onError);
      resolve();
    });
  });

  let reason: string | undefined;
  try {
    if (cfg.allowedGid !== undefined) {
      try {
        fs.chownSync(socketPath, -1, cfg.allowedGid);
      } catch {
        // The ownership check below reports a gid mismatch.
      }
      fs.chmodSync(socketPath, 0o660);
    } else {
      fs.chmodSync(socketPath, 0o600);
    }
  } catch (err) {
    reason = `cannot set listener socket mode: ${(err as Error).message}`;
  }
  if (reason === undefined) {
    const l = checkListenerSocket({ ...cfg, credUid });
    if (!l.ok) reason = l.reason;
  }
  if (reason === undefined) {
    const a = checkLocalApiSocket(cfg);
    if (!a.ok) reason = a.reason;
  }
  if (reason === undefined) {
    state.enabled = true;
    state.disabledReason = undefined;
  } else {
    state.disabledReason = reason;
  }

  const source: ExternalIdentitySource = {
    kind: 'tailscale',
    async authenticate(req: IdentityRequest): Promise<VerifiedExternalIdentity | null> {
      // Not accepted by this listener: Tailscale headers on any other
      // connection are not a Tailscale identity.
      if (typeof req.socket !== 'object' || req.socket === null || !accepted.has(req.socket)) return null;
      if (!state.enabled) refuse('source_disabled', state.disabledReason ?? 'disabled');
      // ipn/ipnlocal/serve.go:1173-1176: set by tailscaled for Funnel (public
      // internet) traffic, after stripping any inbound copy (serve.go:1161-1167).
      if (headerValue(req.headers['tailscale-funnel-request']) !== undefined) {
        refuse('funnel', 'request arrived through Tailscale Funnel');
      }
      const addr = peerAddress(req.headers);
      if (addr === undefined) refuse('no_peer', 'X-Forwarded-For has no peer IP address');
      const node = await whois(localApiSocketPath, addr, timeoutMs);
      return verifyNode(node, cfg, Date.now());
    },
  };

  return {
    server,
    source,
    get enabled() {
      return state.enabled;
    },
    get disabledReason() {
      return state.disabledReason;
    },
    close(): Promise<void> {
      return new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    },
  };
}

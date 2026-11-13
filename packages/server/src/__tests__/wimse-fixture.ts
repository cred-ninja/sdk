/**
 * A real WIMSE trust domain for server tests: a WIT issuer, a workload key,
 * WIT minting, and HTTP-signature / WPT request signing in the shape
 * supertest sends. No fakes: requests go through createWimseIdentitySource.
 */
import request from 'supertest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createDpopProof } from '@credninja/sdk';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';
import { createWimseIdentitySource, type WimseSourceConfig } from '../identity/wimse.js';
import { loadTrustBundle, type TrustAnchorKeys } from '../identity/trust-bundle.js';
import { signWimseRequest } from '../identity/http-signature.js';
import { createReplayCache, type ExternalIdentityMapping } from '../identity/types.js';
import { newAgent, type AgentIdentity } from './token-helpers.js';
import type { TxnTokenTrust } from '../identity/txn-token.js';

export const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
export const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
export const BASE = 'http://localhost:3456';
export const CALENDAR = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
export const sha256b64url = (s: string) => crypto.createHash('sha256').update(s, 'ascii').digest('base64url');

export function es256Jws(header: object, claims: object, key: crypto.KeyObject): string {
  const input = `${b64(header)}.${b64(claims)}`;
  return `${input}.${crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

export interface TrustDomain {
  name: string;
  anchors: TrustAnchorKeys;
  issuer: crypto.KeyPairKeyObjectResult;
  /** A workload in this domain with its own key and WIT. */
  workload(subPath?: string, claims?: Record<string, unknown>): Workload;
}

export interface Workload {
  subject: string;
  wit: string;
  key: crypto.KeyPairKeyObjectResult;
}

export function trustDomain(name: string): TrustDomain {
  const issuer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const anchors = loadTrustBundle(
    { jwks: { keys: [{ ...issuer.publicKey.export({ format: 'jwk' }), kid: `${name}-k1`, use: 'wit-svid' } as any] } },
    { keyUse: 'wit-svid' },
  );
  return {
    name,
    anchors,
    issuer,
    workload(subPath = '/agent/planner', claims = {}) {
      const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const now = Math.floor(Date.now() / 1000);
      const subject = `spiffe://${name}${subPath}`;
      const wit = es256Jws({ alg: 'ES256', kid: `${name}-k1`, typ: 'wit+jwt' }, {
        sub: subject, iat: now - 10, exp: now + 3600,
        cnf: { jwk: { ...key.publicKey.export({ format: 'jwk' }), alg: 'ES256' } }, ...claims,
      }, issuer.privateKey);
      return { subject, wit, key };
    },
  };
}

/** A Txn-Token Service for one trust domain (draft-ietf-oauth-transaction-tokens-11 §9). */
export function txnIssuer(aud: string) {
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kid = `${aud}-tts`;
  const keys = loadTrustBundle(
    { jwks: { keys: [{ ...key.publicKey.export({ format: 'jwk' }), kid, use: 'sig' } as any] } },
    { keyUse: 'sig' },
  );
  return {
    keys,
    mint(claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}): string {
      const now = Math.floor(Date.now() / 1000);
      return es256Jws({ alg: 'ES256', typ: 'txntoken+jwt', kid, ...header }, {
        iat: now - 5, exp: now + 300, aud, txn: crypto.randomUUID(), sub: 'user:default',
        scope: 'calendar.read', req_wl: `gateway.${aud}`, ...claims,
      }, key.privateKey);
    },
    trust(over: Partial<TxnTokenTrust> = {}): TxnTokenTrust {
      return {
        aud, keys,
        userSubject: { claim: 'sub', pattern: '^user:([A-Za-z0-9._@-]{1,128})$' },
        scopeMap: { google: { 'calendar.read': ['calendar.readonly'], 'calendar.write': ['calendar.events'] } },
        ...over,
      };
    },
  };
}

/** Headers for an HTTP-signed request to `pathAndQuery` on the test server. */
export function httpSigHeaders(w: Workload, method: string, pathAndQuery: string, opts: {
  body?: string;
  headers?: Record<string, string>;
  audience?: string;
  signResponse?: boolean;
  created?: number;
} = {}): Record<string, string> {
  const [p, q] = pathAndQuery.split('?');
  return signWimseRequest({
    method,
    path: p,
    query: q,
    headers: opts.headers ?? {},
    body: opts.body === undefined ? undefined : Buffer.from(opts.body),
    wit: w.wit,
    privateKey: w.key.privateKey,
    alg: 'ES256',
    audience: opts.audience ?? `${BASE}${p}`,
    signResponse: opts.signResponse,
    created: opts.created,
  });
}

/** Headers for a WIT + WPT request (wpt-02). */
export function wptHeaders(w: Workload, pathOnly: string, extra: Record<string, unknown> = {}): Record<string, string> {
  const now = Math.floor(Date.now() / 1000);
  const wpt = es256Jws({ alg: 'ES256', typ: 'wpt+jwt' }, {
    aud: `${BASE}${pathOnly}`, exp: now + 60, jti: crypto.randomBytes(16).toString('base64url'), wth: sha256b64url(w.wit), ...extra,
  }, w.key.privateKey);
  return { 'workload-identity-token': w.wit, authorization: `WPT ${wpt}` };
}

export function send(app: any, method: 'get' | 'post', pathAndQuery: string, headers: Record<string, string>, body?: string) {
  let r = request(app)[method](pathAndQuery);
  for (const [k, v] of Object.entries(headers)) r = r.set(k, v);
  if (body !== undefined) r = r.set('content-type', headers['content-type'] ?? 'application/json').send(body);
  return r;
}

const dirs: string[] = [];
export function cleanupDirs(): void {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
}

/**
 * A server trusting `domains`, with one agent mapped from `mapSubject`, a
 * stored Google connection for user `default` and a Permission for
 * calendar.readonly (plus `extraScopes`).
 */
export async function wimseServer(opts: {
  domains: TrustDomain[];
  mapSubject: (agent: AgentIdentity) => ExternalIdentityMapping[] | string;
  config?: Partial<ServerConfig>;
  source?: Partial<WimseSourceConfig>;
  scopes?: string[];
  txnTokens?: Record<string, TxnTokenTrust>;
}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-wimse-'));
  dirs.push(dir);
  const agent = await newAgent();
  const source = createWimseIdentitySource({
    trustDomains: Object.fromEntries(opts.domains.map((d) => [d.name, d.anchors])),
    replay: createReplayCache(),
    ...opts.source,
  });
  const mapped = opts.mapSubject(agent);
  const mappings = typeof mapped === 'string' ? [{ kind: 'wimse' as const, subject: mapped, agentDid: agent.did }] : mapped;
  const scopes = opts.scopes ?? ['calendar.readonly'];
  const server = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'sqlite', tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: ADMIN, agentToken: BEARER, redirectBaseUri: BASE,
    providers: [{ slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: [] }],
    externalIdentity: { sources: [source], mappings, ...(opts.txnTokens ? { txnTokens: opts.txnTokens } : {}) },
    ...opts.config,
  });
  await server.vault.init();
  await server.tofu.init();
  const now = new Date().toISOString();
  await server.vault.registerAgent({
    id: `agt_${crypto.randomBytes(6).toString('hex')}`, did: agent.did, fingerprint: crypto.randomBytes(16).toString('hex'),
    name: 'planner', scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now,
  });
  await server.vault.store({
    provider: 'google', userId: 'default', accessToken: 'ya29.wimse', refreshToken: '1//r',
    expiresAt: new Date(Date.now() + 3600_000), scopes,
  });
  const perm = await request(server.app).post('/admin/permissions').set('Authorization', `Bearer ${ADMIN}`)
    .send({ agentId: agent.did, connectionId: 'google', allowedScopes: scopes });
  return { ...server, agent, permissionId: perm.body.permission?.id as string, dir };
}

/** POST /api/v1/delegate authenticated by WIT + HTTP-sig, with the agent's DPoP for the token binding. */
export function delegateWithHttpSig(app: any, agent: AgentIdentity, w: Workload, body: Record<string, unknown> = {}, extraHeaders: Record<string, string> = {}) {
  const json = JSON.stringify({ token_format: 'handle', agent_did: agent.did, service: 'google', user_id: 'default', scopes: ['calendar.readonly'], ...body });
  const headers = httpSigHeaders(w, 'POST', '/api/v1/delegate', { body: json, headers: { 'content-type': 'application/json', ...extraHeaders } });
  return send(app, 'post', '/api/v1/delegate', { ...headers, dpop: createDpopProof(agent, 'POST', `${BASE}/api/v1/delegate`) }, json);
}

/**
 * POST /api/v1/use with the Delegation Token and DPoP proof, plus a WIT and
 * HTTP signature over the whole request (Authorization included).
 */
export function useWithHttpSig(app: any, agent: AgentIdentity, token: string, w: Workload | null, body: Record<string, unknown>, opts: {
  extraHeaders?: Record<string, string>;
  tamper?: (h: Record<string, string>) => void;
} = {}) {
  const json = JSON.stringify(body);
  const base = {
    'content-type': 'application/json',
    authorization: `DPoP ${token}`,
    dpop: createDpopProof(agent, 'POST', `${BASE}/api/v1/use`, token, body),
    ...opts.extraHeaders,
  };
  const headers = w ? httpSigHeaders(w, 'POST', '/api/v1/use', { body: json, headers: base }) : base;
  opts.tamper?.(headers);
  return send(app, 'post', '/api/v1/use', headers, json);
}

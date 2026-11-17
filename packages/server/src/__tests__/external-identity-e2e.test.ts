/**
 * The real WIMSE and Tailscale sources in front of the real server: a
 * request authenticates as a mapped agent end to end, and the refusals that
 * only show at that level are refused there. Tailscale uses a fake LocalAPI;
 * no tailnet is involved.
 */
import { describe, it, expect, afterEach } from 'vitest';
import request from 'supertest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto, { generateKeyPairSync } from 'node:crypto';
import { createDpopProof } from '@credninja/sdk';
import { createServer } from '../server.js';
import { createWimseIdentitySource } from '../identity/wimse.js';
import { loadTrustBundle } from '../identity/trust-bundle.js';
import { startTailscaleListener } from '../identity/tailscale.js';
import { createReplayCache, type ExternalIdentitySource, type ExternalIdentityMapping } from '../identity/types.js';
import { newAgent, type AgentIdentity } from './token-helpers.js';

const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const TD = 'prod.example';
const SUB = `spiffe://${TD}/ns/agents/sa/planner`;
const TAILNET = 'example-tail.ts.net';
const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()!(); });

function tmp(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cxe-'));
  fs.chmodSync(d, 0o700);
  cleanups.push(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
}

async function server(sources: ExternalIdentitySource[], mappings: (agent: AgentIdentity) => ExternalIdentityMapping[]) {
  const dir = tmp();
  const agent = await newAgent();
  const s = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'sqlite', tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: ADMIN, agentToken: BEARER, redirectBaseUri: BASE,
    providers: [{ slug: 'google', clientId: 'id', clientSecret: 'secret', defaultScopes: [] }],
    externalIdentity: { sources, mappings: mappings(agent) },
  });
  await s.vault.init();
  await s.tofu.init();
  const now = new Date().toISOString();
  await s.vault.registerAgent({ id: 'agt_e2e', did: agent.did, fingerprint: crypto.randomBytes(16).toString('hex'), name: 'planner', scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now });
  return { ...s, agent };
}

// ── WIMSE ───────────────────────────────────────────────────────────────────
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
function es256(header: object, claims: object, key: crypto.KeyObject): string {
  const input = `${b64(header)}.${b64(claims)}`;
  return `${input}.${crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}
const sha = (s: string) => crypto.createHash('sha256').update(s, 'ascii').digest('base64url');

function wimse() {
  const issuer = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const workload = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const bundle = { keys: [{ ...issuer.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'wit-svid' }] };
  const source = createWimseIdentitySource({ trustDomains: { [TD]: loadTrustBundle({ jwks: bundle as any }, { keyUse: 'wit-svid' }) }, replay: createReplayCache() });
  const now = Math.floor(Date.now() / 1000);
  const wit = es256({ alg: 'ES256', kid: 'k1', typ: 'wit+jwt' },
    { sub: SUB, iat: now - 10, exp: now + 3600, cnf: { jwk: { ...workload.publicKey.export({ format: 'jwk' }), alg: 'ES256' } } }, issuer.privateKey);
  const headers = (aud: string) => ({
    'Workload-Identity-Token': wit,
    Authorization: `WPT ${es256({ alg: 'ES256', typ: 'wpt+jwt' }, { aud, exp: now + 60, jti: crypto.randomBytes(16).toString('base64url'), wth: sha(wit) }, workload.privateKey)}`,
  });
  return { source, headers };
}

describe('WIMSE workload identity through the server', () => {
  it('a mapped workload reaches an agent route with its WIT and WPT, and no agent token', async () => {
    const w = wimse();
    const { app } = await server([w.source], (a) => [{ kind: 'wimse', subject: SUB, agentDid: a.did }]);
    const res = await request(app).get('/api/v1/connections?user_id=default').set(w.headers(`${BASE}/api/v1/connections`));
    expect(res.status).toBe(200);
  });

  it('a WPT addressed to another route of the same broker is refused', async () => {
    const w = wimse();
    const { app } = await server([w.source], (a) => [{ kind: 'wimse', subject: SUB, agentDid: a.did }]);
    const res = await request(app).get('/api/v1/connections?user_id=default').set(w.headers(`${BASE}/api/v1/providers`));
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toBe('WPT');
  });
});

// ── Tailscale ───────────────────────────────────────────────────────────────
async function fakeLocalApi(peer: string, stableId: string) {
  const dir = tmp();
  const socketPath = path.join(dir, 'tailscaled.sock');
  const api = http.createServer((req, res) => {
    const addr = new URL(req.url ?? '/', 'http://local').searchParams.get('addr');
    if (addr !== peer) { res.writeHead(404); res.end('no match'); return; }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ Node: { StableID: stableId, Name: `agent-1.${TAILNET}.`, Tags: ['tag:agent'] }, UserProfile: {}, CapMap: {} }));
  });
  await new Promise<void>((r) => api.listen(socketPath, r));
  cleanups.push(() => new Promise<void>((r) => api.close(() => r())));
  return socketPath;
}

function viaSocket(socketPath: string, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath, path: '/api/v1/connections?user_id=default', method: 'GET', headers }, (res) => { res.resume(); resolve(res.statusCode ?? 0); });
    req.on('error', reject);
    req.end();
  });
}

describe('Tailscale node identity through the server', () => {
  async function tailnet(listenerDirMode: number) {
    const localApiSocketPath = await fakeLocalApi('100.64.0.7', 'nNODE1');
    const listenerDir = tmp();
    fs.chmodSync(listenerDir, listenerDirMode);
    cleanups.push(() => fs.chmodSync(listenerDir, 0o700));
    const listenerSocketPath = path.join(listenerDir, 'ts.sock');
    let source: ExternalIdentitySource | undefined;
    const lazy: ExternalIdentitySource = { kind: 'tailscale', authenticate: (r) => source!.authenticate(r) };
    const s = await server([lazy], (a) => [{ kind: 'tailscale', subject: 'tailscale:node:nNODE1', agentDid: a.did }]);
    const listener = await startTailscaleListener(s.app, {
      listenerSocketPath, localApiSocketPath, tailnet: TAILNET, localApiOwnerUid: process.getuid!(),
    });
    source = listener.source;
    cleanups.push(() => listener.close());
    const dpop = () => createDpopProof(s.agent, 'GET', `${BASE}/api/v1/connections`);
    return { ...s, listener, listenerSocketPath, dpop };
  }

  it('a tailnet peer authenticates as its mapped agent with a DPoP proof', async () => {
    const t = await tailnet(0o700);
    expect(t.listener.enabled).toBe(true);
    expect(await viaSocket(t.listenerSocketPath, { 'X-Forwarded-For': '100.64.0.7', DPoP: t.dpop() })).toBe(200);
    // The same peer without the agent's DPoP proof is the node, not the agent.
    expect(await viaSocket(t.listenerSocketPath, { 'X-Forwarded-For': '100.64.0.7' })).toBe(401);
  });

  it('forged X-Forwarded-For through a socket that fails the ownership and mode check is refused', async () => {
    const t = await tailnet(0o777);
    expect(t.listener.enabled).toBe(false);
    expect(await viaSocket(t.listenerSocketPath, { 'X-Forwarded-For': '100.64.0.7', DPoP: t.dpop() })).toBe(401);
  });

  it('a TCP request forging the tailnet headers gets no Tailscale identity', async () => {
    const t = await tailnet(0o700);
    const res = await request(t.app).get('/api/v1/connections?user_id=default')
      .set('X-Forwarded-For', '100.64.0.7').set('Tailscale-User-Login', 'admin@example.com').set('DPoP', t.dpop());
    expect(res.status).toBe(401);
    expect(res.body.error).not.toBe('invalid_tailnet_identity');
  });
});

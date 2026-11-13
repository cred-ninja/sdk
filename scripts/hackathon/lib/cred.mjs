// Start a Cred server for the hackathon from a plain JSON configuration:
// trusted WIMSE trust domains (trust bundle files), optional Txn-Token trust
// per domain, and the agents that workloads map to. Uses the built packages
// (run `npm run build` first; demo.mjs and serve.mjs do it when needed).
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
export const serverDist = path.join(root, 'packages/server/dist/index.js');
export const sdkDist = path.join(root, 'packages/sdk/dist/esm/index.js');

export async function loadPackages() {
  if (!fs.existsSync(serverDist) || !fs.existsSync(sdkDist)) {
    throw new Error('Cred is not built. Run `npm ci && npm run build` from the repository root first.');
  }
  const server = await import(serverDist);
  const sdk = await import(sdkDist);
  return { server, sdk };
}

async function freePort(host) {
  const s = http.createServer();
  await new Promise((r) => s.listen(0, host, r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

/**
 * Config shape (see docs/HACKATHON.md):
 * {
 *   host, port (0: any free port), publicUrl (optional; default http://host:port),
 *   trustDomains: { "<td>": { witBundle: "<path to JWKS / SPIFFE bundle>", keyUse: "wit-svid" } },
 *   txnTokens: { "<td>": { aud, jwks: "<path>", keyUse: "sig", userSubject: { claim, pattern }, scopeMap, required } },
 *   httpSignature: { audiences: [], minNonceLength },
 *   user: "alice", connectionScopes: [...],
 *   agents: [ { name, workload: "spiffe://<td>/<path>", allowedScopes: [...] } ]
 * }
 */
export async function startCred(cfg, { stateDir, quiet = true } = {}) {
  const { server: cred, sdk } = await loadPackages();
  const host = cfg.host ?? '127.0.0.1';
  const port = cfg.port && cfg.port !== 0 ? cfg.port : await freePort(host);
  const baseUrl = (cfg.publicUrl ?? `http://${host}:${port}`).replace(/\/$/, '');
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const adminToken = `cred_admin_${crypto.randomBytes(24).toString('hex')}`;
  const agentToken = `cred_at_${crypto.randomBytes(24).toString('hex')}`;

  // Trust anchors, loaded from files exchanged out of band.
  const trustDomains = {};
  for (const [td, t] of Object.entries(cfg.trustDomains ?? {})) {
    trustDomains[td] = cred.loadTrustBundle({ path: t.witBundle }, { keyUse: t.keyUse ?? 'wit-svid' });
  }
  const txnTokens = {};
  for (const [td, t] of Object.entries(cfg.txnTokens ?? {})) {
    txnTokens[td] = {
      aud: t.aud ?? td,
      keys: cred.loadTrustBundle({ path: t.jwks }, { keyUse: t.keyUse ?? 'sig' }),
      ...(t.userSubject ? { userSubject: t.userSubject } : {}),
      scopeMap: t.scopeMap ?? {},
      ...(t.required === false ? { required: false } : {}),
    };
  }

  // One did:key identity per agent; a workload maps to exactly one agent.
  const agents = {};
  const mappings = [];
  for (const a of cfg.agents ?? []) {
    const identity = await sdk.generateAgentIdentity();
    agents[a.name] = { ...a, identity, did: identity.did };
    if (a.workload) mappings.push({ kind: 'wimse', subject: a.workload, agentDid: identity.did });
  }

  const source = cred.createWimseIdentitySource({
    trustDomains,
    replay: cred.createReplayCache(),
    httpSignature: cfg.httpSignature ?? {},
  });

  const logs = [];
  const originalWarn = console.warn;
  if (quiet) console.warn = (...args) => logs.push(args.join(' '));

  const s = cred.createServer({
    port, host,
    vaultPassphrase: crypto.randomBytes(24).toString('hex'),
    vaultStorage: 'sqlite', vaultPath: path.join(stateDir, 'vault.sqlite'),
    tofuStorage: 'sqlite', tofuPath: path.join(stateDir, 'tofu.sqlite'),
    adminToken, agentToken, redirectBaseUri: baseUrl,
    providers: [{ slug: 'google', clientId: 'hackathon-demo', clientSecret: 'hackathon-demo', defaultScopes: [] }],
    externalIdentity: { sources: [source], mappings, ...(Object.keys(txnTokens).length ? { txnTokens } : {}) },
  });
  await s.vault.init();
  await s.tofu.init();

  const now = new Date().toISOString();
  const user = cfg.user ?? 'alice';
  // The user's delegated credential at the provider (a placeholder token for the mock provider).
  await s.vault.store({
    provider: 'google', userId: user, accessToken: `ya29.demo-${crypto.randomBytes(6).toString('hex')}`, refreshToken: '1//demo',
    expiresAt: new Date(Date.now() + 3600_000), scopes: cfg.connectionScopes ?? ['calendar.readonly', 'calendar.events'],
  });
  const httpServer = http.createServer(s.app);
  await new Promise((r) => httpServer.listen(port, host, r));

  const admin = (method, p, body) => fetch(`${baseUrl}${p}`, {
    method, headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));

  for (const a of Object.values(agents)) {
    await s.vault.registerAgent({
      id: `agt_${a.name}`, did: a.did, fingerprint: crypto.randomBytes(16).toString('hex'),
      name: a.name, scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: now, updatedAt: now,
    });
    if (a.allowedScopes?.length) {
      const p = await admin('POST', '/admin/permissions', { agentId: a.did, connectionId: 'google', allowedScopes: a.allowedScopes });
      if (p.status >= 300) throw new Error(`permission for ${a.name}: ${p.status} ${JSON.stringify(p.body)}`);
      a.permissionId = p.body?.permission?.id;
    }
  }

  return {
    baseUrl, adminToken, agentToken, agents, user, vault: s.vault, logs, sdk, cred, admin,
    async close() {
      console.warn = originalWarn;
      httpServer.closeAllConnections();
      await new Promise((r) => httpServer.close(r));
    },
  };
}

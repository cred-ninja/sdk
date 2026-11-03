import { describe, it, expect, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import request from 'supertest';
import { CredGuard, rateLimitPolicy, scopeFilterPolicy } from '@credninja/guard';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

const ADMIN = 'admin-token-for-policy-tests';
const tmpDirs: string[] = [];

afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-admin-policy-'));
  tmpDirs.push(dir);
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'file',
    tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN,
    agentToken: 'cred_at_policy_tests',
    providers: [{ slug: 'github', clientId: 'id', clientSecret: 'secret', defaultScopes: ['repo'] }],
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}

function buildGuard() {
  return new CredGuard({
    policies: [
      rateLimitPolicy({ maxRequests: 100, windowMs: 60_000 }),
      scopeFilterPolicy({ allowedScopes: { github: ['repo', 'gist'] } }),
    ],
    decisionHistorySize: 100,
  });
}

describe('GET /admin/policy', () => {
  it('does not exist by default, nor with a guard alone', async () => {
    const a = createServer(config());
    await a.vault.init();
    expect((await request(a.app).get('/admin/policy').set('Authorization', `Bearer ${ADMIN}`)).status).toBe(404);
    const b = createServer(config({ guard: buildGuard() }));
    await b.vault.init();
    expect((await request(b.app).get('/admin/policy').set('Authorization', `Bearer ${ADMIN}`)).status).toBe(404);
  });

  it('requires admin auth', async () => {
    const { app, vault } = createServer(config({ guard: buildGuard(), policyDiagnostics: true }));
    await vault.init();
    expect((await request(app).get('/admin/policy')).status).toBe(401);
    expect((await request(app).get('/admin/policy').set('Authorization', 'Bearer wrong')).status).toBe(401);
  });

  it('reports the snapshot, interpretation and findings from recorded decisions, and changes nothing', async () => {
    const guard = buildGuard();
    const { app, vault } = createServer(config({ guard, policyDiagnostics: true, policyDiagnosisOptions: { minObservations: 5 } }));
    await vault.init();
    for (let i = 0; i < 6; i += 1) {
      await guard.evaluate({ provider: 'github', agentTokenHash: 'a', requestedScopes: ['repo'], consentedScopes: ['repo'], timestamp: new Date().toISOString() });
    }
    const before = (await guard.evaluate({ provider: 'github', agentTokenHash: 'a', requestedScopes: ['gist'], consentedScopes: ['gist'], timestamp: new Date().toISOString() })).allowed;
    expect(before).toBe(true);

    const res = await request(app).get('/admin/policy').set('Authorization', `Bearer ${ADMIN}`);
    expect(res.status).toBe(200);
    expect(res.body.snapshot.policies.map((entry: any) => entry.name)).toEqual(['rate-limit', 'scope-filter']);
    expect(res.body.interpretation.providers[0]).toMatchObject({ provider: 'github', allowedScopes: ['repo', 'gist'] });
    expect(res.body.diagnosis.observed.events).toBe(7);
    const unused = res.body.diagnosis.findings.find((finding: any) => finding.code === 'unused-allowed-scope');
    expect(unused).toBeUndefined(); // gist was requested once, so it is in use
    const slack = res.body.diagnosis.findings.find((finding: any) => finding.code === 'rate-limit-slack');
    expect(slack?.suggestedEffect).toBe('narrowing');

    const partial = await request(app).get('/admin/policy?include=interpretation').set('Authorization', `Bearer ${ADMIN}`);
    expect(partial.status).toBe(200);
    expect(partial.body.snapshot).toBeUndefined();
    expect(partial.body.snapshotHash).toBe(res.body.snapshot.hash);
    expect(partial.body.diagnosis).toBeUndefined();

    // Read-only: the guard's chain and behaviour are unchanged.
    expect(guard.getPolicyNames()).toEqual(['rate-limit', 'scope-filter']);
    expect((await guard.evaluate({ provider: 'github', agentTokenHash: 'a', requestedScopes: ['gist'], consentedScopes: ['gist'], timestamp: new Date().toISOString() })).allowed).toBe(true);
    expect(vault.queryAuditEvents({ limit: 50 }).filter((event) => (event.resource.type as string) === 'policy')).toEqual([]);
  });
});

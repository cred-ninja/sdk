import { describe, it, expect, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import request from 'supertest';
import {
  CredGuard,
  rateLimitPolicy,
  scopeFilterPolicy,
  PolicyWeightSpaceEditor,
  generateApproverKeyPair,
  signProposal,
} from '@credninja/guard';
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

describe('/admin/policy', () => {
  it('does not exist without a policy editor', async () => {
    const { app, vault } = createServer(config({ guard: buildGuard() }));
    await vault.init();
    const res = await request(app).get('/admin/policy').set('Authorization', `Bearer ${ADMIN}`);
    expect(res.status).toBe(404);
  });

  it('requires admin auth', async () => {
    const guard = buildGuard();
    const { app, vault } = createServer(config({ guard, policyEditor: new PolicyWeightSpaceEditor(guard) }));
    await vault.init();
    expect((await request(app).get('/admin/policy')).status).toBe(401);
    expect((await request(app).post('/admin/policy/proposals').send({ patch: [], rationale: 'x' })).status).toBe(401);
  });

  it('inspects, proposes, refuses an unsigned apply, applies a signed one, and audits each step', async () => {
    const guard = buildGuard();
    const approver = generateApproverKeyPair();
    const editor = new PolicyWeightSpaceEditor(guard, { approvers: [{ id: 'kieran', publicKey: approver.publicKey }] });
    const { app, vault } = createServer(config({ guard, policyEditor: editor }));
    await vault.init();
    const admin = () => ({ Authorization: `Bearer ${ADMIN}` });

    const inspect = await request(app).get('/admin/policy').set(admin());
    expect(inspect.status).toBe(200);
    expect(inspect.body.snapshot.policies.map((entry: any) => entry.name)).toEqual(['rate-limit', 'scope-filter']);
    expect(inspect.body.interpretation.providers[0].allowedScopes).toEqual(['repo', 'gist']);
    expect(inspect.body.pendingProposals).toEqual([]);

    const bad = await request(app).post('/admin/policy/proposals').set(admin()).send({
      patch: [{ op: 'replace', path: '/rate-limit/maxRequests', value: 'many' }],
      rationale: 'x',
    });
    expect(bad.status).toBe(400);
    expect(bad.body.error).toBe('invalid_patch');

    const proposed = await request(app).post('/admin/policy/proposals').set(admin()).send({
      patch: [{ op: 'remove', path: '/scope-filter/allowedScopes/github/1' }],
      rationale: 'gist is unused',
      proposer: 'did:key:z6MkAgent',
    });
    expect(proposed.status).toBe(201);
    const proposal = proposed.body.proposal;
    expect(proposal.classification.effect).toBe('narrowing');
    expect(proposal.classification.magnitude.touched).toBe(1);
    expect(proposed.body.approvalRequired).toBe(true);

    const fetched = await request(app).get(`/admin/policy/proposals/${proposal.id}`).set(admin());
    expect(fetched.status).toBe(200);
    expect(fetched.body.proposal.hash).toBe(proposal.hash);

    const unsigned = await request(app).post(`/admin/policy/proposals/${proposal.id}/apply`).set(admin()).send({});
    expect(unsigned.status).toBe(403);
    expect(unsigned.body.error).toBe('approval_required');

    const applied = await request(app).post(`/admin/policy/proposals/${proposal.id}/apply`).set(admin()).send({
      approvals: [signProposal(proposal, 'kieran', approver.privateKey)],
    });
    expect(applied.status).toBe(200);
    expect(applied.body).toMatchObject({ applied: true, approvers: ['kieran'], rebuilt: ['scope-filter'], kept: ['rate-limit'] });

    const gone = await request(app).post(`/admin/policy/proposals/${proposal.id}/apply`).set(admin()).send({});
    expect(gone.status).toBe(404);

    const decision = await guard.evaluate({
      provider: 'github', agentTokenHash: 'x', requestedScopes: ['gist'], consentedScopes: ['gist'], timestamp: new Date().toISOString(),
    });
    expect(decision.allowed).toBe(false);

    const audit = vault.queryAuditEvents({ limit: 50 }).filter((event) => event.resource.type === 'policy');
    expect(audit.map((event) => [event.action, event.outcome])).toEqual(expect.arrayContaining([
      ['create', 'success'],
      ['deny', 'denied'],
      ['update', 'success'],
    ]));
    const update = audit.find((event) => event.action === 'update');
    expect(update?.resource.id).toBe(proposal.id);
    expect(update?.metadata).toMatchObject({ approvers: ['kieran'], effect: 'narrowing', rebuilt: ['scope-filter'] });
  });

  it('answers 409 when the chain moved under a proposal', async () => {
    const guard = buildGuard();
    const approver = generateApproverKeyPair();
    const editor = new PolicyWeightSpaceEditor(guard, { approvers: [{ id: 'kieran', publicKey: approver.publicKey }] });
    const { app, vault } = createServer(config({ guard, policyEditor: editor }));
    await vault.init();
    const proposed = await request(app).post('/admin/policy/proposals').set('Authorization', `Bearer ${ADMIN}`).send({
      patch: [{ op: 'replace', path: '/rate-limit/maxRequests', value: 10 }],
      rationale: 'tighter',
    });
    guard.addPolicy({ name: 'extra', evaluate: () => ({ decision: 'ALLOW', policy: 'extra' }) });
    const res = await request(app).post(`/admin/policy/proposals/${proposed.body.proposal.id}/apply`).set('Authorization', `Bearer ${ADMIN}`).send({
      approvals: [signProposal(proposed.body.proposal, 'kieran', approver.privateKey)],
    });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('base_mismatch');
  });
});

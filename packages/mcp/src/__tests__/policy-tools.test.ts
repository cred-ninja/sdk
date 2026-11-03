import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import {
  CredGuard,
  rateLimitPolicy,
  scopeFilterPolicy,
  PolicyWeightSpaceEditor,
  generateApproverKeyPair,
  signProposal,
} from '@credninja/guard';
import { createCredMcpServer } from '../server.js';
import type { CredMcpLocalConfig } from '../config.js';
import { shouldWrapWithGuard } from '../guard-wiring.js';

const TEST_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-policy-tools-vault.json');

function cleanupVaultFiles() {
  for (const suffix of ['', '.salt', '.check']) {
    const p = TEST_VAULT_PATH + suffix;
    if (fs.existsSync(p)) fs.unlinkSync(p);
  }
}

function makeLocalConfig(overrides: Partial<CredMcpLocalConfig> = {}): CredMcpLocalConfig {
  return {
    mode: 'local',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultPath: TEST_VAULT_PATH,
    vaultStorage: 'file',
    providers: {},
    agentDid: 'did:key:z6MkTestAgent',
    ...overrides,
  };
}

async function connectedClient(config: CredMcpLocalConfig) {
  const server = createCredMcpServer(config);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, server };
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<{ isError?: boolean; payload: any }> {
  const result = await client.callTool({ name, arguments: args });
  return { isError: result.isError as boolean | undefined, payload: JSON.parse(String((result.content as any[])[0].text)) };
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

describe('policy weight-space tools', () => {
  afterEach(() => {
    cleanupVaultFiles();
  });

  it('are not listed, and not callable, without a policy editor', async () => {
    const { client } = await connectedClient(makeLocalConfig({ guard: buildGuard() }));
    const names = (await client.listTools()).tools.map((tool) => tool.name);
    expect(names).not.toContain('cred_policy_inspect');
    const result = await client.callTool({ name: 'cred_policy_inspect', arguments: {} });
    expect(result.isError).toBe(true);
    expect(String((result.content as any[])[0].text)).toContain('Unknown tool');
  });

  it('inspect is read-only, exempt from guard wrapping, and reports snapshot, interpretation and diagnosis', async () => {
    const guard = buildGuard();
    const editor = new PolicyWeightSpaceEditor(guard);
    const { client } = await connectedClient(makeLocalConfig({ guard, policyEditor: editor }));
    const names = (await client.listTools()).tools.map((tool) => tool.name);
    expect(names).toEqual(expect.arrayContaining(['cred_policy_inspect', 'cred_policy_propose', 'cred_policy_apply']));
    expect(shouldWrapWithGuard('cred_policy_inspect', 'local')).toBe(false);
    expect(shouldWrapWithGuard('cred_policy_propose', 'local')).toBe(true);
    expect(shouldWrapWithGuard('cred_policy_apply', 'local')).toBe(true);

    const { isError, payload } = await call(client, 'cred_policy_inspect');
    expect(isError).toBeUndefined();
    expect(payload.snapshot.policies.map((entry: any) => entry.name)).toEqual(['rate-limit', 'scope-filter']);
    expect(payload.interpretation.providers[0]).toMatchObject({ provider: 'github', allowedScopes: ['repo', 'gist'] });
    expect(payload.diagnosis.observed.events).toBeGreaterThanOrEqual(0);

    const partial = await call(client, 'cred_policy_inspect', { include: ['interpretation'] });
    expect(partial.payload.snapshot).toBeUndefined();
    expect(partial.payload.snapshotHash).toBe(payload.snapshot.hash);
  });

  it('propose dry-runs a patch and apply needs a signed approval the agent cannot forge', async () => {
    const guard = buildGuard();
    const approver = generateApproverKeyPair();
    const editor = new PolicyWeightSpaceEditor(guard, { approvers: [{ id: 'kieran', publicKey: approver.publicKey }] });
    const { client } = await connectedClient(makeLocalConfig({ guard, policyEditor: editor }));

    const proposed = await call(client, 'cred_policy_propose', {
      patch: [{ op: 'add', path: '/scope-filter/allowedScopes/github/-', value: 'workflow' }],
      rationale: 'CI run needs workflow scope',
    });
    expect(proposed.isError).toBeUndefined();
    expect(proposed.payload.proposal.proposer).toBe('did:key:z6MkTestAgent');
    expect(proposed.payload.proposal.classification.effect).toBe('widening');
    expect(proposed.payload.approvalRequired).toBe(true);
    expect(editor.snapshot().hash).toBe(proposed.payload.proposal.baseHash);

    const unsigned = await call(client, 'cred_policy_apply', { proposal_id: proposed.payload.proposal.id });
    expect(unsigned.isError).toBe(true);
    expect(unsigned.payload.error).toBe('approval_required');

    const forged = await call(client, 'cred_policy_apply', {
      proposal_id: proposed.payload.proposal.id,
      approvals: [signProposal(proposed.payload.proposal, 'kieran', generateApproverKeyPair().privateKey)],
    });
    expect(forged.isError).toBe(true);
    expect(forged.payload.error).toBe('approval_invalid');

    const approved = await call(client, 'cred_policy_apply', {
      proposal_id: proposed.payload.proposal.id,
      approvals: [signProposal(proposed.payload.proposal, 'kieran', approver.privateKey)],
    });
    expect(approved.isError).toBeUndefined();
    expect(approved.payload).toMatchObject({ applied: true, approvers: ['kieran'], rebuilt: ['scope-filter'], kept: ['rate-limit'] });
    const decision = await guard.evaluate({
      provider: 'github', agentTokenHash: 'x', requestedScopes: ['workflow'], consentedScopes: ['workflow'], timestamp: new Date().toISOString(),
    });
    expect(decision.allowed).toBe(true);
  });

  it('reports invalid patches with the failing op instead of a stack trace', async () => {
    const guard = buildGuard();
    const { client } = await connectedClient(makeLocalConfig({ guard, policyEditor: new PolicyWeightSpaceEditor(guard) }));
    const bad = await call(client, 'cred_policy_propose', {
      patch: [{ op: 'replace', path: '/rate-limit/maxRequests', value: 'lots' }],
      rationale: 'x',
    });
    expect(bad.isError).toBe(true);
    expect(bad.payload.error).toBe('invalid_patch');
    expect(bad.payload.message).toContain('positive integer');
    const missing = await call(client, 'cred_policy_propose', { patch: [{ op: 'remove', path: '/nope' }], rationale: 'x' });
    expect(missing.payload).toMatchObject({ error: 'invalid_patch', opIndex: 0 });
  });
});

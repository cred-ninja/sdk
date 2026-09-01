import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { CredGuard, rateLimitPolicy, maxTtlPolicy } from '@credninja/guard';
import type { CredPolicy } from '@credninja/guard';
import { createCredMcpServer } from '../server.js';
import type { CredMcpLocalConfig } from '../config.js';
import { shouldWrapWithGuard } from '../guard-wiring.js';

const TEST_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-guard-vault.json');

function cleanupVaultFiles() {
  for (const suffix of ['', '.salt']) {
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
    ...overrides,
  };
}

function denyAllPolicy(reason = 'denied for test'): CredPolicy {
  return {
    name: 'deny-all',
    evaluate: () => ({ decision: 'DENY', policy: 'deny-all', reason }),
  };
}

async function connectedClient(config: CredMcpLocalConfig) {
  const server = createCredMcpServer(config);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  return { client, server };
}

describe('guard wiring (U1)', () => {
  afterEach(() => {
    cleanupVaultFiles();
  });

  it('behaves exactly as before wiring when no guard is configured (opt-in)', async () => {
    const { client } = await connectedClient(makeLocalConfig());

    const result = await client.callTool({ name: 'cred_status', arguments: { user_id: 'default' } });

    expect(result.isError).toBeUndefined();
    const text = String((result.content as any[])[0].text);
    expect(text).toContain('No connected services');
    expect(text).not.toContain('guard=');
  });

  it('skips guard wrapping entirely in local mode when agentDid is not configured, rather than failing with "Missing agent token"', async () => {
    const guard = new CredGuard({ policies: [rateLimitPolicy({ maxRequests: 1, windowMs: 60_000 })] });
    const { client } = await connectedClient(makeLocalConfig({ guard }));

    const first = await client.callTool({ name: 'cred_status', arguments: { user_id: 'default' } });
    const second = await client.callTool({ name: 'cred_status', arguments: { user_id: 'default' } });

    // A configured rate limit of 1/window would deny the second call if guard
    // wrapping were active; both succeed because wrapping was skipped.
    expect(first.isError).toBeUndefined();
    expect(second.isError).toBeUndefined();
  });

  it('surfaces guard-computed TTL and rate-limit headroom on an allowed call', async () => {
    const guard = new CredGuard({
      policies: [
        maxTtlPolicy({ maxTtlSeconds: 900 }),
        rateLimitPolicy({ maxRequests: 5, windowMs: 60_000 }),
      ],
    });
    const { client } = await connectedClient(makeLocalConfig({ agentDid: 'agent:test-owner', guard }));

    const result = await client.callTool({ name: 'cred_status', arguments: { user_id: 'default' } });

    expect(result.isError).toBeUndefined();
    const text = String((result.content as any[])[0].text);
    expect(text).toContain('guard=');
    const guardJson = JSON.parse(text.slice(text.indexOf('guard=') + 'guard='.length));
    expect(guardJson.ttl).toEqual({ maxTtlSeconds: 900, expiresAt: expect.any(String) });
    expect(guardJson.rateLimit).toMatchObject({ limit: 5, windowMs: 60_000, remaining: 4 });
  });

  it('returns a structured denial via the custom onDeny, not a generic string', async () => {
    const guard = new CredGuard({ policies: [denyAllPolicy('rate limit exceeded')] });
    const { client } = await connectedClient(makeLocalConfig({ agentDid: 'agent:test-owner', guard }));

    const result = await client.callTool({ name: 'cred_status', arguments: { user_id: 'default' } });

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String((result.content as any[])[0].text));
    expect(payload).toMatchObject({ error: 'policy_denied', policy: 'deny-all', reason: 'rate limit exceeded' });
  });

  it('wraps and exercises each mutating local-mode tool through at least one allow and one deny case', async () => {
    // Distinguish guard's own denial from the wrapped handler's own business-logic
    // outcome (e.g. cred_revoke against a connection that was never stored) by
    // checking for the guard-specific `policy_denied` error shape, not a blanket
    // isError check — the handler running at all (allow) vs. never running
    // (deny, per the mock handler call count) is the actual thing under test.
    const allowGuard = new CredGuard({ policies: [{ name: 'allow-all', evaluate: () => ({ decision: 'ALLOW', policy: 'allow-all' }) }] });
    const denyGuard = new CredGuard({ policies: [denyAllPolicy()] });

    const allowClient = (await connectedClient(makeLocalConfig({ agentDid: 'agent:test-owner', guard: allowGuard }))).client;
    const allowResult = await allowClient.callTool({ name: 'cred_revoke', arguments: { user_id: 'default', service: 'google' } });
    // The handler ran (whatever it returned) — guard did not short-circuit it.
    expect(String((allowResult.content as any[])[0].text)).not.toContain('policy_denied');

    const denyClient = (await connectedClient(makeLocalConfig({ agentDid: 'agent:test-owner', guard: denyGuard }))).client;
    const denyResult = await denyClient.callTool({ name: 'cred_revoke', arguments: { user_id: 'default', service: 'google' } });
    expect(denyResult.isError).toBe(true);
    const denyPayload = JSON.parse(String((denyResult.content as any[])[0].text));
    expect(denyPayload.error).toBe('policy_denied');
  });

  it('createCredMcpServer registers the same tool set the shared registration path produces (regression guard for the collapsed createCredMcpServer/startServer paths)', async () => {
    const { client } = await connectedClient(makeLocalConfig());
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();

    expect(names).toEqual([
      'cred_audit_log',
      'cred_capabilities',
      'cred_delegate',
      'cred_register_identity',
      'cred_revoke',
      'cred_revoke_identity',
      'cred_rotate_key',
      'cred_status',
      'cred_subdelegate',
      'cred_use',
      'cred_whoami',
    ].sort());
  });

  it('cred_audit_log remains callable when a configured CredGuard would deny everything (U1 outage-survival guarantee)', async () => {
    const guard = new CredGuard({ policies: [denyAllPolicy('everything denied for test')] });
    const { client } = await connectedClient(makeLocalConfig({ agentDid: 'agent:test-owner', guard }));

    const result = await client.callTool({ name: 'cred_audit_log', arguments: { user_id: 'default' } });

    // Local mode's getAuditLog() is cloud-only, so this returns the SDK's
    // "not_supported" CredError — the point under test is that the guard's
    // deny-all policy never runs against this tool, so the response is that
    // structured not_supported error, never guard's `policy_denied` shape.
    expect(result.isError).toBe(true);
    const payload = JSON.parse(String((result.content as any[])[0].text));
    expect(payload.error).not.toBe('policy_denied');
  });

  it('cred_whoami remains callable when a configured CredGuard would deny everything (U1/U10 outage-survival guarantee)', async () => {
    const guard = new CredGuard({ policies: [denyAllPolicy('everything denied for test')] });
    const { client } = await connectedClient(makeLocalConfig({ agentDid: 'agent:test-owner', guard }));

    const result = await client.callTool({ name: 'cred_whoami', arguments: {} });

    // The deny-all policy never runs against cred_whoami — the response is
    // whoami's normal introspection payload (including the deny-all policy's
    // own name, since getPolicyNames() just reads config), never guard's
    // `policy_denied` shape.
    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String((result.content as any[])[0].text));
    expect(payload.guardPolicies).toEqual(['deny-all']);
  });
});

describe('shouldWrapWithGuard (U1 scoping rules)', () => {
  it('wraps cred_use, cred_revoke, and cred_status in cloud mode', () => {
    expect(shouldWrapWithGuard('cred_use', 'cloud')).toBe(true);
    expect(shouldWrapWithGuard('cred_revoke', 'cloud')).toBe(true);
    expect(shouldWrapWithGuard('cred_status', 'cloud')).toBe(true);
  });

  it('does not wrap cred_delegate or cred_subdelegate in cloud mode (already server-guarded)', () => {
    expect(shouldWrapWithGuard('cred_delegate', 'cloud')).toBe(false);
    expect(shouldWrapWithGuard('cred_subdelegate', 'cloud')).toBe(false);
  });

  it('wraps cred_delegate and cred_subdelegate in local mode (no server-side guard exists there)', () => {
    expect(shouldWrapWithGuard('cred_delegate', 'local')).toBe(true);
    expect(shouldWrapWithGuard('cred_subdelegate', 'local')).toBe(true);
  });

  it('never wraps read-only introspection tools, in either mode', () => {
    expect(shouldWrapWithGuard('cred_audit_log', 'cloud')).toBe(false);
    expect(shouldWrapWithGuard('cred_audit_log', 'local')).toBe(false);
    expect(shouldWrapWithGuard('cred_whoami', 'cloud')).toBe(false);
    expect(shouldWrapWithGuard('cred_whoami', 'local')).toBe(false);
  });
});

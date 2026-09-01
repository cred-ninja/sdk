import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { CredGuard, rateLimitPolicy, maxTtlPolicy } from '@credninja/guard';
import type { CredPolicy } from '@credninja/guard';
import { createCredMcpServer } from '../server.js';
import type { CredMcpLocalConfig } from '../config.js';
import { handleWhoami } from '../tools/whoami.js';
import { syntheticProvider } from '../guard-wiring.js';

// U10 (docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md):
// cred_whoami — read-only self-introspection, never guard-wrapped.

const TEST_VAULT_PATH = path.join(import.meta.dirname ?? __dirname, '../../.test-whoami-vault.json');

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

async function whoamiPayload(client: Client): Promise<any> {
  const result = await client.callTool({ name: 'cred_whoami', arguments: {} });
  expect(result.isError).toBeUndefined();
  return JSON.parse(String((result.content as any[])[0].text));
}

describe('cred_whoami (U10)', () => {
  afterEach(() => {
    cleanupVaultFiles();
  });

  it('returns the calling agent\'s active guard policy names', async () => {
    const guard = new CredGuard({
      policies: [
        rateLimitPolicy({ maxRequests: 10, windowMs: 60_000 }),
        maxTtlPolicy({ maxTtlSeconds: 900 }),
      ],
    });

    const result = await handleWhoami({}, { guard, agentTokenHash: 'test-hash' });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.guardPolicies).toEqual(['rate-limit', 'max-ttl']);
  });

  it('reflects current rate-limit headroom, changing across successive calls as the caller consumes budget', async () => {
    const guard = new CredGuard({
      policies: [rateLimitPolicy({ maxRequests: 5, windowMs: 60_000 })],
    });
    const { client } = await connectedClient(makeLocalConfig({ agentDid: 'agent:test-owner', guard }));
    const statusProvider = syntheticProvider('cred_status');

    // No calls yet: cred_status has no tracked bucket, so it doesn't appear.
    const before = await whoamiPayload(client);
    expect(before.rateLimit.find((r: any) => r.provider === statusProvider)).toBeUndefined();

    // Consume two units of budget on a DIFFERENT, guard-wrapped tool under
    // the same agent identity.
    await client.callTool({ name: 'cred_status', arguments: { user_id: 'default' } });
    await client.callTool({ name: 'cred_status', arguments: { user_id: 'default' } });

    const afterTwo = await whoamiPayload(client);
    const entryAfterTwo = afterTwo.rateLimit.find((r: any) => r.provider === statusProvider);
    expect(entryAfterTwo).toMatchObject({ limit: 5, windowMs: 60_000, remaining: 3 });

    // Consume a third unit and confirm headroom keeps shrinking.
    await client.callTool({ name: 'cred_status', arguments: { user_id: 'default' } });
    const afterThree = await whoamiPayload(client);
    const entryAfterThree = afterThree.rateLimit.find((r: any) => r.provider === statusProvider);
    expect(entryAfterThree).toMatchObject({ limit: 5, windowMs: 60_000, remaining: 2 });
  });

  it('works without erroring when no guard is configured at all', async () => {
    const result = await handleWhoami({}, {});

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.guardPolicies).toBeUndefined();
    expect(payload.rateLimit).toBeUndefined();
  });

  it('works without erroring when no guard is configured, via the full MCP server', async () => {
    const { client } = await connectedClient(makeLocalConfig());
    const payload = await whoamiPayload(client);
    expect(payload.guardPolicies).toBeUndefined();
    expect(payload.rateLimit).toBeUndefined();
  });

  it('remains callable when a deliberately deny-all CredGuard is configured (U1/U10 outage-survival guarantee)', async () => {
    const guard = new CredGuard({ policies: [denyAllPolicy('everything denied for test')] });
    const { client } = await connectedClient(makeLocalConfig({ agentDid: 'agent:test-owner', guard }));

    const payload = await whoamiPayload(client);

    // The deny-all policy never runs against cred_whoami — proof that it
    // stayed outside guard wrapping rather than the policy happening to
    // "allow" this particular call.
    expect(payload.guardPolicies).toEqual(['deny-all']);
  });

  it('remains callable when the configured CredGuard throws while being read', async () => {
    const throwingGuard = {
      getPolicyNames: () => {
        throw new Error('guard subsystem unavailable');
      },
    } as unknown as CredGuard;

    const result = await handleWhoami({}, { guard: throwingGuard, agentTokenHash: 'test-hash' });

    // The outer try/catch still returns a CallToolResult (never throws), so
    // the tool call itself always completes — even though this particular
    // response is an error result.
    expect(result.isError).toBe(true);
  });

  it('omits effectiveScopes when selfAgentId is not configured', async () => {
    const result = await handleWhoami({}, { cred: {} as any });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.effectiveScopes).toBeUndefined();
  });

  it('populates effectiveScopes from listPermissions when available (cloud-mode best effort)', async () => {
    const cred = {
      listPermissions: async (agentId: string) => {
        expect(agentId).toBe('agent_self');
        return [
          { allowedScopes: ['gmail.readonly'] },
          { allowedScopes: ['calendar.readonly', 'gmail.readonly'] },
        ];
      },
    } as any;

    const result = await handleWhoami({}, { cred, selfAgentId: 'agent_self' });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.effectiveScopes.sort()).toEqual(['calendar.readonly', 'gmail.readonly']);
  });

  it('omits effectiveScopes rather than erroring when listPermissions is unsupported (local mode)', async () => {
    const cred = {
      listPermissions: async () => {
        throw new Error('listPermissions() is only supported in cloud mode in this version');
      },
    } as any;

    const result = await handleWhoami({}, { cred, selfAgentId: 'agent_self' });

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.effectiveScopes).toBeUndefined();
  });
});

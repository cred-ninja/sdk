import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { CredError } from '@credninja/sdk';
import { handleRegisterIdentity } from '../tools/register-identity.js';
import { handleRotateKey } from '../tools/rotate-key.js';
import { handleRevokeIdentity } from '../tools/revoke-identity.js';
import { createCredMcpServer } from '../server.js';
import type { CredMcpLocalConfig } from '../config.js';

// U4 (docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md):
// self-service identity lifecycle tools wrapping Cred.registerWebBotAuthKey,
// Cred.rotateWebBotAuthKey, and Cred.revokeAgent.

describe('cred_register_identity', () => {
  it('registers a new key and returns key metadata', async () => {
    const result = await handleRegisterIdentity(
      { public_key: 'base64-encoded-public-key', initial_scopes: ['calendar.readonly'] },
      {
        cred: {
          registerWebBotAuthKey: async (params: any) => ({
            agentId: 'agent_123',
            fingerprint: 'sha256:abc',
            keyId: 'key_1',
            status: 'active',
            initialScopes: params.initialScopes,
            metadata: params.metadata ?? {},
            signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
            createdAt: '2026-08-31T00:00:00.000Z',
            updatedAt: '2026-08-31T00:00:00.000Z',
            claimedAt: null,
            revokedAt: null,
          }),
        } as any,
      },
    );

    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.agentId).toBe('agent_123');
    expect(payload.fingerprint).toBe('sha256:abc');
    expect(payload.status).toBe('active');
    expect(payload.initialScopes).toEqual(['calendar.readonly']);
  });

  it('surfaces a CredError as a structured error, not a crash', async () => {
    const result = await handleRegisterIdentity(
      { public_key: 'base64-encoded-public-key' },
      {
        cred: {
          registerWebBotAuthKey: async () => {
            throw new CredError('Forbidden', 'forbidden', 403);
          },
        } as any,
      },
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload).toMatchObject({ error: 'forbidden', statusCode: 403 });
  });
});

describe('cred_rotate_key', () => {
  it("rotates using context.selfAgentId and returns the new key plus grace-period expiry", async () => {
    let receivedAgentId: string | undefined;
    const result = await handleRotateKey(
      { public_key: 'new-base64-public-key' },
      {
        selfAgentId: 'agent_self',
        cred: {
          rotateWebBotAuthKey: async (params: any) => {
            receivedAgentId = params.agentId;
            return {
              agentId: params.agentId,
              fingerprint: 'sha256:new',
              keyId: 'key_2',
              status: 'active',
              initialScopes: [],
              metadata: {},
              signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
              createdAt: '2026-08-31T00:00:00.000Z',
              updatedAt: '2026-08-31T00:00:00.000Z',
              claimedAt: null,
              revokedAt: null,
              previousFingerprint: 'sha256:old',
              previousKeyId: 'key_1',
              graceExpiresAt: '2026-09-01T00:00:00.000Z',
            };
          },
        } as any,
      },
    );

    expect(result.isError).toBeUndefined();
    expect(receivedAgentId).toBe('agent_self');
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.agentId).toBe('agent_self');
    expect(payload.fingerprint).toBe('sha256:new');
    expect(payload.previousFingerprint).toBe('sha256:old');
    expect(payload.graceExpiresAt).toBe('2026-09-01T00:00:00.000Z');
  });

  it('prefers an explicit agent_id over context.selfAgentId', async () => {
    let receivedAgentId: string | undefined;
    await handleRotateKey(
      { public_key: 'new-key', agent_id: 'agent_other' },
      {
        selfAgentId: 'agent_self',
        cred: {
          rotateWebBotAuthKey: async (params: any) => {
            receivedAgentId = params.agentId;
            return {
              agentId: params.agentId,
              fingerprint: 'sha256:new',
              keyId: 'key_2',
              status: 'active',
              initialScopes: [],
              metadata: {},
              signatureAgent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
              createdAt: '2026-08-31T00:00:00.000Z',
              updatedAt: '2026-08-31T00:00:00.000Z',
              claimedAt: null,
              revokedAt: null,
              previousFingerprint: 'sha256:old',
              previousKeyId: 'key_1',
              graceExpiresAt: '2026-09-01T00:00:00.000Z',
            };
          },
        } as any,
      },
    );

    expect(receivedAgentId).toBe('agent_other');
  });

  it('returns a structured error when no agent_id and no selfAgentId are available', async () => {
    const result = await handleRotateKey(
      { public_key: 'new-key' },
      { cred: { rotateWebBotAuthKey: async () => { throw new Error('should not be called'); } } as any },
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.error).toBe('missing_agent_id');
  });

  it('surfaces a CredError (e.g. a 403 from the ownership check) as a structured error, not a crash', async () => {
    const result = await handleRotateKey(
      { public_key: 'new-key' },
      {
        selfAgentId: 'agent_self',
        cred: {
          rotateWebBotAuthKey: async () => {
            throw new CredError('Cannot rotate another agent\'s key', 'forbidden', 403);
          },
        } as any,
      },
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload).toMatchObject({ error: 'forbidden', statusCode: 403 });
  });
});

describe('cred_revoke_identity', () => {
  it('revokes using context.selfAgentId and returns confirmation', async () => {
    let receivedAgentId: string | undefined;
    const result = await handleRevokeIdentity(
      {},
      {
        selfAgentId: 'agent_self',
        cred: {
          revokeAgent: async (agentId: string) => {
            receivedAgentId = agentId;
          },
        } as any,
      },
    );

    expect(result.isError).toBeUndefined();
    expect(receivedAgentId).toBe('agent_self');
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload).toMatchObject({ revoked: true, agentId: 'agent_self' });
  });

  it('prefers an explicit agent_id over context.selfAgentId', async () => {
    let receivedAgentId: string | undefined;
    await handleRevokeIdentity(
      { agent_id: 'agent_other' },
      {
        selfAgentId: 'agent_self',
        cred: {
          revokeAgent: async (agentId: string) => {
            receivedAgentId = agentId;
          },
        } as any,
      },
    );

    expect(receivedAgentId).toBe('agent_other');
  });

  it('returns a structured error when no agent_id and no selfAgentId are available', async () => {
    const result = await handleRevokeIdentity(
      {},
      { cred: { revokeAgent: async () => { throw new Error('should not be called'); } } as any },
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload.error).toBe('missing_agent_id');
  });

  it('surfaces a CredError (e.g. a 403 from the ownership check) as a structured error, not a crash', async () => {
    const result = await handleRevokeIdentity(
      { agent_id: 'agent_other' },
      {
        selfAgentId: 'agent_self',
        cred: {
          revokeAgent: async () => {
            throw new CredError('Cannot revoke another agent\'s identity', 'forbidden', 403);
          },
        } as any,
      },
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse(String(result.content[0]?.text));
    expect(payload).toMatchObject({ error: 'forbidden', statusCode: 403 });
  });
});

describe('identity lifecycle tools registration (integration)', () => {
  const TEST_VAULT_PATH = path.join(
    import.meta.dirname ?? __dirname,
    '../../.test-identity-tools-vault.json',
  );

  afterEach(() => {
    for (const suffix of ['', '.salt']) {
      const p = TEST_VAULT_PATH + suffix;
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  });

  function makeLocalConfig(): CredMcpLocalConfig {
    return {
      mode: 'local',
      vaultPassphrase: 'test-passphrase-not-for-production',
      vaultPath: TEST_VAULT_PATH,
      vaultStorage: 'file',
      providers: {},
    };
  }

  it('all three tools are registered and appear via ListToolsRequestSchema/client.listTools()', async () => {
    const server = createCredMcpServer(makeLocalConfig());
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'test-client', version: '1.0.0' });
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);

    expect(names).toContain('cred_register_identity');
    expect(names).toContain('cred_rotate_key');
    expect(names).toContain('cred_revoke_identity');
  });
});

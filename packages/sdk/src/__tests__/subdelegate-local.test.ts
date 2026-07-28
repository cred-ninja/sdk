import { beforeEach, describe, expect, it, vi } from 'vitest';
import crypto, { createPrivateKey, sign } from 'node:crypto';
import { Cred, verifyDelegationReceipt } from '../index';

const mockVault = {
  init: vi.fn().mockResolvedValue(undefined),
  get: vi.fn(),
  getAgentByDid: undefined as undefined | ReturnType<typeof vi.fn>,
  getPermission: undefined as undefined | ReturnType<typeof vi.fn>,
  checkPermissionRateLimit: undefined as undefined | ReturnType<typeof vi.fn>,
  store: vi.fn(),
  list: vi.fn(),
  delete: vi.fn(),
  writeAuditEvent: undefined as undefined | ReturnType<typeof vi.fn>,
};

const mockValidateSubDelegation = vi.fn((input: {
  parent: { delegationId: string; scopesGranted: string[]; chainDepth: number; service: string; userId: string; appClientId: string; agentDid: string };
  childAgentDid: string;
  service: string;
  userId: string;
  appClientId: string;
  requestedScopes?: string[];
  permission: { allowedScopes: string[]; delegatable: boolean; maxDelegationDepth: number };
}) => {
  if (!input.permission.delegatable) {
    const error = new Error('Permission is not delegatable') as Error & { code: string };
    error.code = 'delegation_not_allowed';
    throw error;
  }
  if (input.parent.chainDepth + 1 > input.permission.maxDelegationDepth) {
    const error = new Error('Depth exceeded') as Error & { code: string };
    error.code = 'depth_exceeded';
    throw error;
  }
  const requested = input.requestedScopes && input.requestedScopes.length > 0
    ? input.requestedScopes
    : input.parent.scopesGranted;
  const widened = requested.filter((scope) => !input.parent.scopesGranted.includes(scope));
  if (widened.length > 0) {
    const error = new Error('Requested scopes exceed parent delegation') as Error & { code: string };
    error.code = 'scope_escalation_denied';
    throw error;
  }
  const grantedScopes = requested.filter((scope) => (
    input.parent.scopesGranted.includes(scope) && input.permission.allowedScopes.includes(scope)
  ));
  if (grantedScopes.length === 0) {
    const error = new Error('No scopes granted') as Error & { code: string };
    error.code = 'no_scopes_granted';
    throw error;
  }
  return {
    parentDelegationId: input.parent.delegationId,
    chainDepth: input.parent.chainDepth + 1,
    grantedScopes,
  };
});

vi.mock('@credninja/vault', () => {
  return {
    CredVault: class MockCredVault {
      constructor() {
        Object.assign(this, mockVault);
      }
    },
    validateSubDelegation: (...args: Parameters<typeof mockValidateSubDelegation>) =>
      mockValidateSubDelegation(...args),
  };
});

vi.mock('@credninja/oauth', () => ({
  createAdapter: () => ({ refreshAccessToken: vi.fn() }),
}));

const TEST_VAULT_PASSPHRASE = 'test-pass';

function makeLocalCred(overrides?: { receiptTtlSeconds?: number; receiptAudience?: string }) {
  return new Cred({
    mode: 'local',
    vault: { passphrase: TEST_VAULT_PASSPHRASE, path: '/tmp/test-vault.json', storage: 'file' },
    providers: { github: { clientId: 'cid', clientSecret: 'secret' } },
    ...overrides,
  });
}

// ── Local receipt forging helpers (mirror Cred's local receipt key derivation) ─

function getTestLocalReceiptSigningKey(passphrase: string) {
  const seed = crypto.scryptSync(passphrase, 'cred:local-receipt:v1', 32);
  return createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      seed,
    ]),
    format: 'der',
    type: 'pkcs8',
  });
}

function decodeReceiptPayload(receipt: string): Record<string, unknown> {
  const [, payloadB64] = receipt.split('.');
  return JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
}

/** Re-sign a receipt payload (with arbitrary claim overrides) using the test vault's derived key. */
function forgeReceipt(passphrase: string, payloadOverrides: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payloadOverrides)).toString('base64url');
  const signatureInput = Buffer.from(`${header}.${payloadB64}`, 'utf8');
  const signature = sign(null, signatureInput, getTestLocalReceiptSigningKey(passphrase)).toString('base64url');
  return `${header}.${payloadB64}.${signature}`;
}

beforeEach(() => {
  vi.clearAllMocks();
  mockVault.init.mockResolvedValue(undefined);
  mockVault.getAgentByDid = undefined;
  mockVault.getPermission = undefined;
  mockVault.checkPermissionRateLimit = undefined;
  mockVault.writeAuditEvent = undefined;
  mockValidateSubDelegation.mockClear();
});

describe('Cred.subDelegate() local mode', () => {
  it('issues a child delegation with incremented chain depth', async () => {
    const cred = makeLocalCred();

    mockVault.getAgentByDid = vi.fn()
      .mockResolvedValueOnce({
        id: 'agt_parent',
        status: 'active',
        scopeCeiling: ['repo', 'read:user'],
      })
      .mockResolvedValueOnce({
        id: 'agt_child',
        status: 'active',
        scopeCeiling: ['repo'],
      });
    mockVault.getPermission = vi.fn()
      .mockResolvedValueOnce({
        id: 'perm_parent',
        allowedScopes: ['repo', 'read:user'],
        requiresApproval: false,
        delegatable: true,
        maxDelegationDepth: 2,
        createdAt: new Date(),
        createdBy: 'admin',
      })
      .mockResolvedValueOnce({
        id: 'perm_child',
        allowedScopes: ['repo'],
        requiresApproval: false,
        delegatable: true,
        maxDelegationDepth: 2,
        createdAt: new Date(),
        createdBy: 'admin',
      });
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'user-1',
      accessToken: 'token',
      scopes: ['repo', 'read:user'],
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
    });

    const root = await cred.delegate({
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkParent',
      scopes: ['repo', 'read:user'],
    });

    const child = await cred.subDelegate({
      parentReceipt: root.receipt!,
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkChild',
      scopes: ['repo'],
    });

    expect(child.parentDelegationId).toBe(root.delegationId);
    expect(child.chainDepth).toBe(1);
    expect(child.scopes).toEqual(['repo']);
    expect(child.receipt).toBeDefined();
  });

  it('rejects scope widening beyond the parent receipt', async () => {
    const cred = makeLocalCred();

    mockVault.getAgentByDid = vi.fn()
      .mockResolvedValueOnce({
        id: 'agt_parent',
        status: 'active',
        scopeCeiling: ['repo'],
      })
      .mockResolvedValueOnce({
        id: 'agt_child',
        status: 'active',
        scopeCeiling: ['repo', 'delete_repo'],
      });
    mockVault.getPermission = vi.fn()
      .mockResolvedValueOnce({
        id: 'perm_parent',
        allowedScopes: ['repo'],
        requiresApproval: false,
        delegatable: true,
        maxDelegationDepth: 2,
        createdAt: new Date(),
        createdBy: 'admin',
      })
      .mockResolvedValueOnce({
        id: 'perm_child',
        allowedScopes: ['repo', 'delete_repo'],
        requiresApproval: false,
        delegatable: true,
        maxDelegationDepth: 2,
        createdAt: new Date(),
        createdBy: 'admin',
      });
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'user-1',
      accessToken: 'token',
      scopes: ['repo'],
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
    });

    const root = await cred.delegate({
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkParent',
      scopes: ['repo'],
    });

    await expect(cred.subDelegate({
      parentReceipt: root.receipt!,
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkChild',
      scopes: ['repo', 'delete_repo'],
    })).rejects.toMatchObject({ code: 'scope_escalation_denied' });
  });
});

describe('Cred local mode — receipt exp/aud claims', () => {
  it('mints exp (default 3600s TTL) and no aud when receiptAudience is unset', async () => {
    const cred = makeLocalCred();
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'user-1',
      accessToken: 'token',
      scopes: ['repo'],
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
    });

    const root = await cred.delegate({
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkParent',
      scopes: ['repo'],
    });

    const payload = decodeReceiptPayload(root.receipt!);
    expect(payload.iat).toBeTypeOf('number');
    expect(payload.exp).toBe((payload.iat as number) + 3600);
    expect(payload.aud).toBeUndefined();
  });

  it('respects a custom receiptTtlSeconds and receiptAudience', async () => {
    const cred = makeLocalCred({ receiptTtlSeconds: 120, receiptAudience: 'https://aud.example.com' });
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'user-1',
      accessToken: 'token',
      scopes: ['repo'],
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
    });

    const root = await cred.delegate({
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkParent',
      scopes: ['repo'],
    });

    const payload = decodeReceiptPayload(root.receipt!);
    expect(payload.exp).toBe((payload.iat as number) + 120);
    expect(payload.aud).toBe('https://aud.example.com');
  });
});

describe('Cred.subDelegate() local mode — receipt expiry enforcement', () => {
  it('rejects an expired parent receipt', async () => {
    const cred = makeLocalCred();

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiredReceipt = forgeReceipt(TEST_VAULT_PASSPHRASE, {
      iss: 'did:key:local-cred',
      sub: 'did:key:z6MkParent',
      iat: nowSeconds - 7200,
      exp: nowSeconds - 3600,
      service: 'github',
      scopes: ['repo'],
      userId: 'user-1',
      appClientId: 'local',
      delegationId: 'local_github_user-1',
      chainDepth: 0,
    });

    await expect(cred.subDelegate({
      parentReceipt: expiredReceipt,
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkChild',
      scopes: ['repo'],
    })).rejects.toMatchObject({ code: 'receipt_expired' });
  });

  it('rejects a legacy parent receipt (no exp claim) older than the configured receipt TTL', async () => {
    const cred = makeLocalCred({ receiptTtlSeconds: 5 });

    const nowSeconds = Math.floor(Date.now() / 1000);
    const legacyReceipt = forgeReceipt(TEST_VAULT_PASSPHRASE, {
      iss: 'did:key:local-cred',
      sub: 'did:key:z6MkParent',
      iat: nowSeconds - 60, // no exp field — well past the 5s TTL
      service: 'github',
      scopes: ['repo'],
      userId: 'user-1',
      appClientId: 'local',
      delegationId: 'local_github_user-1',
      chainDepth: 0,
    });

    await expect(cred.subDelegate({
      parentReceipt: legacyReceipt,
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkChild',
      scopes: ['repo'],
    })).rejects.toMatchObject({ code: 'receipt_expired' });
  });

  it('accepts a legacy parent receipt (no exp claim) within the configured receipt TTL', async () => {
    const cred = makeLocalCred({ receiptTtlSeconds: 3600 });

    mockVault.getPermission = vi.fn().mockResolvedValue({
      id: 'perm_child',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 2,
      createdAt: new Date(),
      createdBy: 'admin',
    });
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'user-1',
      accessToken: 'token',
      scopes: ['repo'],
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
    });

    const nowSeconds = Math.floor(Date.now() / 1000);
    const legacyReceipt = forgeReceipt(TEST_VAULT_PASSPHRASE, {
      iss: 'did:key:local-cred',
      sub: 'did:key:z6MkParent',
      iat: nowSeconds - 5, // no exp field, well within the 3600s TTL
      service: 'github',
      scopes: ['repo'],
      userId: 'user-1',
      appClientId: 'local',
      delegationId: 'local_github_user-1',
      chainDepth: 0,
    });

    const child = await cred.subDelegate({
      parentReceipt: legacyReceipt,
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkChild',
      scopes: ['repo'],
    });

    expect(child.scopes).toEqual(['repo']);
  });
});

describe('Cred.subDelegate() local mode — ancestor status check', () => {
  it('denies sub-delegation when the ancestor (parent) agent has been revoked', async () => {
    const cred = makeLocalCred();
    const parentDid = 'did:key:z6MkParent';

    // Parent is active at root-delegation time (so the parent receipt can be
    // minted), but has since been revoked by the time a sub-delegation is
    // attempted against it — the ancestor check must catch that even though
    // the requesting child agent itself is unaffected.
    let parentStatus: 'active' | 'revoked' = 'active';
    mockVault.getAgentByDid = vi.fn(async (did: string) => {
      if (did === parentDid) {
        return { id: 'agt_parent', status: parentStatus, scopeCeiling: [] as string[] };
      }
      return null;
    });
    mockVault.getPermission = vi.fn().mockResolvedValue({
      id: 'perm_parent',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 2,
      createdAt: new Date(),
      createdBy: 'admin',
    });
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'user-1',
      accessToken: 'token',
      scopes: ['repo'],
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
    });

    const root = await cred.delegate({
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: parentDid,
      scopes: ['repo'],
    });

    parentStatus = 'revoked';

    await expect(cred.subDelegate({
      parentReceipt: root.receipt!,
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkChild',
      scopes: ['repo'],
    })).rejects.toMatchObject({ code: 'ancestor_agent_revoked' });
  });

  it('denies a two-hop-removed sub-delegation when a revoked grandparent is still in the chain', async () => {
    // Regression test for the full-lineage ancestor check: a revoked
    // grandparent must block new descendants even when the immediate
    // parent presenting the receipt is still active. Exercises real
    // cred.delegate()/cred.subDelegate() calls for both hops so the
    // `lineage` claim is populated exactly as production would produce it
    // (not hand-forged in the test).
    const cred = makeLocalCred();
    const grandparentDid = 'did:key:z6MkGrandparent';
    const parentDid = 'did:key:z6MkParent';
    const childDid = 'did:key:z6MkChild';

    let grandparentStatus: 'active' | 'revoked' = 'active';
    const agentRecords: Record<string, { id: string; status: string; scopeCeiling: string[] }> = {
      [grandparentDid]: { id: 'agt_grandparent', status: 'active', scopeCeiling: [] },
      [parentDid]: { id: 'agt_parent', status: 'active', scopeCeiling: [] },
      [childDid]: { id: 'agt_child', status: 'active', scopeCeiling: [] },
    };
    mockVault.getAgentByDid = vi.fn(async (did: string) => {
      if (did === grandparentDid) {
        return { ...agentRecords[did], status: grandparentStatus };
      }
      return agentRecords[did] ?? null;
    });
    mockVault.getPermission = vi.fn().mockResolvedValue({
      id: 'perm_any',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 5,
      createdAt: new Date(),
      createdBy: 'admin',
    });
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'user-1',
      accessToken: 'token',
      scopes: ['repo'],
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
    });

    // Root receipt, signed for the grandparent (chainDepth 0, no ancestors).
    const root = await cred.delegate({
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: grandparentDid,
      scopes: ['repo'],
    });

    // Hop 1: grandparent -> parent, minted for real so `lineage` is exactly
    // what production would produce.
    const hop1 = await cred.subDelegate({
      parentReceipt: root.receipt!,
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: parentDid,
      scopes: ['repo'],
    });
    expect(hop1.chainDepth).toBe(1);

    const parentPayload = JSON.parse(Buffer.from(hop1.receipt!.split('.')[1], 'base64url').toString('utf8'));
    expect(parentPayload.lineage).toEqual([grandparentDid]);

    // Grandparent is revoked *after* the parent receipt was minted — the
    // parent agent itself remains active throughout.
    grandparentStatus = 'revoked';

    // Hop 2: parent (still active) attempts to sub-delegate to a fresh
    // child two hops down from the now-revoked grandparent.
    await expect(cred.subDelegate({
      parentReceipt: hop1.receipt!,
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: childDid,
      scopes: ['repo'],
    })).rejects.toMatchObject({ code: 'ancestor_agent_revoked' });
  });

  it('allows sub-delegation when the vault has no agent record for the parent DID', async () => {
    const cred = makeLocalCred();

    mockVault.getAgentByDid = vi.fn().mockResolvedValue(null);
    mockVault.getPermission = vi.fn().mockResolvedValue({
      id: 'perm_child',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 2,
      createdAt: new Date(),
      createdBy: 'admin',
    });
    mockVault.get.mockResolvedValue({
      provider: 'github',
      userId: 'user-1',
      accessToken: 'token',
      scopes: ['repo'],
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600_000),
    });

    const root = await cred.delegate({
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkParent',
      scopes: ['repo'],
    });

    const child = await cred.subDelegate({
      parentReceipt: root.receipt!,
      service: 'github',
      userId: 'user-1',
      appClientId: 'local',
      agentDid: 'did:key:z6MkChild',
      scopes: ['repo'],
    });

    expect(child.scopes).toEqual(['repo']);
  });
});

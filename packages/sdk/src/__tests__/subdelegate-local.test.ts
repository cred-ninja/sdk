import { beforeEach, describe, expect, it, vi } from 'vitest';
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

function makeLocalCred() {
  return new Cred({
    mode: 'local',
    vault: { passphrase: 'test-pass', path: '/tmp/test-vault.json', storage: 'file' },
    providers: { github: { clientId: 'cid', clientSecret: 'secret' } },
  });
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

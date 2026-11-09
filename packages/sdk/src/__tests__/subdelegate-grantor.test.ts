import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey, scryptSync, sign } from 'node:crypto';
import { CredVault } from '@credninja/vault';
import { Cred } from '../index.js';
import { didKeyForPublicKey } from '../identity.js';

/**
 * Local-mode sub-delegation must gate on the GRANTOR's Permission.
 *
 * Regression coverage for a privately reported issue: `subDelegateLocal`
 * passed the RECEIVING agent's Permission into the delegatable/depth check,
 * so a delegating agent whose own Permission had `delegatable: false` (or
 * `maxDelegationDepth: 0`) could still sub-delegate as long as the receiving
 * agent's Permission allowed it — and, inversely, a receiving agent with
 * `delegatable: false` was wrongly blocked from receiving.
 *
 * Real vault, DID-keyed Permission rows, no registered agent records (the
 * same fixture shape as opaque-constraints.test.ts).
 */

const PASSPHRASE = 'test-grantor';
const directories: string[] = [];
afterEach(() => {
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

interface PermSpec {
  allowedScopes: string[];
  delegatable: boolean;
  maxDelegationDepth: number;
}

async function local(opts: {
  parent: PermSpec;
  child: PermSpec;
  grandchild?: PermSpec;
  storedScopes?: string[];
}) {
  const directory = mkdtempSync(join(tmpdir(), 'cred-grantor-'));
  directories.push(directory);
  const options = { passphrase: PASSPHRASE, path: join(directory, 'vault.sqlite'), storage: 'sqlite' as const };
  const vault = new CredVault(options);
  await vault.init();
  await vault.store({
    provider: 'github',
    userId: 'user-test',
    accessToken: 'test-token',
    scopes: opts.storedScopes ?? ['repo'],
  });
  await vault.createPermission({
    agentId: 'did:key:parent', connectionId: 'github', requiresApproval: false, createdBy: 'test',
    ...opts.parent,
  });
  await vault.createPermission({
    agentId: 'did:key:child', connectionId: 'github', requiresApproval: false, createdBy: 'test',
    ...opts.child,
  });
  if (opts.grandchild) {
    await vault.createPermission({
      agentId: 'did:key:grandchild', connectionId: 'github', requiresApproval: false, createdBy: 'test',
      ...opts.grandchild,
    });
  }
  return new Cred({ mode: 'local', vault: options, providers: {} });
}

function parentReceipt(chainDepth = 0, scopes: string[] = ['repo']): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      scryptSync(PASSPHRASE, 'cred:local-receipt:v1', 32),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const payload = Buffer.from(JSON.stringify({
    iss: didKeyForPublicKey(createPublicKey(privateKey)),
    sub: 'did:key:parent',
    service: 'github',
    userId: 'user-test',
    appClientId: 'local',
    delegationId: 'del_parent',
    scopes,
    chainDepth,
    iat: Math.floor(Date.now() / 1000),
  })).toString('base64url');
  return `${header}.${payload}.${sign(null, Buffer.from(`${header}.${payload}`), privateKey).toString('base64url')}`;
}

const ALLOWING_CHILD: PermSpec = { allowedScopes: ['repo'], delegatable: true, maxDelegationDepth: 5 };

describe('Cred.subDelegate() local mode — grantor permission gate', () => {
  it('blocks when the GRANTOR delegatable is false, even though the recipient allows delegation', async () => {
    const cred = await local({
      parent: { allowedScopes: ['repo'], delegatable: false, maxDelegationDepth: 5 },
      child: ALLOWING_CHILD,
    });
    await expect(cred.subDelegate({
      parentReceipt: parentReceipt(), service: 'github', userId: 'user-test', agentDid: 'did:key:child',
    })).rejects.toMatchObject({ code: 'delegation_not_allowed' });
  });

  it('blocks when the GRANTOR maxDelegationDepth is 0', async () => {
    const cred = await local({
      parent: { allowedScopes: ['repo'], delegatable: true, maxDelegationDepth: 0 },
      child: ALLOWING_CHILD,
    });
    await expect(cred.subDelegate({
      parentReceipt: parentReceipt(), service: 'github', userId: 'user-test', agentDid: 'did:key:child',
    })).rejects.toMatchObject({ code: 'depth_exceeded' });
  });

  it('allows depth exactly equal to the grantor max, and blocks one past it', async () => {
    const cred = await local({
      parent: { allowedScopes: ['repo'], delegatable: true, maxDelegationDepth: 1 },
      child: ALLOWING_CHILD,
    });
    const child = await cred.subDelegate({
      parentReceipt: parentReceipt(0), service: 'github', userId: 'user-test', agentDid: 'did:key:child',
    });
    expect(child.chainDepth).toBe(1);

    await expect(cred.subDelegate({
      parentReceipt: parentReceipt(1), service: 'github', userId: 'user-test', agentDid: 'did:key:child',
    })).rejects.toMatchObject({ code: 'depth_exceeded' });
  });

  it('allows a recipient whose own delegatable is false — that flag gates the NEXT hop, not receipt', async () => {
    const cred = await local({
      parent: { allowedScopes: ['repo'], delegatable: true, maxDelegationDepth: 5 },
      child: { allowedScopes: ['repo'], delegatable: false, maxDelegationDepth: 0 },
      grandchild: ALLOWING_CHILD,
    });
    const child = await cred.subDelegate({
      parentReceipt: parentReceipt(), service: 'github', userId: 'user-test', agentDid: 'did:key:child',
    });
    expect(child.scopes).toEqual(['repo']);

    // …and when that recipient tries to delegate onward, ITS delegatable=false now gates.
    await expect(cred.subDelegate({
      parentReceipt: child.receipt!, service: 'github', userId: 'user-test', agentDid: 'did:key:grandchild',
    })).rejects.toMatchObject({ code: 'delegation_not_allowed' });
  });

  it('still attenuates granted scopes to the recipient allowedScopes', async () => {
    const cred = await local({
      parent: { allowedScopes: ['repo', 'admin:org'], delegatable: true, maxDelegationDepth: 5 },
      child: { allowedScopes: ['repo'], delegatable: true, maxDelegationDepth: 5 },
      storedScopes: ['repo', 'admin:org'],
    });
    const child = await cred.subDelegate({
      parentReceipt: parentReceipt(0, ['repo', 'admin:org']),
      service: 'github',
      userId: 'user-test',
      agentDid: 'did:key:child',
      scopes: ['repo', 'admin:org'],
    });
    expect(child.scopes).toEqual(['repo']);
  });

  it('still denies scope widening beyond the parent delegation', async () => {
    const cred = await local({
      parent: { allowedScopes: ['repo'], delegatable: true, maxDelegationDepth: 5 },
      child: { allowedScopes: ['repo', 'delete_repo'], delegatable: true, maxDelegationDepth: 5 },
    });
    await expect(cred.subDelegate({
      parentReceipt: parentReceipt(), service: 'github', userId: 'user-test',
      agentDid: 'did:key:child', scopes: ['repo', 'delete_repo'],
    })).rejects.toMatchObject({ code: 'scope_escalation_denied' });
  });

  it('valid multi-hop delegation still works when every grantor allows it', async () => {
    const cred = await local({
      parent: { allowedScopes: ['repo'], delegatable: true, maxDelegationDepth: 2 },
      child: { allowedScopes: ['repo'], delegatable: true, maxDelegationDepth: 2 },
      grandchild: ALLOWING_CHILD,
    });
    const child = await cred.subDelegate({
      parentReceipt: parentReceipt(), service: 'github', userId: 'user-test', agentDid: 'did:key:child',
    });
    const grandchild = await cred.subDelegate({
      parentReceipt: child.receipt!, service: 'github', userId: 'user-test', agentDid: 'did:key:grandchild',
    });
    expect(grandchild.chainDepth).toBe(2);
    expect(grandchild.scopes).toEqual(['repo']);
  });
});

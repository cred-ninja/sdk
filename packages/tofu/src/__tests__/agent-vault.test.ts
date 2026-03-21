import { createPrivateKey, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createAgentVault, generateKeypair } from '../index.js';

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), 'tofu-agent-vault-'));
}

const backends = [
  { name: 'file', file: 'agents.json' },
  { name: 'sqlite', file: 'agents.sqlite' },
] as const;

describe.each(backends)('AgentVault (%s)', ({ name, file }) => {
  let tmpDir: string | null = null;

  afterEach(() => {
    if (tmpDir) {
      rmSync(tmpDir, { recursive: true, force: true });
      tmpDir = null;
    }
  });

  it('registers, retrieves, claims, and revokes identities', async () => {
    tmpDir = makeTmpDir();
    const vault = await createAgentVault({
      storage: name,
      path: join(tmpDir, file),
    });
    const keypair = await generateKeypair();

    const registered = await vault.registerAgent({
      publicKey: keypair.publicKey,
      initialScopes: ['calendar.readonly'],
      metadata: { label: 'agent-1' },
    });
    const created = await vault.getAgent(registered.fingerprint);

    expect(created).not.toBeNull();
    expect(created?.agentId).toBe(registered.agentId);
    expect(created?.status).toBe('unclaimed');
    expect(created?.initialScopes).toEqual(['calendar.readonly']);
    expect(created?.metadata).toEqual({ label: 'agent-1' });

    await vault.claimAgent({ fingerprint: registered.fingerprint, ownerUserId: 'user-123' });
    const claimed = await vault.getAgent(registered.fingerprint);
    expect(claimed?.status).toBe('claimed');
    expect(claimed?.ownerUserId).toBe('user-123');
    expect(claimed?.claimedAt).toBeInstanceOf(Date);

    await expect(
      vault.claimAgent({ fingerprint: registered.fingerprint, ownerUserId: 'user-456' }),
    ).rejects.toThrow('already claimed');

    await vault.revokeAgent(registered.fingerprint);
    const revoked = await vault.getAgent(registered.fingerprint);
    expect(revoked?.status).toBe('revoked');
    expect(revoked?.revokedAt).toBeInstanceOf(Date);
  });

  it('verifies signatures for registered keys and denies revoked identities', async () => {
    tmpDir = makeTmpDir();
    const vault = await createAgentVault({
      storage: name,
      path: join(tmpDir, file),
    });
    const keypair = await generateKeypair();
    const privateKey = createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        Buffer.from(keypair.privateKey),
      ]),
      format: 'der',
      type: 'pkcs8',
    });

    const { fingerprint } = await vault.registerAgent({ publicKey: keypair.publicKey });
    const payload = Buffer.from('verify me');
    const signature = sign(null, payload, privateKey);

    expect(await vault.verifySignature(fingerprint, payload, signature)).toBe(true);

    await vault.revokeAgent(fingerprint);
    expect(await vault.verifySignature(fingerprint, payload, signature)).toBe(false);
  });
});

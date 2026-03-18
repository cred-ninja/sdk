import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { createAgentVault, AgentVault } from '../agent-vault.js';

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), 'agent-vault-test-'));
}

/** Generate a raw Ed25519 key pair for testing. */
function generateTestKeypair(): { publicKey: Uint8Array; privateKeyDer: Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const rawPublic = new Uint8Array(spki.slice(-32));
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
  return { publicKey: rawPublic, privateKeyDer: pkcs8 };
}

/** Compute the expected fingerprint from a raw public key. */
function computeFingerprint(publicKey: Uint8Array): string {
  const hex = Buffer.from(publicKey).toString('hex');
  return createHash('sha256').update(hex).digest('hex');
}

describe('AgentVault — SQLite backend', () => {
  let tmpDir: string;
  let vault: AgentVault;

  beforeEach(async () => {
    tmpDir = makeTmpDir();
    vault = await createAgentVault({
      passphrase: 'unused',
      storage: 'sqlite',
      path: join(tmpDir, 'agent-vault.db'),
    });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('registerAgent stores and getAgent retrieves correctly', async () => {
    const { publicKey } = generateTestKeypair();

    const result = await vault.registerAgent({ publicKey });
    expect(result.agentId).toBeTruthy();
    expect(result.fingerprint).toBeTruthy();

    const agent = await vault.getAgent(result.fingerprint);
    expect(agent).not.toBeNull();
    expect(agent!.agentId).toBe(result.agentId);
    expect(agent!.publicKey).toBe(Buffer.from(publicKey).toString('hex'));
    expect(agent!.status).toBe('unclaimed');
    expect(agent!.ownerUserId).toBeNull();
    expect(agent!.initialScopes).toEqual([]);
    expect(agent!.metadata).toEqual({});
    expect(agent!.createdAt).toBeInstanceOf(Date);
    expect(agent!.updatedAt).toBeInstanceOf(Date);
  });

  it('fingerprint is SHA-256 of hex-encoded public key', async () => {
    const { publicKey } = generateTestKeypair();
    const expectedFingerprint = computeFingerprint(publicKey);

    const result = await vault.registerAgent({ publicKey });
    expect(result.fingerprint).toBe(expectedFingerprint);
  });

  it('stores initialScopes and metadata', async () => {
    const { publicKey } = generateTestKeypair();

    const result = await vault.registerAgent({
      publicKey,
      initialScopes: ['read', 'write'],
      metadata: { name: 'test-agent', version: 2 },
    });

    const agent = await vault.getAgent(result.fingerprint);
    expect(agent!.initialScopes).toEqual(['read', 'write']);
    expect(agent!.metadata).toEqual({ name: 'test-agent', version: 2 });
  });

  it('claimAgent changes status and ownerUserId', async () => {
    const { publicKey } = generateTestKeypair();
    const { fingerprint } = await vault.registerAgent({ publicKey });

    await vault.claimAgent({ fingerprint, ownerUserId: 'user-123' });

    const agent = await vault.getAgent(fingerprint);
    expect(agent!.status).toBe('claimed');
    expect(agent!.ownerUserId).toBe('user-123');
    expect(agent!.updatedAt.getTime()).toBeGreaterThanOrEqual(agent!.createdAt.getTime());
  });

  it('getAgent returns null for unknown fingerprint', async () => {
    const agent = await vault.getAgent('0000000000000000000000000000000000000000000000000000000000000000');
    expect(agent).toBeNull();
  });

  it('verifyAgentSignature returns true for valid signature', async () => {
    const { publicKey, privateKeyDer } = generateTestKeypair();
    const { fingerprint } = await vault.registerAgent({ publicKey });

    const payload = Buffer.from('hello world');
    const { createPrivateKey } = await import('node:crypto');
    const privKeyObj = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
    const signature = sign(null, payload, privKeyObj);

    const valid = await vault.verifyAgentSignature(fingerprint, payload, signature);
    expect(valid).toBe(true);
  });

  it('verifyAgentSignature returns false for tampered payload', async () => {
    const { publicKey, privateKeyDer } = generateTestKeypair();
    const { fingerprint } = await vault.registerAgent({ publicKey });

    const payload = Buffer.from('hello world');
    const { createPrivateKey } = await import('node:crypto');
    const privKeyObj = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
    const signature = sign(null, payload, privKeyObj);

    const tampered = Buffer.from('tampered payload');
    const valid = await vault.verifyAgentSignature(fingerprint, tampered, signature);
    expect(valid).toBe(false);
  });

  it('verifyAgentSignature returns false for unknown fingerprint', async () => {
    const valid = await vault.verifyAgentSignature(
      '0000000000000000000000000000000000000000000000000000000000000000',
      Buffer.from('payload'),
      Buffer.from('sig'),
    );
    expect(valid).toBe(false);
  });

  it('rejects invalid public key length', async () => {
    await expect(
      vault.registerAgent({ publicKey: new Uint8Array(16) }),
    ).rejects.toThrow('must be 32 bytes');
  });
});

describe('AgentVault — File backend', () => {
  let tmpDir: string;
  let vault: AgentVault;

  beforeEach(async () => {
    tmpDir = makeTmpDir();
    vault = await createAgentVault({
      passphrase: 'unused',
      storage: 'file',
      path: join(tmpDir, 'agent-vault.json'),
    });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('registerAgent stores and getAgent retrieves correctly', async () => {
    const { publicKey } = generateTestKeypair();

    const result = await vault.registerAgent({ publicKey });
    const agent = await vault.getAgent(result.fingerprint);

    expect(agent).not.toBeNull();
    expect(agent!.agentId).toBe(result.agentId);
    expect(agent!.status).toBe('unclaimed');
  });

  it('claimAgent works with file backend', async () => {
    const { publicKey } = generateTestKeypair();
    const { fingerprint } = await vault.registerAgent({ publicKey });

    await vault.claimAgent({ fingerprint, ownerUserId: 'owner-abc' });

    const agent = await vault.getAgent(fingerprint);
    expect(agent!.status).toBe('claimed');
    expect(agent!.ownerUserId).toBe('owner-abc');
  });

  it('verifyAgentSignature works with file backend', async () => {
    const { publicKey, privateKeyDer } = generateTestKeypair();
    const { fingerprint } = await vault.registerAgent({ publicKey });

    const payload = Buffer.from('file backend test');
    const { createPrivateKey } = await import('node:crypto');
    const privKeyObj = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
    const signature = sign(null, payload, privKeyObj);

    const valid = await vault.verifyAgentSignature(fingerprint, payload, signature);
    expect(valid).toBe(true);
  });

  it('fingerprint is consistent across backends', async () => {
    const { publicKey } = generateTestKeypair();
    const expected = computeFingerprint(publicKey);

    const result = await vault.registerAgent({ publicKey });
    expect(result.fingerprint).toBe(expected);
  });
});

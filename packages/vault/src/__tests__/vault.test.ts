import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createVault, CredVault } from '../vault.js';
import type { RefreshAdapter, VaultEntry } from '../types.js';

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), 'vault-test-'));
}

describe('CredVault — SQLite backend', () => {
  let tmpDir: string;
  let vault: CredVault;

  beforeEach(async () => {
    tmpDir = makeTmpDir();
    vault = await createVault({
      passphrase: 'test-passphrase-sqlite',
      storage: 'sqlite',
      path: join(tmpDir, 'vault.db'),
    });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('stores and retrieves a token round-trip', async () => {
    await vault.store({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'ya29.access-token-xyz',
    });

    const entry = await vault.get({ provider: 'google', userId: 'user-1' });
    expect(entry).not.toBeNull();
    expect(entry!.accessToken).toBe('ya29.access-token-xyz');
  });

  it('stores and retrieves refresh token', async () => {
    await vault.store({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'access-token',
      refreshToken: '1//refresh-token-abc',
    });

    const entry = await vault.get({ provider: 'google', userId: 'user-1' });
    expect(entry!.refreshToken).toBe('1//refresh-token-abc');
  });

  it('returns null for non-existent entry', async () => {
    const entry = await vault.get({ provider: 'google', userId: 'nobody' });
    expect(entry).toBeNull();
  });

  it('deletes a credential', async () => {
    await vault.store({ provider: 'github', userId: 'user-1', accessToken: 'ghu_token' });
    await vault.delete({ provider: 'github', userId: 'user-1' });

    const entry = await vault.get({ provider: 'github', userId: 'user-1' });
    expect(entry).toBeNull();
  });

  it('delete is idempotent', async () => {
    await expect(
      vault.delete({ provider: 'github', userId: 'nobody' })
    ).resolves.not.toThrow();
  });

  it('lists all connections for a userId', async () => {
    await vault.store({ provider: 'google', userId: 'user-1', accessToken: 'token-g' });
    await vault.store({ provider: 'github', userId: 'user-1', accessToken: 'token-gh' });
    await vault.store({ provider: 'slack', userId: 'user-2', accessToken: 'token-s' });

    const connections = await vault.list({ userId: 'user-1' });
    expect(connections).toHaveLength(2);
    expect(connections.map((c) => c.provider).sort()).toEqual(['github', 'google']);
  });

  it('stores unicode access tokens correctly', async () => {
    const unicode = '🔑 tëst tökën with ünïcödë';
    await vault.store({ provider: 'custom', userId: 'user-1', accessToken: unicode });

    const entry = await vault.get({ provider: 'custom', userId: 'user-1' });
    expect(entry!.accessToken).toBe(unicode);
  });

  it('stores empty string access token correctly', async () => {
    await vault.store({ provider: 'custom', userId: 'user-1', accessToken: '' });

    const entry = await vault.get({ provider: 'custom', userId: 'user-1' });
    expect(entry!.accessToken).toBe('');
  });

  it('rejects decryption with wrong passphrase', async () => {
    const dbPath = join(tmpDir, 'vault.db');

    // Store with correct passphrase
    await vault.store({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'secret-token',
    });

    // Open same DB with wrong passphrase
    const wrongVault = await createVault({
      passphrase: 'WRONG-passphrase',
      storage: 'sqlite',
      path: dbPath,
    });

    // Should throw (GCM auth tag failure) — never returns real data
    await expect(
      wrongVault.get({ provider: 'google', userId: 'user-1' })
    ).rejects.toThrow();
  });

  it('preserves expiresAt and scopes', async () => {
    const expiresAt = new Date(Date.now() + 3600_000);
    await vault.store({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'token',
      expiresAt,
      scopes: ['calendar.readonly', 'gmail.readonly'],
    });

    const entry = await vault.get({ provider: 'google', userId: 'user-1' });
    expect(entry!.expiresAt?.toISOString()).toBe(expiresAt.toISOString());
    expect(entry!.scopes).toEqual(['calendar.readonly', 'gmail.readonly']);
  });

  it('auto-refreshes expired token when adapter provided', async () => {
    const pastDate = new Date(Date.now() - 10_000); // already expired

    await vault.store({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'old-access-token',
      refreshToken: 'refresh-token-abc',
      expiresAt: pastDate,
    });

    const mockAdapter: RefreshAdapter = {
      refreshAccessToken: vi.fn().mockResolvedValue({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        expiresIn: 3600,
      }),
    };

    const entry = await vault.get({
      provider: 'google',
      userId: 'user-1',
      adapter: mockAdapter,
      clientId: 'client-id',
      clientSecret: 'client-secret',
    });

    expect(mockAdapter.refreshAccessToken).toHaveBeenCalledWith(
      'refresh-token-abc',
      'client-id',
      'client-secret'
    );
    expect(entry!.accessToken).toBe('new-access-token');
    expect(entry!.refreshToken).toBe('new-refresh-token');

    // Verify new token was persisted
    const persisted = await vault.get({ provider: 'google', userId: 'user-1' });
    expect(persisted!.accessToken).toBe('new-access-token');
  });

  it('does NOT auto-refresh valid (non-expired) token', async () => {
    const futureDate = new Date(Date.now() + 3600_000);

    await vault.store({
      provider: 'google',
      userId: 'user-1',
      accessToken: 'valid-token',
      refreshToken: 'refresh-token',
      expiresAt: futureDate,
    });

    const mockAdapter: RefreshAdapter = {
      refreshAccessToken: vi.fn(),
    };

    const entry = await vault.get({
      provider: 'google',
      userId: 'user-1',
      adapter: mockAdapter,
      clientId: 'cid',
      clientSecret: 'cs',
    });

    expect(mockAdapter.refreshAccessToken).not.toHaveBeenCalled();
    expect(entry!.accessToken).toBe('valid-token');
  });
});

describe('CredVault — File backend', () => {
  let tmpDir: string;
  let vault: CredVault;

  beforeEach(async () => {
    tmpDir = makeTmpDir();
    vault = await createVault({
      passphrase: 'test-passphrase-file',
      storage: 'file',
      path: join(tmpDir, 'vault.json'),
    });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('stores and retrieves a token round-trip', async () => {
    await vault.store({
      provider: 'github',
      userId: 'user-2',
      accessToken: 'ghu_xyz123',
    });

    const entry = await vault.get({ provider: 'github', userId: 'user-2' });
    expect(entry!.accessToken).toBe('ghu_xyz123');
  });

  it('stores and retrieves refresh token via file backend', async () => {
    await vault.store({
      provider: 'google',
      userId: 'user-2',
      accessToken: 'at',
      refreshToken: 'rt-abc',
    });

    const entry = await vault.get({ provider: 'google', userId: 'user-2' });
    expect(entry!.refreshToken).toBe('rt-abc');
  });

  it('deletes from file backend', async () => {
    await vault.store({ provider: 'github', userId: 'user-2', accessToken: 'token' });
    await vault.delete({ provider: 'github', userId: 'user-2' });

    const entry = await vault.get({ provider: 'github', userId: 'user-2' });
    expect(entry).toBeNull();
  });

  it('lists connections from file backend', async () => {
    await vault.store({ provider: 'google', userId: 'user-2', accessToken: 'g-token' });
    await vault.store({ provider: 'slack', userId: 'user-2', accessToken: 's-token' });

    const list = await vault.list({ userId: 'user-2' });
    expect(list).toHaveLength(2);
  });

  it('rejects wrong passphrase on file backend', async () => {
    const jsonPath = join(tmpDir, 'vault.json');

    await vault.store({ provider: 'google', userId: 'u1', accessToken: 'secret' });

    const wrongVault = await createVault({
      passphrase: 'WRONG',
      storage: 'file',
      path: jsonPath,
    });

    await expect(wrongVault.get({ provider: 'google', userId: 'u1' })).rejects.toThrow();
  });
});

describe('CredVault — throws before init', () => {
  it('auto-initializes on first operation (lazy init)', async () => {
    const vault = new CredVault({
      passphrase: 'pass',
      storage: 'file',
      path: '/tmp/test-vault-lazy-init.json',
    });

    // Should NOT throw — lazy init kicks in automatically
    await vault.store({ provider: 'google', userId: 'u', accessToken: 'token' });
    const result = await vault.get({ provider: 'google', userId: 'u' });
    expect(result).not.toBeNull();
    expect(result!.accessToken).toBe('token');

    // Cleanup
    const fs = await import('fs');
    try { fs.unlinkSync('/tmp/test-vault-lazy-init.json'); } catch {}
    try { fs.unlinkSync('/tmp/test-vault-lazy-init.json.salt'); } catch {}
  });
});

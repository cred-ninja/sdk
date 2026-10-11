import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createVault } from '../vault.js';
import type { CredVault } from '../vault.js';
import type { RefreshAdapter } from '../types.js';

const HOUR = 60 * 60 * 1000;

for (const storage of ['sqlite', 'file'] as const) {
  describe(`CredVault.getStored (${storage} backend)`, () => {
    let dir: string;
    let vault: CredVault;

    beforeEach(async () => {
      dir = mkdtempSync(join(tmpdir(), 'vault-get-stored-'));
      vault = await createVault({
        passphrase: 'get-stored-test',
        storage,
        path: join(dir, storage === 'sqlite' ? 'vault.db' : 'vault.json'),
      });
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    it('returns a fresh entry, same as get()', async () => {
      const expiresAt = new Date(Date.now() + HOUR);
      await vault.store({ provider: 'google', userId: 'u1', accessToken: 'a1', refreshToken: 'r1', expiresAt, scopes: ['s1'] });
      const stored = await vault.getStored({ provider: 'google', userId: 'u1' });
      expect(stored).toMatchObject({ provider: 'google', userId: 'u1', accessToken: 'a1', refreshToken: 'r1', scopes: ['s1'] });
      expect(stored?.expiresAt?.toISOString()).toBe(expiresAt.toISOString());
      expect(stored?.createdAt).toBeInstanceOf(Date);
      const got = await vault.get({ provider: 'google', userId: 'u1' });
      expect(stored).toEqual(got);
    });

    it('returns an expired entry with a refresh token, without refreshing it', async () => {
      const expiresAt = new Date(Date.now() - HOUR);
      await vault.store({ provider: 'google', userId: 'u1', accessToken: 'old', refreshToken: 'r1', expiresAt });
      expect(await vault.get({ provider: 'google', userId: 'u1' })).toBeNull();
      const stored = await vault.getStored({ provider: 'google', userId: 'u1' });
      expect(stored).toMatchObject({ accessToken: 'old', refreshToken: 'r1' });
      expect(stored?.expiresAt?.toISOString()).toBe(expiresAt.toISOString());
      // Nothing was rewritten: get() with an adapter still sees the expired entry and refreshes it.
      let calls = 0;
      const adapter: RefreshAdapter = {
        async refreshAccessToken() {
          calls += 1;
          return { accessToken: 'new', expiresIn: 3600 };
        },
      };
      const refreshed = await vault.get({ provider: 'google', userId: 'u1', adapter, clientId: 'c', clientSecret: 's' });
      expect(calls).toBe(1);
      expect(refreshed?.accessToken).toBe('new');
    });

    it('returns an expired entry without a refresh token', async () => {
      const expiresAt = new Date(Date.now() - HOUR);
      await vault.store({ provider: 'github', userId: 'u2', accessToken: 'gho_old', expiresAt });
      expect(await vault.get({ provider: 'github', userId: 'u2' })).toBeNull();
      expect(await vault.list({ userId: 'u2' })).toHaveLength(storage === 'file' ? 1 : 0);
      const stored = await vault.getStored({ provider: 'github', userId: 'u2' });
      expect(stored).toMatchObject({ accessToken: 'gho_old' });
      expect(stored?.refreshToken).toBeUndefined();
    });

    it('returns null when absent', async () => {
      expect(await vault.getStored({ provider: 'google', userId: 'nobody' })).toBeNull();
      await vault.store({ provider: 'google', userId: 'u1', accessToken: 'a1' });
      expect(await vault.getStored({ provider: 'github', userId: 'u1' })).toBeNull();
      await vault.delete({ provider: 'google', userId: 'u1' });
      expect(await vault.getStored({ provider: 'google', userId: 'u1' })).toBeNull();
    });
  });
}

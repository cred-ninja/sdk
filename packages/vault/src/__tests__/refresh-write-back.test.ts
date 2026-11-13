// A refresh writes its tokens back only over the row it refreshed. A delete
// or a new store that lands while the provider call is in flight wins.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createVault, CredVault } from '../vault.js';
import type { RefreshAdapter } from '../types.js';

function deferred<T = void>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

/** An adapter whose refresh waits until the test releases it. */
function pausedAdapter(result: { accessToken: string; refreshToken?: string; expiresIn?: number }) {
  const started = deferred();
  const release = deferred();
  const adapter: RefreshAdapter = {
    refreshAccessToken: vi.fn(async () => {
      started.resolve();
      await release.promise;
      return result;
    }),
  };
  return { adapter, started, release };
}

const CLIENT = { clientId: 'client-id', clientSecret: 'client-secret' };

for (const storage of ['sqlite', 'file'] as const) {
  describe(`refresh write-back (${storage} backend)`, () => {
    let tmpDir: string;
    let vault: CredVault;

    beforeEach(async () => {
      tmpDir = mkdtempSync(join(tmpdir(), 'vault-refresh-'));
      vault = await createVault({ passphrase: `refresh-${storage}`, storage, path: join(tmpDir, storage === 'sqlite' ? 'vault.db' : 'vault.json') });
      await vault.store({
        provider: 'google',
        userId: 'user-1',
        accessToken: 'expired-access',
        refreshToken: 'old-refresh',
        expiresAt: new Date(Date.now() - 1000),
        scopes: ['gmail.readonly'],
      });
    });

    afterEach(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it('a delete during an in-flight refresh stays deleted', async () => {
      const { adapter, started, release } = pausedAdapter({ accessToken: 'refreshed-access', refreshToken: 'rotated-refresh', expiresIn: 3600 });
      const pending = vault.get({ provider: 'google', userId: 'user-1', adapter, ...CLIENT });
      await started.promise;

      await vault.delete({ provider: 'google', userId: 'user-1' });
      release.resolve();

      // The caller is not handed tokens for a connection that no longer exists.
      expect(await pending).toBeNull();
      expect(await vault.getStored({ provider: 'google', userId: 'user-1' })).toBeNull();
      expect(await vault.list({ userId: 'user-1' })).toEqual([]);
    });

    it('a reconnect during an in-flight refresh is not overwritten', async () => {
      const { adapter, started, release } = pausedAdapter({ accessToken: 'refreshed-access', refreshToken: 'rotated-refresh', expiresIn: 3600 });
      const pending = vault.get({ provider: 'google', userId: 'user-1', adapter, ...CLIENT });
      await started.promise;

      await vault.delete({ provider: 'google', userId: 'user-1' });
      await vault.store({
        provider: 'google',
        userId: 'user-1',
        accessToken: 'reconnected-access',
        refreshToken: 'reconnected-refresh',
        expiresAt: new Date(Date.now() + 3600_000),
        scopes: ['calendar.readonly'],
      });
      release.resolve();

      const entry = await pending;
      expect(entry?.accessToken).toBe('reconnected-access');
      expect(entry?.scopes).toEqual(['calendar.readonly']);
      const stored = await vault.getStored({ provider: 'google', userId: 'user-1' });
      expect(stored?.accessToken).toBe('reconnected-access');
      expect(stored?.refreshToken).toBe('reconnected-refresh');
      expect(stored?.scopes).toEqual(['calendar.readonly']);
    });

    it('an uncontended refresh still persists its tokens', async () => {
      const { adapter, started, release } = pausedAdapter({ accessToken: 'refreshed-access', refreshToken: 'rotated-refresh', expiresIn: 3600 });
      const pending = vault.get({ provider: 'google', userId: 'user-1', adapter, ...CLIENT });
      await started.promise;
      release.resolve();

      expect((await pending)?.accessToken).toBe('refreshed-access');
      const stored = await vault.getStored({ provider: 'google', userId: 'user-1' });
      expect(stored?.accessToken).toBe('refreshed-access');
      expect(stored?.refreshToken).toBe('rotated-refresh');
      expect(stored?.scopes).toEqual(['gmail.readonly']);
    });

    it('two overlapping refreshes leave one consistent row and both callers get a token', async () => {
      const first = pausedAdapter({ accessToken: 'first-access', refreshToken: 'first-refresh', expiresIn: 3600 });
      const second = pausedAdapter({ accessToken: 'second-access', refreshToken: 'second-refresh', expiresIn: 3600 });
      const a = vault.get({ provider: 'google', userId: 'user-1', adapter: first.adapter, ...CLIENT });
      await first.started.promise;
      const b = vault.get({ provider: 'google', userId: 'user-1', adapter: second.adapter, ...CLIENT });
      await second.started.promise;

      first.release.resolve();
      expect((await a)?.accessToken).toBe('first-access');
      second.release.resolve();
      // The second refresh lost the race: it is handed the row the first wrote.
      expect((await b)?.accessToken).toBe('first-access');

      const stored = await vault.getStored({ provider: 'google', userId: 'user-1' });
      expect(stored?.accessToken).toBe('first-access');
      expect(stored?.refreshToken).toBe('first-refresh');
    });
  });
}

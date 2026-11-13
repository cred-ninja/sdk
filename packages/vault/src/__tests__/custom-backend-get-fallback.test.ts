/**
 * A custom storage backend written before `getForRefresh` existed.
 *
 * `getStored()` — the accessor the delegation paths use to decide what the
 * stored connection covers, and now also the entry they issue against — reads
 * through `getForRefresh()` when the backend has one and falls back to `get()`
 * when it does not. The fallback is not equivalent: a backend's `get()` may
 * hide an expired row, so an expired connection is reported as no connection at
 * all. That is a documented compatibility limit, not a refusal to decide: an
 * absent or hidden row covers nothing, and the refusal it produces names no
 * credential.
 *
 * These cases pin the fallback's three shapes — an absent row, an expired row
 * and a backend that throws — so the wording in the release notes and the
 * server README stays true to the code.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CredVault } from '../vault.js';
import type { StorageBackend } from '../storage/interface.js';

const PASSPHRASE = 'test-passphrase-custom-backend';
const TOKEN = 'synthetic-custom-backend-token';
const dirs: string[] = [];

afterAll(() => {
  for (const made of dirs) rmSync(made, { recursive: true, force: true });
});

/** A real vault whose backend is then aged to the pre-getForRefresh interface. */
async function vaultWithoutGetForRefresh(): Promise<{ vault: CredVault; backend: Partial<StorageBackend> }> {
  const where = mkdtempSync(join(tmpdir(), 'cred-custom-backend-'));
  dirs.push(where);
  const vault = new CredVault({ passphrase: PASSPHRASE, path: join(where, 'vault.json'), storage: 'file' });
  await vault.init();
  const backend = (vault as unknown as { backend: Partial<StorageBackend> }).backend;
  // Exactly the interface a backend written for 2.0.0 offers. Both members are
  // prototype methods on the built-in backends, so they are shadowed rather
  // than deleted.
  backend.getForRefresh = undefined;
  backend.replaceIfUnchanged = undefined;
  return { vault, backend };
}

describe('getStored() on a backend without getForRefresh', () => {
  it('reads an ordinary row through get(), the same row get() returns', async () => {
    const { vault, backend } = await vaultWithoutGetForRefresh();
    await vault.store({ provider: 'github', userId: 'alice', accessToken: TOKEN, scopes: ['public_repo'], expiresAt: new Date(Date.now() + 3_600_000) });

    const stored = await vault.getStored({ provider: 'github', userId: 'alice' });
    const fetched = await vault.get({ provider: 'github', userId: 'alice' });
    expect(stored?.accessToken).toBe(TOKEN);
    expect(fetched?.accessToken).toBe(TOKEN);
    expect(stored?.scopes).toEqual(['public_repo']);
    expect(fetched?.scopes).toEqual(['public_repo']);
    // One accessor, one row: the fallback cannot disagree with get() about an
    // ordinary entry, which is why the pinned-credential path can use it.
    expect(backend.get).toBeTypeOf('function');
  });

  it('reports an absent row as null, never as an error carrying a credential', async () => {
    const { vault } = await vaultWithoutGetForRefresh();
    const stored = await vault.getStored({ provider: 'github', userId: 'nobody' });
    const fetched = await vault.get({ provider: 'github', userId: 'nobody' });
    expect(stored).toBeNull();
    expect(fetched).toBeNull();
  });

  it('reports an expired row that get() hides as no connection at all', async () => {
    const { vault } = await vaultWithoutGetForRefresh();
    await vault.store({ provider: 'github', userId: 'alice', accessToken: TOKEN, scopes: ['public_repo'], expiresAt: new Date(Date.now() - 60_000) });

    // getForRefresh would still return this row; the fallback does not, so the
    // accessor that decides reports no connection.
    expect(await vault.getStored({ provider: 'github', userId: 'alice' })).toBeNull();
    expect(await vault.get({ provider: 'github', userId: 'alice' })).toBeNull();
  });

  it('surfaces a backend error without adding credential material to it', async () => {
    const { vault, backend } = await vaultWithoutGetForRefresh();
    await vault.store({ provider: 'github', userId: 'alice', accessToken: TOKEN, scopes: ['public_repo'], expiresAt: new Date(Date.now() + 3_600_000) });
    backend.get = (provider: string, userId: string) => {
      throw new Error(`custom backend unavailable: ${provider}/${userId}`);
    };

    const stored = await vault.getStored({ provider: 'github', userId: 'alice' }).then(
      () => null,
      (error: Error) => error,
    );
    expect(stored).toBeInstanceOf(Error);
    // The failure names the connection, never the credential inside it.
    expect((stored as Error).message).toContain('github/alice');
    expect((stored as Error).message).not.toContain(TOKEN);
  });
});

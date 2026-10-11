import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { createVault } from '../vault.js';
import type { CredVault } from '../vault.js';
import { ReservedVaultUserIdError } from '../link/index.js';
import { LINK_VAULT_ACCESS } from '../link/vault-access.js';
import type { LinkVaultAccess } from '../link/vault-access.js';
import * as vaultPackage from '../index.js';

const RESERVED = ['link:conn_abc123', 'link-staged:ltx_abc123', 'link:', 'link-staged:'];
const FORGED: unknown[] = [
  Symbol('credninja.vault.linkAccess'),
  Symbol.for('credninja.vault.linkAccess'),
  'LINK_VAULT_ACCESS',
  'credninja.vault.linkAccess',
  true,
  {},
];

for (const storage of ['sqlite', 'file'] as const) {
  describe(`CredVault refuses reserved Link user ids (${storage} backend)`, () => {
    let dir: string;
    let vault: CredVault;

    beforeEach(async () => {
      dir = mkdtempSync(join(tmpdir(), 'vault-reserved-'));
      vault = await createVault({
        passphrase: 'reserved-id-test',
        storage,
        path: join(dir, storage === 'sqlite' ? 'vault.db' : 'vault.json'),
      });
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
    });

    /** Every public CredVault method that takes a userId, called with `userId` and optional access. */
    function calls(userId: string, access?: LinkVaultAccess): Array<[string, () => Promise<unknown>]> {
      return [
        ['store', () => vault.store({ provider: 'google', userId, accessToken: 'tok' }, access)],
        ['get', () => vault.get({ provider: 'google', userId }, access)],
        ['get (with adapter)', () => vault.get({
          provider: 'google', userId, clientId: 'c', clientSecret: 's',
          adapter: { refreshAccessToken: async () => ({ accessToken: 'x' }) },
        }, access)],
        ['getStored', () => vault.getStored({ provider: 'google', userId }, access)],
        ['delete', () => vault.delete({ provider: 'google', userId }, access)],
        ['list', () => vault.list({ userId }, access)],
        ['getRotationByConnection', () => vault.getRotationByConnection('google', userId, access)],
      ];
    }

    it.each(RESERVED)('every userId method throws ReservedVaultUserIdError for %j without the capability', async (userId) => {
      for (const [name, call] of calls(userId)) {
        const err = await call().then(() => null, (e: unknown) => e);
        expect(err, name).toBeInstanceOf(ReservedVaultUserIdError);
        expect((err as ReservedVaultUserIdError).code).toBe('reserved_user_id');
        expect((err as Error).message).toMatch(/reserved/);
      }
    });

    it('forged capabilities (same-description symbols, strings, objects) are refused', async () => {
      for (const forged of FORGED) {
        for (const [name, call] of calls('link:conn_abc123', forged as LinkVaultAccess)) {
          await expect(call(), `${name} with ${String(forged)}`).rejects.toBeInstanceOf(ReservedVaultUserIdError);
        }
      }
    });

    it('a refused store writes nothing', async () => {
      await expect(vault.store({ provider: 'google', userId: 'link:conn_abc123', accessToken: 'tok' })).rejects.toBeInstanceOf(ReservedVaultUserIdError);
      expect(await vault.getStored({ provider: 'google', userId: 'link:conn_abc123' }, LINK_VAULT_ACCESS)).toBeNull();
    });

    it('with the internal capability every method works on reserved ids', async () => {
      const userId = 'link:conn_abc123';
      await vault.store({ provider: 'google', userId, accessToken: 'tok', scopes: ['a'] }, LINK_VAULT_ACCESS);
      expect((await vault.get({ provider: 'google', userId }, LINK_VAULT_ACCESS))?.accessToken).toBe('tok');
      expect((await vault.getStored({ provider: 'google', userId }, LINK_VAULT_ACCESS))?.scopes).toEqual(['a']);
      expect(await vault.list({ userId }, LINK_VAULT_ACCESS)).toHaveLength(1);
      expect(await vault.getRotationByConnection('google', userId, LINK_VAULT_ACCESS)).toBeNull();
      await vault.delete({ provider: 'google', userId }, LINK_VAULT_ACCESS);
      expect(await vault.getStored({ provider: 'google', userId }, LINK_VAULT_ACCESS)).toBeNull();
    });

    it('ordinary user ids are unaffected, with or without an access argument', async () => {
      for (const userId of ['user-123', 'Link:conn_abc', ' link:conn_abc', 'linkconn', 'link']) {
        await vault.store({ provider: 'google', userId, accessToken: `t-${userId}` });
        expect((await vault.get({ provider: 'google', userId }))?.accessToken).toBe(`t-${userId}`);
        expect((await vault.getStored({ provider: 'google', userId }))?.accessToken).toBe(`t-${userId}`);
        expect(await vault.list({ userId })).toHaveLength(1);
        await vault.delete({ provider: 'google', userId });
        expect(await vault.get({ provider: 'google', userId })).toBeNull();
      }
    });
  });
}

describe('Link vault capability visibility', () => {
  it('is not exported from the package entry point; the typed error is', () => {
    const exported = Object.values(vaultPackage) as unknown[];
    expect(exported).not.toContain(LINK_VAULT_ACCESS);
    expect(Object.keys(vaultPackage).some((k) => /access/i.test(k) && k !== 'ReservedVaultUserIdError')).toBe(false);
    expect(vaultPackage.ReservedVaultUserIdError).toBe(ReservedVaultUserIdError);
  });
});

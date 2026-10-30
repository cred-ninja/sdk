/**
 * Consent records (draft-sweeney-wimse-credential-delegation-02 Section
 * 8.2) are written once and never changed.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import Database from 'better-sqlite3';
import { CredVault } from '../vault.js';
import type { RecordConsentInput } from '../consent.js';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function input(id: string, overrides: Partial<RecordConsentInput> = {}): RecordConsentInput {
  return {
    id,
    subject: 'user-1',
    agentDid: 'did:key:z6MkAgent',
    service: 'google',
    capabilities: [{ type: 'cred_delegation', provider: 'google', operations: ['drive.readonly'] }],
    source: 'permission',
    approvedBy: 'admin',
    expiresAt: null,
    chainContext: { chainDepth: 0 },
    ...overrides,
  };
}

describe.each(['sqlite', 'file'] as const)('consent records (%s)', (storage) => {
  async function vault() {
    const dir = mkdtempSync(join(tmpdir(), 'cred-consent-'));
    dirs.push(dir);
    const path = join(dir, storage === 'sqlite' ? 'vault.db' : 'vault.json');
    const v = new CredVault({ passphrase: 'consent-test-passphrase', storage, path });
    await v.init();
    return { v, path };
  }

  it('stores a record and reads it back with a grant time', async () => {
    const { v } = await vault();
    const stored = await v.recordConsent(input('consent_1'));
    expect(stored).toMatchObject(input('consent_1'));
    expect(Date.parse(stored.grantedAt)).not.toBeNaN();
    expect(await v.getConsent('consent_1')).toEqual(stored);
    expect(await v.getConsent('missing')).toBeNull();
  });

  it('keeps the first record when an id is replayed', async () => {
    const { v } = await vault();
    const first = await v.recordConsent(input('consent_1'));
    const replay = await v.recordConsent(input('consent_1', { approvedBy: 'someone-else' }));
    expect(replay).toEqual(first);
  });

  it('revokes consents by id, subject or agent, once, and never by an empty filter', async () => {
    const { v } = await vault();
    await v.recordConsent(input('c1'));
    await v.recordConsent(input('c2', { agentDid: 'did:key:z6MkOther' }));
    await v.recordConsent(input('c3', { subject: 'user-2' }));
    expect(await v.revokeConsents({}, 'nothing')).toEqual([]);
    expect(await v.revokeConsents({ subject: 'user-1', agentDid: 'did:key:z6MkAgent' }, 'key compromise')).toEqual(['c1']);
    expect(await v.revokeConsents({ subject: 'user-1' }, 'again')).toEqual(['c2']);
    expect((await v.getConsentRevocation('c1'))).toMatchObject({ consentId: 'c1', reason: 'key compromise' });
    expect(await v.getConsentRevocation('c3')).toBeNull();
    // The record itself is unchanged.
    expect(await v.getConsent('c1')).toMatchObject({ approvedBy: 'admin' });
  });

  it('purges only records whose retention ended, counting from the later of grant and expiry', async () => {
    const { v } = await vault();
    await v.recordConsent(input('old'));
    await v.recordConsent(input('long', { expiresAt: new Date(Date.now() + 400 * 86_400_000).toISOString() }));
    const future = new Date(Date.now() + 60_000);
    expect(await v.purgeConsents(future)).toBe(1);
    expect(await v.getConsent('old')).toBeNull();
    expect(await v.getConsent('long')).not.toBeNull();
  });

  if (storage === 'sqlite') {
    it('refuses an update made directly in the database', async () => {
      const { v, path } = await vault();
      await v.recordConsent(input('consent_1'));
      const db = new Database(path);
      expect(() => db.prepare("UPDATE vault_consents SET approved_by = 'attacker' WHERE id = 'consent_1'").run())
        .toThrow(/immutable/);
      db.close();
    });
  }
});

/**
 * The vault refuses a passphrase other than the one it was created with,
 * before any read or write: a wrong passphrase would otherwise extend the
 * audit chain under the wrong key, and a later verification would report a
 * configuration mistake as tampering.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, rmSync, statSync, unlinkSync, writeFileSync } from 'fs';
import { dirname, join } from 'path';
import { tmpdir } from 'os';
import Database from 'better-sqlite3';
import { CredVault } from '../vault.js';
import type { AuditEvent } from '../audit.js';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function vaultPath(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'cred-passphrase-check-'));
  dirs.push(dir);
  return join(dir, name);
}

function event(id: string): AuditEvent {
  return {
    id,
    timestamp: new Date(),
    actor: { type: 'agent', id: 'did:key:z6MkAgent' },
    action: 'delegate',
    resource: { type: 'token', id: 'google/alice' },
    outcome: 'success',
    correlationId: `corr_${id}`,
  };
}

describe('vault passphrase check', () => {
  it('writes a check value on first init and accepts the same passphrase again', async () => {
    const path = vaultPath('vault.db');
    await new CredVault({ passphrase: 'right-passphrase', storage: 'sqlite', path }).init();
    expect(existsSync(`${path}.check`)).toBe(true);
    expect(statSync(`${path}.check`).mode & 0o777).toBe(0o600);
    await expect(new CredVault({ passphrase: 'right-passphrase', storage: 'sqlite', path }).init()).resolves.toBeUndefined();
  });

  it('refuses another passphrase before any audit row is written', async () => {
    const path = vaultPath('vault.db');
    const first = new CredVault({ passphrase: 'right-passphrase', storage: 'sqlite', path });
    await first.init();
    first.writeAuditEvent(event('evt_1'));

    const wrong = new CredVault({ passphrase: 'wrong-passphrase', storage: 'sqlite', path });
    await expect(wrong.init()).rejects.toThrow(/passphrase does not match/);
    expect(() => wrong.writeAuditEvent(event('evt_2'))).toThrow();

    const db = new Database(path);
    expect((db.prepare('SELECT COUNT(*) AS n FROM vault_audit_events').get() as { n: number }).n).toBe(1);
    db.close();
    expect(first.verifyAuditChain()).toMatchObject({ ok: true, entries: 1 });
  });

  it('pins the passphrase of a vault created before the check existed', async () => {
    const path = vaultPath('vault.db');
    await new CredVault({ passphrase: 'right-passphrase', storage: 'sqlite', path }).init();
    unlinkSync(`${path}.check`);

    await new CredVault({ passphrase: 'right-passphrase', storage: 'sqlite', path }).init();
    expect(existsSync(`${path}.check`)).toBe(true);
    await expect(new CredVault({ passphrase: 'wrong-passphrase', storage: 'sqlite', path }).init())
      .rejects.toThrow(/passphrase does not match/);
  });

  it('starts a new check value when the vault is reset by removing its salt', async () => {
    const path = vaultPath('vault.db');
    await new CredVault({ passphrase: 'old-passphrase', storage: 'sqlite', path }).init();
    rmSync(path);
    unlinkSync(`${path}.salt`);
    await expect(new CredVault({ passphrase: 'new-passphrase', storage: 'sqlite', path }).init()).resolves.toBeUndefined();
    expect(statSync(`${path}.check`).mode & 0o777).toBe(0o600);
    await expect(new CredVault({ passphrase: 'old-passphrase', storage: 'sqlite', path }).init())
      .rejects.toThrow(/passphrase does not match/);
  });

  it('converges on one salt and check value when two instances create the vault at once', async () => {
    const path = vaultPath('vault.db');
    const passphrase = 'right-passphrase';
    await Promise.all(Array.from({ length: 4 }, () => new CredVault({ passphrase, storage: 'sqlite', path }).init()));
    await expect(new CredVault({ passphrase, storage: 'sqlite', path }).init()).resolves.toBeUndefined();
    expect(readdirSync(dirname(path)).filter((name) => name.endsWith('.tmp'))).toEqual([]);
  });

  it('names the check file and the way out when the passphrase does not match', async () => {
    const path = vaultPath('vault.db');
    await new CredVault({ passphrase: 'right-passphrase', storage: 'sqlite', path }).init();
    await expect(new CredVault({ passphrase: 'wrong-passphrase', storage: 'sqlite', path }).init())
      .rejects.toThrow(new RegExp(`${path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\.check.*remove it`));
  });

  it('enforces the check on file storage as well', async () => {
    const path = vaultPath('vault.json');
    await new CredVault({ passphrase: 'right-passphrase', storage: 'file', path }).init();
    await expect(new CredVault({ passphrase: 'wrong-passphrase', storage: 'file', path }).init())
      .rejects.toThrow(/passphrase does not match/);
  });

  it('refuses a corrupt check value instead of rewriting it', async () => {
    const path = vaultPath('vault.db');
    await new CredVault({ passphrase: 'right-passphrase', storage: 'sqlite', path }).init();
    writeFileSync(`${path}.check`, 'not-hex');
    await expect(new CredVault({ passphrase: 'right-passphrase', storage: 'sqlite', path }).init())
      .rejects.toThrow(/check value/);
  });
});

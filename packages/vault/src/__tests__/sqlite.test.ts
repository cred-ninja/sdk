import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SQLiteBackend } from '../storage/sqlite.js';
import type { StoredRow } from '../types.js';

function makeRow(overrides: Partial<StoredRow> = {}): StoredRow {
  const now = new Date().toISOString();
  return {
    provider: 'google',
    userId: 'user-123',
    accessTokenEnc: 'deadbeef',
    accessTokenIv: 'aabbccdd00112233aabbccdd00112233',
    accessTokenTag: '00112233445566778899aabbccddeeff',
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

describe('SQLiteBackend', () => {
  let tmpDir: string;
  let backend: SQLiteBackend;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vault-sqlite-test-'));
    backend = new SQLiteBackend(join(tmpDir, 'vault.db'));
    backend.init();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('creates table on init without errors', () => {
    // init() is called in beforeEach — if it didn't throw, it succeeded
    expect(true).toBe(true);
  });

  it('returns null for missing entry', () => {
    const result = backend.get('google', 'nonexistent');
    expect(result).toBeNull();
  });

  it('stores and retrieves a row', () => {
    const row = makeRow();
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result).not.toBeNull();
    expect(result!.accessTokenEnc).toBe(row.accessTokenEnc);
    expect(result!.accessTokenIv).toBe(row.accessTokenIv);
    expect(result!.accessTokenTag).toBe(row.accessTokenTag);
  });

  it('upserts on duplicate provider+userId', () => {
    const row1 = makeRow({ accessTokenEnc: 'ciphertext-v1' });
    backend.store(row1);

    const row2 = makeRow({ accessTokenEnc: 'ciphertext-v2' });
    backend.store(row2);

    const result = backend.get('google', 'user-123');
    expect(result!.accessTokenEnc).toBe('ciphertext-v2');
  });

  it('stores optional refresh token fields', () => {
    const row = makeRow({
      refreshTokenEnc: 'refresh-cipher',
      refreshTokenIv: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      refreshTokenTag: 'cccccccccccccccccccccccccccccccc',
    });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result!.refreshTokenEnc).toBe('refresh-cipher');
  });

  it('deletes a row', () => {
    backend.store(makeRow());
    backend.delete('google', 'user-123');

    const result = backend.get('google', 'user-123');
    expect(result).toBeNull();
  });

  it('delete is idempotent (no throw for missing)', () => {
    expect(() => backend.delete('google', 'nonexistent')).not.toThrow();
  });

  it('lists rows by userId', () => {
    backend.store(makeRow({ provider: 'google', userId: 'user-abc' }));
    backend.store(makeRow({ provider: 'github', userId: 'user-abc' }));
    backend.store(makeRow({ provider: 'slack', userId: 'user-xyz' }));

    const results = backend.list('user-abc');
    expect(results).toHaveLength(2);
    expect(results.map((r) => r.provider).sort()).toEqual(['github', 'google']);
  });

  it('returns empty array when no rows for userId', () => {
    const results = backend.list('no-such-user');
    expect(results).toEqual([]);
  });

  it('preserves expiresAt and scopes', () => {
    const now = new Date().toISOString();
    const row = makeRow({
      expiresAt: now,
      scopes: '["calendar","email"]',
    });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result!.expiresAt).toBe(now);
    expect(result!.scopes).toBe('["calendar","email"]');
  });
});

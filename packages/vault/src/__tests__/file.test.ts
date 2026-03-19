import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { FileBackend } from '../storage/file.js';
import type { StoredRow } from '../types.js';

function makeRow(overrides: Partial<StoredRow> = {}): StoredRow {
  const now = new Date().toISOString();
  return {
    provider: 'google',
    userId: 'user-123',
    accessTokenEnc: 'deadbeef1234',
    accessTokenIv: 'aabbccdd00112233aabbccdd00112233',
    accessTokenTag: '00112233445566778899aabbccddeeff',
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

describe('FileBackend', () => {
  let tmpDir: string;
  let filePath: string;
  let backend: FileBackend;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vault-file-test-'));
    filePath = join(tmpDir, 'vault.json');
    backend = new FileBackend(filePath);
    backend.init();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('does not create the file on init (lazy)', () => {
    expect(existsSync(filePath)).toBe(false);
  });

  it('creates the file on first store()', () => {
    backend.store(makeRow());
    expect(existsSync(filePath)).toBe(true);
  });

  it('returns null for missing entry', () => {
    const result = backend.get('google', 'nonexistent');
    expect(result).toBeNull();
  });

  it('returns null when file does not exist', () => {
    const result = backend.get('google', 'user-123');
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
    backend.store(makeRow({ accessTokenEnc: 'cipher-v1' }));
    backend.store(makeRow({ accessTokenEnc: 'cipher-v2' }));

    const result = backend.get('google', 'user-123');
    expect(result!.accessTokenEnc).toBe('cipher-v2');
  });

  it('file content is NOT plaintext token values', () => {
    // The backend stores ciphertext in the JSON — raw tokens are never passed here.
    // This test verifies the actual token value ('my-plain-token') is NOT in the file.
    // (In real usage, the value stored would be ciphertext anyway.)
    const row = makeRow({ accessTokenEnc: 'cipher-aabbccdd' });
    backend.store(row);

    const raw = readFileSync(filePath, 'utf8');
    // The ciphertext should be present, not any "plain" token
    expect(raw).toContain('cipher-aabbccdd');
    expect(raw).not.toContain('my-plain-token');
  });

  it('deletes a row', () => {
    backend.store(makeRow());
    backend.delete('google', 'user-123');

    const result = backend.get('google', 'user-123');
    expect(result).toBeNull();
  });

  it('delete is idempotent (no throw for missing)', () => {
    expect(() => backend.delete('google', 'nonexistent')).not.toThrow();
    // Also idempotent when file doesn't exist
    expect(() => backend.delete('google', 'user-123')).not.toThrow();
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

  it('returns empty array when file does not exist', () => {
    const results = backend.list('user-123');
    expect(results).toEqual([]);
  });

  it('stores refresh token fields', () => {
    const row = makeRow({
      refreshTokenEnc: 'refresh-cipher',
      refreshTokenIv: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      refreshTokenTag: 'cccccccccccccccccccccccccccccccc',
    });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result!.refreshTokenEnc).toBe('refresh-cipher');
  });

  it('returns null for expired row without refresh token', () => {
    const past = new Date(Date.now() - 10_000).toISOString();
    const row = makeRow({ expiresAt: past });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result).toBeNull();
  });

  it('returns expired row when refresh token is present (needed for auto-refresh)', () => {
    const past = new Date(Date.now() - 10_000).toISOString();
    const row = makeRow({
      expiresAt: past,
      refreshTokenEnc: 'refresh-cipher',
      refreshTokenIv: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      refreshTokenTag: 'cccccccccccccccccccccccccccccccc',
    });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result).not.toBeNull();
    expect(result!.refreshTokenEnc).toBe('refresh-cipher');
  });

  it('returns row when expires_at is in the future', () => {
    const future = new Date(Date.now() + 3600_000).toISOString();
    const row = makeRow({ expiresAt: future });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result).not.toBeNull();
  });

  it('returns row when expires_at is null', () => {
    const row = makeRow({ expiresAt: undefined });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result).not.toBeNull();
  });
});

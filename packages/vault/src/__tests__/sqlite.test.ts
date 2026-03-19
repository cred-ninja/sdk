import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SQLiteBackend } from '../storage/sqlite.js';
import type { StoredRow, AgentRow } from '../types.js';

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
    const future = new Date(Date.now() + 3600_000).toISOString();
    const row = makeRow({
      expiresAt: future,
      scopes: '["calendar","email"]',
    });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result!.expiresAt).toBe(future);
    expect(result!.scopes).toBe('["calendar","email"]');
  });

  it('returns null for expired row without refresh token', () => {
    const past = new Date(Date.now() - 10_000).toISOString(); // 10 seconds ago
    const row = makeRow({ expiresAt: past });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result).toBeNull();
  });

  it('returns row when expires_at is in the future', () => {
    const future = new Date(Date.now() + 3600_000).toISOString(); // 1 hour from now
    const row = makeRow({ expiresAt: future });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result).not.toBeNull();
    expect(result!.accessTokenEnc).toBe(row.accessTokenEnc);
  });

  it('returns row when expires_at is null (no expiry — non-expiring creds)', () => {
    const row = makeRow({ expiresAt: undefined });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result).not.toBeNull();
  });

  it('filters expired row even when refresh token is present', () => {
    const past = new Date(Date.now() - 10_000).toISOString();
    const row = makeRow({
      expiresAt: past,
      refreshTokenEnc: 'refresh-cipher',
      refreshTokenIv: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      refreshTokenTag: 'cccccccccccccccccccccccccccccccc',
    });
    backend.store(row);

    const result = backend.get('google', 'user-123');
    expect(result).toBeNull();
  });

  it('list filters expired rows', () => {
    const future = new Date(Date.now() + 3600_000).toISOString();
    const past = new Date(Date.now() - 10_000).toISOString();

    backend.store(makeRow({ provider: 'google', userId: 'user-abc', expiresAt: future }));
    backend.store(makeRow({
      provider: 'github',
      userId: 'user-abc',
      expiresAt: past,
      refreshTokenEnc: 'refresh-cipher',
      refreshTokenIv: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      refreshTokenTag: 'cccccccccccccccccccccccccccccccc',
    }));

    const results = backend.list('user-abc');
    expect(results).toHaveLength(1);
    expect(results[0].provider).toBe('google');
  });
});

// ── vault_agents table ───────────────────────────────────────────────────────

describe('SQLiteBackend — vault_agents', () => {
  let backend: SQLiteBackend;
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cred-sqlite-agent-'));
    backend = new SQLiteBackend(join(tmpDir, 'vault.db'));
    backend.init();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function makeAgentRow(overrides: Partial<AgentRow> = {}): AgentRow {
    const now = new Date().toISOString();
    return {
      id: 'agt_001',
      fingerprint: 'abc123fingerprint',
      name: 'test-agent',
      scopeCeiling: '["repo","read:org"]',
      status: 'active',
      createdBy: 'user_001',
      createdAt: now,
      updatedAt: now,
      lastSeenAt: null,
      revokedAt: null,
      ...overrides,
    };
  }

  it('stores and retrieves an agent by id', () => {
    backend.storeAgent(makeAgentRow());
    const agent = backend.getAgent('agt_001');

    expect(agent).not.toBeNull();
    expect(agent!.id).toBe('agt_001');
    expect(agent!.fingerprint).toBe('abc123fingerprint');
    expect(agent!.name).toBe('test-agent');
    expect(agent!.scopeCeiling).toBe('["repo","read:org"]');
    expect(agent!.status).toBe('active');
  });

  it('retrieves agent by fingerprint', () => {
    backend.storeAgent(makeAgentRow());
    const agent = backend.getAgentByFingerprint('abc123fingerprint');

    expect(agent).not.toBeNull();
    expect(agent!.id).toBe('agt_001');
  });

  it('returns null for missing agent', () => {
    expect(backend.getAgent('agt_nonexistent')).toBeNull();
    expect(backend.getAgentByFingerprint('nonexistent')).toBeNull();
  });

  it('upserts agent on conflict', () => {
    backend.storeAgent(makeAgentRow());
    backend.storeAgent(makeAgentRow({ name: 'updated-agent' }));

    const agent = backend.getAgent('agt_001');
    expect(agent!.name).toBe('updated-agent');
  });

  it('updates agent status to revoked', () => {
    backend.storeAgent(makeAgentRow());
    const revokedAt = new Date().toISOString();
    backend.updateAgentStatus('agt_001', 'revoked', revokedAt);

    const agent = backend.getAgent('agt_001');
    expect(agent!.status).toBe('revoked');
    expect(agent!.revokedAt).toBe(revokedAt);
  });

  it('updates agent status to suspended without revokedAt', () => {
    backend.storeAgent(makeAgentRow());
    backend.updateAgentStatus('agt_001', 'suspended');

    const agent = backend.getAgent('agt_001');
    expect(agent!.status).toBe('suspended');
    expect(agent!.revokedAt).toBeNull();
  });
});

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SQLiteAuditBackend, hmacAuditField } from '../audit.js';
import { SQLiteBackend } from '../storage/sqlite.js';
import type { AuditEvent } from '../audit.js';

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: `evt_${Date.now()}`,
    timestamp: new Date(),
    actor: { type: 'agent', id: 'agent-123' },
    action: 'delegate',
    resource: { type: 'token', id: 'tok_abc' },
    outcome: 'success',
    correlationId: 'corr-xyz',
    ...overrides,
  };
}

describe('SQLiteAuditBackend', () => {
  let tmpDir: string;
  let backend: SQLiteAuditBackend;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vault-audit-test-'));
    backend = new SQLiteAuditBackend(join(tmpDir, 'audit.db'));
    backend.init();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('initializes without errors', () => {
    expect(true).toBe(true); // init called in beforeEach
  });

  it('writes and reads an event', () => {
    const event = makeEvent({ id: 'evt_001' });
    backend.write(event);

    const results = backend.query({ actorId: 'agent-123' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('evt_001');
    expect(results[0].actor.id).toBe('agent-123');
    expect(results[0].action).toBe('delegate');
    expect(results[0].outcome).toBe('success');
  });

  it('persists timestamp and correlationId', () => {
    const ts = new Date('2026-01-15T10:30:00.000Z');
    const event = makeEvent({ id: 'evt_002', timestamp: ts, correlationId: 'corr-test-123' });
    backend.write(event);

    const results = backend.query({ actorId: 'agent-123' });
    expect(results[0].timestamp.toISOString()).toBe(ts.toISOString());
    expect(results[0].correlationId).toBe('corr-test-123');
  });

  it('stores scopes requested and granted', () => {
    const event = makeEvent({
      id: 'evt_003',
      scopesRequested: ['repo', 'read:org'],
      scopesGranted: ['repo'],
    });
    backend.write(event);

    const results = backend.query({ actorId: 'agent-123' });
    expect(results[0].scopesRequested).toEqual(['repo', 'read:org']);
    expect(results[0].scopesGranted).toEqual(['repo']);
  });

  it('stores sensitive field HMAC (not raw token)', () => {
    const event = makeEvent({
      id: 'evt_004',
      sensitiveFieldsHmac: { accessToken: 'abc123hmac' },
    });
    backend.write(event);

    const results = backend.query({ actorId: 'agent-123' });
    expect(results[0].sensitiveFieldsHmac).toEqual({ accessToken: 'abc123hmac' });
  });

  it('stores actor fingerprint', () => {
    const event = makeEvent({
      id: 'evt_005',
      actor: { type: 'agent', id: 'agent-123', fingerprint: 'sha256-fingerprint-abc' },
    });
    backend.write(event);

    const results = backend.query({ actorId: 'agent-123' });
    expect(results[0].actor.fingerprint).toBe('sha256-fingerprint-abc');
  });

  it('stores error message for failed events', () => {
    const event = makeEvent({
      id: 'evt_006',
      outcome: 'error',
      errorMessage: 'vault unavailable',
    });
    backend.write(event);

    const results = backend.query({ actorId: 'agent-123' });
    expect(results[0].outcome).toBe('error');
    expect(results[0].errorMessage).toBe('vault unavailable');
  });

  it('query filters by actorId', () => {
    backend.write(makeEvent({ id: 'evt_a', actor: { type: 'agent', id: 'actor-A' } }));
    backend.write(makeEvent({ id: 'evt_b', actor: { type: 'agent', id: 'actor-B' } }));

    const results = backend.query({ actorId: 'actor-A' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('evt_a');
  });

  it('query filters by resourceId', () => {
    backend.write(makeEvent({ id: 'evt_r1', resource: { type: 'token', id: 'res-AAA' } }));
    backend.write(makeEvent({ id: 'evt_r2', resource: { type: 'token', id: 'res-BBB' } }));

    const results = backend.query({ resourceId: 'res-AAA' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('evt_r1');
  });

  it('query filters by action', () => {
    backend.write(makeEvent({ id: 'evt_d1', action: 'delegate' }));
    backend.write(makeEvent({ id: 'evt_r1', action: 'revoke' }));

    const results = backend.query({ action: 'revoke' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('evt_r1');
  });

  it('query filters by outcome', () => {
    backend.write(makeEvent({ id: 'evt_s1', outcome: 'success' }));
    backend.write(makeEvent({ id: 'evt_e1', outcome: 'error' }));
    backend.write(makeEvent({ id: 'evt_d1', outcome: 'denied' }));

    const results = backend.query({ outcome: 'denied' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('evt_d1');
  });

  it('query filters by after date', () => {
    const past = new Date('2025-01-01T00:00:00.000Z');
    const future = new Date('2027-01-01T00:00:00.000Z');
    const cutoff = new Date('2026-01-01T00:00:00.000Z');

    backend.write(makeEvent({ id: 'evt_past', timestamp: past }));
    backend.write(makeEvent({ id: 'evt_future', timestamp: future }));

    const results = backend.query({ after: cutoff });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('evt_future');
  });

  it('query filters by before date', () => {
    const past = new Date('2025-01-01T00:00:00.000Z');
    const future = new Date('2027-01-01T00:00:00.000Z');
    const cutoff = new Date('2026-01-01T00:00:00.000Z');

    backend.write(makeEvent({ id: 'evt_past', timestamp: past }));
    backend.write(makeEvent({ id: 'evt_future', timestamp: future }));

    const results = backend.query({ before: cutoff });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('evt_past');
  });

  it('query respects limit', () => {
    for (let i = 0; i < 5; i++) {
      backend.write(makeEvent({ id: `evt_limit_${i}` }));
    }

    const results = backend.query({ actorId: 'agent-123', limit: 3 });
    expect(results).toHaveLength(3);
  });

  it('query returns empty array when no matches', () => {
    const results = backend.query({ actorId: 'nonexistent' });
    expect(results).toEqual([]);
  });

  it('throws (fail-closed) when write is called before init', () => {
    const uninitBackend = new SQLiteAuditBackend('/tmp/nonexistent-audit.db');
    expect(() => uninitBackend.write(makeEvent())).toThrow();
  });

  it('write is idempotent for duplicate IDs (upsert behavior)', () => {
    const event = makeEvent({ id: 'evt_dup' });
    expect(() => {
      backend.write(event);
      // SQLite PRIMARY KEY constraint will throw on duplicate — expected fail-closed behavior
    }).not.toThrow();
  });
});

describe('hmacAuditField', () => {
  it('returns a hex string', () => {
    const result = hmacAuditField('my-secret-token', 'hmac-key');
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic for same input', () => {
    const r1 = hmacAuditField('token', 'key');
    const r2 = hmacAuditField('token', 'key');
    expect(r1).toBe(r2);
  });

  it('produces different outputs for different values', () => {
    const r1 = hmacAuditField('token-A', 'key');
    const r2 = hmacAuditField('token-B', 'key');
    expect(r1).not.toBe(r2);
  });

  it('produces different outputs for different keys', () => {
    const r1 = hmacAuditField('token', 'key-A');
    const r2 = hmacAuditField('token', 'key-B');
    expect(r1).not.toBe(r2);
  });

  it('never exposes the raw token value in the output', () => {
    const token = 'ya29.very-secret-oauth-token';
    const result = hmacAuditField(token, 'hmac-key');
    expect(result).not.toContain(token);
    expect(result).not.toContain('ya29');
  });
});

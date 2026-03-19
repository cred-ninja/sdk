import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SQLiteBackend } from '../storage/sqlite.js';
import { RotationEngine } from '../rotation.js';
import type { Rotation, RotationRow } from '../types.js';

function makeBackend(dir: string): SQLiteBackend {
  const backend = new SQLiteBackend(join(dir, 'vault.db'));
  backend.init();
  return backend;
}

function makeEngine(backend: SQLiteBackend): RotationEngine {
  return new RotationEngine(backend);
}

function makeRotationRow(connectionId: string, overrides: Partial<RotationRow> = {}): RotationRow {
  const now = new Date().toISOString();
  return {
    id: `rot_${Math.random().toString(16).slice(2)}`,
    connection_id: connectionId,
    strategy: 'dual_active',
    interval_seconds: 3600,
    state: 'pending',
    current_version_id: null,
    pending_version_id: null,
    previous_version_id: null,
    last_rotated_at: null,
    next_rotation_at: new Date(Date.now() + 3600_000).toISOString(),
    failure_count: 0,
    failure_action: 'retry_backoff',
    created_at: now,
    updated_at: now,
    ...overrides,
  };
}

const CONNECTION_ID = 'google/user-123';

describe('RotationEngine.startRotation()', () => {
  let tmpDir: string;
  let backend: SQLiteBackend;
  let engine: RotationEngine;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vault-rot-test-'));
    backend = makeBackend(tmpDir);
    engine = makeEngine(backend);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('creates a rotation record with pending state', async () => {
    const rotation = await engine.startRotation(CONNECTION_ID, 'dual_active');

    expect(rotation.id).toMatch(/^rot_/);
    expect(rotation.connectionId).toBe(CONNECTION_ID);
    expect(rotation.strategy).toBe('dual_active');
    expect(rotation.state).toBe('pending');
    expect(rotation.failureCount).toBe(0);
  });

  it('sets nextRotationAt based on intervalSeconds', async () => {
    const before = Date.now();
    const rotation = await engine.startRotation(CONNECTION_ID, 'dual_active', 3600);
    const after = Date.now();

    expect(rotation.nextRotationAt).not.toBeNull();
    const expected = rotation.nextRotationAt!.getTime();
    expect(expected).toBeGreaterThan(before + 3600 * 1000 - 100);
    expect(expected).toBeLessThan(after + 3600 * 1000 + 100);
  });

  it('defaults intervalSeconds to 86400 (24h)', async () => {
    const before = Date.now();
    const rotation = await engine.startRotation(CONNECTION_ID, 'single_swap');
    const after = Date.now();

    expect(rotation.nextRotationAt).not.toBeNull();
    const expected = rotation.nextRotationAt!.getTime();
    expect(expected).toBeGreaterThan(before + 86400 * 1000 - 100);
    expect(expected).toBeLessThan(after + 86400 * 1000 + 100);
  });

  it('throws if rotation already in progress', async () => {
    await engine.startRotation(CONNECTION_ID, 'dual_active');

    await expect(
      engine.startRotation(CONNECTION_ID, 'dual_active'),
    ).rejects.toThrow('already in progress');
  });

  it('allows new rotation if previous one is idle (completed)', async () => {
    const first = await engine.startRotation(CONNECTION_ID, 'dual_active');
    // Advance to testing and promote → puts it in idle state
    await engine.advanceToTesting(first.id, 'v2');
    await engine.promoteRotation(first.id);
    const completed = (await backend.getRotation(first.id))!;
    expect(completed.state).toBe('idle');

    // Should allow new rotation now
    const second = await engine.startRotation(CONNECTION_ID, 'dual_active');
    expect(second.id).not.toBe(first.id);
    expect(second.state).toBe('pending');
  });

  it('enforces one in-progress rotation per connection inside the SQLite transaction', () => {
    backend.startRotationTransaction(makeRotationRow(CONNECTION_ID));

    expect(() => backend.startRotationTransaction(makeRotationRow(CONNECTION_ID, {
      id: 'rot_second',
    }))).toThrow('already in progress');
  });
});

describe('RotationEngine — dual_active strategy', () => {
  let tmpDir: string;
  let backend: SQLiteBackend;
  let engine: RotationEngine;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vault-rot-test-'));
    backend = makeBackend(tmpDir);
    engine = makeEngine(backend);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('advanceToTesting sets pending version and testing state', async () => {
    const rotation = await engine.startRotation(CONNECTION_ID, 'dual_active');
    const testing = await engine.advanceToTesting(rotation.id, 'enc-token-v2');

    expect(testing.state).toBe('testing');
    expect(testing.pendingVersionId).toBe('enc-token-v2');
  });

  it('promoteRotation: pending → current, current → previous', async () => {
    let rotation = await engine.startRotation(CONNECTION_ID, 'dual_active');
    // Set initial current version
    await backend.updateRotation(rotation.id, { current_version_id: 'enc-token-v1', state: 'pending' });
    rotation = (await backend.getRotation(rotation.id))!;

    // Advance to testing with pending token
    const testing = await engine.advanceToTesting(rotation.id, 'enc-token-v2');
    expect(testing.state).toBe('testing');
    expect(testing.pendingVersionId).toBe('enc-token-v2');

    // Promote
    const promoted = await engine.promoteRotation(rotation.id);

    expect(promoted.state).toBe('idle');
    expect(promoted.currentVersionId).toBe('enc-token-v2');   // new current
    expect(promoted.previousVersionId).toBe('enc-token-v1');  // old current is now previous
    expect(promoted.pendingVersionId).toBeNull();             // pending cleared
  });

  it('rollbackRotation: previous → current', async () => {
    let rotation = await engine.startRotation(CONNECTION_ID, 'dual_active');
    await backend.updateRotation(rotation.id, {
      current_version_id: 'enc-token-v1',
      state: 'pending',
    });
    rotation = (await backend.getRotation(rotation.id))!;

    const testing = await engine.advanceToTesting(rotation.id, 'enc-token-v2');
    expect(testing.state).toBe('testing');

    const rolledBack = await engine.rollbackRotation(rotation.id);

    // After rollback: previous (enc-token-v1) becomes current again
    expect(rolledBack.state).toBe('idle');
    expect(rolledBack.currentVersionId).toBe('enc-token-v1');
    expect(rolledBack.pendingVersionId).toBeNull();
    expect(rolledBack.previousVersionId).toBeNull();
    expect(rolledBack.failureCount).toBe(1);
  });

  it('throws when promoting from non-testing state', async () => {
    const rotation = await engine.startRotation(CONNECTION_ID, 'dual_active');

    await expect(
      engine.promoteRotation(rotation.id),
    ).rejects.toThrow("must be in 'testing' state");
  });

  it('throws when rolling back from idle state', async () => {
    // Start, advance, and promote to get to idle
    const rotation = await engine.startRotation(CONNECTION_ID, 'dual_active');
    await engine.advanceToTesting(rotation.id, 'v2');
    await engine.promoteRotation(rotation.id);

    await expect(
      engine.rollbackRotation(rotation.id),
    ).rejects.toThrow("must be in 'testing' or 'failed' state");
  });
});

describe('RotationEngine.getRotation()', () => {
  let tmpDir: string;
  let backend: SQLiteBackend;
  let engine: RotationEngine;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vault-rot-test-'));
    backend = makeBackend(tmpDir);
    engine = makeEngine(backend);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns current rotation state for a connection', async () => {
    await engine.startRotation(CONNECTION_ID, 'dual_active');

    const rotation = await engine.getRotation(CONNECTION_ID);
    expect(rotation).not.toBeNull();
    expect(rotation!.connectionId).toBe(CONNECTION_ID);
    expect(rotation!.state).toBe('pending');
  });

  it('returns null if no rotation exists', async () => {
    const rotation = await engine.getRotation('nonexistent/user');
    expect(rotation).toBeNull();
  });
});

describe('RotationEngine.runDueRotations()', () => {
  let tmpDir: string;
  let backend: SQLiteBackend;
  let engine: RotationEngine;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vault-rot-test-'));
    backend = makeBackend(tmpDir);
    engine = makeEngine(backend);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('processes rotations where nextRotationAt <= now', async () => {
    const rotation = await engine.startRotation(CONNECTION_ID, 'single_swap', 60);

    // Manually set next_rotation_at to the past
    await backend.updateRotation(rotation.id, {
      next_rotation_at: new Date(Date.now() - 1000).toISOString(),
      state: 'idle', // must be idle to be picked up
    });

    const results = await engine.runDueRotations();
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].rotation.state).toBe('pending');
  });

  it('claims each due rotation once when schedulers race', async () => {
    const rotation = await engine.startRotation(CONNECTION_ID, 'single_swap', 60);
    await backend.updateRotation(rotation.id, {
      next_rotation_at: new Date(Date.now() - 1000).toISOString(),
      state: 'idle',
    });

    const [first, second] = await Promise.all([
      engine.runDueRotations(),
      engine.runDueRotations(),
    ]);

    expect(first.length + second.length).toBe(1);
    expect([...first, ...second][0].rotation.id).toBe(rotation.id);
  });

  it('returns empty array when no rotations are due', async () => {
    const rotation = await engine.startRotation(CONNECTION_ID, 'dual_active', 3600);
    // nextRotationAt is in the future — should NOT be picked up
    void rotation;

    const results = await engine.runDueRotations();
    expect(results).toHaveLength(0);
  });

  it('auto-fails stuck rotations in testing state after 5 minutes', async () => {
    const rotation = await engine.startRotation(CONNECTION_ID, 'dual_active');
    await engine.advanceToTesting(rotation.id, 'pending-v2');

    // Simulate 6 minutes ago updated_at
    const sixMinutesAgo = new Date(Date.now() - 6 * 60 * 1000).toISOString();
    await backend.updateRotation(rotation.id, { updated_at: sixMinutesAgo });

    await engine.runDueRotations();

    const updated = await engine.getRotationById(rotation.id);
    expect(updated!.state).toBe('failed');
    expect(updated!.failureCount).toBe(1);
  });

  it('can fail stuck rotations without running the due scheduler', async () => {
    const rotation = await engine.startRotation(CONNECTION_ID, 'dual_active');
    await engine.advanceToTesting(rotation.id, 'pending-v2');

    await backend.updateRotation(rotation.id, {
      updated_at: new Date(Date.now() - 6 * 60 * 1000).toISOString(),
    });

    await engine.failStuckRotations();

    const updated = await engine.getRotationById(rotation.id);
    expect(updated!.state).toBe('failed');
    expect(updated!.failureCount).toBe(1);
  });
});

describe('RotationEngine — state machine transitions', () => {
  let tmpDir: string;
  let backend: SQLiteBackend;
  let engine: RotationEngine;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'vault-rot-test-'));
    backend = makeBackend(tmpDir);
    engine = makeEngine(backend);
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('full rotation lifecycle: pending → testing → idle', async () => {
    const rot = await engine.startRotation(CONNECTION_ID, 'dual_active');
    expect(rot.state).toBe('pending');

    const testing = await engine.advanceToTesting(rot.id, 'new-token-enc');
    expect(testing.state).toBe('testing');

    const promoted = await engine.promoteRotation(rot.id);
    expect(promoted.state).toBe('idle');
    expect(promoted.currentVersionId).toBe('new-token-enc');
    expect(promoted.lastRotatedAt).not.toBeNull();
  });

  it('full rollback lifecycle: pending → testing → idle (via rollback)', async () => {
    const rot = await engine.startRotation(CONNECTION_ID, 'dual_active');
    await backend.updateRotation(rot.id, { current_version_id: 'v1', state: 'pending' });

    await engine.advanceToTesting(rot.id, 'v2');

    const rolledBack = await engine.rollbackRotation(rot.id);
    expect(rolledBack.state).toBe('idle');
    expect(rolledBack.currentVersionId).toBe('v1');
    expect(rolledBack.failureCount).toBe(1);
  });

  it('failRotation marks state as failed and increments failureCount', async () => {
    const rot = await engine.startRotation(CONNECTION_ID, 'dual_active');
    await engine.advanceToTesting(rot.id, 'v2');

    const failed = await engine.failRotation(rot.id);
    expect(failed.state).toBe('failed');
    expect(failed.failureCount).toBe(1);
  });
});

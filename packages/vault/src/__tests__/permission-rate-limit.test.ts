import { beforeEach, describe, expect, it } from 'vitest';
import { SQLiteBackend } from '../storage/sqlite';

const ID = 'perm_rate';
const MINUTE = 60_000;
/** An exact multiple of a minute, so a fixed clock-aligned window would turn over here. */
const BOUNDARY = 1_800_000_000_000 - (1_800_000_000_000 % MINUTE);
const at = (ms: number) => new Date(ms);

describe('checkPermissionRateLimit', () => {
  let backend: SQLiteBackend;
  beforeEach(() => {
    backend = new SQLiteBackend(':memory:');
    backend.init();
  });

  it('holds across a clock boundary: one per minute cannot admit two a few milliseconds apart', () => {
    expect(backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY - 1))).toBe(true);
    expect(backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY + 1))).toBe(false);
  });

  it('never admits more than the limit in any trailing window', () => {
    const start = BOUNDARY - 30_000;
    for (let i = 0; i < 5; i += 1) expect(backend.checkPermissionRateLimit(ID, 5, MINUTE, at(start + i))).toBe(true);
    // A fixed window would have refilled all five at BOUNDARY, 30 seconds later.
    expect(backend.checkPermissionRateLimit(ID, 5, MINUTE, at(BOUNDARY + 1))).toBe(false);
    expect(backend.checkPermissionRateLimit(ID, 5, MINUTE, at(start + MINUTE - 1))).toBe(false);
  });

  it('admits again once the earlier request has left the window, and not before', () => {
    expect(backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY))).toBe(true);
    expect(backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY + MINUTE - 1))).toBe(false);
    expect(backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY + MINUTE))).toBe(true);
  });

  it('a refused request does not extend the wait', () => {
    expect(backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY))).toBe(true);
    for (let i = 1; i < 5; i += 1) expect(backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY + i * 1000))).toBe(false);
    expect(backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY + MINUTE))).toBe(true);
  });

  it('counts two requests in one millisecond', () => {
    expect(backend.checkPermissionRateLimit(ID, 2, MINUTE, at(BOUNDARY))).toBe(true);
    expect(backend.checkPermissionRateLimit(ID, 2, MINUTE, at(BOUNDARY))).toBe(true);
    expect(backend.checkPermissionRateLimit(ID, 2, MINUTE, at(BOUNDARY))).toBe(false);
  });

  it('keeps permissions apart, and prunes what has left the window', () => {
    expect(backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY))).toBe(true);
    expect(backend.checkPermissionRateLimit('perm_other', 1, MINUTE, at(BOUNDARY))).toBe(true);
    for (let i = 1; i <= 50; i += 1) backend.checkPermissionRateLimit(ID, 1, MINUTE, at(BOUNDARY + i * MINUTE));
    const db = (backend as unknown as { ensureDb(): { prepare(sql: string): { get(id: string): { n: number } } } }).ensureDb();
    expect(db.prepare('SELECT COUNT(*) AS n FROM vault_rate_limit_counters WHERE permission_id = ?').get(ID).n).toBe(1);
  });

  it('refuses on a limit that makes no sense', () => {
    for (const [max, windowMs] of [[1, 0], [1, -1000], [0, MINUTE], [1, 1e20], [1, Number.NaN]]) {
      expect(backend.checkPermissionRateLimit(ID, max as number, windowMs as number, at(BOUNDARY))).toBe(false);
    }
  });
});

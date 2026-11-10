import { mkdtempSync, rmSync, unlinkSync } from 'node:fs';
import os from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fork, type ChildProcess } from 'node:child_process';
import Database from 'better-sqlite3';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DurableBudgetStore, executeBudgetedOperation, prepareBudgetOperation } from '../durable-budget-admission.js';
import * as publicVault from '../index.js';

const auth = {
  issuer: 'https://issuer.example', tenant: 'tenant-a', grantId: 'grant-a', tokenId: 'root',
  subject: 'subject-a', holder: 'holder-a', provider: 'example', connectionId: 'connection-a',
  policyVersion: 'policy-1', grantEpoch: 1, connectionEpoch: 1,
};
const connection = {
  issuer: auth.issuer, tenant: auth.tenant, subject: auth.subject, provider: auth.provider,
  connectionId: auth.connectionId, epoch: 1,
};
const grant = {
  ...connection, grantId: auth.grantId, policyVersion: auth.policyVersion, connectionEpoch: 1, maxCalls: 2,
};
const token = { ...auth, parentId: null, expiresAt: 4_000_000_000_000, constraints: [{ key: 'max_calls', max_lifetime: 2 }] };
const operation = () => prepareBudgetOperation({ method: 'post', target: 'https://provider.example/items?q=a',
  body: Buffer.from('payload'), headers: { 'Content-Type': 'text/plain' } });
function register(store: DurableBudgetStore) {
  store.registerConnection(connection);
  store.registerGrant(grant);
  store.registerToken(token);
}

const dirs: string[] = [];
const stores: DurableBudgetStore[] = [];
const workers: ChildProcess[] = [];
type WorkerMessage = { type: string; pid: number; sends: number; denials: number; code?: string };
function startWorker(configuration: Record<string, unknown>) {
  const child = fork(join(__dirname, 'fixtures/budget-process.cjs'), [], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'], execArgv: [] });
  workers.push(child);
  const messages: WorkerMessage[] = [];
  child.on('message', message => messages.push(message as WorkerMessage));
  const next = (type: string): Promise<WorkerMessage> => new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { cleanup(); reject(new Error(`worker_timeout:${type}`)); }, 10000);
    const inspect = () => {
      const failure = messages.find(m => m.type === 'failure');
      const result = messages.find(m => m.type === type);
      if (failure) { cleanup(); reject(new Error(`worker_failure:${failure.code}`)); }
      else if (result) { cleanup(); resolve(result); }
    };
    const cleanup = () => { clearTimeout(timeout); child.off('message', inspect); };
    child.on('message', inspect); inspect();
  });
  child.send({ type: 'configure', identity, ...configuration });
  return { child, next };
}
function pathForStore() {
  const dir = mkdtempSync(join(process.env.TMPDIR || os.tmpdir(), 'cred-admission-'));
  dirs.push(dir);
  return join(dir, 'admission.sqlite');
}
const identity = { issuer: 'https://issuer.example', deploymentEpoch: 'deployment-1' };
function open(path: string, initialize?: 'new') {
  const store = new DurableBudgetStore({ path, ...identity, initialize });
  stores.push(store);
  return store;
}
function admissionSnapshot(db: Database.Database) {
  return {
    requests: db.prepare('SELECT * FROM admission_requests ORDER BY request_key').all(),
    accounts: db.prepare('SELECT * FROM admission_accounts ORDER BY owner,type').all(),
    reservations: db.prepare('SELECT * FROM admission_request_accounts ORDER BY request_key,owner,type').all(),
    transitions: db.prepare('SELECT * FROM admission_transitions ORDER BY sequence').all(),
  };
}
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(workers.splice(0).map(child => new Promise<void>(resolve => {
    if (child.exitCode !== null || child.signalCode !== null) { resolve(); return; }
    child.once('exit', () => resolve()); child.kill('SIGKILL');
  })));
  for (const store of stores.splice(0)) store.close();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('durable budget admission', () => {
  it('R3 uses the OS temporary directory when TMPDIR is absent', () => {
    // Capture the configured root before removing TMPDIR; never use the real OS fallback here.
    const root = os.tmpdir();
    const fallback = vi.spyOn(os, 'tmpdir').mockReturnValue(root);
    vi.stubEnv('TMPDIR', undefined);
    try {
      expect(process.env.TMPDIR).toBeUndefined();
      const path = pathForStore();
      expect(dirname(dirname(path))).toBe(root);
      expect(basename(path)).toBe('admission.sqlite');
      expect(fallback).toHaveBeenCalledOnce();
    } finally {
      vi.unstubAllEnvs();
      fallback.mockRestore();
    }
  });

  it('R3 preserves an explicitly configured TMPDIR instead of the OS fallback', () => {
    const root = os.tmpdir();
    const configured = mkdtempSync(join(root, 'cred-admission-configured-'));
    dirs.push(configured);
    const fallback = vi.spyOn(os, 'tmpdir').mockReturnValue(root);
    vi.stubEnv('TMPDIR', configured);
    try {
      const path = pathForStore();
      expect(dirname(dirname(path))).toBe(configured);
      expect(basename(path)).toBe('admission.sqlite');
      expect(fallback).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllEnvs();
      fallback.mockRestore();
    }
  });

  it('R1 binds dispatch and retry to intrinsic bytes rather than mutable iterator values', async () => {
    const store = open(pathForStore(), 'new'); register(store);
    const body = new Uint8Array([65]);
    let value = 65;
    let iteratorCalls = 0;
    const mutable = { valueOf: () => value };
    Object.defineProperty(body, Symbol.iterator, { value: function* () { iteratorCalls++; yield mutable; } });
    const input = { method: 'POST', target: 'https://provider.example/items', body };
    const prepared = prepareBudgetOperation(input);
    let sends = 0;
    let observed: number[] = [];
    let elementType = '';
    const result = await executeBudgetedOperation(store, auth, 'intrinsic-bytes', prepared, 'worker', async wire => {
      sends++;
      value = 66; body[0] = 66;
      observed = Array.from(Buffer.from(wire.body));
      elementType = typeof wire.body[0];
      return { reference: 'intrinsic-result' };
    });
    const retry = async () => { sends++; return { reference: 'unexpected' }; };
    expect(await executeBudgetedOperation(store, auth, 'intrinsic-bytes',
      prepareBudgetOperation({ ...input, body: new Uint8Array([65]) }), 'retry', retry)).toEqual(result);
    await expect(executeBudgetedOperation(store, auth, 'intrinsic-bytes',
      prepareBudgetOperation({ ...input, body: new Uint8Array([66]) }), 'retry', retry)).rejects.toThrow(/idempotency_conflict/);
    expect(result.state).toBe('finalized');
    expect(sends).toBe(1);
    expect(observed).toEqual([65]);
    expect(elementType).toBe('number');
    expect(iteratorCalls).toBe(0);
    expect(store.accounts(auth).every(a => a.charged === 1 && a.reserved === 0)).toBe(true);
  });

  it.each(['GET', 'HEAD'])('R1 prepares an empty intrinsic %s body despite a nonempty custom iterator', async method => {
    const store = open(pathForStore(), 'new'); register(store);
    const body = new Uint8Array();
    let iteratorCalls = 0;
    Object.defineProperty(body, Symbol.iterator, { value: function* () { iteratorCalls++; yield 65; } });
    const prepared = prepareBudgetOperation({ method, target: 'https://provider.example/items', body });
    let observed: number[] | undefined;
    const result = await executeBudgetedOperation(store, auth, 'empty-intrinsic', prepared, 'worker', async wire => {
      observed = Array.from(Buffer.from(wire.body));
      return { reference: 'empty-result' };
    });
    expect(result.state).toBe('finalized');
    expect(observed).toEqual([]);
    expect(iteratorCalls).toBe(0);
  });

  it.each(['GET', 'HEAD'])('R1 rejects a nonempty intrinsic %s body even when its length is shadowed', method => {
    const body = new Uint8Array([65]);
    let lengthReads = 0;
    Object.defineProperty(body, 'length', { get: () => { lengthReads++; return 0; } });
    expect(() => prepareBudgetOperation({ method, target: 'https://provider.example/items', body })).toThrow(/invalid_body/);
    expect(lengthReads).toBe(0);
  });

  it('R1 snapshots operation fields once before validation and dispatch', async () => {
    const store = open(pathForStore(), 'new'); register(store);
    const original = { method: 'post', target: 'https://provider.example/items',
      headers: { Accept: 'application/json' }, body: new Uint8Array([65]) };
    const changed = { method: 'DELETE', target: 'https://provider.example/changed',
      headers: { Accept: 'text/plain' }, body: new Uint8Array([66]) };
    const reads: Record<string, number> = {};
    const input = new Proxy(original, { get(target, key, receiver) {
      if (typeof key !== 'string') return Reflect.get(target, key, receiver);
      reads[key] = (reads[key] ?? 0) + 1;
      return Reflect.get(reads[key] === 1 ? target : changed, key, receiver);
    } });
    const prepared = prepareBudgetOperation(input);
    let observed: unknown;
    const result = await executeBudgetedOperation(store, auth, 'field-snapshot', prepared, 'worker', async wire => {
      observed = wire;
      return { reference: 'field-result' };
    });
    expect(result.state).toBe('finalized');
    expect(observed).toEqual({ method: 'POST', target: original.target,
      headers: { accept: 'application/json' }, body: [65] });
    expect(reads).toEqual({ method: 1, target: 1, headers: 1, body: 1 });
  });

  it.each([
    { kind: 'Uint8Array', make: () => new Uint8Array([0, 127, 255]), expected: [0, 127, 255] },
    { kind: 'Buffer', make: () => Buffer.from([0, 127, 255]), expected: [0, 127, 255] },
    { kind: 'Uint8Array subarray', make: () => new Uint8Array([9, 0, 127, 255, 9]).subarray(1, 4), expected: [0, 127, 255] },
    { kind: 'Buffer subarray', make: () => Buffer.from([9, 0, 127, 255, 9]).subarray(1, 4), expected: [0, 127, 255] },
    { kind: 'empty Uint8Array', make: () => new Uint8Array(), expected: [] },
    { kind: 'empty Buffer', make: () => Buffer.alloc(0), expected: [] },
    { kind: 'omitted body', make: () => undefined, expected: [] },
  ])('R1 preserves detached $kind bytes and exact retries', async ({ kind, make, expected }) => {
    const store = open(pathForStore(), 'new'); register(store);
    const body = make();
    if (kind.includes('subarray')) expect(body!.byteOffset).toBeGreaterThan(0);
    const input = { method: 'POST', target: 'https://provider.example/items', body };
    const prepared = prepareBudgetOperation(input);
    body?.fill(9);
    let sends = 0;
    let observed: readonly number[] | undefined;
    const result = await executeBudgetedOperation(store, auth, 'ordinary-bytes', prepared, 'worker', async wire => {
      sends++; observed = wire.body;
      return { reference: 'ordinary-result' };
    });
    expect(result.state).toBe('finalized');
    expect(observed).toEqual(expected);
    expect(Object.isFrozen(observed)).toBe(true);
    expect(await executeBudgetedOperation(store, auth, 'ordinary-bytes',
      prepareBudgetOperation({ ...input, body: new Uint8Array(expected) }), 'retry', async () => {
        sends++; return { reference: 'unexpected' };
      })).toEqual(result);
    expect(sends).toBe(1);
  });

  it('R1 ignores caller-defined byte-view hooks during capture', async () => {
    const store = open(pathForStore(), 'new'); register(store);
    const body = new Uint8Array([9, 65, 255, 9]).subarray(1, 3);
    let reads = 0;
    for (const key of [Symbol.iterator, 'values', 'length', 'buffer', 'byteOffset', 'byteLength', 'constructor']) {
      Object.defineProperty(body, key, { get() { reads++; throw new Error('caller-controlled byte-view hook'); } });
    }
    const prepared = prepareBudgetOperation({ method: 'POST', target: 'https://provider.example/items', body });
    body[0] = 66;
    let observed: readonly number[] | undefined;
    const result = await executeBudgetedOperation(store, auth, 'byte-hooks', prepared, 'worker', async wire => {
      observed = wire.body; return { reference: 'hooks-result' };
    });
    expect(result.state).toBe('finalized');
    expect(observed).toEqual([65, 255]);
    expect(reads).toBe(0);
  });

  it.each(['method', 'target', 'headers', 'body'])('R1 rejects an accessor operation %s without invoking it', field => {
    let reads = 0;
    const input = { method: 'POST', target: 'https://provider.example/items', headers: {}, body: new Uint8Array() };
    Object.defineProperty(input, field, { get() { reads++; throw new Error('must not invoke'); } });
    expect(() => prepareBudgetOperation(input)).toThrow(/invalid_accessor/);
    expect(reads).toBe(0);
  });

  it('does not change journaling or schema when pointed at an unrelated existing database', () => {
    const path = pathForStore();
    let db = new Database(path); db.exec('CREATE TABLE unrelated (value TEXT)');
    expect(db.pragma('journal_mode', { simple: true })).toBe('delete'); db.close();
    expect(() => open(path)).toThrow(/store_incompatible|store_unavailable/);
    db = new Database(path);
    expect(db.pragma('journal_mode', { simple: true })).toBe('delete');
    expect(db.prepare('SELECT name FROM sqlite_master').all()).toEqual([{ name: 'unrelated' }]);
    db.close();
  });

  it('refuses unsupported initialization options instead of accidentally opening an existing store', () => {
    const path = pathForStore(); open(path, 'new').close();
    expect(() => new DurableBudgetStore({ path, ...identity, initialize: 'create-if-missing' } as never)).toThrow(/invalid_initialize/);
    expect(() => new DurableBudgetStore({ path, ...identity, memoryFallback: true } as never)).toThrow(/unsupported_field/);
    expect(() => new DurableBudgetStore({ path, ...identity, busyTimeoutMs: -1 })).toThrow(/invalid_timeout/);
  });

  it('releases an unclaimed reservation exactly once and keeps the cancellation tombstone on restart', async () => {
    const path = pathForStore(); let store = open(path, 'new'); register(store);
    store.reserve(auth, 'cancel', operation());
    const cancelled = store.cancel(auth, 'cancel', operation());
    expect(cancelled.state).toBe('cancelled');
    expect(store.cancel(auth, 'cancel', operation())).toEqual(cancelled);
    expect(store.accounts(auth).every(a => a.charged === 0 && a.reserved === 0)).toBe(true);
    store.close(); store = open(path);
    let sends = 0;
    expect(await executeBudgetedOperation(store, auth, 'cancel', operation(), 'worker', async () => { sends++; return { reference: 'no' }; })).toEqual(cancelled);
    expect(sends).toBe(0);
  });

  it('enforces the tighter intermediate subtree across multiple descendant generations', async () => {
    const store = open(pathForStore(), 'new'); store.registerConnection(connection); store.registerGrant({ ...grant, maxCalls: 10 });
    store.registerToken({ ...token, constraints: [{ key: 'max_calls', max_subtree: 3 }] });
    store.registerToken({ ...token, tokenId: 'middle', parentId: 'root', constraints: [{ key: 'max_calls', max_subtree: 1 }] });
    store.registerToken({ ...token, tokenId: 'leaf', parentId: 'middle', constraints: [{ key: 'max_calls', max_subtree: 1 }, { key: 'max_calls', max_lifetime: 1 }] });
    let sends = 0;
    const send = async () => { sends++; return { reference: 'leaf-result' }; };
    await executeBudgetedOperation(store, { ...auth, tokenId: 'leaf' }, 'leaf-1', operation(), 'worker', send);
    const before = store.accounts(auth);
    await expect(executeBudgetedOperation(store, { ...auth, tokenId: 'middle' }, 'middle-1', operation(), 'worker', send)).rejects.toThrow(/budget_exceeded/);
    expect(store.accounts(auth)).toEqual(before);
    expect(store.accounts({ ...auth, tokenId: 'leaf' }).every(a => a.charged === 1)).toBe(true);
    expect(sends).toBe(1);
  });

  it('denies a vanished durable file rather than continuing on an unlinked database', async () => {
    const path = pathForStore(); const store = open(path, 'new'); register(store); unlinkSync(path);
    let sends = 0;
    await expect(executeBudgetedOperation(store, auth, 'vanished', operation(), 'worker', async () => { sends++; return { reference: 'no' }; })).rejects.toThrow(/store_unavailable/);
    expect(sends).toBe(0);
    expect(() => open(path)).toThrow(/store_unavailable/);
  });

  it('rejects zero allowance, forged prepared handles and non-byte operations', async () => {
    const store = open(pathForStore(), 'new'); store.registerConnection(connection); store.registerGrant({ ...grant, maxCalls: 0 }); store.registerToken(token);
    let sends = 0;
    const send = async () => { sends++; return { reference: 'no' }; };
    await expect(executeBudgetedOperation(store, auth, 'zero', operation(), 'worker', send)).rejects.toThrow(/budget_exceeded/);
    await expect(executeBudgetedOperation(store, auth, 'forged', {} as never, 'worker', send)).rejects.toThrow(/invalid_prepared_operation/);
    expect(() => prepareBudgetOperation({ method: 'POST', target: 'https://provider.example', body: 'string' } as never)).toThrow(/invalid_body/);
    expect(() => prepareBudgetOperation({ method: 'CONNECT', target: 'https://provider.example' })).toThrow(/invalid_method/);
    expect(() => prepareBudgetOperation({ method: 'GET', target: 'http://provider.example' })).toThrow(/invalid_target/);
    expect(() => prepareBudgetOperation({ method: 'POST', target: 'https://provider.example', headers: { Accept: 'value\r\nInjected: yes' } })).toThrow(/invalid_header/);
    expect(sends).toBe(0);
  });

  it('exports the opt-in store and adapter without replacing the legacy ledger', () => {
    expect(publicVault.DurableBudgetStore).toBe(DurableBudgetStore);
    expect(publicVault.executeBudgetedOperation).toBe(executeBudgetedOperation);
    expect(publicVault.prepareBudgetOperation).toBe(prepareBudgetOperation);
    expect(publicVault.SqliteCumulativeLedger).toBeTypeOf('function');
  });

  it.each(['unsafe-outcome', 'wrong-context', 'missing-fence'] as const)('fails closed on corrupt request %s instead of returning fabricated state', async damage => {
    const path = pathForStore(); const store = open(path, 'new'); register(store);
    await executeBudgetedOperation(store, auth, 'request-corrupt', operation(), 'worker', async () => ({ reference: 'safe' }));
    const db = new Database(path);
    if (damage === 'unsafe-outcome') db.prepare('UPDATE admission_requests SET outcome=?').run(JSON.stringify({ reference: 'safe', body: 'must-not-return' }));
    if (damage === 'wrong-context') db.prepare('UPDATE admission_requests SET context=?').run(JSON.stringify({ ...auth, holder: 'wrong' }));
    if (damage === 'missing-fence') db.exec('UPDATE admission_requests SET fence=NULL');
    db.close();
    let sends = 0;
    await expect(executeBudgetedOperation(store, auth, 'request-corrupt', operation(), 'worker', async () => { sends++; return { reference: 'no' }; }))
      .rejects.toThrow(/store_corrupt|store_unavailable|idempotency_conflict/);
    expect(sends).toBe(0);
  });


  it.each(['connection', 'grant'] as const)('rejects malformed stored %s identity instead of trusting partial metadata', async kind => {
    const path = pathForStore(); const store = open(path, 'new'); register(store);
    const db = new Database(path);
    if (kind === 'connection') db.prepare('UPDATE admission_connections SET metadata=?').run(JSON.stringify({ ...connection, tenant: 'wrong-tenant' }));
    else db.prepare('UPDATE admission_grants SET metadata=?').run(JSON.stringify({ ...grant, grantId: 'wrong-grant' }));
    let sends = 0;
    await expect(executeBudgetedOperation(store, auth, 'corrupt-binding', operation(), 'worker', async () => { sends++; return { reference: 'no' }; }))
      .rejects.toThrow(/authority_mismatch/);
    expect(sends).toBe(0);
    expect(db.prepare('SELECT COUNT(*) AS n FROM admission_requests').get()).toEqual({ n: 0 });
    db.close();
  });

  it('rejects schema additions with names resembling SQLite internals', () => {
    const path = pathForStore(); open(path, 'new').close();
    const db = new Database(path); db.exec('CREATE TABLE sqliteXunexpected (value TEXT)'); db.close();
    expect(() => open(path)).toThrow(/store_incompatible/);
  });


  it.each(['siblings', 'reissuance', 'same-request'] as const)('serializes genuine separate-process %s competition', async mode => {
    const path = pathForStore(); const store = open(path, 'new');
    store.registerConnection(connection); store.registerGrant({ ...grant, maxCalls: mode === 'siblings' ? 10 : 3 });
    const constraints = [{ key: 'max_calls', max_lifetime: 3 }, { key: 'max_calls', max_subtree: 3 }];
    store.registerToken({ ...token, constraints });
    const localWorkers = Array.from({ length: 4 }, (_, index) => {
      const rootId = `root-${index}`;
      const child = { ...token, tokenId: `child-${index}`, parentId: mode === 'reissuance' ? rootId : 'root', constraints };
      if (mode !== 'reissuance') store.registerToken(child);
      return startWorker({ path, mode, index, count: 3,
        auth: mode === 'same-request' ? auth : { ...auth, tokenId: child.tokenId },
        ...(mode === 'same-request' ? { sharedKey: 'one-request' } : {}),
        ...(mode === 'reissuance' ? { registration: { connection, grant: { ...grant, maxCalls: 3 }, tokens: [{ ...token, tokenId: rootId, constraints }, child] } } : {}),
      });
    });
    const ready = await Promise.all(localWorkers.map(w => w.next('ready')));
    expect(new Set(ready.map(r => r.pid)).size).toBe(4);
    expect(ready.every(r => r.pid !== process.pid)).toBe(true);
    for (const worker of localWorkers) worker.child.send({ type: 'go' });
    const results = await Promise.all(localWorkers.map(w => w.next('done')));
    const expected = mode === 'same-request' ? 1 : 3;
    expect(results.reduce((sum, result) => sum + result.sends, 0)).toBe(expected);
    expect(store.accounts(auth).find(a => a.type === 'grant')).toMatchObject({ reserved: 0, charged: expected });
    const db = new Database(path);
    try {
      expect(db.prepare('SELECT COUNT(*) AS n FROM admission_requests').get()).toEqual({ n: expected });
      expect(db.prepare("SELECT COUNT(*) AS n FROM admission_transitions WHERE event='dispatch_claimed'").get()).toEqual({ n: expected });
    } finally { db.close(); }
  }, 15000);

  it.each(['crash-claimed', 'crash-reserved'] as const)('recovers after a real process kill at %s without unsafe resend', async mode => {
    const path = pathForStore(); let store = open(path, 'new'); register(store); store.close();
    const worker = startWorker({ path, auth, mode });
    await worker.next('ready'); worker.child.send({ type: 'go' }); await worker.next('crash-ready');
    await new Promise<void>(resolve => { worker.child.once('exit', () => resolve()); worker.child.kill('SIGKILL'); });
    store = open(path);
    let sends = 0;
    const result = await executeBudgetedOperation(store, auth, 'crash-request', operation(), 'survivor', async () => { sends++; return { reference: 'recovered-reservation' }; });
    expect(sends).toBe(mode === 'crash-claimed' ? 0 : 1);
    expect(result.state).toBe(mode === 'crash-claimed' ? 'dispatch_claimed' : 'finalized');
    expect(store.accounts(auth).every(a => a.charged === 1 && a.reserved === 0)).toBe(true);
  }, 15000);

  it('fails closed on cross-process write-lock contention and admits only after the lock releases', async () => {
    const path = pathForStore(); const initialized = open(path, 'new'); register(initialized); initialized.close();
    const store = new DurableBudgetStore({ path, ...identity, busyTimeoutMs: 20 }); stores.push(store);
    const worker = startWorker({ path, mode: 'lock' }); await worker.next('ready');
    let sends = 0;
    const transport = async () => { sends++; return { reference: 'after-lock' }; };
    await expect(executeBudgetedOperation(store, auth, 'locked', operation(), 'worker', transport)).rejects.toThrow(/store_unavailable/);
    expect(sends).toBe(0);
    worker.child.send({ type: 'go' }); await worker.next('done');
    expect((await executeBudgetedOperation(store, auth, 'locked', operation(), 'worker', transport)).state).toBe('finalized');
    expect(sends).toBe(1);
  }, 15000);

  it.each(['missing-account', 'missing-parent', 'cycle', 'malformed-parent', 'unsupported-ancestor', 'unsafe-counter', 'missing-reservation'] as const)
  ('denies corrupt %s state before transport', async corruption => {
    const path = pathForStore(); const store = open(path, 'new'); register(store);
    const child = { ...auth, tokenId: 'child' };
    store.registerToken({ ...token, ...child, parentId: 'root' });
    if (corruption === 'missing-reservation') store.reserve(child, 'corrupt', operation());
    const db = new Database(path); db.pragma('foreign_keys = OFF');
    if (corruption === 'missing-account') db.prepare("DELETE FROM admission_accounts WHERE type='grant'").run();
    if (corruption === 'missing-parent') db.prepare("DELETE FROM admission_tokens WHERE token_id='root'").run();
    if (['cycle', 'malformed-parent', 'unsupported-ancestor'].includes(corruption)) {
      const damaged = { ...token, ...(corruption === 'cycle' ? { parentId: 'child' } : corruption === 'malformed-parent' ? { parentId: 17 } : { constraints: [{ key: 'max_calls', mystery: 1 }] }) };
      db.prepare("UPDATE admission_tokens SET metadata=? WHERE token_id='root'").run(JSON.stringify(damaged));
    }
    if (corruption === 'unsafe-counter') { db.pragma('ignore_check_constraints = ON'); db.exec('UPDATE admission_accounts SET charged=9007199254740992'); }
    if (corruption === 'missing-reservation') db.exec('DELETE FROM admission_request_accounts');
    const before = db.prepare('SELECT * FROM admission_accounts ORDER BY owner,type').all();
    let sends = 0;
    await expect(executeBudgetedOperation(store, child, 'corrupt', operation(), 'worker', async () => { sends++; return { reference: 'no' }; }))
      .rejects.toThrow(/account_corrupt|chain_incomplete|invalid_identity|unsupported_constraint|invalid_integer|reservation_corrupt/);
    expect(sends).toBe(0);
    expect(db.prepare('SELECT * FROM admission_accounts ORDER BY owner,type').all()).toEqual(before);
    db.close();
  });

  it.each(['reserved', 'dispatch_claimed', 'cancelled'] as const)('rolls back counters, request and audit together when %s transition fails', async event => {
    const path = pathForStore(); const store = open(path, 'new'); register(store);
    if (event !== 'reserved') store.reserve(auth, 'fault', operation());
    if (event === 'cancelled') store.revokeToken(auth);
    const db = new Database(path);
    db.exec(`CREATE TRIGGER injected_failure BEFORE INSERT ON admission_transitions WHEN NEW.event='${event}' BEGIN SELECT RAISE(ABORT, 'injected'); END`);
    const before = db.prepare('SELECT reserved,charged FROM admission_accounts ORDER BY owner,type').all();
    const beforeRequests = db.prepare('SELECT * FROM admission_requests').all();
    const beforeEvents = db.prepare('SELECT * FROM admission_transitions').all();
    let sends = 0;
    const send = async () => { sends++; return { reference: 'safe' }; };
    await expect(executeBudgetedOperation(store, auth, 'fault', operation(), 'worker', send)).rejects.toThrow(/store_unavailable/);
    expect(db.prepare('SELECT reserved,charged FROM admission_accounts ORDER BY owner,type').all()).toEqual(before);
    expect(db.prepare('SELECT * FROM admission_requests').all()).toEqual(beforeRequests);
    expect(db.prepare('SELECT * FROM admission_transitions').all()).toEqual(beforeEvents);
    expect(sends).toBe(0);
    db.exec('DROP TRIGGER injected_failure'); db.close();
    const result = await executeBudgetedOperation(store, auth, 'fault', operation(), 'worker', send);
    expect(result.state).toBe(event === 'cancelled' ? 'cancelled' : 'finalized');
    expect(sends).toBe(event === 'cancelled' ? 0 : 1);
  });

  it('does not lose a committed definitive outcome when its acknowledgement is lost', async () => {
    const store = open(pathForStore(), 'new'); register(store);
    const finalize = store.finalize.bind(store);
    vi.spyOn(store, 'finalize').mockImplementationOnce((fence, outcome) => { finalize(fence, outcome); throw new Error('lost commit acknowledgement'); });
    let sends = 0;
    const send = async () => { sends++; return { reference: 'committed' }; };
    const result = await executeBudgetedOperation(store, auth, 'ack', operation(), 'worker', send);
    expect(result).toEqual({ requestKey: 'ack', state: 'finalized', outcome: { reference: 'committed' } });
    expect(await executeBudgetedOperation(store, auth, 'ack', operation(), 'worker', send)).toEqual(result);
    expect(sends).toBe(1);
  });

  it('retains a claim when the store becomes unavailable after transport', async () => {
    const path = pathForStore(); let store = open(path, 'new'); register(store);
    let sends = 0;
    await expect(executeBudgetedOperation(store, auth, 'unavailable', operation(), 'worker', async () => {
      sends++; store.close(); return { reference: 'effect-happened' };
    })).rejects.toThrow(/store_unavailable/);
    store = open(path);
    expect(store.accounts(auth).every(a => a.charged === 1 && a.reserved === 0)).toBe(true);
    expect((await executeBudgetedOperation(store, auth, 'unavailable', operation(), 'other', async () => { sends++; return { reference: 'no' }; })).state).toBe('dispatch_claimed');
    expect(sends).toBe(1);
  });

  it('uses exact safe-integer boundaries and never increments beyond them', async () => {
    const path = pathForStore(); const store = open(path, 'new');
    store.registerConnection(connection); store.registerGrant({ ...grant, maxCalls: Number.MAX_SAFE_INTEGER });
    store.registerToken({ ...token, constraints: [{ key: 'max_calls', max_lifetime: Number.MAX_SAFE_INTEGER }] });
    const db = new Database(path);
    // Synthetic pre-existing history at the upper boundary, not generated dispatches.
    db.prepare('UPDATE admission_accounts SET charged=?').run(Number.MAX_SAFE_INTEGER - 1); db.close();
    let sends = 0;
    const send = async () => { sends++; return { reference: 'last-exact-unit' }; };
    expect((await executeBudgetedOperation(store, auth, 'last', operation(), 'worker', send)).state).toBe('finalized');
    expect(store.accounts(auth).every(a => a.charged === Number.MAX_SAFE_INTEGER)).toBe(true);
    await expect(executeBudgetedOperation(store, auth, 'overflow', operation(), 'worker', send)).rejects.toThrow(/budget_exceeded/);
    expect(sends).toBe(1);
    for (const maxCalls of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
      expect(() => store.registerGrant({ ...grant, grantId: 'bad-bound', maxCalls })).toThrow(/invalid_integer/);
    }
  });


  it('binds retries to exact normalized bytes, query, forwarded headers and selected identity', async () => {
    const path = pathForStore();
    const store = open(path, 'new'); register(store);
    const body = Buffer.from([0, 255, 1]);
    const headers = { 'Content-Type': ' application/octet-stream ', Accept: 'application/json' };
    const prepared = prepareBudgetOperation({ method: 'post', target: 'https://PROVIDER.example:443/items?q=1', body, headers });
    body.fill(9); headers.Accept = 'changed';
    let calls = 0;
    const result = await executeBudgetedOperation(store, auth, 'bound-key', prepared, 'worker', async wire => {
      calls++;
      expect(wire).toEqual({ method: 'POST', target: 'https://provider.example/items?q=1', body: [0, 255, 1],
        headers: { accept: 'application/json', 'content-type': 'application/octet-stream' } });
      expect(Object.isFrozen(wire) && Object.isFrozen(wire.headers) && Object.isFrozen(wire.body)).toBe(true);
      return { reference: 'byte-result' };
    });
    expect(result.state).toBe('finalized');
    const exact = { method: 'POST', target: 'https://provider.example/items?q=1', body: Buffer.from([0, 255, 1]),
      headers: { accept: 'application/json', 'content-type': 'application/octet-stream' } };
    const send = async () => { calls++; return { reference: 'unexpected' }; };
    expect(await executeBudgetedOperation(store, auth, 'bound-key', prepareBudgetOperation(exact), 'new-worker', send)).toEqual(result);
    for (const changed of [{ body: Buffer.from([0, 255, 2]) }, { target: 'https://provider.example/items?q=2' },
      { method: 'PUT' }, { headers: { accept: 'text/plain' } }]) {
      await expect(executeBudgetedOperation(store, auth, 'bound-key', prepareBudgetOperation({ ...exact, ...changed }), 'worker', send)).rejects.toThrow(/idempotency_conflict/);
    }
    for (const field of ['tenant', 'grantId', 'tokenId', 'holder', 'subject', 'provider', 'connectionId', 'policyVersion'] as const) {
      await expect(executeBudgetedOperation(store, { ...auth, [field]: 'different' }, 'bound-key', prepared, 'worker', send)).rejects.toThrow(/idempotency_conflict/);
      await expect(executeBudgetedOperation(store, { ...auth, [field]: 'different' }, `new-${field}`, prepared, 'worker', send)).rejects.toThrow(/authority_mismatch|chain_incomplete/);
    }
    for (const field of ['grantEpoch', 'connectionEpoch'] as const) {
      await expect(executeBudgetedOperation(store, { ...auth, [field]: 2 }, 'bound-key', prepared, 'worker', send)).rejects.toThrow(/idempotency_conflict/);
    }
    expect(calls).toBe(1);
    const db = new Database(path);
    try {
      const stored = JSON.stringify(db.prepare('SELECT * FROM admission_requests').all());
      expect(stored).not.toContain('provider.example/items');
      expect(stored).not.toContain('application/octet-stream');
      expect(JSON.stringify(result)).not.toContain('fingerprint');
    } finally { db.close(); }
  });

  it('keeps grant-wide continuity across old/new roots and their descendants without resetting token lifetime semantics', async () => {
    const store = open(pathForStore(), 'new');
    store.registerConnection(connection); store.registerGrant({ ...grant, maxCalls: 3 });
    const constraints = [{ key: 'max_calls', max_lifetime: 3 }, { key: 'max_calls', max_subtree: 3 }];
    for (const root of ['old-root', 'new-root']) {
      store.registerToken({ ...token, tokenId: root, constraints });
      store.registerToken({ ...token, tokenId: `${root}-child`, parentId: root, constraints });
    }
    let calls = 0;
    const send = (tokenId: string) => executeBudgetedOperation(store, { ...auth, tokenId }, tokenId, operation(), 'worker', async () => { calls++; return { reference: `r-${calls}` }; });
    await send('old-root-child'); await send('new-root'); await send('new-root-child');
    store.registerGrant({ ...grant, maxCalls: 3 });
    expect(store.accounts({ ...auth, tokenId: 'old-root' }).find(a => a.type === 'max_lifetime')?.charged).toBe(0);
    expect(store.accounts({ ...auth, tokenId: 'new-root' }).find(a => a.type === 'max_lifetime')?.charged).toBe(1);
    await expect(send('old-root')).rejects.toThrow(/budget_exceeded/);
    store.registerToken({ ...token, tokenId: 'third-root', constraints });
    await expect(send('third-root')).rejects.toThrow(/budget_exceeded/);
    expect(calls).toBe(3);
  });

  it('uses composite namespace keys and does not mix tenants or separately authorized grants', async () => {
    const store = open(pathForStore(), 'new');
    let calls = 0;
    for (const [tenant, grantId] of [['a|b', 'c'], ['a', 'b|c'], ['a', 'c']]) {
      const scoped = { ...auth, tenant, grantId, holder: `holder-${tenant}-${grantId}` };
      store.registerConnection({ ...connection, tenant });
      store.registerGrant({ ...grant, tenant, grantId, maxCalls: 1 });
      store.registerToken({ ...token, ...scoped });
      await executeBudgetedOperation(store, scoped, JSON.stringify([tenant, grantId]), operation(), 'worker', async () => { calls++; return { reference: 'separate' }; });
      expect(store.accounts(scoped).find(a => a.type === 'grant')).toMatchObject({ charged: 1, reserved: 0 });
    }
    expect(calls).toBe(3);
  });

  it.each(['before', 'after'] as const)('checks token expiry %s dispatch claim', async order => {
    let now = 1000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const path = pathForStore(); const store = open(path, 'new');
    store.registerConnection(connection); store.registerGrant(grant);
    store.registerToken({ ...token, expiresAt: 2000 });
    store.reserve(auth, 'expiry', operation());
    if (order === 'before') now = 2000;
    const claimed = store.claim(auth, 'expiry', operation(), 'worker');
    if (order === 'after') { now = 2000; store.finalize(claimed.dispatch!, { reference: 'already-in-flight' }); }
    expect(claimed.request.state).toBe(order === 'before' ? 'cancelled' : 'dispatch_claimed');
    let calls = 0;
    await expect(executeBudgetedOperation(store, auth, 'expired', operation(), 'worker', async () => { calls++; return { reference: 'no' }; })).rejects.toThrow(/expired/);
    expect(calls).toBe(0);
    const db = new Database(path);
    try { expect(db.prepare("SELECT reserved,charged FROM admission_accounts WHERE type='grant'").get()).toEqual({ reserved: 0, charged: order === 'before' ? 0 : 1 }); }
    finally { db.close(); }
  });

  it.each(['finalize', 'markIndeterminate'] as const)('R2 rejects accessor-fence target switching in %s without changing either request', async action => {
    const path = pathForStore(); const store = open(path, 'new'); register(store);
    store.reserve(auth, 'fence-a', operation());
    const a = store.claim(auth, 'fence-a', operation(), 'worker-a').dispatch!;
    store.reserve(auth, 'fence-b', operation());
    const b = store.claim(auth, 'fence-b', operation(), 'worker-b').dispatch!;
    const expectedB = action === 'finalize' ? store.finalize(b, { reference: 'committed-b' })
      : { requestKey: 'fence-b', state: 'dispatch_claimed' };
    const db = new Database(path, { readonly: true });
    try {
      const snapshot = () => admissionSnapshot(db);
      const before = snapshot();
      let reads = 0;
      const malicious = { ...a, get requestKey() { return ++reads === 1 ? a.requestKey : b.requestKey; } };
      expect(() => store[action](malicious, { reference: 'cross-request-outcome' })).toThrow(/invalid_accessor/);
      expect(reads).toBe(0);
      expect(snapshot()).toEqual(before);
      let sends = 0;
      const transport = async () => { sends++; return { reference: 'unexpected' }; };
      expect(await executeBudgetedOperation(store, auth, 'fence-a', operation(), 'retry', transport))
        .toEqual({ requestKey: 'fence-a', state: 'dispatch_claimed' });
      expect(await executeBudgetedOperation(store, auth, 'fence-b', operation(), 'retry', transport))
        .toEqual(expectedB);
      expect(sends).toBe(0);
      expect(snapshot()).toEqual(before);
    } finally { db.close(); }
  });

  it.each(['finalize', 'markIndeterminate'] as const)('R2 rejects non-data, extra, missing and malformed fences in %s', async action => {
    const path = pathForStore(); const store = open(path, 'new'); register(store);
    store.reserve(auth, 'closed-a', operation());
    const a = store.claim(auth, 'closed-a', operation(), 'worker-a').dispatch!;
    store.reserve(auth, 'closed-b', operation());
    store.claim(auth, 'closed-b', operation(), 'worker-b');
    const db = new Database(path, { readonly: true });
    try {
      const before = admissionSnapshot(db);
      const reject = (input: unknown, error: RegExp) => {
        expect(() => store[action](input as never, { reference: 'no' })).toThrow(error);
        expect(admissionSnapshot(db)).toEqual(before);
      };
      for (const field of ['requestKey', 'executor', 'fence'] as const) {
        let reads = 0;
        const accessor = { ...a };
        Object.defineProperty(accessor, field, { get() { reads++; return a[field]; } });
        reject(accessor, /invalid_accessor/);
        expect(reads).toBe(0);
        const missing: Record<string, unknown> = { ...a };
        delete missing[field];
        reject(missing, /invalid_identity/);
        for (const value of [undefined, null, 0, {}, '', '\n', 'x'.repeat(1025)]) {
          reject({ ...a, [field]: value }, /invalid_identity/);
        }
      }
      reject({ ...a, extra: true }, /unsupported_field/);
      reject({ ...a, [Symbol('extra')]: true }, /unsupported_field/);
      reject(Object.defineProperty({ ...a }, 'hidden', { value: true }), /unsupported_field/);
      for (const input of [null, undefined, 1, [], Object.create(a)]) reject(input, /invalid_object/);
      for (const stale of [{ ...a, requestKey: 'closed-b' }, { ...a, executor: 'worker-b' }, { ...a, fence: 'wrong-fence' }]) {
        reject(stale, /stale_executor/);
      }
      let sends = 0;
      for (const key of ['closed-a', 'closed-b']) {
        expect((await executeBudgetedOperation(store, auth, key, operation(), 'retry', async () => {
          sends++; return { reference: 'unexpected' };
        })).state).toBe('dispatch_claimed');
      }
      expect(sends).toBe(0);
      expect(admissionSnapshot(db)).toEqual(before);
    } finally { db.close(); }
  });

  it.each(['finalize', 'markIndeterminate'] as const)('R2 uses one detached data-fence snapshot throughout %s', action => {
    const path = pathForStore(); const store = open(path, 'new'); register(store);
    store.reserve(auth, 'snapshot-a', operation());
    const a = store.claim(auth, 'snapshot-a', operation(), 'worker-a').dispatch!;
    store.reserve(auth, 'snapshot-b', operation());
    const b = store.claim(auth, 'snapshot-b', operation(), 'worker-b').dispatch!;
    const beforeAccounts = store.accounts(auth);
    const reads: Record<string, number> = {};
    const input = new Proxy({ ...a }, { get(target, key, receiver) {
      if (typeof key !== 'string') return Reflect.get(target, key, receiver);
      reads[key] = (reads[key] ?? 0) + 1;
      return Reflect.get(reads[key] === 1 ? target : b, key, receiver);
    } });
    const expected = { requestKey: 'snapshot-a', state: action === 'finalize' ? 'finalized' : 'indeterminate',
      ...(action === 'finalize' ? { outcome: { reference: 'snapshot-result' } } : {}) };
    expect(store[action](input, { reference: 'snapshot-result' })).toEqual(expected);
    expect(reads).toEqual({ requestKey: 1, executor: 1, fence: 1 });
    expect(store.reserve(auth, 'snapshot-a', operation())).toEqual(expected);
    expect(store.reserve(auth, 'snapshot-b', operation())).toEqual({ requestKey: 'snapshot-b', state: 'dispatch_claimed' });
    expect(store.accounts(auth)).toEqual(beforeAccounts);
    const db = new Database(path, { readonly: true });
    try {
      expect(db.prepare('SELECT request_key,event FROM admission_transitions ORDER BY sequence').all()).toEqual([
        { request_key: 'snapshot-a', event: 'reserved' }, { request_key: 'snapshot-a', event: 'dispatch_claimed' },
        { request_key: 'snapshot-b', event: 'reserved' }, { request_key: 'snapshot-b', event: 'dispatch_claimed' },
        { request_key: 'snapshot-a', event: expected.state },
      ]);
    } finally { db.close(); }
  });

  it('R2 accepts serialized and frozen fences without duplicating terminal transitions', async () => {
    const path = pathForStore(); const store = open(path, 'new'); register(store);
    store.reserve(auth, 'serialized-a', operation());
    const a = store.claim(auth, 'serialized-a', operation(), 'worker-a').dispatch!;
    store.reserve(auth, 'serialized-b', operation());
    const b = store.claim(auth, 'serialized-b', operation(), 'worker-b').dispatch!;
    expect(Object.isFrozen(a) && Object.isFrozen(b)).toBe(true);
    const serializedA = JSON.parse(JSON.stringify(a));
    const serializedB = JSON.parse(JSON.stringify(b));
    const beforeAccounts = store.accounts(auth);
    const finalized = store.finalize(serializedA, { reference: 'serialized-result', status: 201 });
    expect(store.finalize(a, { reference: 'serialized-result', status: 201 })).toEqual(finalized);
    expect(store.markIndeterminate(serializedA)).toEqual(finalized);
    expect(() => store.finalize(serializedA, { reference: 'conflict' })).toThrow(/outcome_conflict/);
    const uncertain = store.markIndeterminate(serializedB);
    expect(store.markIndeterminate(b)).toEqual(uncertain);
    expect(store.markIndeterminate(Object.assign(Object.create(null), serializedB))).toEqual(uncertain);
    expect(() => store.finalize(serializedB, { reference: 'late-result' })).toThrow(/invalid_transition/);
    const db = new Database(path, { readonly: true });
    try {
      const before = admissionSnapshot(db);
      let sends = 0;
      for (const result of [finalized, uncertain]) {
        expect(await executeBudgetedOperation(store, auth, result.requestKey, operation(), 'retry', async () => {
          sends++; return { reference: 'unexpected' };
        })).toEqual(result);
      }
      expect(sends).toBe(0);
      expect(admissionSnapshot(db)).toEqual(before);
      expect(db.prepare("SELECT event,COUNT(*) AS n FROM admission_transitions WHERE event IN ('finalized','indeterminate') GROUP BY event ORDER BY event").all())
        .toEqual([{ event: 'finalized', n: 1 }, { event: 'indeterminate', n: 1 }]);
      expect(store.accounts(auth)).toEqual(beforeAccounts);
    } finally { db.close(); }
  });

  it('rejects stale executors, duplicate claims and conflicting outcomes', () => {
    const store = open(pathForStore(), 'new'); register(store);
    store.reserve(auth, 'fenced', operation());
    const dispatch = store.claim(auth, 'fenced', operation(), 'worker-a').dispatch!;
    expect(store.claim(auth, 'fenced', operation(), 'worker-a').dispatch).toBeUndefined();
    expect(store.claim(auth, 'fenced', operation(), 'worker-b').dispatch).toBeUndefined();
    for (const stale of [{ ...dispatch, executor: 'worker-b' }, { ...dispatch, fence: 'stale' }]) {
      expect(() => store.finalize(stale, { reference: 'no' })).toThrow(/stale_executor/);
      expect(() => store.markIndeterminate(stale)).toThrow(/stale_executor/);
    }
    const result = store.finalize(dispatch, { reference: 'yes' });
    expect(store.finalize(dispatch, { reference: 'yes' })).toEqual(result);
    expect(store.markIndeterminate(dispatch)).toEqual(result);
    expect(() => store.finalize(dispatch, { reference: 'different' })).toThrow(/outcome_conflict/);
    expect(store.accounts(auth).every(a => a.charged === 1 && a.reserved === 0)).toBe(true);
  });

  it('rejects conflicting immutable connection, grant and token registrations', () => {
    const store = open(pathForStore(), 'new'); register(store);
    store.reserve(auth, 'held', operation());
    const before = store.accounts(auth);
    for (const change of [{ parentId: 'another' }, { expiresAt: token.expiresAt - 1 }, { holder: 'other' }, { subject: 'other' },
      { provider: 'other' }, { connectionId: 'other' }, { grantEpoch: 2 }, { connectionEpoch: 2 }, { policyVersion: 'other' },
      { constraints: [{ key: 'max_calls', max_lifetime: 1 }] }]) {
      expect(() => store.registerToken({ ...token, ...change })).toThrow(/registration_conflict/);
    }
    expect(() => store.registerGrant({ ...grant, maxCalls: 99 })).toThrow(/registration_conflict/);
    expect(() => store.registerGrant({ ...grant, subject: 'other' })).toThrow(/registration_conflict/);
    expect(() => store.registerConnection({ ...connection, epoch: 2 })).toThrow(/registration_conflict/);
    expect(() => store.registerConnection({ ...connection, subject: 'other' })).toThrow(/registration_conflict/);
    register(store);
    expect(store.accounts(auth)).toEqual(before);
  });

  it.each([
    [{ key: 'max_calls', mystery: 1 }], [{ key: 'max_spend', max_lifetime: 1 }],
    [{ key: 'max_calls', max: 1 }], [{ key: 'region', one_of: ['test'] }],
    [{ key: 'max_calls', max_lifetime: 0.5 }], [{ key: 'max_calls', max_lifetime: Number.MAX_SAFE_INTEGER + 1 }],
    [{ key: 'max_calls', max_subtree: -1 }], [{ key: 'max_calls', max_subtree: Infinity }],
    [{ key: 'max_calls', max_subtree: NaN }], [{ key: 'max_calls', max_lifetime: 1, discarded: true }],
  ])('denies unsupported, malformed or unsafe constraints %# before any transport', async constraints => {
    const store = open(pathForStore(), 'new'); store.registerConnection(connection); store.registerGrant(grant);
    expect(() => store.registerToken({ ...token, constraints: [constraints] as never })).toThrow(/constraint|integer/);
    let sends = 0;
    await expect(executeBudgetedOperation(store, auth, 'denied', operation(), 'worker', async () => { sends++; return { reference: 'no' }; })).rejects.toThrow(/chain_incomplete/);
    expect(sends).toBe(0);
  });

  it('refuses attenuations that omit, loosen or change the type of a parent restriction', () => {
    const store = open(pathForStore(), 'new'); register(store);
    for (const constraints of [[], [{ key: 'max_calls', max_lifetime: 3 }], [{ key: 'max_calls', max_subtree: 1 }]]) {
      expect(() => store.registerToken({ ...token, tokenId: 'child', parentId: 'root', constraints })).toThrow(/invalid_attenuation/);
    }
    expect(() => store.registerToken({ ...token, tokenId: 'child', parentId: 'root', expiresAt: token.expiresAt + 1 })).toThrow(/invalid_attenuation/);
    expect(() => store.registerToken({ ...token, tokenId: 'orphan', parentId: 'missing' })).toThrow(/chain_incomplete/);
  });

  it.each(['missing-table', 'altered-schema', 'wrong-version', 'empty-file'] as const)('refuses an existing %s store without repairing it', variant => {
    const path = pathForStore();
    if (variant !== 'empty-file') open(path, 'new').close();
    const db = new Database(path);
    if (variant === 'missing-table') db.exec('DROP TABLE admission_transitions');
    if (variant === 'altered-schema') db.exec('ALTER TABLE admission_requests ADD COLUMN unexpected TEXT');
    if (variant === 'wrong-version') db.pragma('user_version = 9');
    db.close();
    expect(() => open(path)).toThrow(/store_incompatible|store_unavailable/);
    expect(() => open(path, 'new')).toThrow(/store_unavailable/);
  });

  it('refuses missing constraints and extra authorization/outcome fields instead of silently discarding restrictions', () => {
    const store = open(pathForStore(), 'new'); register(store);
    expect(() => store.registerToken({ ...token, tokenId: 'missing', constraints: undefined } as never)).toThrow(/invalid_constraints/);
    expect(() => store.registerGrant({ ...grant, grantId: 'extra', quantities: {} } as never)).toThrow(/unsupported_field/);
    expect(() => store.registerConnection({ ...connection, connectionId: 'extra', constraints: [] } as never)).toThrow(/unsupported_field/);
    store.reserve(auth, 'outcome', operation());
    const dispatch = store.claim(auth, 'outcome', operation(), 'worker').dispatch!;
    expect(() => store.finalize(dispatch, { reference: 'safe', body: 'not-for-storage' } as never)).toThrow(/unsupported_field/);
    expect(() => store.finalize(dispatch, { reference: 'https://provider.example/private?token=synthetic' })).toThrow(/invalid_outcome/);
    expect(() => store.finalize(dispatch, { reference: 'safe', status: 200.5 })).toThrow(/invalid_outcome/);
    expect(store.finalize(dispatch, { reference: 'safe', status: 200 }).state).toBe('finalized');
  });

  it('rejects caller quantities and credential-bearing prepared operations before transport', async () => {
    const store = open(pathForStore(), 'new'); register(store);
    let calls = 0;
    const transport = async () => { calls++; return { reference: 'no' }; };
    await expect(executeBudgetedOperation(store, { ...auth, quantities: { max_calls: 0 } } as typeof auth, 'forged', operation(), 'worker', transport))
      .rejects.toThrow(/unsupported_field/);
    for (const header of ['Authorization', 'Proxy-Authorization', 'Cookie', 'X-API-Key', 'X-Auth-Token', 'custom-credential']) {
      expect(() => prepareBudgetOperation({ method: 'POST', target: 'https://provider.example', headers: { [header]: 'synthetic-value' } })).toThrow(/unsupported_header/);
    }
    expect(() => prepareBudgetOperation({ method: 'GET', target: 'https://synthetic:password@provider.example' })).toThrow(/invalid_target/);
    expect(() => prepareBudgetOperation({ method: 'GET', target: 'https://provider.example/?access_token=synthetic' })).toThrow(/invalid_target/);
    expect(() => prepareBudgetOperation({ method: 'POST', target: 'https://provider.example', headers: { Accept: 'a', accept: 'b' } })).toThrow(/duplicate_header/);
    expect(() => prepareBudgetOperation({ method: 'POST', target: 'https://provider.example', quantities: { max_calls: 0 } } as never)).toThrow(/unsupported_field/);
    expect(calls).toBe(0);
  });

  it.each(['connection', 'grant', 'revocation'] as const)('cancels a reservation after authoritative %s change without registration reactivating it', async change => {
    const path = pathForStore();
    const store = open(path, 'new'); register(store);
    store.reserve(auth, 'epoch-race', operation());
    if (change === 'connection') store.advanceConnectionEpoch(connection, 1, 2);
    if (change === 'grant') store.advanceGrantEpoch(auth, 1, 2);
    if (change === 'revocation') store.revokeGrant(auth);
    register(store);
    expect(store.claim(auth, 'epoch-race', operation(), 'worker').request.state).toBe('cancelled');
    let sends = 0;
    await expect(executeBudgetedOperation(store, auth, 'denied', operation(), 'worker', async () => { sends++; return { reference: 'no' }; })).rejects.toThrow(/authority_mismatch/);
    expect(sends).toBe(0);
    const db = new Database(path);
    try { expect(db.prepare<[], { reserved: number; charged: number }>('SELECT reserved,charged FROM admission_accounts').all().every(a => a.reserved === 0 && a.charged === 0)).toBe(true); }
    finally { db.close(); }
    if (change === 'grant') {
      const renewed = { ...auth, tokenId: 'renewed', grantEpoch: 2 };
      store.registerToken({ ...token, ...renewed });
      expect((await executeBudgetedOperation(store, renewed, 'new-epoch', operation(), 'worker', async () => ({ reference: 'yes' }))).state).toBe('finalized');
      expect(() => store.advanceGrantEpoch(auth, 2, 1)).toThrow(/invalid_epoch/);
    }
  });

  it.each(['response-loss', 'finalization-failure'] as const)('retains charges and never resends after %s', async fault => {
    const path = pathForStore();
    let store = open(path, 'new');
    register(store);
    if (fault === 'finalization-failure') {
      const db = new Database(path);
      db.exec("CREATE TRIGGER fail_finalization BEFORE INSERT ON admission_transitions WHEN NEW.event='finalized' BEGIN SELECT RAISE(ABORT, 'injected'); END");
      db.close();
    }
    let calls = 0;
    const transport = async () => { calls++; if (fault === 'response-loss') throw new Error('lost response'); return { reference: 'safe-result' }; };
    expect(await executeBudgetedOperation(store, auth, 'uncertain', operation(), 'worker', transport)).toEqual({ requestKey: 'uncertain', state: 'indeterminate' });
    expect(store.accounts(auth).every(a => a.charged === 1 && a.reserved === 0)).toBe(true);
    store.close();
    if (fault === 'finalization-failure') {
      const db = new Database(path); db.exec('DROP TRIGGER fail_finalization'); db.close();
    }
    store = open(path);
    expect((await executeBudgetedOperation(store, auth, 'uncertain', operation(), 'new-worker', transport)).state).toBe('indeterminate');
    expect(store.cancel(auth, 'uncertain', operation()).state).toBe('indeterminate');
    expect(calls).toBe(1);
  });

  it.each(['before', 'after'] as const)('orders ancestor revocation %s claim without refunding in-flight work', async order => {
    const path = pathForStore();
    const store = open(path, 'new');
    register(store);
    const child = { ...auth, tokenId: 'child', holder: 'child-holder' };
    store.registerToken({ ...token, ...child, parentId: 'root' });
    const op = operation();
    store.reserve(child, 'race', op);
    if (order === 'before') store.revokeToken(auth);
    const claimed = store.claim(child, 'race', op, 'worker');
    if (order === 'after') store.revokeToken(auth);
    expect(claimed.request.state).toBe(order === 'before' ? 'cancelled' : 'dispatch_claimed');
    if (order === 'after') {
      expect(store.cancel(child, 'race', op).state).toBe('dispatch_claimed');
      expect(store.finalize(claimed.dispatch!, { reference: 'in-flight' }).state).toBe('finalized');
    }
    let sends = 0;
    await executeBudgetedOperation(store, child, 'race', op, 'other-worker', async () => { sends++; return { reference: 'unexpected' }; });
    expect(sends).toBe(0);
    const db = new Database(path);
    try {
      expect(db.prepare("SELECT reserved,charged FROM admission_accounts WHERE type='grant'").get()).toEqual({ reserved: 0, charged: order === 'before' ? 0 : 1 });
      expect(db.prepare('SELECT event FROM admission_transitions ORDER BY sequence').all()).toEqual(
        (order === 'before' ? ['reserved', 'token_revoked', 'cancelled'] : ['reserved', 'dispatch_claimed', 'token_revoked', 'finalized']).map(event => ({ event })),
      );
    } finally { db.close(); }
    await expect(executeBudgetedOperation(store, child, 'new-after-revoke', op, 'worker', async () => { sends++; return { reference: 'no' }; })).rejects.toThrow(/revoked/);
    expect(sends).toBe(0);
  });

  it('derives every lineage account atomically while leaving parent lifetime uncharged', async () => {
    const store = open(pathForStore(), 'new');
    store.registerConnection(connection);
    store.registerGrant({ ...grant, maxCalls: 10 });
    const rootConstraints = [{ key: 'max_calls', max_lifetime: 2 }, { key: 'max_calls', max_subtree: 2 }];
    store.registerToken({ ...token, constraints: rootConstraints });
    for (const tokenId of ['a', 'b', 'c']) store.registerToken({ ...token, tokenId, parentId: 'root',
      constraints: [{ key: 'max_calls', max_lifetime: 1 }, { key: 'max_calls', max_subtree: 2 }] });
    let calls = 0;
    const send = (tokenId: string, key: string) => executeBudgetedOperation(store, { ...auth, tokenId }, key, operation(), 'worker', async () => {
      calls++; return { reference: `result-${calls}` };
    });
    await send('a', 'a1');
    const before = store.accounts({ ...auth, tokenId: 'a' });
    await expect(send('a', 'a2')).rejects.toThrow(/budget_exceeded/);
    expect(store.accounts({ ...auth, tokenId: 'a' })).toEqual(before);
    await send('b', 'b1');
    await expect(send('c', 'c1')).rejects.toThrow(/budget_exceeded/);
    expect(store.accounts(auth)).toEqual([
      { owner: 'grant-a', type: 'grant', bound: 10, reserved: 0, charged: 2 },
      { owner: 'root', type: 'max_lifetime', bound: 2, reserved: 0, charged: 0 },
      { owner: 'root', type: 'max_subtree', bound: 2, reserved: 0, charged: 2 },
    ]);
    expect(store.accounts({ ...auth, tokenId: 'c' }).filter(a => a.owner === 'c').every(a => a.charged === 0 && a.reserved === 0)).toBe(true);
    expect(calls).toBe(2);
  });

  it('charges one root dispatch and replays its durable safe outcome after restart without resending', async () => {
    const path = pathForStore();
    let store = open(path, 'new');
    register(store);
    let calls = 0;
    const transport = async (request: { method: string; body: readonly number[] }) => {
      calls++;
      expect(request.method).toBe('POST');
      expect(Buffer.from(request.body).toString()).toBe('payload');
      return { reference: 'outcome-1', status: 201 };
    };
    const result = await executeBudgetedOperation(store, auth, 'request-1', operation(), 'worker-1', transport);
    expect(result).toEqual({ requestKey: 'request-1', state: 'finalized', outcome: { reference: 'outcome-1', status: 201 } });
    expect(store.accounts(auth).map(a => [a.type, a.reserved, a.charged])).toEqual([
      ['grant', 0, 1], ['max_lifetime', 0, 1],
    ]);
    store.close();
    store = open(path);
    register(store);
    expect(await executeBudgetedOperation(store, auth, 'request-1', operation(), 'worker-2', transport)).toEqual(result);
    expect(calls).toBe(1);
    await executeBudgetedOperation(store, auth, 'request-2', operation(), 'worker-2', transport);
    await expect(executeBudgetedOperation(store, auth, 'request-3', operation(), 'worker-2', transport)).rejects.toThrow(/budget_exceeded/);
    expect(calls).toBe(2);
  });

  it('requires explicit new-store initialization and preserves immutable deployment identity on reopen', () => {
    const path = pathForStore();
    expect(() => open(path)).toThrow(/store_unavailable/);
    const store = open(path, 'new');
    store.close();
    expect(() => open(path)).not.toThrow();
    expect(() => open(path, 'new')).toThrow(/store_unavailable/);
    expect(() => new DurableBudgetStore({ path, ...identity, deploymentEpoch: 'deployment-2' }))
      .toThrow(/store_incompatible/);
    expect(() => new DurableBudgetStore({ path, ...identity, issuer: 'https://other.example' }))
      .toThrow(/store_incompatible/);
    expect(() => new DurableBudgetStore({ path: ':memory:', ...identity })).toThrow(/durable_path/);
  });
});

/**
 * A shared replay store across server instances: a WPT jti or request
 * signature nonce accepted at one replica is refused at another. Without one,
 * each process keeps its own cache (the default).
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { createInMemorySharedReplayStore, type SharedReplayStore } from '../identity/types.js';
import { WIMSE_PROBLEM_TYPES } from '../identity/http-signature.js';
import { cleanupDirs, httpSigHeaders, send, trustDomain, wimseServer, wptHeaders } from './wimse-fixture.js';

const CONN = '/api/v1/connections?user_id=default';

afterEach(() => {
  vi.restoreAllMocks();
  cleanupDirs();
});

async function replicas(sharedReplay?: SharedReplayStore) {
  const b = trustDomain('domain-b.example');
  const w = b.workload();
  const make = () => wimseServer({ domains: [b], mapSubject: () => w.subject, ...(sharedReplay ? { source: { sharedReplay } } : {}) });
  return { w, one: await make(), two: await make() };
}

describe('shared replay store', () => {
  it('refuses at a second instance a signed request the first accepted', async () => {
    const { w, one, two } = await replicas(createInMemorySharedReplayStore());
    const h = httpSigHeaders(w, 'GET', CONN);
    expect((await send(one.app, 'get', CONN, h)).status).toBe(200);
    const replayed = await send(two.app, 'get', CONN, h);
    expect(replayed.status).toBe(400);
    expect(replayed.body.type).toBe(WIMSE_PROBLEM_TYPES.signatureInvalid);
  });

  it('refuses at a second instance a WPT the first accepted', async () => {
    const { w, one, two } = await replicas(createInMemorySharedReplayStore());
    const h = wptHeaders(w, '/api/v1/connections');
    expect((await send(one.app, 'get', CONN, h)).status).toBe(200);
    expect((await send(two.app, 'get', CONN, h)).status).toBe(401);
  });

  it('without a shared store each instance keeps its own cache (the per-process default)', async () => {
    const { w, one, two } = await replicas();
    const h = httpSigHeaders(w, 'GET', CONN);
    expect((await send(one.app, 'get', CONN, h)).status).toBe(200);
    expect((await send(two.app, 'get', CONN, h)).status).toBe(200);
    expect((await send(two.app, 'get', CONN, h)).status).toBe(400);
  });

  it('a failing store refuses the request (fails closed), and records the reason', async () => {
    const failing: SharedReplayStore = { checkAndRecord: async () => { throw new Error('connection refused'); } };
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { w, one } = await replicas(failing);
    expect((await send(one.app, 'get', CONN, httpSigHeaders(w, 'GET', CONN))).status).toBe(400);
    expect((await send(one.app, 'get', CONN, wptHeaders(w, '/api/v1/connections'))).status).toBe(401);
    expect(warn.mock.calls.some((c) => String(c[0]).includes('replay_store_unavailable'))).toBe(true);
  });

  it('a store that resolves anything but true refuses', async () => {
    const odd = { checkAndRecord: async () => undefined } as unknown as SharedReplayStore;
    const { w, one } = await replicas(odd);
    expect((await send(one.app, 'get', CONN, httpSigHeaders(w, 'GET', CONN))).status).toBe(400);
  });
});

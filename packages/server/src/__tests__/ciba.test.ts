import { describe, it, expect } from 'vitest';
import { ApprovalCapacityError, ApprovalStore, askExternalProvider, CIBA_GRANT_TYPE } from '../ciba.js';

const base = {
  subject: 'alice', agentDid: 'did:key:z6MkAgent', jkt: 'jkt_a', service: 'github', appClientId: 'local',
  scopes: ['repo'], constraints: [], approver: 'subject' as const,
};

describe('ApprovalStore', () => {
  it('polls pending, slows a fast poller, then redeems an approval once', () => {
    const store = new ApprovalStore();
    const t0 = 1_000_000;
    const req = store.create(base, { now: t0, intervalSeconds: 5 });
    expect(store.poll(req.authReqId, 'jkt_a', t0)).toMatchObject({ ok: false, error: 'authorization_pending' });
    expect(store.poll(req.authReqId, 'jkt_a', t0 + 1000)).toMatchObject({ ok: false, error: 'slow_down' });
    expect(store.decide(req.authReqId, 'subject', 'approve', 'alice', t0 + 2000)?.status).toBe('approved');
    expect(store.poll(req.authReqId, 'jkt_a', t0 + 20_000)).toMatchObject({ ok: true });
    expect(store.poll(req.authReqId, 'jkt_a', t0 + 40_000)).toMatchObject({ ok: false, error: 'invalid_grant' });
  });

  it('answers only the agent the request is bound to', () => {
    const store = new ApprovalStore();
    const req = store.create(base);
    store.decide(req.authReqId, 'subject', 'approve', 'alice');
    expect(store.poll(req.authReqId, 'jkt_other')).toMatchObject({ ok: false, error: 'invalid_grant' });
  });

  it('reports a denial and an expiry', () => {
    const store = new ApprovalStore();
    const denied = store.create(base);
    store.decide(denied.authReqId, 'subject', 'deny', 'alice');
    expect(store.poll(denied.authReqId, 'jkt_a')).toMatchObject({ ok: false, error: 'access_denied' });
    const t0 = 2_000_000;
    const late = store.create(base, { now: t0, expiresInSeconds: 60 });
    expect(store.poll(late.authReqId, 'jkt_a', t0 + 61_000)).toMatchObject({ ok: false, error: 'expired_token' });
    expect(store.decide(late.authReqId, 'subject', 'approve', 'alice', t0 + 61_000)).toBeNull();
    // An approval not redeemed in time lapses too.
    const unredeemed = store.create(base, { now: t0, expiresInSeconds: 60 });
    store.decide(unredeemed.authReqId, 'subject', 'approve', 'alice', t0 + 1000);
    expect(store.poll(unredeemed.authReqId, 'jkt_a', t0 + 61_000)).toMatchObject({ ok: false, error: 'expired_token' });
  });

  it('caps live requests per agent, per subject and per pair, and frees finished ones', () => {
    const store = new ApprovalStore(undefined, { maxPerAgent: 3, maxPerSubject: 3, maxPerPair: 2 });
    const t0 = 3_000_000;
    const other = 'did:key:z6MkOther';
    store.create(base, { now: t0 });
    const second = store.create(base, { now: t0 });
    // One agent has its share of alice: it cannot ask her again...
    expect(store.hasCapacity({ agentDid: base.agentDid, subject: 'alice' }, t0)).toBe(false);
    expect(() => store.create(base, { now: t0 })).toThrow(ApprovalCapacityError);
    // ...but another agent still can, and it can still ask someone else.
    expect(store.hasCapacity({ agentDid: other, subject: 'alice' }, t0)).toBe(true);
    expect(store.hasCapacity({ agentDid: base.agentDid, subject: 'bob' }, t0)).toBe(true);
    store.create({ ...base, subject: 'bob' }, { now: t0 });
    // Now the agent holds its own cap of 3, for any subject.
    expect(store.hasCapacity({ agentDid: base.agentDid, subject: 'carol' }, t0)).toBe(false);
    store.create({ ...base, agentDid: other }, { now: t0 });
    // And alice holds her cap of 3, from any agent.
    expect(store.hasCapacity({ agentDid: 'did:key:z6MkThird', subject: 'alice' }, t0)).toBe(false);
    store.decide(second.authReqId, 'subject', 'deny', 'alice', t0);
    expect(store.hasCapacity({ agentDid: base.agentDid, subject: 'alice' }, t0)).toBe(true);
    // A denied request is kept for the last poll, then forgotten.
    expect(store.poll(second.authReqId, 'jkt_a', t0 + 1000)).toMatchObject({ error: 'access_denied' });
    store.hasCapacity({ agentDid: base.agentDid, subject: 'alice' }, t0 + 61_000);
    expect(store.get(second.authReqId, t0 + 61_000)).toBeNull();
  });

  it('caps live requests overall', () => {
    const store = new ApprovalStore(undefined, { maxRequests: 1 });
    store.create(base);
    expect(store.hasCapacity({ agentDid: 'did:key:z6MkOther', subject: 'bob' })).toBe(false);
    expect(() => store.create({ ...base, agentDid: 'did:key:z6MkOther', subject: 'bob' })).toThrow(ApprovalCapacityError);
  });

  it('needs both roles under approver both, and refuses a role the permission does not name', () => {
    const store = new ApprovalStore();
    const both = store.create({ ...base, approver: 'both' });
    expect(store.decide(both.authReqId, 'subject', 'approve', 'alice')?.status).toBe('pending');
    expect(store.decide(both.authReqId, 'admin', 'approve', 'admin')?.status).toBe('approved');
    const subjectOnly = store.create(base);
    expect(store.decide(subjectOnly.authReqId, 'admin', 'approve', 'admin')).toBeNull();
    const adminOnly = store.create({ ...base, approver: 'admin' });
    expect(store.decide(adminOnly.authReqId, 'subject', 'approve', 'alice')).toBeNull();
  });

  it('signs approval links per request', () => {
    const store = new ApprovalStore();
    const a = store.create(base);
    const b = store.create(base);
    expect(store.verifyLink(a.authReqId, store.linkSignature(a.authReqId))).toBe(true);
    expect(store.verifyLink(a.authReqId, store.linkSignature(b.authReqId))).toBe(false);
    expect(store.verifyLink(a.authReqId, undefined)).toBe(false);
    expect(new ApprovalStore().verifyLink(a.authReqId, store.linkSignature(a.authReqId))).toBe(false);
  });
});

describe('askExternalProvider', () => {
  const provider = { backchannelAuthenticationEndpoint: 'https://op.example/bc', tokenEndpoint: 'https://op.example/token', clientId: 'cred', clientSecret: 's3cret' };
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  it('asks the OP as its CIBA client and resolves on approval', async () => {
    const calls: Array<{ url: string; body: string; auth: string | null }> = [];
    const replies = [json({ auth_req_id: 'op_1', interval: 1 }), json({ error: 'authorization_pending' }, 400), json({ access_token: 'x' })];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      calls.push({ url, body: String(init.body), auth: new Headers(init.headers).get('authorization') });
      return replies.shift()!;
    }) as unknown as typeof fetch;
    const decision = await askExternalProvider(provider, { subject: 'alice', bindingMessage: 'A1', expiresAt: Date.now() + 60_000 }, { fetchImpl, sleep: async () => {} });
    expect(decision).toBe('approve');
    expect(calls[0]!.url).toBe('https://op.example/bc');
    expect(new URLSearchParams(calls[0]!.body).get('login_hint')).toBe('alice');
    expect(calls[0]!.auth).toBe(`Basic ${Buffer.from('cred:s3cret').toString('base64')}`);
    expect(new URLSearchParams(calls[1]!.body).get('grant_type')).toBe(CIBA_GRANT_TYPE);
  });

  it('resolves a denial and a refused start as deny', async () => {
    const denied = [json({ auth_req_id: 'op_1' }), json({ error: 'access_denied' }, 400)];
    expect(await askExternalProvider(provider, { subject: 'alice', expiresAt: Date.now() + 60_000 },
      { fetchImpl: (async () => denied.shift()!) as unknown as typeof fetch, sleep: async () => {} })).toBe('deny');
    expect(await askExternalProvider(provider, { subject: 'alice', expiresAt: Date.now() + 60_000 },
      { fetchImpl: (async () => json({ error: 'unknown_user_id' }, 400)) as unknown as typeof fetch, sleep: async () => {} })).toBe('deny');
  });
});

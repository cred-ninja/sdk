import { afterEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { generateKeyPairSync, sign } from 'node:crypto';
import { CredGuard, clientGrantPolicy } from '@credninja/guard';
import type { CredPolicy, GuardContext } from '@credninja/guard';
import { LINK_OPAQUE_FAILURE_BODY } from '@credninja/protocol';
import { createServer } from '../server.js';
import {
  ADMIN_TOKEN,
  AGENT_TOKEN,
  Browser,
  CALENDAR_URL,
  activate,
  authorizePath,
  basic,
  callback,
  confirm,
  connectAndActivate,
  connectFlow,
  delegate,
  envelopeOf,
  makeHarness,
  par,
  registerClient,
  resultOf,
  toProvider,
  use,
} from './link-harness.js';
import type { Harness } from './link-harness.js';

let h: Harness | null = null;

afterEach(() => {
  h?.close();
  h = null;
});

async function harness(overrides: Parameters<typeof makeHarness>[0] = {}): Promise<Harness> {
  h = await makeHarness(overrides);
  return h;
}

describe('Link delegation enforcement without a Guard', () => {
  it('refuses pending, needs_reauth and revoked connections on delegate and use with typed codes', async () => {
    const { app, server } = await harness();
    const store = server.link!.context.store;
    const client = await registerClient(app);

    const pending = await connectFlow(app, client);
    const p = await delegate(app, { connection_id: pending.connection_id });
    expect(p.status).toBe(403);
    expect(p.body).toMatchObject({ error: 'consent_required' });
    expect(p.body.request_id).toMatch(/^req_/);
    expect(p.headers['cred-request-id']).toBe(p.body.request_id);
    await activate(app, client, pending.connection_id, pending.code);

    const handle = await delegate(app, { connection_id: pending.connection_id, scopes: ['calendar.readonly'] });
    expect(handle.status).toBe(200);

    await store.setConnectionStatus({ connection_id: pending.connection_id, status: 'needs_reauth', now: new Date().toISOString() });
    const d1 = await delegate(app, { connection_id: pending.connection_id });
    expect(d1.status).toBe(403);
    expect(d1.body.error).toBe('reauth_required');
    // The agent holds a Permission, so it gets a reauth_url (redirect mode, fixed subject).
    expect(d1.body.reauth_url).toMatch(/^http:\/\/localhost:3456\/link\/v1\/authorize\?request_uri=urn%3Acred%3Alink%3A/);
    const u1 = await use(app, { delegation_id: handle.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    expect(u1.status).toBe(403);
    expect(u1.body.error).toBe('reauth_required');
    expect(h!.fake.upstream).toHaveLength(0);

    await store.setConnectionStatus({ connection_id: pending.connection_id, status: 'revoked', now: new Date().toISOString() });
    const d2 = await delegate(app, { connection_id: pending.connection_id });
    expect(d2.body.error).toBe('grant_revoked');
    const u2 = await use(app, { delegation_id: handle.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    expect(u2.status).toBe(403);
    expect(u2.body.error).toBe('grant_revoked');
    expect(h!.fake.upstream).toHaveLength(0);
  });

  it('a narrowed grant refuses an outstanding handle at use time', async () => {
    const { app, server } = await harness();
    const client = await registerClient(app);
    const connectionId = await connectAndActivate(app, client);
    const handle = await delegate(app, { connection_id: connectionId, scopes: ['gmail.send'] });
    expect(handle.status).toBe(200);
    const grant = await server.link!.context.store.getGrantForConnection(connectionId);
    await server.link!.context.store.narrowGrant({ grant_id: grant!.id, scopes: ['calendar.readonly'], now: new Date().toISOString() });
    const res = await use(app, { delegation_id: handle.body.delegation_id, url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', method: 'POST', body: {} });
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ error: 'insufficient_scope', scope: 'gmail.send' });
  });

  it('is deny-by-default per agent: permission_required until the backend grants the agent', async () => {
    const { app } = await harness();
    const client = await registerClient(app);
    const connectionId = await connectAndActivate(app, client, { parOverrides: { agent_id: null } });
    const denied = await delegate(app, { connection_id: connectionId });
    expect(denied.status).toBe(403);
    expect(denied.body.error).toBe('permission_required');
    // An agent_id in the body is not identity.
    const spoof = await delegate(app, { connection_id: connectionId, agent_id: 'server-agent' });
    expect(spoof.body.error).toBe('permission_required');

    const set = await request(app).post(`/link/v1/connections/${connectionId}/permissions`).set('Authorization', client.auth)
      .send({ agent_id: 'server-agent', scopes: ['calendar.readonly'] });
    expect(set.status).toBe(200);
    expect(set.body.permission).toMatchObject({ agent_id: 'server-agent', connection_id: connectionId, scopes: ['calendar.readonly'], delegatable: false, max_delegation_depth: 0 });

    const ok = await delegate(app, { connection_id: connectionId });
    expect(ok.status).toBe(200);
    expect(ok.body.scopes).toEqual(['calendar.readonly']);
    const wider = await delegate(app, { connection_id: connectionId, scopes: ['gmail.send'] });
    expect(wider.status).toBe(403);
    expect(wider.body).toMatchObject({ error: 'permission_required', scope: 'gmail.send' });
  });

  it('bounds the permissions route', async () => {
    const { app } = await harness();
    const client = await registerClient(app);
    const other = await registerClient(app);
    const connectionId = await connectAndActivate(app, client);
    const post = (auth: string, id: string, body: unknown) => request(app).post(`/link/v1/connections/${id}/permissions`).set('Authorization', auth).send(body as object);

    const outside = await post(client.auth, connectionId, { agent_id: 'agent-2', scopes: ['drive'] });
    expect(outside.status).toBe(400);
    expect(outside.body.error).toBe('invalid_scope');
    expect((await post(client.auth, connectionId, { scopes: ['calendar.readonly'] })).status).toBe(400);
    expect((await post(client.auth, connectionId, { agent_id: 'a', scopes: 'calendar.readonly' })).status).toBe(400);
    expect((await post(client.auth, connectionId, { agent_id: 'a', scopes: Array.from({ length: 65 }, (_, i) => `s${i}`) })).status).toBe(400);
    expect((await post(client.auth, connectionId, { agent_id: 'x'.repeat(300), scopes: [] })).status).toBe(400);
    const foreign = await post(other.auth, connectionId, { agent_id: 'a', scopes: ['calendar.readonly'] });
    expect(foreign.status).toBe(401);
    expect(foreign.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
    const unknown = await post(client.auth, 'conn_doesnotexist', { agent_id: 'a', scopes: [] });
    expect(unknown.status).toBe(401);
    expect(unknown.text).toBe(foreign.text);
  });

  it('defaults to a handle and refuses raw tokens without the client flag', async () => {
    const { app } = await harness();
    const client = await registerClient(app);
    const connectionId = await connectAndActivate(app, client);
    const raw = await delegate(app, { connection_id: connectionId, token_format: 'raw' });
    expect(raw.status).toBe(400);
    expect(raw.body.error).toBe('invalid_request');
    expect(raw.body.access_token).toBeUndefined();
    const def = await delegate(app, { connection_id: connectionId });
    expect(def.body.token_type).toBe('Delegation');
    expect(def.body.access_token).toBeUndefined();
  });

  it('issues raw tokens only with allow_raw_tokens and a refreshable provider, with an audit event each', async () => {
    const { app, server } = await harness();
    const client = await registerClient(app, { allow_raw_tokens: true });
    const connectionId = await connectAndActivate(app, client);
    const raw = await delegate(app, { connection_id: connectionId, token_format: 'raw' });
    expect(raw.status).toBe(200);
    expect(raw.body.access_token).toBe('ya29.access-1');
    expect(raw.body.expires_in).toBeGreaterThan(0);
    const events = server.vault.queryAuditEvents({ limit: 50 }).filter((e) => e.metadata?.link_raw_token === true);
    expect(events).toHaveLength(1);
    expect(events[0].metadata).toMatchObject({ connection_id: connectionId, client_id: client.client_id });

    // Slack bot tokens never expire: no raw issuance even with the flag.
    const browser = new Browser();
    const requestUri = await par(app, client, { providers: ['slack'], scopes: { slack: ['chat:write'] }, required_scopes: {} });
    const providerUrl = await toProvider(app, browser, requestUri, { provider: 'slack', scopes: ['chat:write'] });
    expect(providerUrl.origin).toBe('https://slack.com');
    const confirmPage = await callback(app, browser, providerUrl, 'slack');
    expect(confirmPage.text).toContain('Acme Workspace');
    const result = resultOf(await confirm(app, browser, confirmPage.text, ['chat:write']));
    if (result.outcome !== 'success') throw new Error('slack flow failed');
    expect((await activate(app, client, result.connection_id, result.code)).status).toBe(200);
    const conn = await server.link!.context.store.getConnection(result.connection_id);
    expect(conn!.provider_account_id).toBe('T0TEAM/U0BOT');
    const slackRaw = await delegate(app, { connection_id: result.connection_id, token_format: 'raw' });
    expect(slackRaw.status).toBe(400);
    expect(slackRaw.body.access_token).toBeUndefined();
    const slackHandle = await delegate(app, { connection_id: result.connection_id });
    expect(slackHandle.status).toBe(200);
  });

  it('pins Salesforce Link handles to the connection instance host', async () => {
    const { app, server } = await harness();
    const client = await registerClient(app);
    const browser = new Browser();
    const requestUri = await par(app, client, { providers: ['salesforce'], scopes: { salesforce: ['api'] }, required_scopes: {} });
    const providerUrl = await toProvider(app, browser, requestUri, { provider: 'salesforce', scopes: ['api'] });
    expect(providerUrl.searchParams.get('scope')!.split(' ').sort()).toEqual(['api', 'refresh_token']);
    const confirmPage = await callback(app, browser, providerUrl, 'salesforce');
    const result = resultOf(await confirm(app, browser, confirmPage.text, ['api']));
    if (result.outcome !== 'success') throw new Error('salesforce flow failed');
    await activate(app, client, result.connection_id, result.code);
    const conn = await server.link!.context.store.getConnection(result.connection_id);
    expect(conn).toMatchObject({
      instance_url: 'https://acme.my.salesforce.com',
      audience: 'https://acme.my.salesforce.com',
      provider_account_id: '00D000000000001AAA/005000000000001AAA',
    });
    const handle = await delegate(app, { connection_id: result.connection_id });
    const other = await use(app, { delegation_id: handle.body.delegation_id, url: 'https://evil.my.salesforce.com/services/data/v60.0/sobjects', method: 'GET' });
    expect(other.status).toBe(400);
    const own = await use(app, { delegation_id: handle.body.delegation_id, url: 'https://acme.my.salesforce.com/services/data/v60.0/sobjects', method: 'GET' });
    expect(own.status).toBe(200);
    expect(h!.fake.upstream.at(-1)!.authorization).toBe('Bearer 00Dsf-access');
  });

  it('refuses a Salesforce instance_url outside the host grammar', async () => {
    const { app } = await harness();
    h!.fake.salesforceInstance = 'https://evil.example.com';
    const client = await registerClient(app);
    const browser = new Browser();
    const requestUri = await par(app, client, { providers: ['salesforce'], scopes: { salesforce: ['api'] }, required_scopes: {} });
    const providerUrl = await toProvider(app, browser, requestUri, { provider: 'salesforce', scopes: ['api'] });
    const res = await callback(app, browser, providerUrl, 'salesforce');
    expect(resultOf(res)).toMatchObject({ outcome: 'error', error: 'provider_error' });
  });

  it('sub-delegation of a Link connection is refused', async () => {
    const { app } = await harness();
    const res = await request(app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${AGENT_TOKEN}`)
      .send({ parent_receipt: 'a.b.c', agent_did: 'did:key:z6Mk', service: 'google', connection_id: 'conn_abc' });
    expect(res.status).toBe(400);
  });
});

describe('Agent identity for Link checks (decision 6)', () => {
  it('uses the verified principal of a custom verifier; another agent cannot use the handle', async () => {
    const { app } = await harness({
      agentToken: undefined,
      agentRequestVerifier: (req) => {
        const id = req.get('x-test-agent');
        return id ? { ok: true, principal: { type: 'test', principalId: id } } : { ok: false };
      },
    });
    const client = await registerClient(app);
    const connectionId = await connectAndActivate(app, client, { parOverrides: { agent_id: 'agent-a' } });
    const asA = await request(app).post('/api/v1/delegate').set('x-test-agent', 'agent-a').send({ connection_id: connectionId });
    expect(asA.status).toBe(200);
    const asB = await request(app).post('/api/v1/delegate').set('x-test-agent', 'agent-b').send({ connection_id: connectionId, agent_id: 'agent-a' });
    expect(asB.status).toBe(403);
    expect(asB.body.error).toBe('permission_required');
    const useAsB = await request(app).post('/api/v1/use').set('x-test-agent', 'agent-b')
      .send({ delegation_id: asA.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    expect(useAsB.status).toBe(403);
    expect(useAsB.body.error).toBe('permission_required');
    const useAsA = await request(app).post('/api/v1/use').set('x-test-agent', 'agent-a')
      .send({ delegation_id: asA.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    expect(useAsA.status).toBe(200);
  });
});

describe('TOFU identity for Link checks', () => {
  it('maps a verified TOFU proof (bound to the connection_id) to tofu:<agentId>', async () => {
    const { app, server } = await harness();
    const client = await registerClient(app);
    const connectionId = await connectAndActivate(app, client, { parOverrides: { agent_id: null } });
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const raw = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }).subarray(-32));
    const registration = await server.tofu.registerAgent({ publicKey: raw, initialScopes: [] });
    const tofuId = `tofu:${registration.agentId}`;
    const proof = (userId: string) => {
      const payload = Buffer.from(JSON.stringify({ service: 'google', userId, appClientId: 'local', scopes: ['calendar.readonly'], timestamp: new Date().toISOString() }));
      return { tofu_fingerprint: registration.fingerprint, tofu_payload: payload.toString('base64'), tofu_signature: sign(null, payload, privateKey).toString('base64') };
    };
    const body = { connection_id: connectionId, service: 'google', scopes: ['calendar.readonly'] };

    // No Permission yet for the TOFU principal.
    const denied = await delegate(app, { ...body, ...proof(connectionId) });
    expect(denied.status).toBe(403);
    expect(denied.body.error).toBe('permission_required');
    await request(app).post(`/link/v1/connections/${connectionId}/permissions`).set('Authorization', client.auth)
      .send({ agent_id: tofuId, scopes: ['calendar.readonly'] });
    const ok = await delegate(app, { ...body, ...proof(connectionId) });
    expect(ok.status).toBe(200);
    // A proof signed for another userId does not establish identity.
    const wrongBinding = await delegate(app, { ...body, ...proof('default') });
    expect(wrongBinding.status).toBe(403);
    expect(wrongBinding.body.error).toBe('permission_required');
    // The static bearer alone is 'server-agent', not the TOFU principal.
    const asBearer = await use(app, { delegation_id: ok.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    expect(asBearer.status).toBe(403);
    expect(asBearer.body.error).toBe('permission_required');
  });
});

describe('Guard integration for Link calls', () => {
  it('passes the Link context from verified state and includes code in guard denials', async () => {
    const seen: GuardContext[] = [];
    let hooksRef: Harness | null = null;
    const recorder: CredPolicy = {
      name: 'recorder',
      async evaluate(ctx) {
        seen.push(ctx);
        return { decision: 'SKIP', policy: 'recorder' };
      },
    };
    const guard = new CredGuard({
      policies: [
        clientGrantPolicy({ hooks: { checkLinkAccess: (input) => hooksRef!.server.link!.context.hooks.checkLinkAccess(input) } }),
        recorder,
      ],
    });
    const { app, server } = await harness({ guard });
    hooksRef = h;
    const client = await registerClient(app);
    const connectionId = await connectAndActivate(app, client);
    const ok = await delegate(app, { connection_id: connectionId, scopes: ['calendar.readonly'] });
    expect(ok.status).toBe(200);
    expect(seen.at(-1)!.link).toEqual({ connectionId, agentId: 'server-agent', operation: 'delegate' });
    const used = await use(app, { delegation_id: ok.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    expect(used.status).toBe(200);
    expect(seen.at(-1)!.link).toMatchObject({ connectionId, agentId: 'server-agent', operation: 'use' });

    // Revoked between delegate and use: the server's own check refuses first.
    await server.link!.context.store.setConnectionStatus({ connection_id: connectionId, status: 'revoked', now: new Date().toISOString() });
    const denied = await use(app, { delegation_id: ok.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    expect(denied.status).toBe(403);
    expect(denied.body.error).toBe('grant_revoked');
  });

  it('includes the policy code in guard deny responses', async () => {
    const denyWithCode: CredPolicy = {
      name: 'deny-with-code',
      async evaluate() {
        return { decision: 'DENY', policy: 'deny-with-code', reason: 'nope', code: 'permission_required' };
      },
    };
    const { app } = await harness({ guard: new CredGuard({ policies: [denyWithCode] }) });
    const res = await delegate(app, { service: 'google', user_id: 'default' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('permission_required');
  });
});

describe('Token loading (decision 7)', () => {
  async function expireTokens(hx: Harness, connectionId: string): Promise<void> {
    const secrets = hx.server.link!.context.secrets;
    const tokens = await secrets.get(connectionId as any);
    await secrets.put(connectionId as any, { ...tokens!, expires_at: new Date(Date.now() - 1000).toISOString() });
  }

  it('refreshes once under concurrency and writes the rotated token back', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const connectionId = await connectAndActivate(hx.app, client);
    const handles = await Promise.all(Array.from({ length: 4 }, () => delegate(hx.app, { connection_id: connectionId, scopes: ['calendar.readonly'] })));
    await expireTokens(hx, connectionId);
    hx.fake.refreshDelayMs = 40;
    const results = await Promise.all(handles.map((d) => use(hx.app, { delegation_id: d.body.delegation_id, url: CALENDAR_URL, method: 'GET' })));
    for (const r of results) expect(r.status).toBe(200);
    expect(hx.fake.refreshCalls).toBe(1);
    const auths = new Set(hx.fake.upstream.map((u) => u.authorization));
    expect(auths.size).toBe(1);
    expect([...auths][0]).toMatch(/^Bearer ya29\.refreshed-/);
    const stored = await hx.server.link!.context.secrets.get(connectionId as any);
    expect(stored!.access_token).toMatch(/^ya29\.refreshed-/);
    expect(stored!.refresh_token).toBe('rt-1');
  });

  it('invalid_grant moves the connection to needs_reauth with a typed reason and a reauth_url', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const connectionId = await connectAndActivate(hx.app, client);
    await expireTokens(hx, connectionId);
    hx.fake.refreshMode = 'invalid_grant';
    const res = await delegate(hx.app, { connection_id: connectionId });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('grant_revoked');
    expect(res.body.reauth_url).toContain('/link/v1/authorize?request_uri=');
    const conn = await hx.server.link!.context.store.getConnection(connectionId);
    expect(conn).toMatchObject({ status: 'needs_reauth', status_reason: 'grant_revoked' });
    const again = await delegate(hx.app, { connection_id: connectionId });
    expect(again.body.error).toBe('grant_revoked');
    expect(hx.fake.refreshCalls).toBe(1);

    // The reauth URL drives a reauth flow on the connection's own subject.
    const reauthUrl = new URL(res.body.reauth_url);
    const browser = new Browser();
    const picker = await browser.get(hx.app, `${reauthUrl.pathname}${reauthUrl.search}`);
    expect(picker.status).toBe(200);
    expect(envelopeOf(picker.text)).toBeTruthy();
  });

  it('a transient refresh failure does not change the connection', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const connectionId = await connectAndActivate(hx.app, client);
    await expireTokens(hx, connectionId);
    hx.fake.refreshMode = 'error';
    const res = await delegate(hx.app, { connection_id: connectionId });
    expect(res.status).toBe(503);
    expect(res.body.error).toBe('temporarily_unavailable');
    expect((await hx.server.link!.context.store.getConnection(connectionId))!.status).toBe('active');
  });
});

describe('Expiry sweep', () => {
  it('ends expired transactions, revokes what they created and deletes staged tokens', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    // Abandoned after confirm: a pending connection with staged tokens.
    const result = await connectFlow(hx.app, client);
    // Abandoned after the exchange, on the confirm screen.
    const browser = new Browser();
    const providerUrl = await toProvider(hx.app, browser, await par(hx.app, client, { subject: 'user-c' }));
    const confirmPage = await callback(hx.app, browser, providerUrl);
    expect(confirmPage.status).toBe(200);

    const ended = await hx.server.link!.sweep(Date.now() + 11 * 60 * 1000);
    expect(ended).toBe(2);
    expect((await hx.server.link!.context.store.getConnection(result.connection_id))!.status).toBe('revoked');
    expect((await hx.server.link!.context.store.getGrantForConnection(result.connection_id))!.status).toBe('expired');
    expect(hx.fake.revocations).toHaveLength(2);
    expect((await activate(hx.app, client, result.connection_id, result.code)).status).toBe(401);
    expect(await hx.server.link!.sweep(Date.now() + 11 * 60 * 1000)).toBe(0);
  });
});

describe('Opaque failures (spec 5 Enumeration)', () => {
  it('are byte-identical across unknown client, bad secret, foreign and unknown connection', async () => {
    const { app } = await harness();
    const client = await registerClient(app);
    const other = await registerClient(app);
    const connectionId = await connectAndActivate(app, client);
    const responses = [
      await request(app).get(`/link/v1/connections/${connectionId}`).set('Authorization', basic('no-such-client', 'whatever')),
      await request(app).get(`/link/v1/connections/${connectionId}`).set('Authorization', basic(client.client_id, 'cred_lcs_wrong')),
      await request(app).get(`/link/v1/connections/${connectionId}`).set('Authorization', other.auth),
      await request(app).get('/link/v1/connections/conn_000000unknown').set('Authorization', client.auth),
      await request(app).get(`/link/v1/connections/${connectionId}`),
      await request(app).delete(`/link/v1/connections/${connectionId}`).set('Authorization', other.auth),
      await request(app).post('/link/v1/par').set('Authorization', basic(client.client_id, 'nope')).send({}),
      await request(app).post(`/link/v1/connections/${connectionId}/refresh`).set('Authorization', other.auth),
    ];
    const ids = new Set<string>();
    for (const res of responses) {
      expect(res.status).toBe(401);
      expect(res.text).toBe(JSON.stringify(LINK_OPAQUE_FAILURE_BODY));
      expect(res.headers['cred-request-id']).toMatch(/^req_/);
      ids.add(res.headers['cred-request-id']);
    }
    expect(ids.size).toBe(responses.length);
    // The foreign client's DELETE changed nothing.
    const still = await request(app).get(`/link/v1/connections/${connectionId}`).set('Authorization', client.auth);
    expect(still.body.status).toBe('active');
  });
});

describe('Reserved Link user ids on legacy entry points (decision 4)', () => {
  it('rejects link: and link-staged: user ids everywhere a user id reaches the vault', async () => {
    const { app, server } = await harness();
    const client = await registerClient(app);
    const connectionId = await connectAndActivate(app, client);
    const reserved = `link:${connectionId}`;
    const q = encodeURIComponent(reserved);
    const admin = (r: request.Test) => r.set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    const agent = (r: request.Test) => r.set('Authorization', `Bearer ${AGENT_TOKEN}`);

    const checks: Array<[string, request.Response]> = [
      ['GET /providers', await admin(request(app).get(`/providers?user_id=${q}`))],
      ['GET /connect', await admin(request(app).get(`/connect?user_id=${q}`))],
      ['GET /connect/:provider', await admin(request(app).get(`/connect/google?user_id=${q}`))],
      ['DELETE /connect/:provider', await admin(request(app).delete(`/connect/google?user_id=${q}`))],
      ['GET /api/token/:provider', await agent(request(app).get(`/api/token/google?user_id=${q}`))],
      ['DELETE /api/token/:provider', await agent(request(app).delete(`/api/token/google?user_id=${q}`))],
      ['GET /api/v1/connections', await agent(request(app).get(`/api/v1/connections?user_id=${q}`))],
      ['DELETE /api/v1/connections/:provider', await agent(request(app).delete(`/api/v1/connections/google?user_id=${q}`))],
      ['POST /api/v1/delegate', await agent(request(app).post('/api/v1/delegate').send({ service: 'google', user_id: reserved }))],
      ['POST /api/v1/delegate (body user_id over query)', await agent(request(app).post(`/api/v1/delegate?user_id=${q}`).send({ service: 'google', user_id: ` ${reserved} ` }))],
      ['POST /api/v1/subdelegate', await agent(request(app).post('/api/v1/subdelegate').send({ parent_receipt: 'a.b.c', agent_did: 'did:key:z', service: 'google', user_id: reserved }))],
      ['GET /api/v1/audit', await agent(request(app).get(`/api/v1/audit?user_id=${q}`))],
      ['GET /api/v1/audit/stream', await agent(request(app).get(`/api/v1/audit/stream?user_id=${q}`))],
      ['GET /api/token/:provider staged', await agent(request(app).get(`/api/token/google?user_id=${encodeURIComponent('link-staged:ltx_abc')}`))],
    ];
    for (const [name, res] of checks) {
      expect({ name, status: res.status }).toEqual({ name, status: 400 });
      expect(res.text).not.toContain('ya29');
    }
    // The Link connection's tokens are untouched.
    expect((await server.link!.context.secrets.get(connectionId as any))!.access_token).toBe('ya29.access-1');
  });

  it('also rejects them with Link disabled (tokens may outlive the configuration)', async () => {
    const { app } = await harness({ linkEnabled: false });
    const res = await request(app).get('/api/token/google?user_id=link%3Aconn_abc').set('Authorization', `Bearer ${AGENT_TOKEN}`);
    expect(res.status).toBe(400);
    const start = await request(app).get('/connect/google?user_id=link-staged%3Altx_abc').set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    expect(start.status).toBe(400);
  });
});

describe('Configuration and pre-existing gap fixes', () => {
  it('fails fast when LINK_ENABLED is set with the file vault backend', () => {
    expect(() => createServer({
      port: 0,
      host: '127.0.0.1',
      vaultPassphrase: 'x',
      vaultStorage: 'file',
      vaultPath: '/tmp/never-created-vault.json',
      tofuStorage: 'file',
      tofuPath: '/tmp/never-created-tofu.json',
      adminToken: ADMIN_TOKEN,
      agentToken: AGENT_TOKEN,
      providers: [],
      redirectBaseUri: 'http://localhost:3456',
      linkEnabled: true,
    })).toThrow(/LINK_ENABLED requires VAULT_STORAGE=sqlite/);
  });

  it('mounts no Link routes when Link is off', async () => {
    const { app, server } = await harness({ linkEnabled: false });
    expect(server.link).toBeNull();
    const res = await request(app).post('/link/v1/par').send({});
    expect(res.status).toBe(404);
  });

  it('brokers Linear and HubSpot API calls (SERVICE_ALLOWLIST)', async () => {
    const { app, server } = await harness({ linkEnabled: false });
    await server.vault.store({ provider: 'linear', userId: 'default', accessToken: 'lin_tok', scopes: ['read'] });
    await server.vault.store({ provider: 'hubspot', userId: 'default', accessToken: 'hub_tok', scopes: ['crm.objects.contacts.read'] });
    const lin = await delegate(app, { service: 'linear', user_id: 'default', token_format: 'handle' });
    expect(lin.status).toBe(200);
    const linUse = await use(app, { delegation_id: lin.body.delegation_id, url: 'https://api.linear.app/graphql', method: 'POST', body: { query: '{ viewer { id } }' } });
    expect(linUse.status).toBe(200);
    expect(h!.fake.upstream.at(-1)).toEqual({ url: 'https://api.linear.app/graphql', authorization: 'Bearer lin_tok' });
    const hub = await delegate(app, { service: 'hubspot', user_id: 'default', token_format: 'handle' });
    const hubUse = await use(app, { delegation_id: hub.body.delegation_id, url: 'https://api.hubapi.com/crm/v3/objects/contacts', method: 'GET' });
    expect(hubUse.status).toBe(200);
    expect(h!.fake.upstream.at(-1)!.url).toBe('https://api.hubapi.com/crm/v3/objects/contacts');
    const offHost = await use(app, { delegation_id: hub.body.delegation_id, url: 'https://evil.example.com/crm/v3/objects/contacts', method: 'GET' });
    expect(offHost.status).toBe(400);
  });
});

describe('Hosted flow and request_uri via authorize with narrowing', () => {
  it('narrows providers and scopes from the widget, never widens', async () => {
    const { app } = await harness();
    const client = await registerClient(app);
    const requestUri = await par(app, client, { providers: ['google', 'slack'], scopes: { google: ['calendar.readonly', 'gmail.send'], slack: ['chat:write'] } });
    const browser = new Browser();
    const q = new URLSearchParams({ request_uri: requestUri, mode: 'redirect', providers: 'google,github', scopes: JSON.stringify({ google: ['gmail.send', 'drive'] }) });
    const picker = await browser.get(app, `/link/v1/authorize?${q.toString()}`);
    expect(picker.status).toBe(200);
    expect(picker.text).toContain('Continue with Google');
    expect(picker.text).not.toContain('Continue with Slack');
    expect(picker.text).not.toContain('Continue with GitHub');
    expect(picker.text).toContain('value="gmail.send"');
    expect(picker.text).not.toContain('value="drive"');
    // The required scope stays (locked).
    expect(picker.text).toContain('value="calendar.readonly"');
    const res = await browser.post(app, '/link/v1/picker', [['e', envelopeOf(picker.text)], ['action', 'continue'], ['provider', 'slack']]);
    expect(resultOf(res)).toMatchObject({ outcome: 'error', error: 'invalid_scope' });
  });

  it('an unparseable authorize query renders the local error page', async () => {
    const { app } = await harness();
    const res = await new Browser().get(app, authorizePath('urn:cred:link:short'));
    expect(res.status).toBe(400);
  });
});

/**
 * Cred Link polish: the narrowing endpoint (POST /link/v1/connections/:id/narrow)
 * and the reconnect diff on the confirmation screen.
 */

import { afterEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { LINK_OPAQUE_FAILURE_BODY } from '@credninja/protocol';
import {
  Browser,
  CALENDAR_URL,
  activate,
  callback,
  confirm,
  connectAndActivate,
  delegate,
  envelopeOf,
  makeHarness,
  par,
  registerClient,
  resultOf,
  toProvider,
  use,
} from './link-harness.js';
import type { Harness, RegisteredClient } from './link-harness.js';

let h: Harness | null = null;

afterEach(() => {
  h?.close();
  h = null;
});

async function harness(): Promise<Harness> {
  h = await makeHarness();
  return h;
}

const GMAIL_SEND_URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send';
const OPAQUE = JSON.stringify(LINK_OPAQUE_FAILURE_BODY);

function narrow(hx: Harness, client: RegisteredClient, connectionId: string, body: Record<string, unknown>) {
  return request(hx.app).post(`/link/v1/connections/${connectionId}/narrow`).set('Authorization', client.auth).send(body);
}

async function setup() {
  const hx = await harness();
  const client = await registerClient(hx.app);
  const conn = await connectAndActivate(hx.app, client);
  const perm = await request(hx.app).post(`/link/v1/connections/${conn}/permissions`).set('Authorization', client.auth)
    .send({ agent_id: 'agent-2', scopes: ['calendar.readonly', 'gmail.send'] });
  expect(perm.status).toBe(200);
  return { hx, client, conn };
}

function grantAudits(hx: Harness) {
  return hx.server.vault.queryAuditEvents({ limit: 200 }).filter((e) => e.resource.type === 'grant');
}

describe('POST /link/v1/connections/:id/narrow', () => {
  it('answers the byte-identical opaque failure for another subject, another client or an unknown id', async () => {
    const { hx, client, conn } = await setup();
    const other = await registerClient(hx.app);
    const responses = [
      await narrow(hx, client, conn, { subject: 'user-b', scopes: ['calendar.readonly'] }),
      await narrow(hx, other, conn, { subject: 'user-a', scopes: ['calendar.readonly'] }),
      await narrow(hx, client, 'conn_0000000000unknown', { subject: 'user-a', scopes: ['calendar.readonly'] }),
      await narrow(hx, client, conn, { scopes: ['calendar.readonly'] }),
      await request(hx.app).get(`/link/v1/connections/${conn}`).set('Authorization', other.auth),
    ];
    for (const res of responses) {
      expect(res.status).toBe(401);
      expect(res.text).toBe(OPAQUE);
      expect(res.headers['cred-request-id']).toMatch(/^req_/);
    }
    expect((await hx.server.link!.context.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('validates scopes and changes nothing on a rejected request', async () => {
    const { hx, client, conn } = await setup();
    const store = hx.server.link!.context.store;
    const before = await store.getGrantForConnection(conn);
    const auditBefore = grantAudits(hx).length;
    for (const scopes of [undefined, [], [''], ['  '], 'calendar.readonly', [42], ['calendar.readonly', 'drive'], ['drive']]) {
      const res = await narrow(hx, client, conn, { subject: 'user-a', scopes });
      expect({ scopes, status: res.status, error: res.body.error }).toEqual({ scopes, status: 400, error: 'invalid_scope' });
    }
    expect(await store.getGrantForConnection(conn)).toEqual(before);
    expect(grantAudits(hx).length).toBe(auditBefore);
  });

  it('keeps every always_required scope the grant holds', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const browser = new Browser();
    const pu = await toProvider(hx.app, browser, await par(hx.app, client, { providers: ['linear'], scopes: { linear: ['issues:create'] }, required_scopes: {} }), { provider: 'linear', scopes: ['issues:create'] });
    const result = resultOf(await confirm(hx.app, browser, (await callback(hx.app, browser, pu, 'linear')).text, ['issues:create', 'read']));
    if (result.outcome !== 'success') throw new Error('linear flow failed');
    expect((await activate(hx.app, client, result.connection_id, result.code)).status).toBe(200);
    const dropRead = await narrow(hx, client, result.connection_id, { subject: 'user-a', scopes: ['issues:create'] });
    expect(dropRead.status).toBe(400);
    expect(dropRead.body.error).toBe('invalid_scope');
    const keepRead = await narrow(hx, client, result.connection_id, { subject: 'user-a', scopes: ['read'] });
    expect(keepRead.status).toBe(200);
    expect(keepRead.body.removed_scopes).toEqual(['issues:create']);
  });

  it('narrows the grant, bumps its version by one, intersects every permission and audits pending and success', async () => {
    const { hx, client, conn } = await setup();
    const ctx = hx.server.link!.context;
    const before = await ctx.store.getGrantForConnection(conn);
    const connBefore = await ctx.store.getConnection(conn);
    const tokensBefore = await ctx.secrets.get(conn as never);
    const fetchesBefore = h!.fake.spy!.mock.calls.length;

    const res = await narrow(hx, client, conn, { subject: 'user-a', scopes: ['https://www.googleapis.com/auth/calendar.readonly'] });
    expect(res.status).toBe(200);
    expect(res.body.changed).toBe(true);
    expect(res.body.removed_scopes).toEqual(['gmail.send']);
    expect(res.body.connection.connection_id).toBe(conn);
    expect(res.body.connection.grant.scopes).toEqual(['calendar.readonly']);
    expect(res.body.connection.grant.version).toBe(before!.version + 1);

    expect((await ctx.permissions.get('server-agent', conn))!.allowedScopes).toEqual(['calendar.readonly']);
    expect((await ctx.permissions.get('agent-2', conn))!.allowedScopes).toEqual(['calendar.readonly']);

    // No provider round trip, no token change, provider scopes untouched.
    expect(h!.fake.spy!.mock.calls.length).toBe(fetchesBefore);
    expect(await ctx.secrets.get(conn as never)).toEqual(tokensBefore);
    expect((await ctx.store.getConnection(conn))!.provider_scopes).toEqual(connBefore!.provider_scopes);

    const narrowEvents = grantAudits(hx).filter((e) => (e.metadata as { reason?: string }).reason === 'narrow');
    expect(narrowEvents.map((e) => e.outcome).sort()).toEqual(['pending', 'success']);
    const success = narrowEvents.find((e) => e.outcome === 'success')!;
    expect(success.metadata).toMatchObject({ before_scopes: ['calendar.readonly', 'gmail.send'], after_scopes: ['calendar.readonly'], reason: 'narrow' });
    const pending = narrowEvents.find((e) => e.outcome === 'pending')!;
    expect(pending.metadata).toMatchObject({ before_scopes: ['calendar.readonly', 'gmail.send'], after_scopes: ['calendar.readonly'] });
  });

  it('is idempotent: equal scopes answer changed false without a write, and repair a failed intersect', async () => {
    const { hx, client, conn } = await setup();
    const ctx = hx.server.link!.context;
    expect((await narrow(hx, client, conn, { subject: 'user-a', scopes: ['calendar.readonly'] })).status).toBe(200);
    const grant = await ctx.store.getGrantForConnection(conn);
    const auditCount = grantAudits(hx).length;

    // Simulate a narrow whose permission intersect step did not run.
    const p = await ctx.permissions.get('agent-2', conn);
    await ctx.permissions.update(p!.id, { allowedScopes: ['calendar.readonly', 'gmail.send'] });

    const again = await narrow(hx, client, conn, { subject: 'user-a', scopes: ['calendar.readonly'] });
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ changed: false, removed_scopes: [] });
    expect(await ctx.store.getGrantForConnection(conn)).toEqual(grant);
    expect(grantAudits(hx).length).toBe(auditCount);
    expect((await ctx.permissions.get('agent-2', conn))!.allowedScopes).toEqual(['calendar.readonly']);
  });

  it('answers the typed code for a connection that is not active', async () => {
    const { hx, client, conn } = await setup();
    await hx.server.link!.context.store.setConnectionStatus({ connection_id: conn, status: 'needs_reauth', now: new Date().toISOString() });
    const res = await narrow(hx, client, conn, { subject: 'user-a', scopes: ['calendar.readonly'] });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('reauth_required');
    expect((await hx.server.link!.context.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('a grant that moves underneath the request gets a retryable error and nothing else changes', async () => {
    const { hx, client, conn } = await setup();
    const store = hx.server.link!.context.store;
    const original = store.narrowGrant.bind(store);
    const before = await store.getGrantForConnection(conn);
    let sawExpected: number | undefined;
    // The version the request read is stale by the time it writes, so the
    // store's compare-and-set refuses it.
    store.narrowGrant = async (input) => {
      sawExpected = input.expected_version;
      return original({ ...input, expected_version: (input.expected_version ?? 0) - 1 });
    };
    let res;
    try {
      res = await narrow(hx, client, conn, { subject: 'user-a', scopes: ['calendar.readonly'] });
    } finally {
      store.narrowGrant = original;
    }
    expect(res.status).toBe(503);
    expect(res.body.error).toBe('temporarily_unavailable');
    expect(sawExpected).toBe(before!.version);
    expect(await store.getGrantForConnection(conn)).toEqual(before);
    expect((await hx.server.link!.context.permissions.get('agent-2', conn))!.allowedScopes).toEqual(['calendar.readonly', 'gmail.send']);
    const success = grantAudits(hx).filter((e) => (e.metadata as { reason?: string }).reason === 'narrow' && e.outcome === 'success');
    expect(success).toEqual([]);
  });

  it('outstanding handles are refused for a removed scope and keep working for scopes that remain', async () => {
    const { hx, client, conn } = await setup();
    const calendarOnly = (await delegate(hx.app, { connection_id: conn, scopes: ['calendar.readonly'] })).body.delegation_id;
    const gmailOnly = (await delegate(hx.app, { connection_id: conn, scopes: ['gmail.send'] })).body.delegation_id;
    const both = (await delegate(hx.app, { connection_id: conn })).body.delegation_id;
    expect((await narrow(hx, client, conn, { subject: 'user-a', scopes: ['calendar.readonly'] })).status).toBe(200);

    expect((await use(hx.app, { delegation_id: calendarOnly, url: CALENDAR_URL, method: 'GET' })).status).toBe(200);
    const g = await use(hx.app, { delegation_id: gmailOnly, url: GMAIL_SEND_URL, method: 'POST', body: {} });
    expect(g.status).toBe(403);
    expect(g.body.error).toBe('insufficient_scope');
    expect((await use(hx.app, { delegation_id: both, url: CALENDAR_URL, method: 'GET' })).status).toBe(200);
    expect((await use(hx.app, { delegation_id: both, url: GMAIL_SEND_URL, method: 'POST', body: {} })).status).toBe(400);
    expect(h!.fake.upstream.map((u) => u.url)).not.toContain(GMAIL_SEND_URL);
  });
});

// ── Reconnect diff ───────────────────────────────────────────────────────────

function listOf(html: string, id: string): string[] {
  const m = new RegExp(`<ul id="${id}">([\\s\\S]*?)</ul>`).exec(html);
  if (!m) throw new Error(`no list ${id}`);
  return Array.from(m[1].matchAll(/data-scope="([^"]+)"/g)).map((x) => x[1]);
}

async function reconnectConfirmPage(hx: Harness, client: RegisteredClient, input: { parScopes: string[]; pick: string[]; subject?: string; browser?: Browser }) {
  const browser = input.browser ?? new Browser();
  const requestUri = await par(hx.app, client, { subject: input.subject ?? 'user-a', scopes: { google: input.parScopes }, required_scopes: {} });
  const pu = await toProvider(hx.app, browser, requestUri, { scopes: input.pick });
  const page = await callback(hx.app, browser, pu);
  expect(page.status).toBe(200);
  return { page, browser, providerUrl: pu };
}

describe('reconnect diff on the confirmation screen', () => {
  it('a narrowing reconnect lists kept and removed, including permissions not offered at all', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    await connectAndActivate(hx.app, client);
    // Offered: both (selected only calendar). gmail.send is offered but unchecked.
    const { page } = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly', 'gmail.send'], pick: ['calendar.readonly'] });
    expect(page.text).toContain('id="cred-link-reconnect"');
    expect(page.text).toContain('already connected');
    expect(page.text).toContain('Anything left unchecked or not listed below will be removed.');
    expect(listOf(page.text, 'cred-reconnect-today')).toEqual(['calendar.readonly', 'gmail.send']);
    expect(listOf(page.text, 'cred-reconnect-kept')).toEqual(['calendar.readonly']);
    expect(listOf(page.text, 'cred-reconnect-added')).toEqual([]);
    expect(listOf(page.text, 'cred-reconnect-removed')).toEqual(['gmail.send']);
    expect(page.text).toContain('Send email as you');

    // Not offered at all (not requested this time): removed unconditionally.
    const notOffered = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly'], pick: ['calendar.readonly'] });
    expect(listOf(notOffered.page.text, 'cred-reconnect-removed')).toEqual(['gmail.send']);
    expect(notOffered.page.text).not.toContain('name="scope" value="gmail.send"');
  });

  it('a widening reconnect lists added; an identical one changes nothing', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    await connectAndActivate(hx.app, client, { scopes: ['calendar.readonly'], confirmScopes: ['calendar.readonly'] });
    const widen = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly', 'gmail.send'], pick: ['calendar.readonly', 'gmail.send'] });
    expect(listOf(widen.page.text, 'cred-reconnect-kept')).toEqual(['calendar.readonly']);
    expect(listOf(widen.page.text, 'cred-reconnect-added')).toEqual(['gmail.send']);
    expect(listOf(widen.page.text, 'cred-reconnect-removed')).toEqual([]);
    const same = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly'], pick: ['calendar.readonly'] });
    expect(listOf(same.page.text, 'cred-reconnect-kept')).toEqual(['calendar.readonly']);
    expect(listOf(same.page.text, 'cred-reconnect-added')).toEqual([]);
    expect(listOf(same.page.text, 'cred-reconnect-removed')).toEqual([]);
  });

  it('is absent for a first connection, for update and for reauth', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const first = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly'], pick: ['calendar.readonly'] });
    expect(first.page.text).not.toContain('cred-link-reconnect');
    const result = resultOf(await confirm(hx.app, first.browser, first.page.text, ['calendar.readonly']));
    if (result.outcome !== 'success') throw new Error('flow failed');
    await activate(hx.app, client, result.connection_id, result.code);

    const update = await par(hx.app, client, { intent: 'update', connection_id: result.connection_id, providers: undefined, scopes: { google: ['gmail.send'] }, required_scopes: {} });
    const b1 = new Browser();
    const up = await callback(hx.app, b1, await toProvider(hx.app, b1, update, { scopes: ['calendar.readonly', 'gmail.send'] }));
    expect(up.text).not.toContain('cred-link-reconnect');

    const reauth = await request(hx.app).post(`/link/v1/connections/${result.connection_id}/reauth`).set('Authorization', client.auth).send({ subject: 'user-a' });
    const b2 = new Browser();
    const re = await callback(hx.app, b2, await toProvider(hx.app, b2, reauth.body.request_uri, { scopes: ['calendar.readonly'] }));
    expect(re.text).not.toContain('cred-link-reconnect');
  });

  it('a re-rendered confirm page (re-entry) shows it too', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    await connectAndActivate(hx.app, client);
    const { browser, providerUrl } = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly', 'gmail.send'], pick: ['calendar.readonly'] });
    const again = await callback(hx.app, browser, providerUrl);
    expect(again.status).toBe(200);
    expect(again.text).toContain('id="cred-link-reconnect"');
    expect(listOf(again.text, 'cred-reconnect-removed')).toEqual(['gmail.send']);
    expect(envelopeOf(again.text)).toBeTruthy();
  });

  it("never shows another subject's or another client's connection on the same account", async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const other = await registerClient(hx.app);
    await connectAndActivate(hx.app, client, { parOverrides: { subject: 'user-b' } });
    await connectAndActivate(hx.app, other);
    const { page } = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly'], pick: ['calendar.readonly'] });
    expect(page.text).not.toContain('cred-link-reconnect');
    expect(page.text).not.toContain('already connected');
  });

  it('activation replaces the grant with exactly the confirmed scopes', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const { page, browser } = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly', 'gmail.send'], pick: ['calendar.readonly'] });
    const result = resultOf(await confirm(hx.app, browser, page.text, ['calendar.readonly']));
    if (result.outcome !== 'success') throw new Error('flow failed');
    expect(result.connection_id).toBe(conn);
    expect((await activate(hx.app, client, conn, result.code)).status).toBe(200);
    expect((await hx.server.link!.context.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly']);
  });

  it('a page rendered before another flow went live for the account is re-rendered with the current diff, not committed', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    // Flow A reaches its confirm page while the account is not connected.
    const a = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly', 'gmail.send'], pick: ['calendar.readonly', 'gmail.send'] });
    expect(a.page.text).not.toContain('cred-link-reconnect');
    expect(a.page.text).toContain('name="reconnect_basis" value="none"');
    // Flow B connects and activates the same account first.
    const conn = await connectAndActivate(hx.app, client);
    const grantBefore = await hx.server.link!.context.store.getGrantForConnection(conn);

    // Submitting A's stale page shows the diff it did not show, and commits nothing.
    const again = await confirm(hx.app, a.browser, a.page.text, ['calendar.readonly']);
    expect(again.status).toBe(200);
    expect(again.text).toContain('id="cred-link-reconnect"');
    expect(again.text).toContain('changed while this page was open');
    expect(again.text).toContain(`name="reconnect_basis" value="${grantBefore!.id}:${grantBefore!.scopes.join(' ')}"`);
    expect(() => resultOf(again)).toThrow();
    expect(await hx.server.link!.context.store.getGrantForConnection(conn)).toEqual(grantBefore);

    // Confirming the re-rendered page goes through and replaces the grant.
    const result = resultOf(await confirm(hx.app, a.browser, again.text, ['calendar.readonly']));
    if (result.outcome !== 'success') throw new Error('flow failed');
    expect(result.connection_id).toBe(conn);
    expect((await activate(hx.app, client, conn, result.code)).status).toBe(200);
    expect((await hx.server.link!.context.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly']);
  });

  it('a diff computed against an older grant version is re-rendered after the grant changed', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const { page, browser } = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly', 'gmail.send'], pick: ['calendar.readonly', 'gmail.send'] });
    expect(listOf(page.text, 'cred-reconnect-today')).toEqual(['calendar.readonly', 'gmail.send']);
    expect((await narrow(hx, client, conn, { subject: 'user-a', scopes: ['calendar.readonly'] })).status).toBe(200);
    const again = await confirm(hx.app, browser, page.text, ['calendar.readonly', 'gmail.send']);
    expect(again.status).toBe(200);
    expect(listOf(again.text, 'cred-reconnect-today')).toEqual(['calendar.readonly']);
    expect(listOf(again.text, 'cred-reconnect-added')).toEqual(['gmail.send']);
  });

  it('escapes everything and keeps the summary in a nonce script config', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    await connectAndActivate(hx.app, client);
    const { page } = await reconnectConfirmPage(hx, client, { parScopes: ['calendar.readonly', 'gmail.send'], pick: ['calendar.readonly'] });
    const cfg = /<script type="application\/json" id="cred-link-config">([\s\S]*?)<\/script>/.exec(page.text)!;
    const parsed = JSON.parse(cfg[1]);
    expect(parsed.reconnect.today).toEqual(['calendar.readonly', 'gmail.send']);
    expect(parsed.reconnect.labels['gmail.send']).toBe('Send email as you');
  });
});

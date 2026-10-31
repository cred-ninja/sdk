/**
 * Regression tests for the defects two independent reviews found in the
 * Cred Link server (formerly the zz-review-* reproduction files). Each test
 * asserts the correct behavior.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import crypto, { generateKeyPairSync } from 'node:crypto';
import util from 'node:util';
import { LINK_OPAQUE_FAILURE_BODY } from '@credninja/protocol';
import { ReservedVaultUserIdError, SqliteLinkStore, VaultLinkSecretStore } from '@credninja/vault';
import { createServer } from '../server.js';
import { googleRemovalIsBrokerEnforced } from '../google-scopes.js';
import {
  ADMIN_TOKEN,
  AGENT_TOKEN,
  APP_ORIGIN,
  APP_REDIRECT,
  BASE,
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
  parBody,
  registerClient,
  resultOf,
  toProvider,
  use,
} from './link-harness.js';
import type { Harness } from './link-harness.js';
import { actorTokenFor, delegateAs, exerciseAs, newAgent } from './token-helpers.js';

let h: Harness | null = null;

afterEach(() => {
  vi.restoreAllMocks();
  h?.close();
  h = null;
});

async function harness(overrides: Parameters<typeof makeHarness>[0] = {}): Promise<Harness> {
  h = await makeHarness(overrides);
  return h;
}

const now = () => new Date().toISOString();

async function expireTokens(hx: Harness, connectionId: string): Promise<void> {
  const secrets = hx.server.link!.context.secrets;
  const tokens = await secrets.get(connectionId as never);
  await secrets.put(connectionId as never, { ...tokens!, expires_at: new Date(Date.now() - 1000).toISOString() });
}

describe('parallel connects for one account (review item 1)', () => {
  it('each connect owns its own pending connection; expiry of the abandoned flow leaves the activated one intact', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const a = await connectFlow(hx.app, client, { browser: new Browser() });
    const b = await connectFlow(hx.app, client, { browser: new Browser() });
    expect(b.connection_id).not.toBe(a.connection_id);
    expect((await activate(hx.app, client, b.connection_id, b.code)).status).toBe(200);
    const tokensB = await hx.server.link!.context.secrets.get(b.connection_id as never);
    const revocationsBefore = hx.fake.revocations.length;

    await hx.server.link!.sweep(Date.now() + 11 * 60 * 1000);

    const store = hx.server.link!.context.store;
    expect((await store.getConnection(b.connection_id))!.status).toBe('active');
    expect((await store.getConnection(a.connection_id))!.status).toBe('revoked');
    expect(await hx.server.link!.context.secrets.get(b.connection_id as never)).toEqual(tokensB);
    // A's staged token belongs to the account that backs B: never revoked at the provider.
    expect(hx.fake.revocations.slice(revocationsBefore)).toEqual([]);
    expect((await delegate(hx.app, { connection_id: b.connection_id, scopes: ['calendar.readonly'] })).status).toBe(200);
  });

  it('a late activation of the first flow is refused, deletes its staged tokens and leaves the live connection untouched', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const a = await connectFlow(hx.app, client, { browser: new Browser() });
    const b = await connectFlow(hx.app, client, { browser: new Browser() });
    expect((await activate(hx.app, client, b.connection_id, b.code)).status).toBe(200);
    const tokensB = await hx.server.link!.context.secrets.get(b.connection_id as never);
    expect(tokensB!.access_token).toBe('ya29.access-2');
    const revocationsBefore = hx.fake.revocations.length;

    const late = await activate(hx.app, client, a.connection_id, a.code);
    expect(late.status).toBe(401);
    expect(late.body).toEqual(LINK_OPAQUE_FAILURE_BODY);

    const ctx = hx.server.link!.context;
    expect(await ctx.secrets.get(b.connection_id as never)).toEqual(tokensB);
    expect((await ctx.store.getConnection(b.connection_id))!.status).toBe('active');
    expect((await ctx.store.getConnection(a.connection_id))!.status).toBe('revoked');
    expect(await ctx.store.listConnections({ client_id: client.client_id, subject: 'user-a' })).toHaveLength(2);
    expect(hx.fake.revocations.slice(revocationsBefore)).toEqual([]);
    expect((await delegate(hx.app, { connection_id: b.connection_id, scopes: ['calendar.readonly'] })).status).toBe(200);
  });

  it('a failed token commit after the database commit leaves the connection needs_reauth, never active without tokens', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const result = await connectFlow(hx.app, client);
    const secrets = hx.server.link!.context.secrets;
    const original = secrets.commitStaged.bind(secrets);
    secrets.commitStaged = async () => { throw new Error('disk full'); };
    let res;
    try {
      res = await activate(hx.app, client, result.connection_id, result.code);
    } finally {
      secrets.commitStaged = original;
    }
    expect(res.status).toBe(401);
    expect(res.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
    const conn = await hx.server.link!.context.store.getConnection(result.connection_id);
    expect(conn).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    const tid = (await hx.server.link!.context.store.listOpenAccountTransactions({ provider: 'google', provider_account_id: 'google-sub-alice' }));
    expect(tid).toEqual([]);
    const d = await delegate(hx.app, { connection_id: result.connection_id });
    expect(d.status).toBe(403);
    expect(d.body.error).toBe('reauth_required');
  });

  it('an active connection with no stored tokens moves to needs_reauth with a typed code, not a repeating 500', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const connectionId = await connectAndActivate(hx.app, client);
    await hx.server.link!.context.secrets.delete(connectionId as never);
    const first = await delegate(hx.app, { connection_id: connectionId });
    expect(first.status).toBe(403);
    expect(first.body.error).toBe('reauth_required');
    expect((await hx.server.link!.context.store.getConnection(connectionId))).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    const second = await delegate(hx.app, { connection_id: connectionId });
    expect(second.status).toBe(403);
    expect(second.body.error).toBe('reauth_required');
  });

  it('a refresh in flight never writes tokens back after the connection is deleted', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const connectionId = await connectAndActivate(hx.app, client);
    const handle = await delegate(hx.app, { connection_id: connectionId, scopes: ['calendar.readonly'] });
    await expireTokens(hx, connectionId);
    hx.fake.refreshDelayMs = 80;
    const inFlight = use(hx.app, { delegation_id: handle.body.delegation_id, url: CALENDAR_URL, method: 'GET' }).then((r) => r);
    await new Promise((r) => setTimeout(r, 20));
    const del = await request(hx.app).delete(`/link/v1/connections/${connectionId}`).set('Authorization', client.auth);
    await inFlight;
    expect(del.status).toBe(200);
    expect(await hx.server.link!.context.secrets.get(connectionId as never)).toBeNull();
    // A refresh that started before the delete and one that starts after both leave nothing behind.
    const after = await use(hx.app, { delegation_id: handle.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    expect(after.status).toBe(403);
    expect(await hx.server.link!.context.secrets.get(connectionId as never)).toBeNull();
  });

  it('the refresh re-checks inside the lock: a revoked connection gets no write-back', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const connectionId = await connectAndActivate(hx.app, client);
    await expireTokens(hx, connectionId);
    const ctx = hx.server.link!.context;
    const conn = await ctx.store.getConnection(connectionId);
    hx.fake.refreshDelayMs = 50;
    const pending = ctx.tokens.load(conn!);
    await new Promise((r) => setTimeout(r, 10));
    await ctx.store.setConnectionStatus({ connection_id: connectionId, status: 'needs_reauth', reason: 'grant_revoked', now: now() });
    const result = await pending;
    expect(result.ok).toBe(false);
    const stored = await ctx.secrets.get(connectionId as never);
    expect(stored!.access_token).toBe('ya29.access-1');
  });
});

describe('provider revocation never breaks another connection (review item 2)', () => {
  it('a cancelled flow under client B does not revoke the account that backs client A', async () => {
    const hx = await harness();
    const clientA = await registerClient(hx.app);
    const clientB = await registerClient(hx.app);
    await connectAndActivate(hx.app, clientA);
    const before = hx.fake.revocations.length;
    const browser = new Browser();
    const providerUrl = await toProvider(hx.app, browser, await par(hx.app, clientB));
    const confirmPage = await callback(hx.app, browser, providerUrl);
    const exit = await confirm(hx.app, browser, confirmPage.text, [], 'cancel');
    expect(resultOf(exit)).toMatchObject({ outcome: 'exit', step: 'confirm' });
    expect(hx.fake.revocations.slice(before)).toEqual([]);
  });

  it('DELETE revokes at the provider only when nothing else on the server uses the account', async () => {
    const hx = await harness();
    const clientA = await registerClient(hx.app);
    const clientB = await registerClient(hx.app);
    const connA = await connectAndActivate(hx.app, clientA);
    const connB = await connectAndActivate(hx.app, clientB, { parOverrides: { subject: 'other-user' } });

    const first = await request(hx.app).delete(`/link/v1/connections/${connA}`).set('Authorization', clientA.auth);
    expect(first.body).toEqual({ connection_id: connA, status: 'revoked', provider_revoked: false });
    expect(hx.fake.revocations).toEqual([]);
    expect(await hx.server.link!.context.secrets.get(connA as never)).toBeNull();
    expect((await delegate(hx.app, { connection_id: connB, scopes: ['calendar.readonly'] })).status).toBe(200);

    // An open transaction with staged tokens for the account also blocks it.
    const browser = new Browser();
    const providerUrl = await toProvider(hx.app, browser, await par(hx.app, clientA, { subject: 'third' }));
    expect((await callback(hx.app, browser, providerUrl)).status).toBe(200);
    const second = await request(hx.app).delete(`/link/v1/connections/${connB}`).set('Authorization', clientB.auth);
    expect(second.body.provider_revoked).toBe(false);
    expect(hx.fake.revocations).toEqual([]);

    // Once that flow is cancelled, its own staged token is the last user: revoked.
    const confirmPage = await callback(hx.app, browser, providerUrl);
    await confirm(hx.app, browser, confirmPage.text, [], 'cancel');
    expect(hx.fake.revocations).toHaveLength(1);
  });

  it('DELETE of the only connection of an account revokes at the provider', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const res = await request(hx.app).delete(`/link/v1/connections/${conn}`).set('Authorization', client.auth);
    expect(res.body).toEqual({ connection_id: conn, status: 'revoked', provider_revoked: true });
    expect(hx.fake.revocations).toEqual([{ provider: 'google', token: 'rt-1' }]);
  });
});

describe('confirmation cannot widen the pushed request (review item 3)', () => {
  it('offers and accepts only requested scopes the provider granted', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const requestUri = await par(hx.app, client, { scopes: { google: ['calendar.readonly'] }, required_scopes: { google: ['calendar.readonly'] } });
    const browser = new Browser();
    const providerUrl = await toProvider(hx.app, browser, requestUri, { scopes: ['calendar.readonly'] });
    // The provider reports gmail.send too (for example previously granted scopes).
    const confirmPage = await callback(hx.app, browser, providerUrl);
    expect(confirmPage.status).toBe(200);
    expect(confirmPage.text).not.toContain('gmail.send');
    const widened = await confirm(hx.app, browser, confirmPage.text, ['calendar.readonly', 'gmail.send']);
    expect(resultOf(widened)).toMatchObject({ outcome: 'error', error: 'invalid_scope' });

    const b2 = new Browser();
    const pu2 = await toProvider(hx.app, b2, await par(hx.app, client, { scopes: { google: ['calendar.readonly'] }, required_scopes: { google: ['calendar.readonly'] } }), { scopes: ['calendar.readonly'] });
    const cp2 = await callback(hx.app, b2, pu2);
    const ok = resultOf(await confirm(hx.app, b2, cp2.text, ['calendar.readonly']));
    if (ok.outcome !== 'success') throw new Error('flow failed');
    expect((await activate(hx.app, client, ok.connection_id, ok.code)).status).toBe(200);
    expect((await hx.server.link!.context.store.getGrantForConnection(ok.connection_id))!.scopes).toEqual(['calendar.readonly']);
    const d = await delegate(hx.app, { connection_id: ok.connection_id, scopes: ['gmail.send'] });
    expect(d.status).toBe(403);
    expect(d.body.error).toBe('insufficient_scope');
  });
});

describe('consent-page identity comes from registration only (review item 4)', () => {
  it('ignores app name and logo from the authorize query; cosmetic fields still apply', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app, { name: 'Acme Corp', theme: { logoUrl: 'https://cdn.acme.example/logo.png', accent: '#112233' } });
    const requestUri = await par(hx.app, client);
    const q = new URLSearchParams({ request_uri: requestUri, mode: 'redirect', app_name: 'Your Bank', logo_url: 'https://evil.example/logo.png', accent: '#abcdef' });
    const page = await new Browser().get(hx.app, `/link/v1/authorize?${q.toString()}`);
    expect(page.status).toBe(200);
    expect(page.text).toContain('Acme Corp');
    expect(page.text).toContain('https://cdn.acme.example/logo.png');
    expect(page.text).not.toContain('Your Bank');
    expect(page.text).not.toContain('evil.example');
    expect(page.text).toContain('--accent:#abcdef');
  });

  it('the registered theme appName wins over the client name', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app, { name: 'acme-internal', theme: { appName: 'Acme' } });
    const page = await new Browser().get(hx.app, authorizePath(await par(hx.app, client)));
    expect(page.text).toContain('Acme is asking');
  });

  it('registration requires a display name without invisible or bidirectional characters', async () => {
    const hx = await harness();
    const post = (body: Record<string, unknown>) => request(hx.app).post('/admin/link/clients').set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({ redirect_uris: [APP_REDIRECT], origins: [APP_ORIGIN], ...body });
    expect((await post({})).status).toBe(400);
    expect((await post({ name: '' })).status).toBe(400);
    expect((await post({ name: 'Acme‮knaB' })).status).toBe(400);
    expect((await post({ name: 'Acme​' })).status).toBe(400);
    expect((await post({ name: 'Acme' })).status).toBe(201);
  });
});

describe('connection_id when Link cannot check it (review item 5)', () => {
  it('Link disabled: delegate and subdelegate naming connection_id are refused before any vault access', async () => {
    const hx = await harness({ linkEnabled: false });
    await hx.server.vault.store({ provider: 'google', userId: 'default', accessToken: 'legacy-default-token', scopes: ['calendar.readonly'] });
    const getSpy = vi.spyOn(hx.server.vault, 'get');
    const res = await delegate(hx.app, { service: 'google', connection_id: 'conn_0123456789abcdef0123456789abcdef', token_format: 'raw' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(JSON.stringify(res.body)).not.toContain('legacy-default-token');
    const sub = await request(hx.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${AGENT_TOKEN}`)
      .send({ parent_receipt: 'a.b.c', agent_did: 'did:key:z', service: 'google', connection_id: 'conn_abc' });
    expect(sub.status).toBe(400);
    expect(sub.body.error).toBe('invalid_request');
    expect(getSpy).not.toHaveBeenCalled();
  });

  it('Link enabled: subdelegate naming connection_id is refused', async () => {
    const hx = await harness();
    const sub = await request(hx.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${AGENT_TOKEN}`)
      .send({ parent_receipt: 'a.b.c', agent_did: 'did:key:z', service: 'google', connection_id: 'conn_abc' });
    expect(sub.status).toBe(400);
    expect(sub.body.error).toBe('invalid_request');
  });
});

describe('embedded mode binding (review item 6)', () => {
  it('the iframe cannot advance to the provider; the top-level POST binds the browser', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const requestUri = await par(hx.app, client, { subject: 'attacker' });
    const iframe = new Browser();
    const picker = await iframe.get(hx.app, authorizePath(requestUri, 'embedded'));
    const envelope = envelopeOf(picker.text);
    const viaIframe = await iframe.post(hx.app, '/link/v1/picker?frame=iframe', [
      ['e', envelope], ['action', 'continue'], ['provider', 'google'], ['scope', 'calendar.readonly'],
    ]);
    expect(viaIframe.status).toBe(400);
    expect(iframe.cookie).toBeNull();
    // The transaction was not touched: the same envelope still works top-level.
    const top = new Browser();
    const ok = await top.post(hx.app, '/link/v1/picker', [['e', envelope], ['action', 'continue'], ['provider', 'google'], ['scope', 'calendar.readonly']]);
    expect(ok.status).toBe(303);
    expect(top.cookie).toBeTruthy();
  });

  it('consent phishing, embedded: a provider URL handed to another browser is refused', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const requestUri = await par(hx.app, client, { subject: 'attacker' });
    const picker = await new Browser().get(hx.app, authorizePath(requestUri, 'embedded'));
    const attackerTop = new Browser();
    const toGoogle = await attackerTop.post(hx.app, '/link/v1/picker', [['e', envelopeOf(picker.text)], ['action', 'continue'], ['provider', 'google'], ['scope', 'calendar.readonly']]);
    expect(toGoogle.status).toBe(303);
    const victim = new Browser();
    const res = await callback(hx.app, victim, new URL(toGoogle.headers.location));
    expect(res.status).toBe(400);
    expect(hx.fake.exchanges).toHaveLength(0);
  });

  it('consent phishing, popup: a provider URL handed to another browser is refused and the flow stays usable', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const attacker = new Browser();
    const providerUrl = await toProvider(hx.app, attacker, await par(hx.app, client, { subject: 'attacker' }), { mode: 'popup' });
    const victim = await callback(hx.app, new Browser(), providerUrl);
    expect(victim.status).toBe(400);
    expect(hx.fake.exchanges).toHaveLength(0);
  });
});

describe('client status (review: disabled client)', () => {
  it('disabling a client stops its connections; no reauth_url is minted; enabling restores them', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const connectionId = await connectAndActivate(hx.app, client);
    expect((await delegate(hx.app, { connection_id: connectionId, scopes: ['calendar.readonly'] })).status).toBe(200);
    const dis = await request(hx.app).post(`/admin/link/clients/${client.client_id}/disable`).set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    expect(dis.body.client.status).toBe('disabled');
    const after = await delegate(hx.app, { connection_id: connectionId, scopes: ['calendar.readonly'] });
    expect(after.status).toBe(403);
    expect(after.body.error).toBe('grant_revoked');

    await hx.server.link!.context.store.setConnectionStatus({ connection_id: connectionId, status: 'needs_reauth', now: now() });
    const noUrl = await delegate(hx.app, { connection_id: connectionId });
    expect(noUrl.status).toBe(403);
    expect(noUrl.body.reauth_url).toBeUndefined();

    const list = await request(hx.app).get('/admin/link/clients').set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    expect(list.body.clients.find((c: { client_id: string }) => c.client_id === client.client_id).status).toBe('disabled');
    const en = await request(hx.app).post(`/admin/link/clients/${client.client_id}/enable`).set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    expect(en.body.client.status).toBe('active');
    await hx.server.link!.context.store.setConnectionStatus({ connection_id: connectionId, status: 'active', now: now() });
    expect((await delegate(hx.app, { connection_id: connectionId, scopes: ['calendar.readonly'] })).status).toBe(200);
  });
});

describe('grant version is informational (review misc, intended behavior)', () => {
  it('a handle minted before needs_reauth is refused meanwhile and works again only when everything is active and covers it', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const connectionId = await connectAndActivate(hx.app, client);
    const handle = await delegate(hx.app, { connection_id: connectionId, scopes: ['calendar.readonly'] });
    const store = hx.server.link!.context.store;
    const callUse = () => use(hx.app, { delegation_id: handle.body.delegation_id, url: CALENDAR_URL, method: 'GET' });

    await store.setConnectionStatus({ connection_id: connectionId, status: 'needs_reauth', reason: 'grant_revoked', now: now() });
    const during = await callUse();
    expect(during.status).toBe(403);
    expect(during.body.error).toBe('grant_revoked');

    await store.setConnectionStatus({ connection_id: connectionId, status: 'active', now: now() });
    const grant = await store.getGrantForConnection(connectionId);
    expect(grant!.version).not.toBe(handle.body.grant_version);
    expect((await callUse()).status).toBe(200);

    // Still subject to the current grant and permission on every call.
    const perms = hx.server.link!.context.permissions;
    const p = await perms.get('server-agent', connectionId);
    await perms.update(p!.id, { allowedScopes: ['gmail.send'] });
    const narrowed = await callUse();
    expect(narrowed.status).toBe(403);
    expect(narrowed.body.error).toBe('permission_required');
  });
});

describe('audit at activation is fail closed (review item 7)', () => {
  it('when the pending record cannot be written nothing changes', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const result = await connectFlow(hx.app, client);
    const original = hx.server.vault.writeAuditEvent.bind(hx.server.vault);
    hx.server.vault.writeAuditEvent = () => { throw new Error('audit down'); };
    let res;
    try {
      res = await activate(hx.app, client, result.connection_id, result.code);
    } finally {
      hx.server.vault.writeAuditEvent = original;
    }
    expect(res.status).toBe(401);
    expect((await hx.server.link!.context.store.getConnection(result.connection_id))!.status).toBe('pending');
    const audit = hx.server.vault.queryAuditEvents({ limit: 50 }).filter((e) => e.resource.type === 'grant' && e.action === 'update');
    expect(audit).toEqual([]);
  });

  it('writes a pending and a success record around activation and deletion', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const connectionId = await connectAndActivate(hx.app, client);
    await request(hx.app).delete(`/link/v1/connections/${connectionId}`).set('Authorization', client.auth);
    const events = hx.server.vault.queryAuditEvents({ limit: 100 }).filter((e) => e.resource.type === 'grant');
    const pairs = events.map((e) => `${e.action}:${e.outcome}`);
    expect(pairs).toEqual(expect.arrayContaining(['update:pending', 'update:success', 'revoke:pending', 'revoke:success']));
  });
});

describe('small hardening items (review item 8)', () => {
  it('rejects RSA client keys under 2048 bits', async () => {
    const hx = await harness();
    const small = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ format: 'jwk' });
    const big = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
    const post = (jwk: Record<string, unknown>) => request(hx.app).post('/admin/link/clients').set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({ name: 'RSA app', redirect_uris: [APP_REDIRECT], origins: [APP_ORIGIN], token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [{ ...jwk, kid: 'k1' }] } });
    expect((await post(small)).status).toBe(400);
    expect((await post(big)).status).toBe(201);
  });

  it('Link handles default to 300 seconds, capped at 900', async () => {
    let hx = await harness();
    let client = await registerClient(hx.app);
    let conn = await connectAndActivate(hx.app, client);
    expect((await delegate(hx.app, { connection_id: conn })).body.expires_in).toBe(300);
    hx.close();
    h = null;
    hx = await harness({ linkHandleTtlSeconds: 5000 });
    client = await registerClient(hx.app);
    conn = await connectAndActivate(hx.app, client);
    expect((await delegate(hx.app, { connection_id: conn })).body.expires_in).toBe(900);
  });

  it('refuses a Link base URL with a path, query or fragment at startup', () => {
    const base = {
      port: 0, host: '127.0.0.1', vaultPassphrase: 'x', vaultStorage: 'sqlite' as const, vaultPath: '/tmp/x-vault.sqlite',
      tofuStorage: 'file' as const, tofuPath: '/tmp/x-tofu.json', adminToken: ADMIN_TOKEN, agentToken: AGENT_TOKEN, allowRawTokens: true, providers: [],
      redirectBaseUri: BASE, linkEnabled: true,
    };
    for (const linkBaseUrl of ['https://cred.example.com/link', 'https://cred.example.com/?x=1', 'https://cred.example.com/#f']) {
      expect(() => createServer({ ...base, linkBaseUrl })).toThrow(/LINK_BASE_URL/);
    }
    expect(() => createServer({ ...base, redirectBaseUri: 'https://cred.example.com/sub' })).toThrow(/LINK_BASE_URL/);
  });

  it('matches Basic and Bearer schemes case-insensitively', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const lower = client.auth.replace(/^Basic /, 'basic ');
    expect((await request(hx.app).post('/link/v1/par').set('Authorization', lower).send(parBody())).status).toBe(201);
    const upper = client.auth.replace(/^Basic /, 'BASIC ');
    expect((await request(hx.app).post('/link/v1/par').set('Authorization', upper).send(parBody())).status).toBe(201);
  });

  it('refuses blank scope entries instead of treating them as "everything"', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    for (const scopes of [[''], ['  '], ['calendar.readonly', ''], 'calendar.readonly,,gmail.send', '', ' ']) {
      const res = await delegate(hx.app, { connection_id: conn, scopes });
      expect({ scopes, status: res.status, error: res.body.error }).toEqual({ scopes, status: 400, error: 'invalid_request' });
    }
    expect((await delegate(hx.app, { connection_id: conn, scopes: [] })).body.scopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('a ReservedVaultUserIdError that reaches the vault is a 400, never a 500', async () => {
    const hx = await harness({ linkEnabled: false });
    vi.spyOn(hx.server.vault, 'get').mockRejectedValue(new ReservedVaultUserIdError('get'));
    vi.spyOn(hx.server.vault, 'delete').mockRejectedValue(new ReservedVaultUserIdError('delete'));
    vi.spyOn(hx.server.vault, 'list').mockRejectedValue(new ReservedVaultUserIdError('list'));
    const agent = (r: request.Test) => r.set('Authorization', `Bearer ${AGENT_TOKEN}`);
    const responses = [
      await agent(request(hx.app).get('/api/token/google?user_id=default')),
      await agent(request(hx.app).delete('/api/token/google?user_id=default')),
      await agent(request(hx.app).get('/api/v1/connections?user_id=default')),
      await agent(request(hx.app).delete('/api/v1/connections/google?user_id=default')),
      await delegateAs(hx.app, await newAgent(), { service: 'google', user_id: 'default' }, { bearer: AGENT_TOKEN }),
      await request(hx.app).get('/providers?user_id=default').set('Authorization', `Bearer ${ADMIN_TOKEN}`),
    ];
    for (const res of responses) {
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('invalid_user_id');
    }
  });

  it('subdelegate turns a ReservedVaultUserIdError from the vault into a 400', async () => {
    const hx = await harness({ linkEnabled: false });
    const vault = hx.server.vault;
    const nowIso = new Date().toISOString();
    const [parentAgent, childAgent] = [await newAgent(), await newAgent()];
    await vault.registerAgent!({ id: 'agt_child', did: childAgent.did, name: 'child', fingerprint: 'fp_child', scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: nowIso, updatedAt: nowIso });
    await vault.createPermission!({ agentId: 'agt_child', connectionId: 'google', allowedScopes: ['calendar.readonly'], delegatable: true, maxDelegationDepth: 3, requiresApproval: false, createdBy: 'admin' });
    const seed = crypto.scryptSync('link-test-passphrase', 'cred:local-receipt:v1', 32);
    const key = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'did:key:local-cred', iat: Math.floor(Date.now() / 1000) - 60, exp: Math.floor(Date.now() / 1000) + 600,
      sub: parentAgent.did, service: 'google', scopes: ['calendar.readonly'], userId: 'default', appClientId: 'local',
      delegationId: 'del_parent', chainDepth: 0,
    })).toString('base64url');
    const receipt = `${header}.${payload}.${crypto.sign(null, Buffer.from(`${header}.${payload}`), key).toString('base64url')}`;
    vi.spyOn(vault, 'get').mockRejectedValue(new ReservedVaultUserIdError('get'));
    const res = await request(hx.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${AGENT_TOKEN}`)
      .send({
        parent_receipt: receipt, actor_token: actorTokenFor(parentAgent, '/api/v1/subdelegate'),
        agent_did: childAgent.did, service: 'google', user_id: 'default', scopes: ['calendar.readonly'],
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_user_id');
  });
});

describe('broker allowlist (review item 9)', () => {
  it('Link off: Linear only at GraphQL, HubSpot only at data APIs, Slack never at auth.revoke', async () => {
    const hx = await harness({ linkEnabled: false });
    await hx.server.vault.store({ provider: 'linear', userId: 'default', accessToken: 'lin_tok', scopes: ['read'] });
    await hx.server.vault.store({ provider: 'hubspot', userId: 'default', accessToken: 'hub_tok', scopes: ['crm.objects.contacts.read'] });
    await hx.server.vault.store({ provider: 'slack', userId: 'default', accessToken: 'xoxb-legacy', scopes: ['chat:write'] });
    const agent = await newAgent();
    const handle = async (service: string) => (await delegateAs(hx.app, agent, { service, user_id: 'default' }, { bearer: AGENT_TOKEN, base: BASE })).body.access_token as string;
    const lin = await handle('linear');
    const hub = await handle('hubspot');
    const slk = await handle('slack');
    const call = (token: string, url: string, method = 'POST') => exerciseAs(hx.app, agent, token, { url, method, ...(method === 'GET' ? {} : { body: {} }) }, { base: BASE });

    expect((await call(lin, 'https://api.linear.app/graphql')).status).toBe(200);
    expect((await call(lin, 'https://api.linear.app/graphql?x=1')).status).toBe(200);
    expect((await call(lin, 'https://api.linear.app/oauth/revoke')).status).toBe(400);
    expect((await call(lin, 'https://api.linear.app/graphqlx')).status).toBe(400);
    expect((await call(lin, 'https://api.linear.app/graphql/')).status).toBe(400);
    expect((await call(hub, 'https://api.hubapi.com/crm/v3/objects/contacts', 'GET')).status).toBe(200);
    expect((await call(hub, 'https://api.hubapi.com/oauth/v1/refresh-tokens/x', 'DELETE')).status).toBe(400);
    expect((await call(hub, 'https://api.hubapi.com/oauth/v1/access-tokens/x', 'GET')).status).toBe(400);
    expect((await call(slk, 'https://slack.com/api/chat.postMessage')).status).toBe(200);
    expect((await call(slk, 'https://slack.com/api/auth.revoke')).status).toBe(400);
    expect((await call(slk, 'https://slack.com/api/AUTH.REVOKE')).status).toBe(400);
    expect((await call(slk, 'https://slack.com/api/apps.uninstall')).status).toBe(400);
    expect(hx.fake.revocations).toEqual([]);
    expect(hx.fake.upstream.map((u) => u.url)).not.toContain('https://api.linear.app/oauth/revoke');
  });

  it('Link on: the same restrictions apply to Link handles', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const slackBrowser = new Browser();
    const slackPu = await toProvider(hx.app, slackBrowser, await par(hx.app, client, { providers: ['slack'], scopes: { slack: ['chat:write'] }, required_scopes: {} }), { provider: 'slack', scopes: ['chat:write'] });
    const slackResult = resultOf(await confirm(hx.app, slackBrowser, (await callback(hx.app, slackBrowser, slackPu, 'slack')).text, ['chat:write']));
    if (slackResult.outcome !== 'success') throw new Error('slack flow failed');
    await activate(hx.app, client, slackResult.connection_id, slackResult.code);
    const slackHandle = (await delegate(hx.app, { connection_id: slackResult.connection_id })).body.delegation_id;
    expect((await use(hx.app, { delegation_id: slackHandle, url: 'https://slack.com/api/auth.revoke', method: 'POST', body: {} })).status).toBe(400);
    expect((await use(hx.app, { delegation_id: slackHandle, url: 'https://slack.com/api/chat.postMessage', method: 'POST', body: {} })).status).toBe(200);

    const linBrowser = new Browser();
    const linPu = await toProvider(hx.app, linBrowser, await par(hx.app, client, { providers: ['linear'], scopes: { linear: ['issues:create'] }, required_scopes: {} }), { provider: 'linear', scopes: ['issues:create'] });
    const linConfirm = await callback(hx.app, linBrowser, linPu, 'linear');
    const linResult = resultOf(await confirm(hx.app, linBrowser, linConfirm.text, ['issues:create', 'read']));
    if (linResult.outcome !== 'success') throw new Error(`linear flow failed: ${JSON.stringify(linResult)}`);
    await activate(hx.app, client, linResult.connection_id, linResult.code);
    const linHandle = (await delegate(hx.app, { connection_id: linResult.connection_id })).body.delegation_id;
    expect((await use(hx.app, { delegation_id: linHandle, url: 'https://api.linear.app/oauth/revoke', method: 'POST', body: {} })).status).toBe(400);
    expect((await use(hx.app, { delegation_id: linHandle, url: 'https://api.linear.app/graphql', method: 'POST', body: { query: '{ viewer { id } }' } })).status).toBe(200);
    expect(hx.fake.revocations).toEqual([]);
  });
});

describe('admin Permission writes on Link connections (review item 10)', () => {
  it('refuses allowedScopes outside the connection grant on create and update', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client, { scopes: ['calendar.readonly'], confirmScopes: ['calendar.readonly'] });
    const admin = (r: request.Test) => r.set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    const outside = await admin(request(hx.app).post('/admin/permissions')).send({ agentId: 'agent-x', connectionId: conn, allowedScopes: ['drive'] });
    expect(outside.status).toBe(400);
    expect(outside.body.error).toBe('invalid_scope');
    const inside = await admin(request(hx.app).post('/admin/permissions')).send({ agentId: 'agent-x', connectionId: conn, allowedScopes: ['calendar.readonly'] });
    expect(inside.status).toBe(201);
    const patch = await admin(request(hx.app).patch(`/admin/permissions/${inside.body.permission.id}`)).send({ allowedScopes: ['calendar.readonly', 'gmail.send'] });
    expect(patch.status).toBe(400);
    const stored = await hx.server.link!.context.permissions.get('agent-x', conn);
    expect(stored!.allowedScopes).toEqual(['calendar.readonly']);
    // Legacy provider-slug permissions are unaffected.
    const legacy = await admin(request(hx.app).post('/admin/permissions')).send({ agentId: 'agent-x', connectionId: 'google', allowedScopes: ['anything'] });
    expect(legacy.status).toBe(201);
  });
});

describe('provider scope reduction on refresh (review item 11)', () => {
  it('narrows the grant and the agent permissions, never widens', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const handle = await delegate(hx.app, { connection_id: conn, scopes: ['calendar.readonly'] });
    await expireTokens(hx, conn);
    hx.fake.googleRefreshScope = 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/calendar.readonly';
    expect((await use(hx.app, { delegation_id: handle.body.delegation_id, url: CALENDAR_URL, method: 'GET' })).status).toBe(200);
    const ctx = hx.server.link!.context;
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly']);
    expect((await ctx.permissions.get('server-agent', conn))!.allowedScopes).toEqual(['calendar.readonly']);
    const d = await delegate(hx.app, { connection_id: conn, scopes: ['gmail.send'] });
    expect(d.status).toBe(403);
    expect(d.body.error).toBe('insufficient_scope');
    const audit = hx.server.vault.queryAuditEvents({ limit: 100 }).filter((e) => (e.metadata as { reason?: string } | undefined)?.reason === 'provider_scope_changed');
    expect(audit).toHaveLength(1);
  });
});

describe('opaque failures are byte-identical (strengthened)', () => {
  it('covers unknown, disabled, wrong-method and private_key_jwt failures and the activate, permissions and reauth paths', async () => {
    const hx = await harness();
    const app = hx.app;
    const secretClient = await registerClient(app);
    const other = await registerClient(app);
    const disabled = await registerClient(app);
    await request(app).post(`/admin/link/clients/${disabled.client_id}/disable`).set('Authorization', `Bearer ${ADMIN_TOKEN}`);
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const otherKey = crypto.generateKeyPairSync('ed25519').privateKey;
    const jwk = { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), kid: 'k1' };
    const jwtReg = await request(app).post('/admin/link/clients').set('Authorization', `Bearer ${ADMIN_TOKEN}`)
      .send({ name: 'JWT', redirect_uris: [APP_REDIRECT], origins: [APP_ORIGIN], token_endpoint_auth_method: 'private_key_jwt', jwks: { keys: [jwk] } });
    const jwtClient = jwtReg.body.client.client_id as string;
    const assertion = (overrides: Record<string, unknown> = {}, signer = privateKey) => {
      const t = Math.floor(Date.now() / 1000);
      const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'k1' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ iss: jwtClient, sub: jwtClient, aud: BASE, iat: t, exp: t + 60, jti: crypto.randomUUID(), ...overrides })).toString('base64url');
      return `${header}.${payload}.${crypto.sign(null, Buffer.from(`${header}.${payload}`), signer).toString('base64url')}`;
    };
    const used = assertion();
    expect((await request(app).get('/link/v1/connections?subject=x').set('Authorization', `Bearer ${used}`)).status).toBe(200);

    const connectionId = await connectAndActivate(app, secretClient);
    const pending = await connectFlow(app, secretClient, { parOverrides: { subject: 'user-p' } });
    const get = (auth: string) => request(app).get(`/link/v1/connections/${connectionId}`).set('Authorization', auth);
    const responses: Array<[string, request.Response]> = [
      ['well-formed unknown client', await get(basic('lc_doesnotexist000000000000', 'cred_lcs_x'))],
      ['bad secret', await get(basic(secretClient.client_id, 'cred_lcs_wrong'))],
      ['disabled client', await get(disabled.auth)],
      ['basic for a private_key_jwt client', await get(basic(jwtClient, 'anything'))],
      ['assertion for a secret client', await get(`Bearer ${assertion({ iss: secretClient.client_id, sub: secretClient.client_id })}`)],
      ['jwt bad signature', await get(`Bearer ${assertion({}, otherKey)}`)],
      ['jwt wrong audience', await get(`Bearer ${assertion({ aud: 'https://elsewhere.example' })}`)],
      ['jwt expired', await get(`Bearer ${assertion({ iat: Math.floor(Date.now() / 1000) - 400, exp: Math.floor(Date.now() / 1000) - 200 })}`)],
      ['jwt replayed jti', await get(`Bearer ${used}`)],
      ['foreign connection', await get(other.auth)],
      ['unknown connection', await request(app).get('/link/v1/connections/conn_0000000000000000').set('Authorization', secretClient.auth)],
      ['activate wrong code', await activate(app, secretClient, pending.connection_id, `cred_lac_${'B'.repeat(43)}`, 'user-p')],
      ['activate foreign client', await activate(app, other, pending.connection_id, pending.code, 'user-p')],
      ['activate malformed', await request(app).post(`/link/v1/connections/${pending.connection_id}/activate`).set('Authorization', secretClient.auth).send({ code: 'x' })],
      ['permissions foreign', await request(app).post(`/link/v1/connections/${connectionId}/permissions`).set('Authorization', other.auth).send({ agent_id: 'a', scopes: [] })],
      ['reauth foreign subject', await request(app).post(`/link/v1/connections/${connectionId}/reauth`).set('Authorization', secretClient.auth).send({ subject: 'someone-else' })],
      ['reauth foreign client', await request(app).post(`/link/v1/connections/${connectionId}/reauth`).set('Authorization', other.auth).send({ subject: 'user-a' })],
    ];
    const ids = new Set<string>();
    for (const [name, res] of responses) {
      expect({ name, status: res.status, text: res.text }).toEqual({ name, status: 401, text: JSON.stringify(LINK_OPAQUE_FAILURE_BODY) });
      expect(res.headers['cred-request-id']).toMatch(/^req_/);
      ids.add(res.headers['cred-request-id']);
    }
    expect(ids.size).toBe(responses.length);
    // None of the failed attempts changed anything: the pending connection can still be activated.
    expect((await activate(app, secretClient, pending.connection_id, pending.code, 'user-p')).status).toBe(200);
  });
});

describe('no secrets in logs', () => {
  it('a full connect, delegate and use flow (and failure paths) never log tokens, secrets or codes', async () => {
    const lines: string[] = [];
    for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        lines.push(args.map((a) => (typeof a === 'string' ? a : util.inspect(a, { depth: 8 }))).join(' '));
      });
    }
    const hx = await harness();
    const client = await registerClient(hx.app, { allow_raw_tokens: true });
    const result = await connectFlow(hx.app, client);
    expect((await activate(hx.app, client, result.connection_id, result.code)).status).toBe(200);
    const handle = await delegate(hx.app, { connection_id: result.connection_id, scopes: ['calendar.readonly'] });
    expect((await use(hx.app, { delegation_id: handle.body.delegation_id, url: CALENDAR_URL, method: 'GET' })).status).toBe(200);
    expect((await delegate(hx.app, { connection_id: result.connection_id, token_format: 'raw' })).status).toBe(200);
    // Failure paths that log.
    hx.fake.refreshMode = 'error';
    await expireTokens(hx, result.connection_id);
    await use(hx.app, { delegation_id: handle.body.delegation_id, url: CALENDAR_URL, method: 'GET' });
    hx.fake.googleExchangeStatus = 400;
    const browser = new Browser();
    await callback(hx.app, browser, await toProvider(hx.app, browser, await par(hx.app, client)));
    await request(hx.app).delete(`/link/v1/connections/${result.connection_id}`).set('Authorization', client.auth);

    const all = lines.join('\n');
    for (const secret of ['ya29.', 'rt-1', 'rt-2', client.client_secret!, result.code, 'g-secret']) {
      expect(all).not.toContain(secret);
    }
  });
});

// ── Verification round (formerly zz-review-v2-*) ────────────────────────────

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('broker URLs cannot hide segments with percent-encoding (v2 item 1)', () => {
  it('refuses encoded dot, slash, backslash and percent in any case, and dot or empty segments', async () => {
    const hx = await harness({ linkEnabled: false });
    await hx.server.vault.store({ provider: 'slack', userId: 'default', accessToken: 'xoxb-legacy', scopes: ['chat:write'] });
    await hx.server.vault.store({ provider: 'hubspot', userId: 'default', accessToken: 'hub_tok', scopes: ['crm.objects.contacts.read'] });
    await hx.server.vault.store({ provider: 'linear', userId: 'default', accessToken: 'lin_tok', scopes: ['read'] });
    await hx.server.vault.store({ provider: 'google', userId: 'default', accessToken: 'g_tok', scopes: ['calendar.readonly'] });
    const agent = await newAgent();
    const handle = async (service: string) => (await delegateAs(hx.app, agent, { service, user_id: 'default' }, { bearer: AGENT_TOKEN, base: BASE })).body.access_token as string;
    const ids = { slack: await handle('slack'), hubspot: await handle('hubspot'), linear: await handle('linear'), google: await handle('google') };
    const call = (service: keyof typeof ids, url: string, method = 'GET') => exerciseAs(hx.app, agent, ids[service], { url, method }, { base: BASE });

    const refused: Array<[keyof typeof ids, string]> = [
      ['slack', 'https://slack.com/api/auth%2Erevoke'],
      ['slack', 'https://slack.com/api/auth%2erevoke'],
      ['slack', 'https://slack.com/api/auth%252Erevoke'],
      ['slack', 'https://slack.com/api/apps%2euninstall'],
      ['hubspot', 'https://api.hubapi.com/crm/..%2Foauth/v1/refresh-tokens/x'],
      ['hubspot', 'https://api.hubapi.com/crm/..%2foauth/v1/refresh-tokens/x'],
      ['hubspot', 'https://api.hubapi.com/crm/%2e%2e/oauth/v1/refresh-tokens/x'],
      ['hubspot', 'https://api.hubapi.com/crm/%252e%252e/oauth/v1/access-tokens/x'],
      ['hubspot', 'https://api.hubapi.com/crm/..%5Coauth/v1/refresh-tokens/x'],
      ['hubspot', 'https://api.hubapi.com/crm//oauth/v1/refresh-tokens/x'],
      ['hubspot', 'https://api.hubapi.com/%63rm/v3/objects/contacts'],
      ['linear', 'https://api.linear.app/graphql%2F..'],
      ['linear', 'https://api.linear.app/graphql%2f'],
      ['linear', 'https://api.linear.app/graphql%2Fx'],
      ['linear', 'https://api.linear.app/graphq%6C'],
      ['google', 'https://www.googleapis.com/calendar/v3/%2E%2E/%2e%2e/oauth2/v1/tokeninfo'],
    ];
    for (const [service, url] of refused) {
      const res = await call(service, url, 'POST');
      expect({ url, status: res.status }).toEqual({ url, status: 400 });
    }
    expect(hx.fake.upstream).toEqual([]);
    expect(hx.fake.revocations).toEqual([]);

    // Ordinary encoding of other characters still works.
    const ok = await call('google', 'https://www.googleapis.com/calendar/v3/calendars/alice%40example.com/events');
    expect(ok.status).toBe(200);
    expect(hx.fake.upstream.at(-1)!.url).toBe('https://www.googleapis.com/calendar/v3/calendars/alice%40example.com/events');
  });
});

describe('refresh racing activation (v2 items 2, 3)', () => {
  it('a refresh in flight when an update is activated does not narrow the freshly widened grant', async () => {
    const hx = await harness();
    const ctx = hx.server.link!.context;
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client, { scopes: ['calendar.readonly'], confirmScopes: ['calendar.readonly'] });
    const browser = new Browser();
    const uri = await par(hx.app, client, { intent: 'update', connection_id: conn, providers: undefined, scopes: { google: ['gmail.send'] }, required_scopes: {} });
    const pu = await toProvider(hx.app, browser, uri, { scopes: ['calendar.readonly', 'gmail.send'] });
    const result = resultOf(await confirm(hx.app, browser, (await callback(hx.app, browser, pu)).text, ['calendar.readonly', 'gmail.send']));
    if (result.outcome !== 'success') throw new Error('update flow failed');
    await expireTokens(hx, conn);
    hx.fake.googleRefreshScope = 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/calendar.readonly';
    hx.fake.refreshDelayMs = 150;
    const inFlight = delegate(hx.app, { connection_id: conn, scopes: ['calendar.readonly'] }).then((r) => r);
    await sleep(40);
    const act = await activate(hx.app, client, conn, result.code);
    await inFlight;
    expect(act.status).toBe(200);
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly', 'gmail.send']);
    expect((await ctx.permissions.get('server-agent', conn))!.allowedScopes).toEqual(['calendar.readonly', 'gmail.send']);
    // The update's tokens are the ones stored (the refresh finished first, under the lock).
    expect((await ctx.secrets.get(conn as never))!.refresh_token).toBe('rt-2');
  });

  it('a refresh request between the activation commits does not flip a new connection to needs_reauth', async () => {
    const hx = await harness();
    const ctx = hx.server.link!.context;
    const client = await registerClient(hx.app);
    const result = await connectFlow(hx.app, client);
    const original = ctx.secrets.commitStaged.bind(ctx.secrets);
    ctx.secrets.commitStaged = async (...args: Parameters<typeof original>) => {
      await sleep(100);
      return original(...args);
    };
    try {
      const activation = activate(hx.app, client, result.connection_id, result.code).then((r) => r);
      await sleep(30);
      const refresh = await request(hx.app).post(`/link/v1/connections/${result.connection_id}/refresh`).set('Authorization', client.auth);
      const act = await activation;
      expect(act.status).toBe(200);
      expect(refresh.status).toBe(200);
      expect((await ctx.store.getConnection(result.connection_id))!.status).toBe('active');
    } finally {
      ctx.secrets.commitStaged = original;
    }
  });

  it('the started-from guard: tokens written while a refresh is in flight survive it', async () => {
    const hx = await harness();
    const ctx = hx.server.link!.context;
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    await expireTokens(hx, conn);
    hx.fake.refreshDelayMs = 100;
    const pending = ctx.tokens.load((await ctx.store.getConnection(conn))!);
    await sleep(30);
    // A reauth's token commit that lands while the refresh holds the old
    // refresh token (written directly, not through the lock, to make the
    // guard itself observable).
    await ctx.secrets.put(conn as never, { access_token: 'ya29.reauth-new', refresh_token: 'rt-reauth-new', expires_at: new Date(Date.now() + 3600_000).toISOString() });
    const result = await pending;
    expect(result.ok).toBe(false);
    const stored = await ctx.secrets.get(conn as never);
    expect(stored).toMatchObject({ access_token: 'ya29.reauth-new', refresh_token: 'rt-reauth-new' });
  });

  it('a reauth activated while a refresh is in flight keeps the reauth tokens', async () => {
    const hx = await harness();
    const ctx = hx.server.link!.context;
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const reauth = await request(hx.app).post(`/link/v1/connections/${conn}/reauth`).set('Authorization', client.auth).send({ subject: 'user-a' });
    const browser = new Browser();
    const pu = await toProvider(hx.app, browser, reauth.body.request_uri, { scopes: ['calendar.readonly', 'gmail.send'] });
    const result = resultOf(await confirm(hx.app, browser, (await callback(hx.app, browser, pu)).text, ['calendar.readonly', 'gmail.send']));
    if (result.outcome !== 'success') throw new Error('reauth flow failed');
    await expireTokens(hx, conn);
    hx.fake.refreshDelayMs = 120;
    const inFlight = delegate(hx.app, { connection_id: conn }).then((r) => r);
    await sleep(30);
    expect((await activate(hx.app, client, conn, result.code)).status).toBe(200);
    await inFlight;
    expect((await ctx.secrets.get(conn as never))).toMatchObject({ access_token: 'ya29.access-2', refresh_token: 'rt-2' });
  });

  it('DELETE takes the connection lock: it waits for a refresh in flight', async () => {
    const hx = await harness();
    const ctx = hx.server.link!.context;
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const order: string[] = [];
    const originalRefresh = ctx.providers.refresh.bind(ctx.providers);
    ctx.providers.refresh = async (...args: Parameters<typeof originalRefresh>) => {
      const r = await originalRefresh(...args);
      order.push('refresh-returned');
      return r;
    };
    const originalStatus = ctx.store.setConnectionStatus.bind(ctx.store);
    ctx.store.setConnectionStatus = async (input) => {
      if (input.status === 'revoked') order.push('delete-revoked-status');
      return originalStatus(input);
    };
    await expireTokens(hx, conn);
    hx.fake.refreshDelayMs = 100;
    const inFlight = delegate(hx.app, { connection_id: conn }).then((r) => r);
    await sleep(30);
    const del = await request(hx.app).delete(`/link/v1/connections/${conn}`).set('Authorization', client.auth);
    await inFlight;
    expect(del.status).toBe(200);
    expect(order).toEqual(['refresh-returned', 'delete-revoked-status']);
    expect(await ctx.secrets.get(conn as never)).toBeNull();
  });
});

describe('a failed token commit on update and reauth (v2 item 7)', () => {
  for (const intent of ['update', 'reauth'] as const) {
    it(`${intent}: the live connection keeps its old tokens and moves to needs_reauth; the new token is not revoked`, async () => {
      // Why needs_reauth: the database commit already applied the new grant
      // and provider scopes, which the old tokens may not cover, so the
      // connection is not left claiming what its tokens cannot do.
      const hx = await harness();
      const ctx = hx.server.link!.context;
      const client = await registerClient(hx.app);
      const conn = await connectAndActivate(hx.app, client, { scopes: ['calendar.readonly'], confirmScopes: ['calendar.readonly'] });
      const uri = intent === 'update'
        ? await par(hx.app, client, { intent: 'update', connection_id: conn, providers: undefined, scopes: { google: ['gmail.send'] }, required_scopes: {} })
        : (await request(hx.app).post(`/link/v1/connections/${conn}/reauth`).set('Authorization', client.auth).send({ subject: 'user-a' })).body.request_uri as string;
      const browser = new Browser();
      const pu = await toProvider(hx.app, browser, uri, { scopes: intent === 'update' ? ['calendar.readonly', 'gmail.send'] : ['calendar.readonly'] });
      const confirmScopes = intent === 'update' ? ['calendar.readonly', 'gmail.send'] : ['calendar.readonly'];
      const result = resultOf(await confirm(hx.app, browser, (await callback(hx.app, browser, pu)).text, confirmScopes));
      if (result.outcome !== 'success') throw new Error(`${intent} flow failed`);
      const original = ctx.secrets.commitStaged.bind(ctx.secrets);
      ctx.secrets.commitStaged = async () => false;
      let res;
      try {
        res = await activate(hx.app, client, conn, result.code);
      } finally {
        ctx.secrets.commitStaged = original;
      }
      expect(res.status).toBe(401);
      expect(res.body).toEqual(LINK_OPAQUE_FAILURE_BODY);
      expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
      expect((await ctx.secrets.get(conn as never))!.access_token).toBe('ya29.access-1');
      expect(hx.fake.revocations).toEqual([]);
      const open = await ctx.store.listOpenAccountTransactions({ provider: 'google', provider_account_id: 'google-sub-alice' });
      expect(open).toEqual([]);
    });
  }

  it('new connection: the staged token is revoked under the rule (nothing else uses the account)', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const result = await connectFlow(hx.app, client);
    const secrets = hx.server.link!.context.secrets;
    const original = secrets.commitStaged.bind(secrets);
    secrets.commitStaged = async () => false;
    try {
      expect((await activate(hx.app, client, result.connection_id, result.code)).status).toBe(401);
    } finally {
      secrets.commitStaged = original;
    }
    expect(hx.fake.revocations).toEqual([{ provider: 'google', token: 'rt-1' }]);
  });
});

describe('provider call timeouts (v2 item 4)', () => {
  it('a stalled refresh releases the lock with a transient error and its late result is not written', async () => {
    const hx = await harness();
    const ctx = hx.server.link!.context;
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    ctx.providers.callTimeoutMs = 50;
    await expireTokens(hx, conn);
    const before = await ctx.secrets.get(conn as never);
    hx.fake.refreshDelayMs = 300;
    const started = Date.now();
    const res = await delegate(hx.app, { connection_id: conn });
    expect(res.status).toBe(503);
    expect(res.body.error).toBe('temporarily_unavailable');
    expect(Date.now() - started).toBeLessThan(250);
    // The late provider answer arrives after the timeout and is not written.
    await sleep(350);
    expect(await ctx.secrets.get(conn as never)).toEqual(before);
    expect((await ctx.store.getConnection(conn))!.status).toBe('active');
  });

  it('a stalled revocation does not hold DELETE', async () => {
    const hx = await harness();
    const ctx = hx.server.link!.context;
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    ctx.providers.callTimeoutMs = 50;
    hx.fake.revokeDelayMs = 300;
    const started = Date.now();
    const res = await request(hx.app).delete(`/link/v1/connections/${conn}`).set('Authorization', client.auth);
    expect(Date.now() - started).toBeLessThan(250);
    expect(res.body).toEqual({ connection_id: conn, status: 'revoked', provider_revoked: false });
    expect(await ctx.secrets.get(conn as never)).toBeNull();
    await sleep(320);
  });
});

describe('the success audit record does not abort activation (v2 item 5)', () => {
  it('logs the failure, runs the hooks and answers success', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const result = await connectFlow(hx.app, client);
    const vault = hx.server.vault;
    const original = vault.writeAuditEvent.bind(vault);
    vault.writeAuditEvent = (event) => {
      if (event.resource.type === 'grant' && event.action === 'update' && event.outcome === 'success') throw new Error('audit down');
      original(event);
    };
    let res;
    try {
      res = await activate(hx.app, client, result.connection_id, result.code);
    } finally {
      vault.writeAuditEvent = original;
    }
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('active');
    expect(await hx.server.link!.context.permissions.get('server-agent', result.connection_id)).not.toBeNull();
    expect((await delegate(hx.app, { connection_id: result.connection_id })).status).toBe(200);
  });
});

// ── Polish-round review (formerly zz-review-polish) ──────────────────────────

describe('polish review: narrowing', () => {
  function narrow(hx: Harness, client: { auth: string }, id: string, body: Record<string, unknown>) {
    return request(hx.app).post(`/link/v1/connections/${id}/narrow`).set('Authorization', client.auth).send(body);
  }

  it('scopes that canonicalize to nothing never narrow the grant to empty', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    for (const scopes of [['/'], ['/', 'calendar.readonly'], [' / ']]) {
      const res = await narrow(hx, client, conn, { subject: 'user-a', scopes });
      expect({ scopes, status: res.status, error: res.body.error }).toEqual({ scopes, status: 400, error: 'invalid_scope' });
    }
    expect((await hx.server.link!.context.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('Slack (enforcement record): records shrink, but a brokered call still reaches upstream', async () => {
    // Known Phase 1 limit, documented in the README and in
    // NarrowConnectionResponse.enforcement: narrowing never changes the
    // provider token, and the broker cannot tell which Slack scope a URL
    // needs, so a still-valid handle can reach any allowlisted Slack URL.
    // To really remove access, run an update or reauth for fewer scopes, or
    // delete the connection.
    const hx = await harness();
    const { app } = hx;
    const client = await registerClient(app);
    const b = new Browser();
    const pu = await toProvider(app, b, await par(app, client, { providers: ['slack'], scopes: { slack: ['chat:write', 'channels:read'] }, required_scopes: {} }), { provider: 'slack', scopes: ['chat:write', 'channels:read'] });
    const r = resultOf(await confirm(app, b, (await callback(app, b, pu, 'slack')).text, ['chat:write', 'channels:read']));
    if (r.outcome !== 'success') throw new Error('slack flow failed');
    expect((await activate(app, client, r.connection_id, r.code)).status).toBe(200);
    const oldHandle = (await delegate(app, { connection_id: r.connection_id })).body.delegation_id;

    const n = await narrow(hx, client, r.connection_id, { subject: 'user-a', scopes: ['channels:read'] });
    expect(n.status).toBe(200);
    expect(n.body.removed_scopes).toEqual(['chat:write']);
    expect(n.body.enforcement).toBe('record');

    // The records: an agent can no longer request or be issued the scope.
    const named = await delegate(app, { connection_id: r.connection_id, scopes: ['chat:write'] });
    expect(named.status).toBe(403);
    const fresh = await delegate(app, { connection_id: r.connection_id });
    expect(fresh.status).toBe(200);
    expect(fresh.body.scopes).toEqual(['channels:read']);

    // The limit: the brokered call still reaches Slack through either handle.
    const post = (id: string) => use(app, { delegation_id: id, url: 'https://slack.com/api/chat.postMessage', method: 'POST', body: { channel: 'C1', text: 'hi' } });
    expect((await post(oldHandle)).status).toBe(200);
    expect((await post(fresh.body.delegation_id)).status).toBe(200);
    expect(hx.fake.upstream.filter((u) => u.url === 'https://slack.com/api/chat.postMessage')).toHaveLength(2);
  });

  it('Google (enforcement broker): a call to a removed scope\'s endpoint is refused before upstream', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const oldHandle = (await delegate(hx.app, { connection_id: conn })).body.delegation_id;
    const n = await narrow(hx, client, conn, { subject: 'user-a', scopes: ['calendar.readonly'] });
    expect(n.status).toBe(200);
    expect(n.body.enforcement).toBe('broker');
    expect((await delegate(hx.app, { connection_id: conn, scopes: ['gmail.send'] })).status).toBe(403);
    const send = await use(hx.app, { delegation_id: oldHandle, url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send', method: 'POST', body: {} });
    expect(send.status).not.toBe(200);
    expect(hx.fake.upstream.map((u) => u.url)).not.toContain('https://gmail.googleapis.com/gmail/v1/users/me/messages/send');
    expect((await use(hx.app, { delegation_id: oldHandle, url: CALENDAR_URL, method: 'GET' })).status).toBe(200);
  });

  it('raw tokens only when the delegated scopes cover everything the provider granted', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app, { allow_raw_tokens: true });
    const conn = await connectAndActivate(hx.app, client);
    expect((await delegate(hx.app, { connection_id: conn, token_format: 'raw' })).status).toBe(200);
    // A request for fewer scopes than the token carries: handle only.
    const partial = await delegate(hx.app, { connection_id: conn, token_format: 'raw', scopes: ['calendar.readonly'] });
    expect(partial.status).toBe(400);
    expect(partial.body.access_token).toBeUndefined();
    expect((await delegate(hx.app, { connection_id: conn, scopes: ['calendar.readonly'] })).status).toBe(200);
    // A narrowed grant: never raw again.
    expect((await narrow(hx, client, conn, { subject: 'user-a', scopes: ['calendar.readonly'] })).status).toBe(200);
    const narrowed = await delegate(hx.app, { connection_id: conn, token_format: 'raw' });
    expect(narrowed.status).toBe(400);
    expect(narrowed.body.access_token).toBeUndefined();
    expect((await delegate(hx.app, { connection_id: conn })).status).toBe(200);
  });

  it('an update confirmed before a narrow and activated after it is refused; the narrow stays in force', async () => {
    const hx = await harness();
    const { app, server } = hx;
    const client = await registerClient(app);
    const conn = await connectAndActivate(app, client);
    const ctx = server.link!.context;
    const oldTokens = await ctx.secrets.get(conn as never);
    const b = new Browser();
    const uri = await par(app, client, { intent: 'update', connection_id: conn, scopes: { google: ['calendar.readonly', 'gmail.send'] }, required_scopes: {} });
    const pu = await toProvider(app, b, uri);
    const r = resultOf(await confirm(app, b, (await callback(app, b, pu, 'google', 'auth-code-2')).text, ['calendar.readonly', 'gmail.send']));
    if (r.outcome !== 'success') throw new Error('update flow failed');
    const [open] = await ctx.store.listOpenAccountTransactions({ provider: 'google', provider_account_id: 'google-sub-alice' }).then(
      (txs) => txs.filter((t) => t.connection_id === conn),
    );
    expect(open).toBeDefined();
    expect(await ctx.secrets.getStaged(open.tid as never)).not.toBeNull();

    expect((await narrow(hx, client, conn, { subject: 'user-a', scopes: ['calendar.readonly'] })).status).toBe(200);
    const revocationsBefore = hx.fake.revocations.length;
    const act = await activate(app, client, conn, r.code);
    expect(act.status).toBe(401);
    expect(act.text).toBe(JSON.stringify(LINK_OPAQUE_FAILURE_BODY));
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly']);
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'active' });
    expect(await ctx.secrets.get(conn as never)).toEqual(oldTokens);
    // The staged tokens are cleaned up; the live connection blocks revocation.
    expect(await ctx.secrets.getStaged(open.tid as never)).toBeNull();
    expect(hx.fake.revocations.length).toBe(revocationsBefore);
    expect((await ctx.store.getTransaction(open.tid))!.outcome).toBe('failed');
  });
});

describe('polish review: startup heal and stale transactions', () => {
  it('a later successful reauth is not undone by the heal of an earlier unsettled activation', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const first = await connectFlow(hx.app, client);
    const ctx = hx.server.link!.context;
    const secrets = ctx.secrets;
    const origCommit = secrets.commitStaged.bind(secrets);
    const origDelete = secrets.deleteStaged.bind(secrets);
    // The token move fails and the staged copy cannot be deleted (a disk error).
    secrets.commitStaged = async () => { throw new Error('disk'); };
    secrets.deleteStaged = async () => { throw new Error('disk'); };
    try {
      expect((await activate(hx.app, client, first.connection_id, first.code)).status).toBe(401);
    } finally {
      secrets.commitStaged = origCommit;
      secrets.deleteStaged = origDelete;
    }
    expect((await ctx.store.getConnection(first.connection_id))!.status).toBe('needs_reauth');
    const [stale] = await ctx.store.listUnsettledActivations();
    expect(stale).toBeDefined();

    // The app reconnects the account; it works.
    const re = await request(hx.app).post(`/link/v1/connections/${first.connection_id}/reauth`).set('Authorization', client.auth).send({ subject: 'user-a', agent_id: 'server-agent' });
    const b = new Browser();
    const pu = await toProvider(hx.app, b, re.body.request_uri);
    const rr = resultOf(await confirm(hx.app, b, (await callback(hx.app, b, pu, 'google', 'auth-code-2')).text, ['calendar.readonly', 'gmail.send']));
    if (rr.outcome !== 'success') throw new Error('reauth failed');
    expect((await activate(hx.app, client, first.connection_id, rr.code)).body.status).toBe('active');
    const liveTokens = await ctx.secrets.get(first.connection_id as never);
    const revocationsBefore = hx.fake.revocations.length;

    // Restart: the stale transaction is cleaned up locally and settled only.
    const next = await hx.restart();
    expect((await next.link!.ready).outcomes).toEqual([{ tid: stale.tid, outcome: 'stale' }]);
    expect((await next.link!.healed).follow_ups).toEqual([{ tid: stale.tid, outcome: 'skipped_stale' }]);
    const after = next.link!.context;
    expect(await after.store.getConnection(first.connection_id)).toMatchObject({ status: 'active' });
    expect(await after.secrets.get(first.connection_id as never)).toEqual(liveTokens);
    expect(await after.secrets.getStaged(stale.tid as never)).toBeNull();
    expect(await after.store.listUnsettledActivations()).toEqual([]);
    expect(hx.fake.revocations.length).toBe(revocationsBefore);
    expect((await delegate(hx.app, { connection_id: first.connection_id })).status).toBe(200);
  });
});

// ── Second review pass (formerly zz-review-polish2) ─────────────────────────

describe('second review: Google narrowing is enforced per API family only', () => {
  const GMAIL_SEND_WWW = 'https://www.googleapis.com/gmail/v1/users/me/messages/send';

  async function googleConnection(hx: Harness, scopes: string[]) {
    hx.fake.googleScope = ['openid', 'https://www.googleapis.com/auth/userinfo.email', ...scopes.map((s) => `https://www.googleapis.com/auth/${s}`)].join(' ');
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client, {
      parOverrides: { scopes: { google: scopes }, required_scopes: {} },
      scopes,
      confirmScopes: scopes,
    });
    return { client, conn };
  }

  function narrow(hx: Harness, client: { auth: string }, id: string, scopes: string[]) {
    return request(hx.app).post(`/link/v1/connections/${id}/narrow`).set('Authorization', client.auth).send({ subject: 'user-a', scopes });
  }

  it('a same-family narrow answers record, and the call still reaches Google (known limit)', async () => {
    // Known Phase 1 limit: the broker tells Google API families apart, not
    // scopes inside a family, so gmail.readonly still unlocks gmail send.
    const hx = await harness();
    const { client, conn } = await googleConnection(hx, ['gmail.readonly', 'gmail.send']);
    const old = (await delegate(hx.app, { connection_id: conn })).body.delegation_id;
    const n = await narrow(hx, client, conn, ['gmail.readonly']);
    expect(n.status).toBe(200);
    expect(n.body.removed_scopes).toEqual(['gmail.send']);
    expect(n.body.enforcement).toBe('record');
    const fresh = (await delegate(hx.app, { connection_id: conn })).body;
    expect(fresh.scopes).toEqual(['gmail.readonly']);
    expect((await delegate(hx.app, { connection_id: conn, scopes: ['gmail.send'] })).status).toBe(403);
    for (const id of [old, fresh.delegation_id]) {
      expect((await use(hx.app, { delegation_id: id, url: GMAIL_SEND_WWW, method: 'POST', body: { raw: 'x' } })).status).toBe(200);
    }
    expect(hx.fake.upstream.filter((u) => u.url === GMAIL_SEND_WWW)).toHaveLength(2);
    // Repeating the narrow (idempotent) gives the same honest answer.
    const again = await narrow(hx, client, conn, ['gmail.readonly']);
    expect(again.body).toMatchObject({ changed: false, enforcement: 'record' });
  });

  it('a whole-family narrow answers broker, and the call is refused before Google', async () => {
    const hx = await harness();
    const { client, conn } = await googleConnection(hx, ['calendar.readonly', 'gmail.readonly', 'gmail.send']);
    const old = (await delegate(hx.app, { connection_id: conn })).body.delegation_id;
    const n = await narrow(hx, client, conn, ['calendar.readonly']);
    expect(n.status).toBe(200);
    expect(n.body.removed_scopes).toEqual(['gmail.readonly', 'gmail.send']);
    expect(n.body.enforcement).toBe('broker');
    const send = await use(hx.app, { delegation_id: old, url: GMAIL_SEND_WWW, method: 'POST', body: { raw: 'x' } });
    expect(send.status).not.toBe(200);
    expect(hx.fake.upstream.map((u) => u.url)).not.toContain(GMAIL_SEND_WWW);
    expect((await use(hx.app, { delegation_id: old, url: CALENDAR_URL, method: 'GET' })).status).toBe(200);
    const again = await narrow(hx, client, conn, ['calendar.readonly']);
    expect(again.body).toMatchObject({ changed: false, enforcement: 'broker' });
  });

  it('a mixed removal (one whole family plus one same-family scope) answers record', async () => {
    const hx = await harness();
    const { client, conn } = await googleConnection(hx, ['calendar.readonly', 'gmail.readonly', 'gmail.send']);
    const old = (await delegate(hx.app, { connection_id: conn })).body.delegation_id;
    const n = await narrow(hx, client, conn, ['gmail.readonly']);
    expect(n.status).toBe(200);
    expect(n.body.removed_scopes).toEqual(['calendar.readonly', 'gmail.send']);
    expect(n.body.enforcement).toBe('record');
    // The calendar family is closed; gmail send is not.
    expect((await use(hx.app, { delegation_id: old, url: CALENDAR_URL, method: 'GET' })).status).not.toBe(200);
    expect((await use(hx.app, { delegation_id: old, url: GMAIL_SEND_WWW, method: 'POST', body: { raw: 'x' } })).status).toBe(200);
  });

  it('the family rule matches the broker table: no family means record', () => {
    expect(googleRemovalIsBrokerEnforced(['gmail.send'], ['calendar.readonly'])).toBe(true);
    expect(googleRemovalIsBrokerEnforced(['gmail.send'], ['gmail.readonly'])).toBe(false);
    expect(googleRemovalIsBrokerEnforced(['https://www.googleapis.com/auth/gmail.send'], ['https://www.googleapis.com/auth/gmail.readonly'])).toBe(false);
    expect(googleRemovalIsBrokerEnforced(['drive.file'], ['drive'])).toBe(false);
    expect(googleRemovalIsBrokerEnforced(['tasks'], ['calendar.readonly'])).toBe(false);
    expect(googleRemovalIsBrokerEnforced(['calendar.events', 'calendar.readonly'], ['contacts.readonly'])).toBe(true);
  });
});

describe('second review: activation compares grant scopes, not versions', () => {
  it('a reauth confirmed while active still activates after the old token died (a status change alone does not refuse)', async () => {
    const hx = await harness();
    const { app, server } = hx;
    const ctx = server.link!.context;
    const client = await registerClient(app);
    const conn = await connectAndActivate(app, client);
    const re = await request(app).post(`/link/v1/connections/${conn}/reauth`).set('Authorization', client.auth).send({ subject: 'user-a', agent_id: 'server-agent' });
    expect(re.status).toBe(201);
    const b = new Browser();
    const pu = await toProvider(app, b, re.body.request_uri);
    const r = resultOf(await confirm(app, b, (await callback(app, b, pu, 'google', 'auth-code-2')).text, ['calendar.readonly', 'gmail.send']));
    if (r.outcome !== 'success') throw new Error('reauth flow failed');
    const [open] = (await ctx.store.listOpenAccountTransactions({ provider: 'google', provider_account_id: 'google-sub-alice' }))
      .filter((t) => t.connection_id === conn);
    const staged = await ctx.secrets.getStaged(open.tid as never);
    expect(staged).not.toBeNull();

    // Meanwhile an agent call refreshes the old token and the provider says
    // invalid_grant (the usual reason a user reconnects).
    const tokens = await ctx.secrets.get(conn as never);
    await ctx.secrets.put(conn as never, { ...tokens!, expires_at: new Date(Date.now() - 1000).toISOString() });
    hx.fake.refreshMode = 'invalid_grant';
    const d = await delegate(app, { connection_id: conn });
    expect(d.body.error).toBe('grant_revoked');
    expect((await ctx.store.getConnection(conn))!.status).toBe('needs_reauth');

    // This reauth is exactly what repairs the dead token.
    const act = await activate(app, client, conn, r.code);
    expect(act.status).toBe(200);
    expect(act.body.status).toBe('active');
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'active' });
    expect((await ctx.secrets.get(conn as never))!.access_token).toBe(staged!.access_token);
    hx.fake.refreshMode = 'ok';
    expect((await delegate(app, { connection_id: conn })).status).toBe(200);
  });

  it('a narrow that lands between the confirm screen check and the confirm commit is caught at activation (connect onto a live connection)', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const store = hx.server.link!.context.store;
    const b = new Browser();
    const uri = await par(hx.app, client, { scopes: { google: ['calendar.readonly', 'gmail.send'] }, required_scopes: {} });
    const page = await callback(hx.app, b, await toProvider(hx.app, b, uri));
    expect(page.text).toContain('id="cred-link-reconnect"');

    // The narrow commits after handleConfirm compared the basis, just before
    // commitConfirm records what the screen showed.
    const original = store.commitConfirm.bind(store);
    let shown: unknown;
    store.commitConfirm = async (input) => {
      shown = input.shown_grant_scopes;
      const grant = await store.getGrantForConnection(conn);
      await store.narrowGrant({ grant_id: grant!.id, scopes: ['calendar.readonly'], expected_version: grant!.version, now: new Date().toISOString() });
      return original(input);
    };
    let result;
    try {
      result = resultOf(await confirm(hx.app, b, page.text, ['calendar.readonly', 'gmail.send']));
    } finally {
      store.commitConfirm = original;
    }
    expect(shown).toEqual(['calendar.readonly', 'gmail.send']);
    if (result.outcome !== 'success') throw new Error('confirm failed');
    const act = await activate(hx.app, client, conn, result.code);
    expect(act.status).toBe(401);
    expect(act.text).toBe(JSON.stringify(LINK_OPAQUE_FAILURE_BODY));
    expect((await store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly']);
  });

  it('the same race on an update is caught too', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const store = hx.server.link!.context.store;
    const b = new Browser();
    const uri = await par(hx.app, client, { intent: 'update', connection_id: conn, scopes: { google: ['calendar.readonly', 'gmail.send'] }, required_scopes: {} });
    const page = await callback(hx.app, b, await toProvider(hx.app, b, uri), 'google', 'auth-code-2');
    const original = store.commitConfirm.bind(store);
    let shown: unknown;
    store.commitConfirm = async (input) => {
      shown = input.shown_grant_scopes;
      const grant = await store.getGrantForConnection(conn);
      await store.narrowGrant({ grant_id: grant!.id, scopes: ['calendar.readonly'], expected_version: grant!.version, now: new Date().toISOString() });
      return original(input);
    };
    let result;
    try {
      result = resultOf(await confirm(hx.app, b, page.text, ['calendar.readonly', 'gmail.send']));
    } finally {
      store.commitConfirm = original;
    }
    expect(shown).toEqual(['calendar.readonly', 'gmail.send']);
    if (result.outcome !== 'success') throw new Error('confirm failed');
    expect((await activate(hx.app, client, conn, result.code)).status).toBe(401);
    expect((await store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly']);
  });

  it('a first connect passes null: the screen showed a new connection', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const store = hx.server.link!.context.store;
    const original = store.commitConfirm.bind(store);
    let shown: unknown = 'unset';
    store.commitConfirm = async (input) => {
      shown = input.shown_grant_scopes;
      return original(input);
    };
    try {
      await connectAndActivate(hx.app, client);
    } finally {
      store.commitConfirm = original;
    }
    expect(shown).toBeNull();
  });
});

describe('final review: a failed token move still intersects the Permissions', () => {
  it('narrowing update, token move fails, a later update re-adds the scope: the agent\'s Permission does not get it back', async () => {
    const hx = await harness();
    const { app } = hx;
    const client = await registerClient(app);
    const conn = await connectAndActivate(app, client);
    const ctx = hx.server.link!.context;
    const perm = await request(app).post(`/link/v1/connections/${conn}/permissions`).set('Authorization', client.auth)
      .send({ agent_id: 'agent-2', scopes: ['calendar.readonly', 'gmail.send'] });
    expect(perm.status).toBe(200);

    // A narrowing update whose token move fails after the database commit.
    const updateTo = async (scopes: string[], code: string) => {
      const b = new Browser();
      const uri = await par(app, client, { intent: 'update', connection_id: conn, scopes: { google: ['calendar.readonly', 'gmail.send'] }, required_scopes: {} });
      const page = await callback(app, b, await toProvider(app, b, uri, { scopes: ['calendar.readonly', 'gmail.send'] }), 'google', code);
      const r = resultOf(await confirm(app, b, page.text, scopes));
      if (r.outcome !== 'success') throw new Error('update failed');
      return r;
    };
    const narrowing = await updateTo(['calendar.readonly'], 'auth-code-2');
    const secrets = ctx.secrets;
    const origCommit = secrets.commitStaged.bind(secrets);
    secrets.commitStaged = async () => { throw new Error('disk'); };
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      expect((await activate(app, client, conn, narrowing.code)).status).toBe(401);
    } finally {
      secrets.commitStaged = origCommit;
    }
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly']);
    expect((await ctx.permissions.get('agent-2', conn))!.allowedScopes).toEqual(['calendar.readonly']);

    // A later update re-adds gmail.send to the grant; agent-2 was never
    // granted it again by the backend.
    const widening = await updateTo(['calendar.readonly', 'gmail.send'], 'auth-code-3');
    expect((await activate(app, client, conn, widening.code)).status).toBe(200);
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(['calendar.readonly', 'gmail.send']);
    expect((await ctx.permissions.get('agent-2', conn))!.allowedScopes).toEqual(['calendar.readonly']);
  });
});


// ── Review of main: activation ordering (formerly zz-review-main) ───────────

describe('review of main: activation settles only after the intersect, and never on a failed needs_reauth write', () => {
  const BOTH = ['calendar.readonly', 'gmail.send'];
  const CAL = ['calendar.readonly'];

  async function updateTo(hx: Harness, client: { client_id: string; auth: string }, conn: string, confirmScopes: string[], agentId?: string) {
    const uri = await par(hx.app, client as never, {
      intent: 'update', connection_id: conn, scopes: { google: BOTH }, required_scopes: {},
      ...(agentId !== undefined ? { agent_id: agentId } : { agent_id: undefined }),
    });
    const b = new Browser();
    const page = await callback(hx.app, b, await toProvider(hx.app, b, uri, { scopes: BOTH }), 'google', 'auth-code-x');
    const r = resultOf(await confirm(hx.app, b, page.text, confirmScopes));
    if (r.outcome !== 'success') throw new Error('update failed');
    return r;
  }

  it('a failed token move whose needs_reauth write also fails keeps the staged copy and leaves the transaction for the heal, which reverts it', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client, { confirmScopes: CAL });
    const ctx = hx.server.link!.context;
    const oldTokens = (await ctx.secrets.get(conn as never))!;
    const pending = await updateTo(hx, client, conn, BOTH);

    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(VaultLinkSecretStore.prototype, 'commitStaged').mockRejectedValueOnce(new Error('vault write failed'));
    vi.spyOn(SqliteLinkStore.prototype, 'setConnectionStatus').mockRejectedValueOnce(new Error('SQLITE_BUSY'));
    const res = await activate(hx.app, client, pending.connection_id, pending.code);
    expect(res.status).toBe(401);
    expect(res.text).toBe(JSON.stringify(LINK_OPAQUE_FAILURE_BODY));
    expect((await ctx.store.getGrantForConnection(conn))!.scopes).toEqual(BOTH);
    // Nothing was revoked or deleted: the heal needs the staged copy.
    const [left] = await ctx.store.listUnsettledActivations();
    expect(left).toBeDefined();
    expect(await ctx.secrets.getStaged(left.tid as never)).not.toBeNull();
    expect(hx.fake.revocations).toEqual([]);
    vi.restoreAllMocks();

    const next = await hx.restart();
    expect((await next.link!.ready).outcomes).toEqual([{ tid: left.tid, outcome: 'reverted' }]);
    await next.link!.healed;
    const after = next.link!.context;
    expect(await after.store.getConnection(conn)).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect((await after.secrets.get(conn as never))!.access_token).toBe(oldTokens.access_token);
  });

  it('a failed onGrantUpdated leaves the activation unsettled; the next start intersects and settles, and a later widening for another agent does not hand the old agent the removed scope', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const ctx0 = hx.server.link!.context;
    expect((await ctx0.permissions.get('server-agent', conn))!.allowedScopes).toEqual(BOTH);

    const narrowing = await updateTo(hx, client, conn, CAL);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(ctx0.hooks, 'onGrantUpdated').mockRejectedValueOnce(new Error('permission store down'));
    const res = await activate(hx.app, client, narrowing.connection_id, narrowing.code);
    expect(res.status).toBe(401);
    expect(res.text).toBe(JSON.stringify(LINK_OPAQUE_FAILURE_BODY));
    expect((await ctx0.store.getGrantForConnection(conn))!.scopes).toEqual(CAL);
    const [left] = await ctx0.store.listUnsettledActivations();
    expect(left).toBeDefined();
    expect((await ctx0.permissions.get('server-agent', conn))!.allowedScopes).toEqual(BOTH);

    const next = await hx.restart();
    expect((await next.link!.ready).outcomes).toEqual([{ tid: left.tid, outcome: 'settled' }]);
    expect((await next.link!.context.permissions.get('server-agent', conn))!.allowedScopes).toEqual(CAL);
    expect(await next.link!.context.store.listUnsettledActivations()).toEqual([]);

    const widening = await updateTo(hx, client, conn, BOTH, 'other-agent');
    expect((await activate(hx.app, client, widening.connection_id, widening.code)).status).toBe(200);
    expect((await delegate(hx.app, { connection_id: conn, scopes: ['gmail.send'] })).status).toBe(403);
    expect((await next.link!.context.permissions.get('other-agent', conn))!.allowedScopes).toEqual(BOTH);
  });

  it('every activation of an existing grant runs onGrantUpdated with the true previous scopes, also when they did not change', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const spy = vi.spyOn(hx.server.link!.context.hooks, 'onGrantUpdated');
    const same = await updateTo(hx, client, conn, BOTH);
    expect((await activate(hx.app, client, same.connection_id, same.code)).status).toBe(200);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0][0]).toMatchObject({ previous_scopes: BOTH, reason: 'activate' });
    expect(spy.mock.calls[0][0].grant.scopes).toEqual(BOTH);
    const narrower = await updateTo(hx, client, conn, CAL);
    expect((await activate(hx.app, client, narrower.connection_id, narrower.code)).status).toBe(200);
    expect(spy.mock.calls[1][0]).toMatchObject({ previous_scopes: BOTH });
    expect(spy.mock.calls[1][0].grant.scopes).toEqual(CAL);
    expect(await hx.server.link!.context.store.listUnsettledActivations()).toEqual([]);
  });
});

// ── Verification of the activation fix (formerly zz-review-fix) ─────────────

describe('verification: quarantine after a failed token move whose needs_reauth write failed', () => {
  const BOTH = ['calendar.readonly', 'gmail.send'];
  const CAL = ['calendar.readonly'];
  const G_CAL_ONLY = 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/calendar.readonly';
  const G_BOTH = 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/gmail.send';

  async function updateTo(hx: Harness, client: { client_id: string; auth: string }, conn: string, confirmScopes: string[], agentId?: string) {
    const uri = await par(hx.app, client as never, {
      intent: 'update', connection_id: conn, scopes: { google: BOTH }, required_scopes: {},
      ...(agentId !== undefined ? { agent_id: agentId } : { agent_id: undefined }),
    });
    const b = new Browser();
    const page = await callback(hx.app, b, await toProvider(hx.app, b, uri, { scopes: BOTH }), 'google', 'auth-code-x');
    const r = resultOf(await confirm(hx.app, b, page.text, confirmScopes));
    if (r.outcome !== 'success') throw new Error('update failed');
    return r;
  }

  /** A narrow connection, then a widening update whose move and status write fail. */
  async function quarantined() {
    const hx = await harness();
    hx.fake.googleScope = G_CAL_ONLY;
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client, { confirmScopes: CAL });
    const ctx = hx.server.link!.context;
    const oldTokens = (await ctx.secrets.get(conn as never))!;
    const handle = (await delegate(hx.app, { connection_id: conn, scopes: CAL })).body.delegation_id as string;
    hx.fake.googleScope = G_BOTH;
    const pending = await updateTo(hx, client, conn, BOTH);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const commit = vi.spyOn(VaultLinkSecretStore.prototype, 'commitStaged').mockRejectedValueOnce(new Error('vault write failed'));
    const status = vi.spyOn(SqliteLinkStore.prototype, 'setConnectionStatus')
      .mockRejectedValueOnce(new Error('SQLITE_BUSY'));
    expect((await activate(hx.app, client, pending.connection_id, pending.code)).status).toBe(401);
    // One attempt only: the quarantine, not a retry, covers a failed write.
    expect(status).toHaveBeenCalledTimes(1);
    commit.mockRestore();
    status.mockRestore();
    const [left] = await ctx.store.listUnsettledActivations();
    expect(left).toBeDefined();
    return { hx, client, conn, ctx, oldTokens, handle, left };
  }

  it('denies delegate, use and the refresh endpoint in process without a provider call; the next start reverts', async () => {
    const { hx, client, conn, ctx, oldTokens, handle, left } = await quarantined();
    expect(ctx.quarantine.has(conn)).toBe(true);
    // The old tokens are expired, so any use would refresh them.
    await ctx.secrets.put(conn as never, { ...oldTokens, expires_at: new Date(Date.now() - 1000).toISOString() });
    const fetches = hx.fake.spy!.mock.calls.length;

    const d = await delegate(hx.app, { connection_id: conn, scopes: CAL });
    expect(d.status).toBe(403);
    expect(d.body.error).toBe('reauth_required');
    const u = await use(hx.app, { delegation_id: handle, url: CALENDAR_URL, method: 'GET' });
    expect(u.status).toBe(403);
    expect(u.body.error).toBe('reauth_required');
    const r = await request(hx.app).post(`/link/v1/connections/${conn}/refresh`).set('Authorization', client.auth);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect(hx.fake.spy!.mock.calls.length).toBe(fetches);
    expect(hx.fake.refreshCalls).toBe(0);
    expect(hx.fake.upstream).toEqual([]);
    // Nothing touched the connection row.
    expect(await ctx.store.getConnection(conn)).toMatchObject({ status: 'active' });

    const next = await hx.restart();
    expect((await next.link!.ready).outcomes).toEqual([{ tid: left.tid, outcome: 'reverted' }]);
    await next.link!.healed;
    expect(await next.link!.context.store.getConnection(conn)).toMatchObject({ status: 'needs_reauth', status_reason: 'reauth_required' });
    expect(next.link!.context.quarantine.has(conn)).toBe(false);
  });

  it('reviewer: a scope-reporting refresh of the old tokens can no longer rewrite the row, so the next start reverts', async () => {
    const { hx, conn, ctx, oldTokens, left } = await quarantined();
    await ctx.secrets.put(conn as never, { ...oldTokens, expires_at: new Date(Date.now() - 1000).toISOString() });
    hx.fake.googleRefreshScope = G_CAL_ONLY;
    expect((await delegate(hx.app, { connection_id: conn, scopes: CAL })).status).toBe(403);
    expect(hx.fake.refreshCalls).toBe(0);

    const next = await hx.restart();
    expect((await next.link!.ready).outcomes).toEqual([{ tid: left.tid, outcome: 'reverted' }]);
    expect(await next.link!.context.store.getConnection(conn)).toMatchObject({ status: 'needs_reauth' });
  });

  it('a later successful activation of the connection clears the quarantine', async () => {
    const { hx, client, conn, ctx } = await quarantined();
    const again = await updateTo(hx, client, conn, BOTH);
    expect((await activate(hx.app, client, again.connection_id, again.code)).status).toBe(200);
    expect(ctx.quarantine.has(conn)).toBe(false);
    expect((await delegate(hx.app, { connection_id: conn, scopes: CAL })).status).toBe(200);
  });

  it('a revoke clears it too', async () => {
    const { hx, client, conn, ctx } = await quarantined();
    expect((await request(hx.app).delete(`/link/v1/connections/${conn}`).set('Authorization', client.auth).query({ subject: 'user-a' })).status).toBe(200);
    expect(ctx.quarantine.has(conn)).toBe(false);
  });
});

describe('verification: the hook-failure branch still writes the grant audit record', () => {
  it('a failed onGrantUpdated leaves the success grant audit event for the committed change', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const conn = await connectAndActivate(hx.app, client);
    const ctx = hx.server.link!.context;
    const uri = await par(hx.app, client, { intent: 'update', connection_id: conn, scopes: { google: ['calendar.readonly', 'gmail.send'] }, required_scopes: {} });
    const b = new Browser();
    const page = await callback(hx.app, b, await toProvider(hx.app, b, uri), 'google', 'auth-code-x');
    const r = resultOf(await confirm(hx.app, b, page.text, ['calendar.readonly']));
    if (r.outcome !== 'success') throw new Error('update failed');
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(ctx.hooks, 'onGrantUpdated').mockRejectedValueOnce(new Error('permission store down'));
    expect((await activate(hx.app, client, conn, r.code)).status).toBe(401);
    const events = hx.server.vault.queryAuditEvents({ limit: 200 })
      .filter((e) => e.resource.type === 'grant' && (e.metadata as { reason?: string }).reason === 'activate' && e.outcome === 'success');
    const narrowing = events.filter((e) => {
      const m = e.metadata as { before_scopes?: string[]; after_scopes?: string[] };
      return JSON.stringify(m.before_scopes) === JSON.stringify(['calendar.readonly', 'gmail.send'])
        && JSON.stringify(m.after_scopes) === JSON.stringify(['calendar.readonly']);
    });
    expect(narrowing).toHaveLength(1);
  });
});

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
import { ReservedVaultUserIdError } from '@credninja/vault';
import { createServer } from '../server.js';
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
      tofuStorage: 'file' as const, tofuPath: '/tmp/x-tofu.json', adminToken: ADMIN_TOKEN, agentToken: AGENT_TOKEN, providers: [],
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
      await agent(request(hx.app).get('/api/token/google')),
      await agent(request(hx.app).delete('/api/token/google')),
      await agent(request(hx.app).get('/api/v1/connections')),
      await agent(request(hx.app).delete('/api/v1/connections/google')),
      await agent(request(hx.app).post('/api/v1/delegate').send({ service: 'google' })),
      await request(hx.app).get('/providers').set('Authorization', `Bearer ${ADMIN_TOKEN}`),
    ];
    for (const res of responses) expect(res.status).toBe(400);
  });

  it('subdelegate turns a ReservedVaultUserIdError from the vault into a 400', async () => {
    const hx = await harness({ linkEnabled: false });
    const vault = hx.server.vault;
    const nowIso = new Date().toISOString();
    await vault.registerAgent!({ id: 'agt_child', did: 'did:key:z6MkChild', name: 'child', fingerprint: 'fp_child', scopeCeiling: [], status: 'active', createdBy: 'admin', createdAt: nowIso, updatedAt: nowIso });
    await vault.createPermission!({ agentId: 'agt_child', connectionId: 'google', allowedScopes: ['calendar.readonly'], delegatable: true, maxDelegationDepth: 3, requiresApproval: false, createdBy: 'admin' });
    const seed = crypto.scryptSync('link-test-passphrase', 'cred:local-receipt:v1', 32);
    const key = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'did:key:local-cred', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600,
      sub: 'did:key:z6MkParent', service: 'google', scopes: ['calendar.readonly'], userId: 'default', appClientId: 'local',
      delegationId: 'del_parent', chainDepth: 0,
    })).toString('base64url');
    const receipt = `${header}.${payload}.${crypto.sign(null, Buffer.from(`${header}.${payload}`), key).toString('base64url')}`;
    vi.spyOn(vault, 'get').mockRejectedValue(new ReservedVaultUserIdError('get'));
    const res = await request(hx.app).post('/api/v1/subdelegate').set('Authorization', `Bearer ${AGENT_TOKEN}`)
      .send({ parent_receipt: receipt, agent_did: 'did:key:z6MkChild', service: 'google', scopes: ['calendar.readonly'] });
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
    const handle = async (service: string) => (await delegate(hx.app, { service, token_format: 'handle' })).body.delegation_id as string;
    const lin = await handle('linear');
    const hub = await handle('hubspot');
    const slk = await handle('slack');
    const call = (id: string, url: string, method = 'POST') => use(hx.app, { delegation_id: id, url, method, ...(method === 'GET' ? {} : { body: {} }) });

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
    const handle = async (service: string) => (await delegate(hx.app, { service, token_format: 'handle' })).body.delegation_id as string;
    const ids = { slack: await handle('slack'), hubspot: await handle('hubspot'), linear: await handle('linear'), google: await handle('google') };
    const call = (service: keyof typeof ids, url: string, method = 'GET') => use(hx.app, { delegation_id: ids[service], url, method });

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

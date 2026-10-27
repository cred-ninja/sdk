/**
 * Explicit user ids on the legacy (non-Link) routes:
 *   1. SINGLE_USER_MODE decides whether a request without user_id acts on
 *      the shared 'default' user or is refused with 400 user_id_required.
 *   2. An agent principal that carries a userId binds the request to it.
 *   3. GET /connect/:provider never takes the user id or scopes from the
 *      query string under the admin session cookie: consent_url and the
 *      admin page use single-use connect requests.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { createServer } from '../server.js';
import type { RequestAgentPrincipal, ServerConfig } from '../config.js';

const AGENT_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN_TOKEN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';

const dirs: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function makeConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-user-id-'));
  dirs.push(dir);
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'user-id-test-passphrase',
    vaultStorage: 'file',
    vaultPath: path.join(dir, 'vault.json'),
    tofuStorage: 'file',
    tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN_TOKEN,
    agentToken: AGENT_TOKEN,
    providers: [
      { slug: 'google', clientId: 'g-id', clientSecret: 'g-secret', defaultScopes: ['openid', 'email'] },
      { slug: 'github', clientId: 'gh-id', clientSecret: 'gh-secret', defaultScopes: ['repo'] },
    ],
    redirectBaseUri: BASE,
    webBotAuthNonceStore: 'memory',
    ...overrides,
  };
}

async function server(overrides: Partial<ServerConfig> = {}) {
  vi.spyOn(console, 'log').mockImplementation(() => undefined);
  const s = createServer(makeConfig(overrides));
  await s.vault.init();
  await s.tofu.init();
  return s;
}

const agent = (r: request.Test) => r.set('Authorization', `Bearer ${AGENT_TOKEN}`);
const admin = (r: request.Test) => r.set('Authorization', `Bearer ${ADMIN_TOKEN}`);

async function adminCookie(app: ReturnType<typeof createServer>['app']): Promise<string[]> {
  const login = await request(app).post('/admin/login').type('form').send({ admin_token: ADMIN_TOKEN, next: '/connect' });
  expect(login.status).toBe(303);
  return login.headers['set-cookie'] as unknown as string[];
}

type App = ReturnType<typeof createServer>['app'];

/**
 * Every legacy call site that resolves a user id, called without one.
 * `query` is appended to the path and `body` merged into the body, so the
 * same table names an explicit user id.
 */
function callSites(app: App, extra: { query?: string; body?: Record<string, unknown> } = {}): Array<[string, () => request.Test]> {
  const q = extra.query ? `?${extra.query}` : '';
  const b = extra.body ?? {};
  return [
    ['GET /providers', () => admin(request(app).get(`/providers${q}`))],
    ['DELETE /connect/:provider', () => admin(request(app).delete(`/connect/google${q}`))],
    ['GET /connect/:provider (Bearer)', () => admin(request(app).get(`/connect/google${q}`))],
    ['POST /connect/:provider/start', () => admin(request(app).post('/connect/google/start').send({ scopes: ['openid'], ...b }))],
    ['GET /api/token/:provider', () => agent(request(app).get(`/api/token/google${q}`))],
    ['GET /api/v1/connections', () => agent(request(app).get(`/api/v1/connections${q}`))],
    ['POST /api/v1/delegate', () => agent(request(app).post('/api/v1/delegate').send({ service: 'google', ...b }))],
    ['POST /api/v1/subdelegate', () => agent(request(app).post('/api/v1/subdelegate').send({ parent_receipt: 'a.b.c', agent_did: 'did:key:z', service: 'google', ...b }))],
    ['GET /api/v1/audit', () => agent(request(app).get(`/api/v1/audit${q}`))],
    ['GET /api/v1/audit/stream', () => agent(request(app).get(`/api/v1/audit/stream${q}`))],
    ['DELETE /api/token/:provider', () => agent(request(app).delete(`/api/token/google${q}`))],
    ['DELETE /api/v1/connections/:provider', () => agent(request(app).delete(`/api/v1/connections/google${q}`))],
  ];
}

describe('rule 1: SINGLE_USER_MODE', () => {
  it('multi-user mode (the default) refuses every call site that names no user id, naming SINGLE_USER_MODE', async () => {
    const { app } = await server();
    for (const [name, call] of callSites(app)) {
      const res = await call();
      expect({ name, status: res.status, error: res.body.error }).toEqual({ name, status: 400, error: 'user_id_required' });
      expect(res.body.message).toContain('SINGLE_USER_MODE');
    }
  });

  it('blank or whitespace-only user_id counts as missing', async () => {
    const { app } = await server();
    for (const blank of ['', '   ']) {
      for (const [name, call] of callSites(app, { query: `user_id=${encodeURIComponent(blank)}`, body: { user_id: blank } })) {
        const res = await call();
        expect({ name, blank, error: res.body.error }).toEqual({ name, blank, error: 'user_id_required' });
      }
    }
  });

  it('single-user mode accepts every call site without a user id (acting on default)', async () => {
    const { app } = await server({ singleUserMode: true });
    for (const [name, call] of callSites(app)) {
      // The stream stays open on success: checked separately below.
      if (name.includes('/stream')) continue;
      const res = await call();
      expect({ name, error: res.body?.error }).not.toEqual({ name, error: 'user_id_required' });
      expect({ name, bad: res.status === 400 && res.body?.error === 'user_id_required' }).toEqual({ name, bad: false });
    }
  });

  it('the audit stream opens without a user id in single-user mode only', async () => {
    for (const singleUserMode of [true, false]) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-user-id-sqlite-'));
      dirs.push(dir);
      const { app } = await server({ singleUserMode, vaultStorage: 'sqlite', vaultPath: path.join(dir, 'vault.sqlite') });
      const listener = app.listen(0, '127.0.0.1');
      await new Promise<void>((r) => listener.once('listening', () => r()));
      const port = (listener.address() as { port: number }).port;
      const status = await new Promise<number>((resolve, reject) => {
        const req = http.get({ host: '127.0.0.1', port, path: '/api/v1/audit/stream', headers: { Authorization: `Bearer ${AGENT_TOKEN}` } }, (res) => {
          resolve(res.statusCode ?? 0);
          req.destroy();
        });
        req.on('error', reject);
      });
      await new Promise<void>((r) => listener.close(() => r()));
      expect({ singleUserMode, status }).toEqual({ singleUserMode, status: singleUserMode ? 200 : 400 });
    }
  });

  it('acts on default in single-user mode, and an explicit default works in both modes', async () => {
    for (const singleUserMode of [true, false]) {
      const { app, vault } = await server({ singleUserMode });
      await vault.store({ provider: 'google', userId: 'default', accessToken: 'ya29.default', scopes: ['openid'] });
      const explicit = await agent(request(app).get('/api/token/google?user_id=default'));
      expect({ singleUserMode, status: explicit.status, token: explicit.body.accessToken }).toEqual({ singleUserMode, status: 200, token: 'ya29.default' });
      const delegated = await agent(request(app).post('/api/v1/delegate').send({ service: 'google', user_id: 'default' }));
      expect({ singleUserMode, status: delegated.status }).toEqual({ singleUserMode, status: 200 });
      const implicit = await agent(request(app).get('/api/token/google'));
      expect({ singleUserMode, status: implicit.status }).toEqual({ singleUserMode, status: singleUserMode ? 200 : 400 });
    }
  });

  it('an explicit user id is used as given (trimmed), never the shared user', async () => {
    const { app, vault } = await server({ singleUserMode: true });
    await vault.store({ provider: 'google', userId: 'default', accessToken: 'ya29.default', scopes: ['openid'] });
    await vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.alice', scopes: ['openid'] });
    expect((await agent(request(app).get('/api/token/google?user_id=%20alice%20'))).body.accessToken).toBe('ya29.alice');
    expect((await agent(request(app).get('/api/token/google?user_id=bob'))).status).toBe(404);
  });

  it('the browser pages answer a short readable page in multi-user mode', async () => {
    const { app } = await server();
    const cookie = await adminCookie(app);
    const page = await request(app).get('/connect').set('Cookie', cookie);
    expect(page.status).toBe(400);
    expect(page.headers['content-type']).toMatch(/html/);
    expect(page.text).toContain('?user_id=');
    expect(page.text).toContain('SINGLE_USER_MODE=true');
    const providersHtml = await request(app).get('/providers').set('Cookie', cookie).set('Accept', 'text/html,application/xhtml+xml');
    expect(providersHtml.status).toBe(400);
    expect(providersHtml.headers['content-type']).toMatch(/html/);
    expect(providersHtml.text).toContain('/providers?user_id=');
    // API clients still get JSON.
    const providersJson = await admin(request(app).get('/providers'));
    expect(providersJson.body.error).toBe('user_id_required');
    // With a user id the page renders.
    expect((await request(app).get('/connect?user_id=alice').set('Cookie', cookie)).status).toBe(200);
  });
});

describe('rule 2: a principal bound to a user id', () => {
  function verifierFor(principal: RequestAgentPrincipal) {
    return () => ({ ok: true as const, principal });
  }

  it('a request without user_id acts on the principal\'s user, in both modes', async () => {
    for (const singleUserMode of [false, true]) {
      const { app, vault } = await server({
        singleUserMode,
        agentRequestVerifier: verifierFor({ type: 'custom', principalId: 'agent-1', userId: 'alice' }),
      });
      await vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.alice', scopes: ['openid'] });
      await vault.store({ provider: 'google', userId: 'default', accessToken: 'ya29.default', scopes: ['openid'] });
      const token = await agent(request(app).get('/api/token/google'));
      expect({ singleUserMode, token: token.body.accessToken }).toEqual({ singleUserMode, token: 'ya29.alice' });
      const named = await agent(request(app).get('/api/token/google?user_id=alice'));
      expect(named.body.accessToken).toBe('ya29.alice');
      const delegated = await agent(request(app).post('/api/v1/delegate').send({ service: 'google', token_format: 'raw' }));
      expect(delegated.status).toBe(200);
      expect(delegated.body.user_id).toBe('alice');
      expect(delegated.body.access_token).toBe('ya29.alice');
    }
  });

  it('a request naming a different user_id is refused with 403 user_id_mismatch on every agent call site', async () => {
    const { app } = await server({ agentRequestVerifier: verifierFor({ type: 'custom', principalId: 'agent-1', userId: 'alice' }) });
    const agentSites = callSites(app, { query: 'user_id=bob', body: { user_id: 'bob' } })
      .filter(([name]) => name.includes('/api/'));
    expect(agentSites).toHaveLength(8);
    for (const [name, call] of agentSites) {
      const res = await call();
      expect({ name, status: res.status, error: res.body.error }).toEqual({ name, status: 403, error: 'user_id_mismatch' });
    }
  });

  it('admin routes ignore the rule; a principal without userId behaves as before plus rule 1', async () => {
    const { app } = await server({ agentRequestVerifier: verifierFor({ type: 'custom', principalId: 'agent-1' }) });
    expect((await agent(request(app).get('/api/token/google'))).body.error).toBe('user_id_required');
    expect((await agent(request(app).get('/api/token/google?user_id=bob'))).status).toBe(404);
    const bound = await server({ agentRequestVerifier: verifierFor({ type: 'custom', principalId: 'agent-1', userId: 'alice' }) });
    expect((await admin(request(bound.app).get('/providers'))).body.error).toBe('user_id_required');
    expect((await admin(request(bound.app).get('/providers?user_id=bob'))).status).toBe(200);
  });

  it('the consent_url of a bound principal is a connect request for that user', async () => {
    const { app, vault } = await server({ agentRequestVerifier: verifierFor({ type: 'custom', principalId: 'agent-1', userId: 'alice' }) });
    const res = await agent(request(app).post('/api/v1/delegate').send({ service: 'google', scopes: ['calendar.readonly'] }));
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('consent_required');
    const consent = new URL(res.body.consent_url);
    expect([...consent.searchParams.keys()]).toEqual(['request']);
    const start = await admin(request(app).get(`${consent.pathname}${consent.search}`));
    expect(start.status).toBe(302);
    const state = new URL(start.headers.location).searchParams.get('state')!;
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      access_token: 'ya29.alice-new', expires_in: 3600, token_type: 'Bearer',
    }), { status: 200, headers: { 'content-type': 'application/json' } }));
    try {
      const cb = await request(app).get(`/connect/google/callback?code=c&state=${encodeURIComponent(state)}`);
      expect(cb.status).toBe(200);
    } finally {
      fetchSpy.mockRestore();
    }
    const entry = await vault.get({ provider: 'google', userId: 'alice' });
    expect(entry?.accessToken).toBe('ya29.alice-new');
    expect(entry?.scopes).toEqual(['calendar.readonly']);
  });
});

describe('rule 3: connect requests', () => {
  async function consentUrl(app: App, userId = 'alice', service = 'google'): Promise<URL> {
    const res = await agent(request(app).post('/api/v1/delegate').send({ service, user_id: userId, appClientId: 'app_1', scopes: ['calendar.readonly'] }));
    expect(res.body.error).toBe('consent_required');
    return new URL(res.body.consent_url);
  }

  it('consent_url carries only a request id: no user id, no scopes, no app client id', async () => {
    const { app } = await server();
    const url = await consentUrl(app);
    expect(`${url.origin}${url.pathname}`).toBe(`${BASE}/connect/google`);
    expect([...url.searchParams.keys()]).toEqual(['request']);
    expect(url.searchParams.get('request')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url.toString()).not.toContain('alice');
  });

  it('a request id works once, under the session cookie, and ignores user_id and scopes in the query', async () => {
    const { app } = await server();
    const cookie = await adminCookie(app);
    const url = await consentUrl(app);
    const first = await request(app).get(`${url.pathname}${url.search}&user_id=mallory&scopes=drive`).set('Cookie', cookie);
    expect(first.status).toBe(302);
    const scope = new URL(first.headers.location).searchParams.get('scope') ?? '';
    expect(scope).toContain('calendar.readonly');
    expect(scope).not.toContain('drive');
    const again = await request(app).get(`${url.pathname}${url.search}`).set('Cookie', cookie);
    expect(again.status).toBe(400);
    expect(again.headers['content-type']).toMatch(/html/);
    expect(again.text).toContain('Request ID');
    expect(again.headers.location).toBeUndefined();
  });

  it('a request id expires after 10 minutes', async () => {
    const { app } = await server();
    const url = await consentUrl(app);
    const now = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(now + 10 * 60 * 1000 + 1);
    const res = await admin(request(app).get(`${url.pathname}${url.search}`));
    expect(res.status).toBe(400);
    expect(res.text).toContain('Request ID');
  });

  it('a request id is tied to its provider (and is spent by a mismatched use)', async () => {
    const { app } = await server();
    const url = await consentUrl(app);
    const wrong = await admin(request(app).get(`/connect/github${url.search}`));
    expect(wrong.status).toBe(400);
    expect(wrong.text).toContain('Request ID');
    expect((await admin(request(app).get(`${url.pathname}${url.search}`))).status).toBe(400);
    expect((await admin(request(app).get('/connect/google?request=unknown'))).status).toBe(400);
  });

  it('GET /connect/:provider with user_id and scopes under the session cookie starts nothing and redirects to the page', async () => {
    const { app } = await server({ singleUserMode: true });
    const cookie = await adminCookie(app);
    const res = await request(app).get('/connect/google?user_id=victim&scopes=drive').set('Cookie', cookie);
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/connect?user_id=victim');
    const bare = await request(app).get('/connect/google?scopes=drive').set('Cookie', cookie);
    expect(bare.status).toBe(303);
    expect(bare.headers.location).toBe('/connect');
  });

  it('the same with the Bearer admin token still starts OAuth (rule 1 applies)', async () => {
    const { app } = await server();
    const res = await admin(request(app).get('/connect/google?user_id=alice&scopes=calendar.readonly'));
    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(/accounts\.google\.com/);
    expect(new URL(res.headers.location).searchParams.get('scope')).toContain('calendar.readonly');
    expect((await admin(request(app).get('/connect/google'))).body.error).toBe('user_id_required');
  });

  it('POST /connect/:provider/start needs a JSON body, and its url starts OAuth once under the cookie', async () => {
    const { app } = await server();
    const cookie = await adminCookie(app);
    const form = await request(app).post('/connect/google/start').set('Cookie', cookie).type('form').send({ user_id: 'alice', scopes: 'openid' });
    expect(form.status).toBe(415);
    const text = await request(app).post('/connect/google/start').set('Cookie', cookie).set('Content-Type', 'text/plain').send('{"user_id":"alice"}');
    expect(text.status).toBe(415);
    const missing = await request(app).post('/connect/google/start').set('Cookie', cookie).send({ scopes: ['openid'] });
    expect(missing.body.error).toBe('user_id_required');
    expect((await request(app).post('/connect/slack/start').set('Cookie', cookie).send({ user_id: 'alice' })).status).toBe(404);
    expect((await request(app).post('/connect/google/start').send({ user_id: 'alice' })).status).toBe(401);

    const ok = await request(app).post('/connect/google/start').set('Cookie', cookie).send({ user_id: 'alice', scopes: ['calendar.readonly', 'gmail.send'] });
    expect(ok.status).toBe(200);
    expect(ok.body.url).toMatch(/^\/connect\/google\?request=[A-Za-z0-9_-]{43}$/);
    const started = await request(app).get(ok.body.url).set('Cookie', cookie);
    expect(started.status).toBe(302);
    const scope = new URL(started.headers.location).searchParams.get('scope') ?? '';
    expect(scope).toContain('calendar.readonly');
    expect(scope).toContain('gmail.send');
    expect((await request(app).get(ok.body.url).set('Cookie', cookie)).status).toBe(400);
  });

  it('the admin page starts connections through POST /connect/:provider/start', async () => {
    const { app } = await server();
    const cookie = await adminCookie(app);
    const page = await request(app).get('/connect?user_id=alice').set('Cookie', cookie);
    expect(page.status).toBe(200);
    expect(page.text).toContain("'/start'");
    expect(page.text).toContain("'Content-Type': 'application/json'");
    expect(page.text).not.toContain("'&scopes='");
  });
});

describe('reserved Link user ids', () => {
  it('are refused on every call site, by query, body and principal', async () => {
    const reserved = 'link:conn_0123456789abcdef0123456789abcdef';
    const { app } = await server();
    for (const [name, call] of callSites(app, { query: `user_id=${encodeURIComponent(reserved)}`, body: { user_id: reserved } })) {
      const res = await call();
      expect({ name, status: res.status, error: res.body.error }).toEqual({ name, status: 400, error: 'invalid_user_id' });
    }
    const cookie = await adminCookie(app);
    expect((await request(app).get(`/connect?user_id=${encodeURIComponent('link-staged:ltx_1')}`).set('Cookie', cookie)).status).toBe(400);

    const bound = await server({ agentRequestVerifier: () => ({ ok: true, principal: { type: 'custom', principalId: 'a', userId: reserved } }) });
    const res = await agent(request(bound.app).get('/api/token/google'));
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_user_id');
  });
});

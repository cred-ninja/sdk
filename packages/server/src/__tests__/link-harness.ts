/**
 * Test harness for Cred Link: a server on temp SQLite files, a fake set of
 * providers behind a fetch spy, and helpers that drive the hosted flow the
 * way a browser would (cookie jar of one cookie, envelopes from the pages).
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import request from 'supertest';
import { vi, expect } from 'vitest';
import type { MockInstance } from 'vitest';
import { parseLinkRedirectResult } from '@credninja/protocol';
import type { LinkResult } from '@credninja/protocol';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

export const AGENT_TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
export const ADMIN_TOKEN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
export const BASE = 'http://localhost:3456';
export const APP_ORIGIN = 'https://app.example.com';
export const APP_REDIRECT = 'https://app.example.com/cred/return';
export const COOKIE_NAME = '__Host-cred_link_tx';

export const PROVIDERS: ServerConfig['providers'] = [
  { slug: 'google', clientId: 'g-client', clientSecret: 'g-secret', defaultScopes: [] },
  { slug: 'github', clientId: 'gh-client', clientSecret: 'gh-secret', defaultScopes: [] },
  { slug: 'slack', clientId: 's-client', clientSecret: 's-secret', defaultScopes: [] },
  { slug: 'notion', clientId: 'n-client', clientSecret: 'n-secret', defaultScopes: [] },
  { slug: 'linear', clientId: 'l-client', clientSecret: 'l-secret', defaultScopes: [] },
  { slug: 'hubspot', clientId: 'h-client', clientSecret: 'h-secret', defaultScopes: [] },
  { slug: 'salesforce', clientId: 'sf-client', clientSecret: 'sf-secret', defaultScopes: [] },
];

export type Server = ReturnType<typeof createServer>;

export interface Harness {
  dir: string;
  config: ServerConfig;
  server: Server;
  app: Server['app'];
  fake: FakeProviders;
  close(): void;
}

export async function makeHarness(overrides: Partial<ServerConfig> = {}): Promise<Harness> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-link-'));
  const config: ServerConfig = {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'link-test-passphrase',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'file',
    tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN_TOKEN,
    agentToken: AGENT_TOKEN,
    providers: PROVIDERS,
    redirectBaseUri: BASE,
    webBotAuthNonceStore: 'memory',
    linkEnabled: true,
    ...overrides,
  };
  const server = createServer(config);
  await server.vault.init();
  await server.tofu.init();
  const fake = new FakeProviders();
  fake.install();
  return {
    dir,
    config,
    server,
    app: server.app,
    fake,
    close() {
      fake.restore();
      server.link?.close();
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

// ── Fake providers ───────────────────────────────────────────────────────────

type RefreshMode = 'ok' | 'invalid_grant' | 'error';

export class FakeProviders {
  spy: MockInstance<typeof fetch> | null = null;
  exchanges: Array<{ provider: string; params: Record<string, string> }> = [];
  refreshCalls = 0;
  revocations: Array<{ provider: string; token: string }> = [];
  upstream: Array<{ url: string; authorization: string | null }> = [];
  googleSub = 'google-sub-alice';
  googleEmail = 'alice@example.com';
  googleScope = 'openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/gmail.send';
  googleExpiresIn = 3600;
  googleExchangeStatus = 200;
  salesforceInstance = 'https://acme.my.salesforce.com';
  /** When set, Google refresh responses report this `scope`. */
  googleRefreshScope: string | undefined = undefined;
  refreshMode: RefreshMode = 'ok';
  revokeDelayMs = 0;
  refreshDelayMs = 0;
  private issued = 0;

  install(): void {
    this.spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => this.handle(input, init));
  }

  restore(): void {
    this.spy?.mockRestore();
    this.spy = null;
  }

  private json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  }

  private async handle(input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const headers = new Headers(init?.headers);
    const body = init?.body;
    const params: Record<string, string> = {};
    if (body instanceof URLSearchParams) for (const [k, v] of body) params[k] = v;
    else if (typeof body === 'string' && body.startsWith('{')) Object.assign(params, JSON.parse(body));

    if (url === 'https://oauth2.googleapis.com/token') {
      if (params.grant_type === 'authorization_code') {
        this.exchanges.push({ provider: 'google', params });
        if (this.googleExchangeStatus !== 200) {
          return this.json(this.googleExchangeStatus, { error: 'invalid_grant', error_description: 'PROVIDER-SECRET-ERROR-TEXT' });
        }
        this.issued++;
        return this.json(200, {
          access_token: `ya29.access-${this.issued}`,
          refresh_token: `rt-${this.issued}`,
          expires_in: this.googleExpiresIn,
          scope: this.googleScope,
          token_type: 'Bearer',
        });
      }
      this.refreshCalls++;
      if (this.refreshDelayMs > 0) await new Promise((r) => setTimeout(r, this.refreshDelayMs));
      if (this.refreshMode === 'invalid_grant') return this.json(400, { error: 'invalid_grant', error_description: 'Token has been expired or revoked.' });
      if (this.refreshMode === 'error') return this.json(503, { error: 'temporarily_unavailable' });
      this.issued++;
      return this.json(200, {
        access_token: `ya29.refreshed-${this.issued}`,
        expires_in: 3600,
        token_type: 'Bearer',
        ...(this.googleRefreshScope !== undefined ? { scope: this.googleRefreshScope } : {}),
      });
    }
    if (url === 'https://openidconnect.googleapis.com/v1/userinfo') {
      return this.json(200, { sub: this.googleSub, email: this.googleEmail });
    }
    if (url === 'https://oauth2.googleapis.com/revoke') {
      if (this.revokeDelayMs > 0) await new Promise((r) => setTimeout(r, this.revokeDelayMs));
      this.revocations.push({ provider: 'google', token: params.token });
      return new Response('', { status: 200 });
    }
    if (url === 'https://slack.com/api/oauth.v2.access') {
      this.exchanges.push({ provider: 'slack', params });
      return this.json(200, {
        ok: true,
        access_token: 'xoxb-bot-token',
        scope: 'chat:write,channels:read',
        token_type: 'bot',
        bot_user_id: 'U0BOT',
        team: { id: 'T0TEAM', name: 'Acme Workspace' },
        authed_user: { id: 'U0HUMAN' },
      });
    }
    if (url === 'https://slack.com/api/auth.revoke') {
      this.revocations.push({ provider: 'slack', token: headers.get('authorization') ?? '' });
      return this.json(200, { ok: true });
    }
    if (url === 'https://login.salesforce.com/services/oauth2/token') {
      this.exchanges.push({ provider: 'salesforce', params });
      return this.json(200, {
        access_token: '00Dsf-access',
        refresh_token: 'sf-refresh',
        instance_url: this.salesforceInstance,
        id: 'https://login.salesforce.com/id/00D000000000001AAA/005000000000001AAA',
        scope: 'api refresh_token',
        token_type: 'Bearer',
      });
    }
    if (url === 'https://login.salesforce.com/services/oauth2/revoke') {
      this.revocations.push({ provider: 'salesforce', token: params.token });
      return new Response('', { status: 200 });
    }
    if (/^https:\/\/[a-z0-9.-]+\.salesforce\.com\/services\/data\//.test(url)) {
      this.upstream.push({ url, authorization: headers.get('authorization') });
      return this.json(200, { records: [] });
    }
    if (url === 'https://api.linear.app/oauth/token') {
      this.exchanges.push({ provider: 'linear', params });
      return this.json(200, { access_token: 'lin_access', refresh_token: 'lin_refresh', expires_in: 86400, scope: 'read,issues:create', token_type: 'Bearer' });
    }
    if (url === 'https://api.linear.app/oauth/revoke') {
      this.revocations.push({ provider: 'linear', token: params.token });
      return new Response('', { status: 200 });
    }
    if (url === 'https://api.linear.app/graphql') {
      this.upstream.push({ url, authorization: headers.get('authorization') });
      return this.json(200, { data: { viewer: { id: 'lin-user-1', email: 'lin@example.com' } } });
    }
    if (url.startsWith('https://slack.com/api/') && !url.includes('oauth.v2.access') && !url.includes('auth.revoke')) {
      this.upstream.push({ url, authorization: headers.get('authorization') });
      return this.json(200, { ok: true });
    }
    if (url === 'https://github.com/login/oauth/access_token') {
      this.exchanges.push({ provider: 'github', params });
      return this.json(200, { access_token: 'gho_token', scope: 'repo', token_type: 'bearer' });
    }
    if (url === 'https://api.github.com/user') {
      return this.json(200, { id: 4242, login: 'octo' });
    }
    if (url.startsWith('https://www.googleapis.com/') || url.startsWith('https://api.linear.app/') || url.startsWith('https://api.hubapi.com/crm')) {
      this.upstream.push({ url, authorization: headers.get('authorization') });
      return this.json(200, { items: [] });
    }
    throw new Error(`unexpected fetch in test: ${url}`);
  }
}

// ── Clients ──────────────────────────────────────────────────────────────────

export interface RegisteredClient {
  client_id: string;
  client_secret?: string;
  auth: string;
}

export function basic(clientId: string, secret: string): string {
  return `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`).toString('base64')}`;
}

export async function registerClient(app: Server['app'], overrides: Record<string, unknown> = {}): Promise<RegisteredClient> {
  const res = await request(app)
    .post('/admin/link/clients')
    .set('Authorization', `Bearer ${ADMIN_TOKEN}`)
    .send({ name: 'Acme', redirect_uris: [APP_REDIRECT], origins: [APP_ORIGIN], ...overrides });
  expect(res.status).toBe(201);
  const client_id = res.body.client.client_id as string;
  const client_secret = res.body.client_secret as string | undefined;
  return { client_id, client_secret, auth: client_secret ? basic(client_id, client_secret) : '' };
}

export function parBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    intent: 'connect',
    subject: 'user-a',
    subject_type: 'user',
    providers: ['google'],
    scopes: { google: ['calendar.readonly', 'gmail.send'] },
    required_scopes: { google: ['calendar.readonly'] },
    redirect_uri: APP_REDIRECT,
    origin: APP_ORIGIN,
    state: 'dev-state-1',
    agent_id: 'server-agent',
    ...overrides,
  };
}

export async function par(app: Server['app'], client: RegisteredClient, overrides: Record<string, unknown> = {}): Promise<string> {
  const res = await request(app).post('/link/v1/par').set('Authorization', client.auth).send(parBody(overrides));
  expect(res.status).toBe(201);
  return res.body.request_uri as string;
}

// ── Browser ──────────────────────────────────────────────────────────────────

/** One browser: a cookie jar holding the Link binding cookie. */
export class Browser {
  cookie: string | null = null;

  remember(res: request.Response): void {
    const raw = res.headers['set-cookie'] as unknown as string[] | undefined;
    for (const c of raw ?? []) {
      const m = new RegExp(`^${COOKIE_NAME}=([^;]+)`).exec(c);
      if (m) this.cookie = m[1];
    }
  }

  async get(app: Server['app'], url: string): Promise<request.Response> {
    const r = request(app).get(url);
    if (this.cookie) r.set('Cookie', `${COOKIE_NAME}=${this.cookie}`);
    const res = await r;
    this.remember(res);
    return res;
  }

  async post(app: Server['app'], url: string, form: Array<[string, string]>): Promise<request.Response> {
    const r = request(app).post(url).type('form').send(new URLSearchParams(form).toString());
    if (this.cookie) r.set('Cookie', `${COOKIE_NAME}=${this.cookie}`);
    const res = await r;
    this.remember(res);
    return res;
  }
}

export function envelopeOf(html: string): string {
  const m = /name="e" value="([^"]+)"/.exec(html);
  if (!m) throw new Error('no envelope on page');
  return m[1];
}

export function pageConfig(html: string): Record<string, any> {
  const m = /<script type="application\/json" id="cred-link-config">([\s\S]*?)<\/script>/.exec(html);
  if (!m) throw new Error('no page config');
  return JSON.parse(m[1]);
}

export function authorizePath(requestUri: string, mode: 'popup' | 'redirect' | 'embedded' = 'redirect', clientId?: string): string {
  const q = new URLSearchParams({ request_uri: requestUri, mode });
  if (clientId) q.set('client_id', clientId);
  return `/link/v1/authorize?${q.toString()}`;
}

/** Drive authorize and the picker; returns the provider redirect URL. */
export async function toProvider(
  app: Server['app'],
  browser: Browser,
  requestUri: string,
  input: { mode?: 'popup' | 'redirect' | 'embedded'; provider?: string; scopes?: string[] } = {},
): Promise<URL> {
  const picker = await browser.get(app, authorizePath(requestUri, input.mode ?? 'redirect'));
  expect(picker.status).toBe(200);
  const res = await browser.post(app, '/link/v1/picker', [
    ['e', envelopeOf(picker.text)],
    ['action', 'continue'],
    ['provider', input.provider ?? 'google'],
    ...(input.scopes ?? ['calendar.readonly', 'gmail.send']).map((s): [string, string] => ['scope', s]),
  ]);
  expect(res.status).toBe(303);
  return new URL(res.headers.location);
}

/** Provider sends the browser back with a code. Returns the confirm page response. */
export async function callback(app: Server['app'], browser: Browser, providerUrl: URL, provider = 'google', code = 'auth-code-1'): Promise<request.Response> {
  const state = providerUrl.searchParams.get('state') ?? '';
  return browser.get(app, `/link/v1/callback/${provider}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`);
}

export async function confirm(app: Server['app'], browser: Browser, confirmPage: string, scopes: string[], action = 'confirm'): Promise<request.Response> {
  return browser.post(app, '/link/v1/confirm', [
    ['e', envelopeOf(confirmPage)],
    ['action', action],
    ...scopes.map((s): [string, string] => ['scope', s]),
  ]);
}

/** The result from a redirect-mode response or a popup result page. */
export function resultOf(res: request.Response): LinkResult {
  if (res.status === 303) {
    const loc = new URL(res.headers.location);
    const result = parseLinkRedirectResult(loc.search);
    if (!result) throw new Error(`no result in ${res.headers.location}`);
    return result;
  }
  const cfg = pageConfig(res.text);
  const { type: _t, v: _v, ...rest } = cfg.result;
  return rest as LinkResult;
}

/** Full connect: returns the success result. */
export async function connectFlow(
  app: Server['app'],
  client: RegisteredClient,
  input: { browser?: Browser; parOverrides?: Record<string, unknown>; scopes?: string[]; confirmScopes?: string[]; mode?: 'popup' | 'redirect' | 'embedded' } = {},
): Promise<Extract<LinkResult, { outcome: 'success' }>> {
  const browser = input.browser ?? new Browser();
  const requestUri = await par(app, client, input.parOverrides);
  const providerUrl = await toProvider(app, browser, requestUri, { mode: input.mode, scopes: input.scopes });
  const confirmPage = await callback(app, browser, providerUrl);
  expect(confirmPage.status).toBe(200);
  const res = await confirm(app, browser, confirmPage.text, input.confirmScopes ?? ['calendar.readonly', 'gmail.send']);
  const result = resultOf(res);
  if (result.outcome !== 'success') throw new Error(`flow failed: ${JSON.stringify(result)}`);
  return result;
}

export async function activate(app: Server['app'], client: RegisteredClient, connectionId: string, code: string, subject = 'user-a'): Promise<request.Response> {
  return request(app)
    .post(`/link/v1/connections/${connectionId}/activate`)
    .set('Authorization', client.auth)
    .send({ code, subject });
}

/** connect + activate; returns the connection id. */
export async function connectAndActivate(app: Server['app'], client: RegisteredClient, input: Parameters<typeof connectFlow>[2] = {}): Promise<string> {
  const result = await connectFlow(app, client, input);
  const res = await activate(app, client, result.connection_id, result.code, (input.parOverrides?.subject as string | undefined) ?? 'user-a');
  expect(res.status).toBe(200);
  expect(res.body.status).toBe('active');
  return result.connection_id;
}

export function delegate(app: Server['app'], body: Record<string, unknown>) {
  return request(app).post('/api/v1/delegate').set('Authorization', `Bearer ${AGENT_TOKEN}`).send(body);
}

export function use(app: Server['app'], body: Record<string, unknown>) {
  return request(app).post('/api/v1/use').set('Authorization', `Bearer ${AGENT_TOKEN}`).send(body);
}

export const CALENDAR_URL = 'https://www.googleapis.com/calendar/v3/users/me/calendarList';

// Migration messages, audit aggregator failure handling, classifier edge cases,
// and default-mode coverage of a mapped call under metering.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { evaluateOperation, methodOverrideChannel } from '@credninja/guard';
import type { AuditEvent } from '@credninja/vault';
import { createRefusalAggregator } from '../audit-route.js';
import { createServer } from '../server.js';
import { delegateAs, exerciseAs, newAgent } from './token-helpers.js';
import type { ServerConfig } from '../config.js';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function config(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-review-mig-'));
  tmpDirs.push(dir);
  return {
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: ADMIN, agentToken: BEARER,
    providers: (['salesforce', 'google', 'github'] as const).map((slug) => ({ slug, clientId: 'id', clientSecret: 'secret', defaultScopes: [] })),
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}
const op = (service: string, method: string, url: string, scopes: string[]) => evaluateOperation({ service, method, url, ...(method === 'GET' ? {} : { body: {} }) }, scopes);

describe('file vaults', () => {
  it('warn at startup and name the way out, in the warning and the refusal', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-review-file-'));
    tmpDirs.push(dir);
    const { app, vault } = createServer(config({ vaultStorage: 'file', vaultPath: path.join(dir, 'vault.json') }));
    const warned = warn.mock.calls.map(([m]) => String(m)).find((m) => m.includes('VAULT_STORAGE=file'));
    expect(warned).toContain('every agent is refused');
    expect(warned).toContain('CRED_ALLOW_AGENTS_WITHOUT_PERMISSION');
    await vault.init();
    await vault.store({ provider: 'google', userId: 'alice', accessToken: 't', scopes: ['calendar.readonly'] });
    const res = await delegateAs(app, await newAgent(), { service: 'google', user_id: 'alice' }, { bearer: BEARER });
    expect(res.body.message).toContain('VAULT_STORAGE=sqlite');
    expect(res.body.message).toContain('CRED_ALLOW_AGENTS_WITHOUT_PERMISSION');
  });

  it('do not warn once the opt-out is set, and sqlite never warns', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    createServer(config());
    expect(warn.mock.calls.some(([m]) => String(m).includes('VAULT_STORAGE=file'))).toBe(false);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-review-file-'));
    tmpDirs.push(dir);
    createServer(config({ vaultStorage: 'file', vaultPath: path.join(dir, 'vault.json'), allowAgentsWithoutPermission: true }));
    expect(warn.mock.calls.some(([m]) => String(m).includes('VAULT_STORAGE=file'))).toBe(false);
  });
});

describe('a Salesforce connection with no stored instance', () => {
  async function setup(instanceUrl?: string) {
    const server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'salesforce', userId: 'alice', accessToken: 'sf', expiresAt: new Date(Date.now() + 3600_000), scopes: ['api'], ...(instanceUrl ? { instanceUrl } : {}) });
    const agent = await newAgent();
    await server.vault.createPermission!({ agentId: agent.did, connectionId: 'salesforce', allowedScopes: ['api'], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
    return { ...server, agent };
  }

  it('gets consent_required with a consent_url at delegate', async () => {
    const { app, agent } = await setup();
    const res = await delegateAs(app, agent, { service: 'salesforce', user_id: 'alice' }, { bearer: BEARER });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('consent_required');
    expect(res.body.consent_url).toContain('/connect/salesforce');
    expect(res.body.access_token).toBeUndefined();
  });

  it('a live delegation gets a consent_url in the refusal at use', async () => {
    const { app, vault, agent } = await setup('https://acme.my.salesforce.com');
    const minted = await delegateAs(app, agent, { service: 'salesforce', user_id: 'alice' }, { bearer: BEARER });
    await vault.store({ provider: 'salesforce', userId: 'alice', accessToken: 'sf', expiresAt: new Date(Date.now() + 3600_000), scopes: ['api'] });
    const res = await exerciseAs(app, agent, minted.body.access_token, { url: 'https://acme.my.salesforce.com/services/data/v60.0/limits', method: 'GET' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('salesforce_instance_unknown');
    expect(res.body.consent_url).toContain('/connect/salesforce');
  });
});

describe('the refusal aggregator when a write fails', () => {
  const refusal = (route: string, actor = 'a'): AuditEvent => ({
    id: crypto.randomUUID(), timestamp: new Date(), actor: { type: 'agent', id: actor }, action: 'deny',
    resource: { type: 'token', id: 'g/u' }, outcome: 'denied', correlationId: 'c', errorMessage: 'e', metadata: { route },
  });

  it('a first event that could not be written is not counted as written', () => {
    const written: AuditEvent[] = [];
    let fail = true;
    const aggregator = createRefusalAggregator({ maxFirstWritesPerActor: 1, write: (event) => {
      if (fail) throw new Error('disk full');
      written.push(event);
    } });
    expect(() => aggregator.record(refusal('/1'))).toThrow('disk full');
    fail = false;
    // Neither held as a repeat of a row that does not exist, nor charged to the cap.
    aggregator.record(refusal('/1'));
    expect(written).toHaveLength(1);
    expect(written[0]!.metadata?.aggregated).toBeUndefined();
  });

  it('flush writes every summary it can, and one failure does not lose the rest', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const written: AuditEvent[] = [];
    let summaries = 0;
    const aggregator = createRefusalAggregator({ write: (event) => {
      if (event.metadata?.aggregated === true && ++summaries === 1) throw new Error('disk full');
      written.push(event);
    } });
    for (const route of ['/1', '/2', '/3']) {
      aggregator.record(refusal(route));
      aggregator.record(refusal(route));
    }
    expect(() => aggregator.flush()).not.toThrow();
    expect(written.filter((e) => e.metadata?.aggregated === true).map((e) => e.metadata?.route)).toEqual(['/2', '/3']);
  });
});

describe('Salesforce trailing slashes', () => {
  const SF = 'https://acme.my.salesforce.com/services/data';

  it('are mapped for that table, the same as without', () => {
    expect(op('salesforce', 'GET', `${SF}/v60.0/limits/`, ['salesforce.read']).outcome).toBe('allowed');
    expect(op('salesforce', 'GET', `${SF}/v60.0/sobjects/Account/`, ['salesforce.read']).outcome).toBe('allowed');
    expect(op('salesforce', 'GET', `${SF}/`, ['salesforce.read']).outcome).toBe('allowed');
    expect(op('salesforce', 'POST', `${SF}/v60.0/sobjects/Account/`, ['salesforce.read']).outcome).toBe('insufficient');
    expect(op('salesforce', 'POST', `${SF}/v60.0/sobjects/Account/`, ['api']).outcome).toBe('allowed');
    expect(op('salesforce', 'POST', `${SF}/v60.0/composite/`, ['api']).outcome).toBe('not_mapped');
  });

  it('are not mapped for any other table', () => {
    expect(op('github', 'GET', 'https://api.github.com/repos/o/r/', ['repo']).outcome).toBe('not_mapped');
    expect(op('google', 'GET', 'https://gmail.googleapis.com/gmail/v1/users/me/messages/', ['gmail.readonly']).outcome).toBe('not_mapped');
    expect(op('notion', 'GET', 'https://api.notion.com/v1/users/', ['notion.read']).outcome).toBe('not_mapped');
  });

  it('forward the same canonical URL', async () => {
    const server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'salesforce', userId: 'alice', accessToken: 'sf', expiresAt: new Date(Date.now() + 3600_000), scopes: ['api'], instanceUrl: 'https://acme.my.salesforce.com' });
    const agent = await newAgent();
    await server.vault.createPermission!({ agentId: agent.did, connectionId: 'salesforce', allowedScopes: ['api'], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
    const minted = await delegateAs(server.app, agent, { service: 'salesforce', user_id: 'alice' }, { bearer: BEARER });
    const upstream = vi.fn(async (_u: unknown, _i?: unknown) => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', upstream);
    const url = `${SF}/v60.0/limits/`;
    expect((await exerciseAs(server.app, agent, minted.body.access_token, { url, method: 'GET' })).status).toBe(200);
    expect(String(upstream.mock.calls[0]![0])).toBe(url);
  });
});

describe('override and path edge cases', () => {
  it('a semicolon-separated method override in the query is refused', () => {
    const url = 'https://api.github.com/repos/o/r';
    for (const query of ['?a=1;_method=DELETE', '?a=1;%5Fmethod=DELETE', '?_method=DELETE;a=1', '?a=1&b=2;$httpMethod=DELETE', '?x;X-HTTP-Method-Override=DELETE']) {
      expect(methodOverrideChannel({ url: `${url}${query}` }), query).toBe('query');
    }
    expect(methodOverrideChannel({ url: `${url}?q=SELECT;method` })).toBe('query');
    expect(methodOverrideChannel({ url: `${url}?q=a;b=c` })).toBeNull();
  });

  it('percent-encoded non-ASCII is refused on routes that have no use for it', () => {
    for (const [service, url, scope] of [
      ['google', 'https://gmail.googleapis.com/gmail/v1/users/me/messages/caf%C3%A9', 'gmail.readonly'],
      ['github', 'https://api.github.com/repos/o/caf%C3%A9', 'repo'],
      ['hubspot', 'https://api.hubapi.com/crm/v3/objects/contacts/caf%C3%A9', 'crm.objects.contacts.read'],
      ['notion', 'https://api.notion.com/v1/pages/caf%C3%A9', 'notion.read'],
      ['salesforce', 'https://acme.my.salesforce.com/services/data/v60.0/sobjects/Caf%C3%A9', 'api'],
    ] as const) {
      const verdict = op(service, 'GET', url, [scope]);
      expect(verdict, url).toEqual({ outcome: 'not_mapped', reason: 'ambiguous_path' });
    }
  });

  it('is allowed where real names use it: repository paths and branches, and Sheets ranges', () => {
    expect(op('github', 'GET', 'https://api.github.com/repos/o/r/contents/caf%C3%A9.txt', ['github.read']).outcome).toBe('allowed');
    expect(op('github', 'GET', 'https://api.github.com/repos/o/r/branches/caf%C3%A9', ['github.read']).outcome).toBe('allowed');
    expect(op('google', 'GET', 'https://sheets.googleapis.com/v4/spreadsheets/abc/values/Caf%C3%A9!A1', ['spreadsheets.readonly']).outcome).toBe('allowed');
  });

  it('even there, an encoding that could normalize into a separator is refused', () => {
    for (const bad of ['%C0%AF', '%EF%BC%8F', '%E2%80%AE', '%FF']) {
      const verdict = op('github', 'GET', `https://api.github.com/repos/o/r/contents/a${bad}b`, ['github.read']);
      expect(verdict, bad).toEqual({ outcome: 'not_mapped', reason: 'ambiguous_path' });
    }
  });

  it('an identity scope reads a public profile, not a user\'s activity', () => {
    const base = 'https://api.github.com/users/octo';
    expect(op('github', 'GET', base, ['read:user']).outcome).toBe('allowed');
    for (const path of ['/events', '/events/orgs/acme', '/received_events', '/orgs', '/repos']) {
      expect(op('github', 'GET', `${base}${path}`, ['read:user']).outcome, path).toBe('insufficient');
      expect(op('github', 'GET', `${base}${path}`, ['github.read']).outcome, path).toBe('insufficient');
      expect(op('github', 'GET', `${base}${path}`, ['repo']).outcome, path).toBe('allowed');
    }
  });
});

describe('the process log', () => {
  it('holds no upstream error text from a failed call', async () => {
    const server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29', expiresAt: new Date(Date.now() + 3600_000), scopes: ['gmail.readonly'] });
    const agent = await newAgent();
    await server.vault.createPermission!({ agentId: agent.did, connectionId: 'google', allowedScopes: ['gmail.readonly'], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
    const minted = await delegateAs(server.app, agent, { service: 'google', user_id: 'alice' }, { bearer: BEARER });
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('fetch failed tok_in_url', { cause: new Error('connect tok_in_cause') }); }));
    const res = await exerciseAs(server.app, agent, minted.body.access_token, { url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages?q=secret', method: 'GET' });
    expect(res.status).toBe(502);
    expect(logged).toHaveBeenCalled();
    const text = logged.mock.calls.map((args) => args.map((a) => (a instanceof Error ? `${a.message} ${String(a.cause)} ${a.stack}` : JSON.stringify(a))).join(' ')).join('\n');
    expect(text).not.toMatch(/tok_in_url|tok_in_cause|secret/);
    expect(text).toContain('TypeError');
  });
});

describe('metering in default mode', () => {
  const DRIVE = 'https://www.googleapis.com/drive/v3/files';
  async function setup(constraints: unknown[]) {
    const server = createServer(config());
    await server.vault.init();
    await server.vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29', expiresAt: new Date(Date.now() + 3600_000), scopes: ['drive.readonly'] });
    const agent = await newAgent();
    await server.vault.createPermission!({ agentId: agent.did, connectionId: 'google', allowedScopes: ['drive.readonly'], requiresApproval: false, delegatable: false, maxDelegationDepth: 1, createdBy: 'test' });
    const minted = await delegateAs(server.app, agent, { service: 'google', user_id: 'alice', constraints }, { bearer: BEARER });
    expect(minted.status, JSON.stringify(minted.body)).toBe(200);
    return { ...server, agent, token: minted.body.access_token as string };
  }
  const items = (n: number) => new Response(JSON.stringify({ items: Array.from({ length: n }, (_, i) => ({ id: i })) }), { status: 200, headers: { 'content-type': 'application/json' } });

  it('a mapped call inside its ceilings runs, and counts against a running total', async () => {
    const { app, agent, token } = await setup([{ key: 'max_calls', max_lifetime: 1 }]);
    vi.stubGlobal('fetch', vi.fn(async () => items(1)));
    expect((await exerciseAs(app, agent, token, { url: DRIVE, method: 'GET' })).status).toBe(200);
    const second = await exerciseAs(app, agent, token, { url: DRIVE, method: 'GET' });
    expect(second.status).toBe(403);
    expect(second.body.error).toBe('cumulative_constraint_exceeded');
  });

  it('a mapped call over a response ceiling is withheld', async () => {
    const { app, agent, token } = await setup([{ key: 'max_rows', max: 1 }]);
    vi.stubGlobal('fetch', vi.fn(async () => items(5)));
    const res = await exerciseAs(app, agent, token, { url: DRIVE, method: 'GET' });
    expect(res.status).toBe(403);
    expect(res.body.withheld).toBe(true);
  });

  it('the classifier refuses first: an uncovered call spends none of the budget', async () => {
    const { app, agent, token } = await setup([{ key: 'max_calls', max_lifetime: 1 }]);
    const upstream = vi.fn(async () => items(1));
    vi.stubGlobal('fetch', upstream);
    const write = await exerciseAs(app, agent, token, { url: DRIVE, method: 'POST', body: { name: 'x' } });
    expect(write.body.error).toBe('scope_insufficient');
    expect(upstream).not.toHaveBeenCalled();
    expect((await exerciseAs(app, agent, token, { url: DRIVE, method: 'GET' })).status).toBe(200);
  });
});

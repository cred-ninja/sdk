import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { GoogleAdapter } from '../adapters/google.js';
import { GitHubAdapter } from '../adapters/github.js';
import { SlackAdapter } from '../adapters/slack.js';
import { NotionAdapter } from '../adapters/notion.js';
import { SalesforceAdapter, SALESFORCE_PRODUCTION, SALESFORCE_SANDBOX } from '../adapters/salesforce.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function mockFetch(data: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: async () => data,
  });
}

const BASE_PARAMS = {
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  redirectUri: 'http://localhost:3000/callback',
  state: 'test-state-abc',
};

// ── Google ────────────────────────────────────────────────────────────────────

describe('GoogleAdapter', () => {
  it('builds auth URL with access_type=offline and prompt=consent', () => {
    const adapter = new GoogleAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['calendar.readonly'],
    }));
    expect(url.searchParams.get('access_type')).toBe('offline');
    expect(url.searchParams.get('prompt')).toBe('consent');
  });

  it('normalizes short scope names with Google prefix', () => {
    const adapter = new GoogleAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['calendar.readonly', 'drive'],
    }));
    const scope = url.searchParams.get('scope')!;
    expect(scope).toContain('https://www.googleapis.com/auth/calendar.readonly');
    expect(scope).toContain('https://www.googleapis.com/auth/drive');
  });

  it('does not double-prefix full https:// scopes', () => {
    const adapter = new GoogleAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['https://www.googleapis.com/auth/calendar.readonly'],
    }));
    const scope = url.searchParams.get('scope')!;
    expect(scope).not.toContain('https://www.googleapis.com/auth/https://');
  });

  it('includes PKCE challenge when provided', () => {
    const adapter = new GoogleAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['drive'],
      codeChallenge: 'test-challenge',
    }));
    expect(url.searchParams.get('code_challenge')).toBe('test-challenge');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('supportsPkce is true', () => {
    expect(new GoogleAdapter().supportsPkce).toBe(true);
  });
});

// ── GitHub ────────────────────────────────────────────────────────────────────

describe('GitHubAdapter', () => {
  beforeEach(() => { vi.stubGlobal('fetch', mockFetch({ access_token: 'ghu_tok', token_type: 'bearer' })); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('uses comma-separated scopes', () => {
    const adapter = new GitHubAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['repo', 'read:user', 'gist'],
    }));
    const scope = url.searchParams.get('scope')!;
    expect(scope).toBe('repo,read:user,gist');
  });

  it('sends Accept: application/json on token exchange', async () => {
    const adapter = new GitHubAdapter();
    await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'test-code' });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.headers['Accept']).toBe('application/json');
  });

  it('does not support PKCE', () => {
    expect(new GitHubAdapter().supportsPkce).toBe(false);
  });

  it('handles DELETE revocation with Basic auth', async () => {
    vi.stubGlobal('fetch', mockFetch({}, 204));
    const adapter = new GitHubAdapter();
    await adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' });
    const [url, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.method).toBe('DELETE');
    expect(url).toContain('/cid/token');
    const expectedAuth = 'Basic ' + Buffer.from('cid:sec').toString('base64');
    expect(init.headers['Authorization']).toBe(expectedAuth);
  });

  it('treats 404 revoke response as success', async () => {
    vi.stubGlobal('fetch', mockFetch({}, 404));
    const adapter = new GitHubAdapter();
    await expect(adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' })).resolves.toBeUndefined();
  });
});

// ── Slack ─────────────────────────────────────────────────────────────────────

describe('SlackAdapter', () => {
  it('uses comma-separated scopes', () => {
    const adapter = new SlackAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['channels:read', 'chat:write', 'users:read'],
    }));
    const scope = url.searchParams.get('scope')!;
    expect(scope).toBe('channels:read,chat:write,users:read');
  });

  it('throws on refreshAccessToken', async () => {
    const adapter = new SlackAdapter();
    await expect(adapter.refreshAccessToken({
      refreshToken: 'tok', clientId: 'cid', clientSecret: 'sec',
    })).rejects.toThrow('Slack tokens do not expire');
  });

  it('extracts access_token from authed_user response', async () => {
    vi.stubGlobal('fetch', mockFetch({
      ok: true,
      authed_user: { access_token: 'xoxp-user-token', scope: 'channels:read' },
    }));
    const adapter = new SlackAdapter();
    const tokens = await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'code' });
    expect(tokens.access_token).toBe('xoxp-user-token');
    vi.unstubAllGlobals();
  });

  it('extracts bot access_token from top-level response', async () => {
    vi.stubGlobal('fetch', mockFetch({
      ok: true,
      access_token: 'xoxb-bot-token',
      scope: 'channels:read',
    }));
    const adapter = new SlackAdapter();
    const tokens = await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'code' });
    expect(tokens.access_token).toBe('xoxb-bot-token');
    vi.unstubAllGlobals();
  });

  it('uses Bearer auth for revocation', async () => {
    vi.stubGlobal('fetch', mockFetch({ ok: true }));
    const adapter = new SlackAdapter();
    await adapter.revokeToken({ token: 'xoxb-token', clientId: 'cid', clientSecret: 'sec' });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.headers['Authorization']).toBe('Bearer xoxb-token');
    vi.unstubAllGlobals();
  });

  it('treats token_revoked error as success on revoke', async () => {
    vi.stubGlobal('fetch', mockFetch({ ok: false, error: 'token_revoked' }));
    const adapter = new SlackAdapter();
    await expect(adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' })).resolves.toBeUndefined();
    vi.unstubAllGlobals();
  });
});

// ── Notion ────────────────────────────────────────────────────────────────────

describe('NotionAdapter', () => {
  it('uses Basic auth header on token exchange', async () => {
    vi.stubGlobal('fetch', mockFetch({ access_token: 'notion-tok', token_type: 'Bearer' }));
    const adapter = new NotionAdapter();
    await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'code' });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const expected = 'Basic ' + Buffer.from('test-client-id:test-client-secret').toString('base64');
    expect(init.headers['Authorization']).toBe(expected);
    vi.unstubAllGlobals();
  });

  it('throws on refreshAccessToken', async () => {
    const adapter = new NotionAdapter();
    await expect(adapter.refreshAccessToken({
      refreshToken: 'tok', clientId: 'cid', clientSecret: 'sec',
    })).rejects.toThrow('Notion tokens do not expire');
  });

  it('revokeToken is a no-op (returns undefined)', async () => {
    const adapter = new NotionAdapter();
    await expect(adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' })).resolves.toBeUndefined();
  });

  it('does not support PKCE', () => {
    expect(new NotionAdapter().supportsPkce).toBe(false);
  });

  it('does not return refresh_token in token response', async () => {
    vi.stubGlobal('fetch', mockFetch({ access_token: 'tok', token_type: 'Bearer', refresh_token: 'ignored' }));
    const adapter = new NotionAdapter();
    const tokens = await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'code' });
    expect(tokens.refresh_token).toBeUndefined();
    vi.unstubAllGlobals();
  });
});

// ── Salesforce ────────────────────────────────────────────────────────────────

describe('SalesforceAdapter', () => {
  it('handles instance_url in token response', async () => {
    vi.stubGlobal('fetch', mockFetch({
      access_token: 'sf-tok',
      token_type: 'Bearer',
      instance_url: 'https://na1.salesforce.com',
      id: 'https://login.salesforce.com/id/00D.../005...',
    }));
    const adapter = new SalesforceAdapter();
    const tokens = await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'code' }) as { instance_url?: string };
    expect(tokens.instance_url).toBe('https://na1.salesforce.com');
    vi.unstubAllGlobals();
  });

  it('supports PKCE', () => {
    expect(new SalesforceAdapter().supportsPkce).toBe(true);
  });

  it('uses sandbox URLs for salesforce-sandbox slug', () => {
    const adapter = new SalesforceAdapter(SALESFORCE_SANDBOX);
    expect(adapter.slug).toBe('salesforce-sandbox');
    expect(adapter.authorizationUrl).toContain('test.salesforce.com');
  });

  it('uses production URLs for default', () => {
    const adapter = new SalesforceAdapter(SALESFORCE_PRODUCTION);
    expect(adapter.authorizationUrl).toContain('login.salesforce.com');
  });
});

// ── Linear ────────────────────────────────────────────────────────────────────

import { LinearAdapter } from '../adapters/linear.js';
import { HubSpotAdapter } from '../adapters/hubspot.js';

describe('LinearAdapter', () => {
  it('uses comma-separated scopes', () => {
    const adapter = new LinearAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read', 'write', 'issues:create'],
    }));
    const scope = url.searchParams.get('scope')!;
    expect(scope).toBe('read,write,issues:create');
  });

  it('supports PKCE (S256)', () => {
    const adapter = new LinearAdapter();
    expect(adapter.supportsPkce).toBe(true);
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read'],
      codeChallenge: 'test-challenge-123',
    }));
    expect(url.searchParams.get('code_challenge')).toBe('test-challenge-123');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('supports token refresh', () => {
    expect(new LinearAdapter().supportsRefresh).toBe(true);
  });

  it('uses correct authorization URL', () => {
    const adapter = new LinearAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read'],
    }));
    expect(url.origin + url.pathname).toBe('https://linear.app/oauth/authorize');
  });

  it('uses correct token URL', () => {
    expect(new LinearAdapter().tokenUrl).toBe('https://api.linear.app/oauth/token');
  });

  it('has revocation URL', () => {
    expect(new LinearAdapter().revocationUrl).toBe('https://api.linear.app/oauth/revoke');
  });

  it('defaults to user actor (no actor param)', () => {
    const adapter = new LinearAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read'],
    }));
    expect(url.searchParams.has('actor')).toBe(false);
  });

  it('sets actor=app for agent mode', () => {
    const adapter = new LinearAdapter('app');
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read', 'write'],
    }));
    expect(url.searchParams.get('actor')).toBe('app');
  });

  it('exchanges code for tokens', async () => {
    vi.stubGlobal('fetch', mockFetch({
      access_token: 'lin_tok_123',
      token_type: 'Bearer',
      expires_in: 86399,
      scope: 'read write',
      refresh_token: 'lin_refresh_456',
    }));
    const adapter = new LinearAdapter();
    const tokens = await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'auth-code' });
    expect(tokens.access_token).toBe('lin_tok_123');
    expect(tokens.refresh_token).toBe('lin_refresh_456');
    expect(tokens.expires_in).toBe(86399);
    vi.unstubAllGlobals();
  });

  it('refreshes tokens', async () => {
    vi.stubGlobal('fetch', mockFetch({
      access_token: 'lin_new_tok',
      expires_in: 86399,
      refresh_token: 'lin_new_refresh',
    }));
    const adapter = new LinearAdapter();
    const result = await adapter.refreshAccessToken({
      refreshToken: 'old_refresh', clientId: 'cid', clientSecret: 'sec',
    });
    expect(result.access_token).toBe('lin_new_tok');
    expect(result.refresh_token).toBe('lin_new_refresh');
    vi.unstubAllGlobals();
  });

  it('slug is linear', () => {
    expect(new LinearAdapter().slug).toBe('linear');
  });
});

// ── HubSpot ───────────────────────────────────────────────────────────────────

describe('HubSpotAdapter', () => {
  it('uses space-separated scopes', () => {
    const adapter = new HubSpotAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['crm.objects.contacts.read', 'crm.objects.contacts.write', 'content'],
    }));
    const scope = url.searchParams.get('scope')!;
    expect(scope).toBe('crm.objects.contacts.read crm.objects.contacts.write content');
  });

  it('does not support PKCE', () => {
    expect(new HubSpotAdapter().supportsPkce).toBe(false);
  });

  it('ignores codeChallenge even if provided', () => {
    const adapter = new HubSpotAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['crm.objects.contacts.read'],
      codeChallenge: 'should-be-ignored',
    }));
    expect(url.searchParams.has('code_challenge')).toBe(false);
    expect(url.searchParams.has('code_challenge_method')).toBe(false);
  });

  it('supports token refresh', () => {
    expect(new HubSpotAdapter().supportsRefresh).toBe(true);
  });

  it('uses correct authorization URL', () => {
    const adapter = new HubSpotAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['crm.objects.contacts.read'],
    }));
    expect(url.origin + url.pathname).toBe('https://app.hubspot.com/oauth/authorize');
  });

  it('uses correct token URL', () => {
    expect(new HubSpotAdapter().tokenUrl).toBe('https://api.hubapi.com/oauth/v1/token');
  });

  it('uses account-specific auth URL when accountId is provided', () => {
    const adapter = new HubSpotAdapter('12345678');
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['crm.objects.contacts.read'],
    }));
    expect(url.origin + url.pathname).toBe('https://app.hubspot.com/oauth/12345678/authorize');
  });

  it('includes optional_scope when provided', () => {
    const adapter = new HubSpotAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['crm.objects.contacts.read'],
      optionalScope: ['automation', 'content'],
    } as Parameters<typeof adapter.buildAuthorizationUrl>[0]));
    expect(url.searchParams.get('optional_scope')).toBe('automation content');
  });

  it('does not include optional_scope param when not provided', () => {
    const adapter = new HubSpotAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['crm.objects.contacts.read'],
    }));
    expect(url.searchParams.has('optional_scope')).toBe(false);
  });

  it('exchanges code for tokens', async () => {
    vi.stubGlobal('fetch', mockFetch({
      access_token: 'hs_tok_123',
      token_type: 'Bearer',
      expires_in: 1800,
      refresh_token: 'hs_refresh_456',
    }));
    const adapter = new HubSpotAdapter();
    const tokens = await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'auth-code' });
    expect(tokens.access_token).toBe('hs_tok_123');
    expect(tokens.refresh_token).toBe('hs_refresh_456');
    expect(tokens.expires_in).toBe(1800);
    vi.unstubAllGlobals();
  });

  it('refreshes tokens', async () => {
    vi.stubGlobal('fetch', mockFetch({
      access_token: 'hs_new_tok',
      expires_in: 1800,
      refresh_token: 'hs_new_refresh',
    }));
    const adapter = new HubSpotAdapter();
    const result = await adapter.refreshAccessToken({
      refreshToken: 'old_refresh', clientId: 'cid', clientSecret: 'sec',
    });
    expect(result.access_token).toBe('hs_new_tok');
    expect(result.refresh_token).toBe('hs_new_refresh');
    vi.unstubAllGlobals();
  });

  it('revokes token via DELETE to refresh-tokens endpoint', async () => {
    vi.stubGlobal('fetch', mockFetch({}, 204));
    const adapter = new HubSpotAdapter();
    await adapter.revokeToken({ token: 'hs_refresh_tok', clientId: 'cid', clientSecret: 'sec' });
    const [url, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.method).toBe('DELETE');
    expect(url).toContain('/oauth/v1/refresh-tokens/hs_refresh_tok');
    vi.unstubAllGlobals();
  });

  it('slug is hubspot', () => {
    expect(new HubSpotAdapter().slug).toBe('hubspot');
  });
});

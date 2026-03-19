import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { GoogleAdapter } from '../adapters/google.js';
import { GitHubAdapter } from '../adapters/github.js';
import { SlackAdapter } from '../adapters/slack.js';
import { NotionAdapter } from '../adapters/notion.js';
import { StripeAdapter } from '../adapters/stripe.js';
import { DiscordAdapter } from '../adapters/discord.js';
import { TwilioAdapter } from '../adapters/twilio.js';
import { JiraAdapter } from '../adapters/jira.js';
import { ZoomAdapter } from '../adapters/zoom.js';
import { AsanaAdapter } from '../adapters/asana.js';
import { PagerDutyAdapter } from '../adapters/pagerduty.js';
import { AwsAdapter } from '../adapters/aws.js';
import { OpenAIAdapter } from '../adapters/openai.js';
import { SendGridAdapter } from '../adapters/sendgrid.js';
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

// ── Stripe ────────────────────────────────────────────────────────────────────

describe('StripeAdapter', () => {
  it('slug is stripe', () => {
    expect(new StripeAdapter().slug).toBe('stripe');
  });

  it('does not support PKCE', () => {
    expect(new StripeAdapter().supportsPkce).toBe(false);
  });

  it('does not support refresh', () => {
    expect(new StripeAdapter().supportsRefresh).toBe(false);
  });

  it('throws on refreshAccessToken', async () => {
    const adapter = new StripeAdapter();
    await expect(adapter.refreshAccessToken({
      refreshToken: 'tok', clientId: 'cid', clientSecret: 'sec',
    })).rejects.toThrow('Stripe Connect OAuth does not support token refresh');
  });

  it('uses correct authorization URL', () => {
    expect(new StripeAdapter().authorizationUrl).toBe('https://connect.stripe.com/oauth/authorize');
  });

  it('uses correct token URL', () => {
    expect(new StripeAdapter().tokenUrl).toBe('https://connect.stripe.com/oauth/token');
  });

  it('has revocation URL', () => {
    expect(new StripeAdapter().revocationUrl).toBe('https://connect.stripe.com/oauth/deauthorize');
  });

  it('builds auth URL correctly', () => {
    const adapter = new StripeAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read_write'],
    }));
    expect(url.searchParams.get('client_id')).toBe('test-client-id');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('scope')).toBe('read_write');
  });
});

// ── Discord ───────────────────────────────────────────────────────────────────

describe('DiscordAdapter', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch({ access_token: 'disc_tok', token_type: 'Bearer', expires_in: 604800, refresh_token: 'disc_refresh' }));
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('slug is discord', () => {
    expect(new DiscordAdapter().slug).toBe('discord');
  });

  it('supports PKCE', () => {
    expect(new DiscordAdapter().supportsPkce).toBe(true);
  });

  it('supports refresh', () => {
    expect(new DiscordAdapter().supportsRefresh).toBe(true);
  });

  it('uses space-separated scopes', () => {
    const adapter = new DiscordAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['identify', 'email', 'guilds'],
    }));
    expect(url.searchParams.get('scope')).toBe('identify email guilds');
  });

  it('uses correct authorization URL', () => {
    const adapter = new DiscordAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['identify'],
    }));
    expect(url.origin + url.pathname).toBe('https://discord.com/oauth2/authorize');
  });

  it('exchanges code for tokens', async () => {
    const adapter = new DiscordAdapter();
    const tokens = await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'disc-code' });
    expect(tokens.access_token).toBe('disc_tok');
    expect(tokens.refresh_token).toBe('disc_refresh');
  });

  it('includes PKCE challenge when provided', () => {
    const adapter = new DiscordAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['identify'],
      codeChallenge: 'challenge123',
    }));
    expect(url.searchParams.get('code_challenge')).toBe('challenge123');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  });
});

// ── Twilio ────────────────────────────────────────────────────────────────────

describe('TwilioAdapter', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch({ access_token: 'twilio_tok', token_type: 'Bearer', expires_in: 3600, refresh_token: 'twilio_refresh' }));
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('slug is twilio', () => {
    expect(new TwilioAdapter().slug).toBe('twilio');
  });

  it('supports PKCE', () => {
    expect(new TwilioAdapter().supportsPkce).toBe(true);
  });

  it('supports refresh', () => {
    expect(new TwilioAdapter().supportsRefresh).toBe(true);
  });

  it('revocationUrl is null', () => {
    expect(new TwilioAdapter().revocationUrl).toBeNull();
  });

  it('revokeToken is a no-op when revocationUrl is null', async () => {
    const adapter = new TwilioAdapter();
    await expect(adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' })).resolves.toBeUndefined();
  });

  it('uses correct authorization URL', () => {
    const adapter = new TwilioAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['offline_access'],
    }));
    expect(url.origin + url.pathname).toBe('https://login.twilio.com/oauth2/authorize');
  });

  it('exchanges code for tokens', async () => {
    const adapter = new TwilioAdapter();
    const tokens = await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'twilio-code' });
    expect(tokens.access_token).toBe('twilio_tok');
  });
});

// ── Jira (Atlassian) ──────────────────────────────────────────────────────────

describe('JiraAdapter', () => {
  it('slug is jira', () => {
    expect(new JiraAdapter().slug).toBe('jira');
  });

  it('supports PKCE', () => {
    expect(new JiraAdapter().supportsPkce).toBe(true);
  });

  it('supports refresh', () => {
    expect(new JiraAdapter().supportsRefresh).toBe(true);
  });

  it('revocationUrl is null', () => {
    expect(new JiraAdapter().revocationUrl).toBeNull();
  });

  it('includes audience=api.atlassian.com in auth URL', () => {
    const adapter = new JiraAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read:jira-work', 'offline_access'],
    }));
    expect(url.searchParams.get('audience')).toBe('api.atlassian.com');
  });

  it('includes prompt=consent in auth URL', () => {
    const adapter = new JiraAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read:jira-work'],
    }));
    expect(url.searchParams.get('prompt')).toBe('consent');
  });

  it('uses correct authorization URL', () => {
    const adapter = new JiraAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read:jira-work'],
    }));
    expect(url.origin + url.pathname).toBe('https://auth.atlassian.com/authorize');
  });

  it('includes PKCE challenge in auth URL', () => {
    const adapter = new JiraAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read:jira-work'],
      codeChallenge: 'jira-challenge-xyz',
    }));
    expect(url.searchParams.get('code_challenge')).toBe('jira-challenge-xyz');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  });
});

// ── Zoom ──────────────────────────────────────────────────────────────────────

describe('ZoomAdapter', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch({ access_token: 'zoom_tok', token_type: 'bearer', expires_in: 3600, refresh_token: 'zoom_refresh' }));
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('slug is zoom', () => {
    expect(new ZoomAdapter().slug).toBe('zoom');
  });

  it('supports PKCE', () => {
    expect(new ZoomAdapter().supportsPkce).toBe(true);
  });

  it('supports refresh', () => {
    expect(new ZoomAdapter().supportsRefresh).toBe(true);
  });

  it('uses Basic auth on token exchange', async () => {
    const adapter = new ZoomAdapter();
    await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'zoom-code' });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const expected = 'Basic ' + Buffer.from('test-client-id:test-client-secret').toString('base64');
    expect(init.headers['Authorization']).toBe(expected);
  });

  it('uses Basic auth on token refresh', async () => {
    const adapter = new ZoomAdapter();
    await adapter.refreshAccessToken({ refreshToken: 'old_tok', clientId: 'cid', clientSecret: 'sec' });
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    const expected = 'Basic ' + Buffer.from('cid:sec').toString('base64');
    expect(init.headers['Authorization']).toBe(expected);
  });

  it('exchanges code for tokens', async () => {
    const adapter = new ZoomAdapter();
    const tokens = await adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'zoom-code' });
    expect(tokens.access_token).toBe('zoom_tok');
    expect(tokens.refresh_token).toBe('zoom_refresh');
  });

  it('revokes token with Basic auth', async () => {
    vi.stubGlobal('fetch', mockFetch({}, 200));
    const adapter = new ZoomAdapter();
    await adapter.revokeToken({ token: 'zoom_tok', clientId: 'cid', clientSecret: 'sec' });
    const [url, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toContain('zoom_tok');
    expect(init.method).toBe('POST');
    const expected = 'Basic ' + Buffer.from('cid:sec').toString('base64');
    expect(init.headers['Authorization']).toBe(expected);
  });

  it('uses correct authorization URL', () => {
    const adapter = new ZoomAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['meeting:read'],
    }));
    expect(url.origin + url.pathname).toBe('https://zoom.us/oauth/authorize');
  });
});

// ── Asana ─────────────────────────────────────────────────────────────────────

describe('AsanaAdapter', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch({ access_token: 'asana_tok', token_type: 'bearer', expires_in: 3600, refresh_token: 'asana_refresh' }));
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('slug is asana', () => {
    expect(new AsanaAdapter().slug).toBe('asana');
  });

  it('does not support PKCE', () => {
    expect(new AsanaAdapter().supportsPkce).toBe(false);
  });

  it('supports refresh', () => {
    expect(new AsanaAdapter().supportsRefresh).toBe(true);
  });

  it('revocationUrl is null', () => {
    expect(new AsanaAdapter().revocationUrl).toBeNull();
  });

  it('revokeToken is a no-op', async () => {
    const adapter = new AsanaAdapter();
    await expect(adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' })).resolves.toBeUndefined();
  });

  it('uses correct authorization URL', () => {
    const adapter = new AsanaAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['default'],
    }));
    expect(url.origin + url.pathname).toBe('https://app.asana.com/-/oauth_authorize');
  });

  it('refreshes tokens', async () => {
    const adapter = new AsanaAdapter();
    const result = await adapter.refreshAccessToken({
      refreshToken: 'old_refresh', clientId: 'cid', clientSecret: 'sec',
    });
    expect(result.access_token).toBe('asana_tok');
    const [, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.method).toBe('POST');
  });
});

// ── PagerDuty ─────────────────────────────────────────────────────────────────

describe('PagerDutyAdapter', () => {
  it('slug is pagerduty', () => {
    expect(new PagerDutyAdapter().slug).toBe('pagerduty');
  });

  it('does not support PKCE', () => {
    expect(new PagerDutyAdapter().supportsPkce).toBe(false);
  });

  it('does not support refresh', () => {
    expect(new PagerDutyAdapter().supportsRefresh).toBe(false);
  });

  it('throws on refreshAccessToken', async () => {
    const adapter = new PagerDutyAdapter();
    await expect(adapter.refreshAccessToken({
      refreshToken: 'tok', clientId: 'cid', clientSecret: 'sec',
    })).rejects.toThrow('PagerDuty OAuth does not support token refresh');
  });

  it('uses correct authorization URL', () => {
    const adapter = new PagerDutyAdapter();
    const url = new URL(adapter.buildAuthorizationUrl({
      ...BASE_PARAMS,
      scopes: ['read'],
    }));
    expect(url.origin + url.pathname).toBe('https://app.pagerduty.com/oauth/authorize');
  });

  it('revokes token via DELETE with Basic auth', async () => {
    vi.stubGlobal('fetch', mockFetch({}, 204));
    const adapter = new PagerDutyAdapter();
    await adapter.revokeToken({ token: 'pd_tok', clientId: 'cid', clientSecret: 'sec' });
    const [url, init] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.method).toBe('DELETE');
    expect(url).toContain('pd_tok');
    const expectedAuth = 'Basic ' + Buffer.from('cid:sec').toString('base64');
    expect(init.headers['Authorization']).toBe(expectedAuth);
    vi.unstubAllGlobals();
  });

  it('treats 404 revoke response as success', async () => {
    vi.stubGlobal('fetch', mockFetch({}, 404));
    const adapter = new PagerDutyAdapter();
    await expect(adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' })).resolves.toBeUndefined();
    vi.unstubAllGlobals();
  });
});

// ── AWS ───────────────────────────────────────────────────────────────────────

describe('AwsAdapter', () => {
  it('slug defaults to aws', () => {
    expect(new AwsAdapter().slug).toBe('aws');
  });

  it('accepts custom slug', () => {
    expect(new AwsAdapter('us-east-1', 'aws-sso').slug).toBe('aws-sso');
  });

  it('supports PKCE', () => {
    expect(new AwsAdapter().supportsPkce).toBe(true);
  });

  it('supports refresh', () => {
    expect(new AwsAdapter().supportsRefresh).toBe(true);
  });

  it('revocationUrl is null', () => {
    expect(new AwsAdapter().revocationUrl).toBeNull();
  });

  it('uses region in authorization URL', () => {
    const adapter = new AwsAdapter('eu-west-1');
    expect(adapter.authorizationUrl).toContain('eu-west-1');
    expect(adapter.authorizationUrl).toContain('oidc.eu-west-1.amazonaws.com');
  });

  it('defaults to us-east-1 region', () => {
    const adapter = new AwsAdapter();
    expect(adapter.authorizationUrl).toContain('us-east-1');
  });

  it('uses correct token URL', () => {
    const adapter = new AwsAdapter('us-east-1');
    expect(adapter.tokenUrl).toBe('https://oidc.us-east-1.amazonaws.com/token');
  });

  it('revokeToken is a no-op', async () => {
    const adapter = new AwsAdapter();
    await expect(adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' })).resolves.toBeUndefined();
  });
});

// ── OpenAI (API key) ──────────────────────────────────────────────────────────

describe('OpenAIAdapter', () => {
  it('slug is openai', () => {
    expect(new OpenAIAdapter().slug).toBe('openai');
  });

  it('supportsOAuth is false', () => {
    expect((new OpenAIAdapter() as { supportsOAuth: boolean }).supportsOAuth).toBe(false);
  });

  it('does not support PKCE', () => {
    expect(new OpenAIAdapter().supportsPkce).toBe(false);
  });

  it('does not support refresh', () => {
    expect(new OpenAIAdapter().supportsRefresh).toBe(false);
  });

  it('throws on buildAuthorizationUrl', () => {
    const adapter = new OpenAIAdapter();
    expect(() => adapter.buildAuthorizationUrl({ ...BASE_PARAMS, scopes: [] }))
      .toThrow('OpenAI does not support OAuth');
  });

  it('throws on exchangeCodeForTokens', async () => {
    const adapter = new OpenAIAdapter();
    await expect(adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'code' }))
      .rejects.toThrow('OpenAI does not support OAuth');
  });

  it('throws on refreshAccessToken', async () => {
    const adapter = new OpenAIAdapter();
    await expect(adapter.refreshAccessToken({ refreshToken: 'tok', clientId: 'cid', clientSecret: 'sec' }))
      .rejects.toThrow('OpenAI API keys do not expire');
  });

  it('throws on revokeToken', async () => {
    const adapter = new OpenAIAdapter();
    await expect(adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' }))
      .rejects.toThrow('OpenAI API keys must be revoked manually');
  });
});

// ── SendGrid (API key) ────────────────────────────────────────────────────────

describe('SendGridAdapter', () => {
  it('slug is sendgrid', () => {
    expect(new SendGridAdapter().slug).toBe('sendgrid');
  });

  it('supportsOAuth is false', () => {
    expect((new SendGridAdapter() as { supportsOAuth: boolean }).supportsOAuth).toBe(false);
  });

  it('does not support PKCE', () => {
    expect(new SendGridAdapter().supportsPkce).toBe(false);
  });

  it('does not support refresh', () => {
    expect(new SendGridAdapter().supportsRefresh).toBe(false);
  });

  it('throws on buildAuthorizationUrl', () => {
    const adapter = new SendGridAdapter();
    expect(() => adapter.buildAuthorizationUrl({ ...BASE_PARAMS, scopes: [] }))
      .toThrow('SendGrid does not support OAuth');
  });

  it('throws on exchangeCodeForTokens', async () => {
    const adapter = new SendGridAdapter();
    await expect(adapter.exchangeCodeForTokens({ ...BASE_PARAMS, code: 'code' }))
      .rejects.toThrow('SendGrid does not support OAuth');
  });

  it('throws on refreshAccessToken', async () => {
    const adapter = new SendGridAdapter();
    await expect(adapter.refreshAccessToken({ refreshToken: 'tok', clientId: 'cid', clientSecret: 'sec' }))
      .rejects.toThrow('SendGrid API keys do not expire');
  });

  it('throws on revokeToken', async () => {
    const adapter = new SendGridAdapter();
    await expect(adapter.revokeToken({ token: 'tok', clientId: 'cid', clientSecret: 'sec' }))
      .rejects.toThrow('SendGrid API keys must be revoked via the dashboard');
  });
});

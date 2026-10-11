import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildLinkAuthorizeQuery, parseLinkAuthorizeQuery } from '@credninja/protocol';
import type { LinkTheme } from '@credninja/protocol';
import { Cred, CredLinkError, buildAuthorizeUrl, link } from '../index.js';
import { ORIGIN, TOKEN } from './helpers.js';

function query(url: string): string {
  return new URL(url).search.slice(1);
}

function thrownCode(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (err) {
    return err instanceof CredLinkError ? err.code : 'not-a-CredLinkError';
  }
  return undefined;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('authorize URL', () => {
  it.each(['popup', 'redirect', 'embedded'] as const)('is built by the contracts helper for mode %s', (mode) => {
    const url = buildAuthorizeUrl({ token: TOKEN, mode });
    expect(url).toBe(`${ORIGIN}/link/v1/authorize?${buildLinkAuthorizeQuery({ request_uri: TOKEN, mode })}`);
    expect(parseLinkAuthorizeQuery(query(url))).toEqual({ request_uri: TOKEN, mode });
  });

  it('defaults to popup mode and the hosted base URL', () => {
    const url = new URL(buildAuthorizeUrl({ token: TOKEN }));
    expect(url.origin).toBe(ORIGIN);
    expect(url.pathname).toBe('/link/v1/authorize');
    expect(parseLinkAuthorizeQuery(url.search)?.mode).toBe('popup');
  });

  it('never carries client_id, subject or redirect_uri', () => {
    const url = new URL(buildAuthorizeUrl({ token: TOKEN, mode: 'redirect' }));
    expect([...url.searchParams.keys()].sort()).toEqual(['mode', 'request_uri']);
  });

  it('passes narrowing providers, scopes and a sanitized theme through', () => {
    const url = buildAuthorizeUrl({
      token: TOKEN,
      mode: 'embedded',
      providers: ['google', 'slack', 'google'],
      scopes: { google: ['https://www.googleapis.com/auth/calendar.readonly', 'gmail.send'] },
      theme: { accent: '#ff0000', radius: 8, font: 'Inter', colorScheme: 'dark', radiusExtra: 1 } as LinkTheme,
    });
    expect(parseLinkAuthorizeQuery(query(url))).toEqual({
      request_uri: TOKEN,
      mode: 'embedded',
      providers: ['google', 'slack'],
      scopes: { google: ['calendar.readonly', 'gmail.send'] },
      theme: { accent: '#ff0000', radius: 8, font: 'Inter', colorScheme: 'dark' },
    });
  });

  it('never sends theme.appName or theme.logoUrl: those come only from the client registration', () => {
    const theme: LinkTheme = { appName: 'Totally Your Bank', logoUrl: 'https://evil.example/bank.png', accent: '#00ff00' };
    for (const mode of ['popup', 'redirect', 'embedded'] as const) {
      const url = buildAuthorizeUrl({ token: TOKEN, mode, theme });
      expect(url).not.toMatch(/app_name|logo_url|Totally|evil\.example/);
      expect(parseLinkAuthorizeQuery(query(url))?.theme).toEqual({ accent: '#00ff00' });
    }
    // Only the ignored fields: no theme parameters at all.
    const bare = new URL(buildAuthorizeUrl({ token: TOKEN, theme: { appName: 'Acme', logoUrl: 'https://acme.example/l.png' } }));
    expect([...bare.searchParams.keys()].sort()).toEqual(['mode', 'request_uri']);
    // Accepted without error by Cred.link, for type compatibility with LinkTheme.
    expect(() => link({ token: TOKEN, theme })).not.toThrow();
  });

  it('supports a self-hosted base URL with a path prefix, and http only on loopback', () => {
    expect(buildAuthorizeUrl({ token: TOKEN, baseUrl: 'https://cred.example.com/cred/' }))
      .toMatch(/^https:\/\/cred\.example\.com\/cred\/link\/v1\/authorize\?/);
    expect(buildAuthorizeUrl({ token: TOKEN, baseUrl: 'http://localhost:3456' }))
      .toMatch(/^http:\/\/localhost:3456\/link\/v1\/authorize\?/);
    expect(thrownCode(() => buildAuthorizeUrl({ token: TOKEN, baseUrl: 'http://cred.example.com' }))).toBe('invalid_options');
    expect(thrownCode(() => buildAuthorizeUrl({ token: TOKEN, baseUrl: 'https://cred.example.com/?x=1' }))).toBe('invalid_options');
    expect(thrownCode(() => buildAuthorizeUrl({ token: TOKEN, baseUrl: 'https://u:p@cred.example.com' }))).toBe('invalid_options');
    expect(thrownCode(() => buildAuthorizeUrl({ token: TOKEN, baseUrl: 'cred.example.com' }))).toBe('invalid_options');
  });
});

describe('Cred.link option validation', () => {
  it('rejects a token that is not a request_uri', () => {
    expect(thrownCode(() => link({ token: 'not-a-token' }))).toBe('invalid_token');
    expect(thrownCode(() => link({ token: `urn:cred:link:short` }))).toBe('invalid_token');
  });

  it.each(['client_id', 'subject', 'redirect_uri', 'state', 'origin'])('refuses %s as an option', (key) => {
    // Deliberately passing a field the type does not allow, as untyped JS would.
    const options = { token: TOKEN, [key]: 'x' } as unknown as Parameters<typeof link>[0];
    expect(thrownCode(() => link(options))).toBe('invalid_options');
  });

  it('rejects empty or unknown providers and malformed scopes', () => {
    expect(thrownCode(() => link({ token: TOKEN, providers: [] }))).toBe('invalid_options');
    // Untyped input, as plain JS would send it.
    expect(thrownCode(() => link({ token: TOKEN, providers: ['myspace'] as unknown as ['google'] }))).toBe('invalid_options');
    expect(thrownCode(() => link({ token: TOKEN, scopes: { google: [''] } }))).toBe('invalid_options');
    expect(thrownCode(() => link({ token: TOKEN, scopes: { myspace: ['x'] } as unknown as { google: string[] } }))).toBe('invalid_options');
  });

  it('rejects an unknown mode, and embedded without a container', () => {
    expect(thrownCode(() => link({ token: TOKEN, mode: 'modal' as unknown as 'popup' }))).toBe('invalid_options');
    expect(thrownCode(() => link({ token: TOKEN, mode: 'embedded' }))).toBe('invalid_options');
  });

  it('touches no browser API when created', () => {
    const open = vi.spyOn(window, 'open');
    const add = vi.spyOn(window, 'addEventListener');
    Cred.link({ token: TOKEN, mode: 'embedded', container: document.createElement('div') });
    Cred.link({ token: TOKEN });
    expect(open).not.toHaveBeenCalled();
    expect(add).not.toHaveBeenCalled();
  });
});

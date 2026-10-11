import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { encodeLinkRedirectResult, parseLinkAuthorizeQuery } from '@credninja/protocol';
import { Cred, CredLinkError, handleRedirect, link, parseRedirectResult } from '../index.js';
import { CODE, TOKEN } from './helpers.js';

const successQuery = encodeLinkRedirectResult({
  outcome: 'success',
  connection_id: 'conn_abc123',
  code: CODE,
  grant_id: 'grt_abc123',
  provider: 'google',
  scopes: ['calendar.readonly', 'gmail.send'],
  state: 'dev-csrf-value',
});

function setUrl(path: string): void {
  window.history.replaceState(null, '', path);
}

beforeEach(() => {
  setUrl('/');
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('redirect mode open()', () => {
  it('navigates the top window to the authorize URL and registers no listener', () => {
    const top = { location: { href: 'https://app.example.com/settings' } };
    const fakeWindow = { top, addEventListener: vi.fn(), open: vi.fn() };
    vi.stubGlobal('window', fakeWindow);
    const cbs = { onSuccess: vi.fn(), onError: vi.fn(), onExit: vi.fn() };
    const handle = link({ token: TOKEN, mode: 'redirect', providers: ['github'], ...cbs });
    handle.open();
    const url = new URL(top.location.href);
    expect(url.origin + url.pathname).toBe('https://link.cred.ninja/link/v1/authorize');
    expect(parseLinkAuthorizeQuery(url.search)).toEqual({ request_uri: TOKEN, mode: 'redirect', providers: ['github'] });
    expect(fakeWindow.addEventListener).not.toHaveBeenCalled();
    expect(fakeWindow.open).not.toHaveBeenCalled();

    top.location.href = 'about:blank';
    handle.open();
    expect(top.location.href).toBe('about:blank');
    handle.close();
    expect(cbs.onExit).not.toHaveBeenCalled();
  });

  it('throws navigation_blocked when the top window refuses navigation, and stays retryable', () => {
    let blocked = true;
    let href = 'https://app.example.com/settings';
    const top = {
      location: {
        get href() {
          return href;
        },
        set href(value: string) {
          if (blocked) throw new DOMException('Blocked a frame from navigating the top window', 'SecurityError');
          href = value;
        },
      },
    };
    vi.stubGlobal('window', { top });
    const handle = link({ token: TOKEN, mode: 'redirect' });
    let error: unknown;
    try {
      handle.open();
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(CredLinkError);
    expect((error as CredLinkError).code).toBe('navigation_blocked');
    expect((error as CredLinkError).message).toContain('SecurityError');
    expect(href).toBe('https://app.example.com/settings');

    // Not stuck: a later open() tries again.
    blocked = false;
    handle.open();
    expect(href).toMatch(/^https:\/\/link\.cred\.ninja\/link\/v1\/authorize\?/);
  });
});

describe('handleRedirect', () => {
  it('reads a success, cleans the Link parameters and keeps the rest of the URL', () => {
    setUrl(`/cred/return?tab=accounts&${successQuery}&utm=x%20y#section`);
    const replace = vi.spyOn(window.history, 'replaceState');
    const onSuccess = vi.fn();
    const result = Cred.handleRedirect({ onSuccess });
    expect(onSuccess).toHaveBeenCalledTimes(1);
    expect(onSuccess).toHaveBeenCalledWith({
      connection_id: 'conn_abc123',
      code: CODE,
      grant_id: 'grt_abc123',
      provider: 'google',
      scopes: ['calendar.readonly', 'gmail.send'],
      state: 'dev-csrf-value',
    });
    expect(result?.outcome).toBe('success');
    expect(replace).toHaveBeenCalledTimes(1);
    expect(window.location.pathname).toBe('/cred/return');
    expect(window.location.search).toBe('?tab=accounts&utm=x%20y');
    expect(window.location.hash).toBe('#section');
  });

  it('delivers at most once per page load', () => {
    setUrl(`/cb?${successQuery}`);
    const onSuccess = vi.fn();
    handleRedirect({ onSuccess });
    expect(handleRedirect({ onSuccess })).toBeNull();
    expect(onSuccess).toHaveBeenCalledTimes(1);
    expect(window.location.search).toBe('');
  });

  it('reads error and exit results with state', () => {
    setUrl('/cb?cred_link=error&error=required_scope_declined&request_id=req_9&state=s1');
    const onError = vi.fn();
    handleRedirect({ onError });
    expect(onError).toHaveBeenCalledWith({ error: 'required_scope_declined', request_id: 'req_9', state: 's1' });

    setUrl('/cb?cred_link=exit&step=provider&provider=notion&state=s2');
    const onExit = vi.fn();
    handleRedirect({ onExit });
    expect(onExit).toHaveBeenCalledWith({ step: 'provider', provider: 'notion', state: 's2' });
    expect(window.location.search).toBe('');
  });

  it('leaves a page without a Link result untouched', () => {
    setUrl('/cb?code=abc&state=mine');
    const replace = vi.spyOn(window.history, 'replaceState');
    const onSuccess = vi.fn();
    expect(handleRedirect({ onSuccess })).toBeNull();
    expect(replace).not.toHaveBeenCalled();
    expect(window.location.search).toBe('?code=abc&state=mine');
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('does not deliver a malformed result and leaves the URL untouched', () => {
    const path = '/cb?keep=1&cred_link=success&connection_id=conn_x&code=nope&grant_id=grt_x&provider=google&scope=a';
    setUrl(path);
    const replace = vi.spyOn(window.history, 'replaceState');
    const cbs = { onSuccess: vi.fn(), onError: vi.fn(), onExit: vi.fn() };
    expect(handleRedirect(cbs)).toBeNull();
    expect(cbs.onSuccess).not.toHaveBeenCalled();
    expect(cbs.onError).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
    expect(window.location.pathname + window.location.search).toBe(path);
  });

  it('is not affected by unrelated malformed parameters, and keeps them byte for byte', () => {
    setUrl(`/cb?bad=%E0%A4%A&${successQuery}&%zz=1&also=%`);
    const onSuccess = vi.fn();
    const result = handleRedirect({ onSuccess });
    expect(result?.outcome).toBe('success');
    expect(onSuccess).toHaveBeenCalledTimes(1);
    expect(window.location.search).toBe('?bad=%E0%A4%A&%zz=1&also=%');
  });

  it('leaves the URL untouched when a Link parameter itself is malformed', () => {
    const path = `/cb?${successQuery.replace('state=dev-csrf-value', 'state=%zz')}`;
    setUrl(path);
    const replace = vi.spyOn(window.history, 'replaceState');
    const onSuccess = vi.fn();
    expect(handleRedirect({ onSuccess })).toBeNull();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
    expect(window.location.pathname + window.location.search).toBe(path);
  });

  it('with an explicit url, parses it and leaves the browser URL alone', () => {
    setUrl('/somewhere?x=1');
    const replace = vi.spyOn(window.history, 'replaceState');
    const onSuccess = vi.fn();
    const result = handleRedirect({ url: `https://app.example.com/cb?${successQuery}`, onSuccess });
    expect(result?.outcome).toBe('success');
    expect(onSuccess).toHaveBeenCalledTimes(1);
    expect(replace).not.toHaveBeenCalled();
  });
});

describe('parseRedirectResult', () => {
  it('accepts an absolute URL, a path, a query string or a Location-like object', () => {
    for (const input of [
      `https://app.example.com/cb?${successQuery}#frag`,
      `/cb?${successQuery}`,
      `?${successQuery}`,
      successQuery,
      { search: `?${successQuery}` },
    ]) {
      expect(parseRedirectResult(input)?.outcome).toBe('success');
    }
    expect(parseRedirectResult(`https://app.example.com/cb?x=%E0%A4%A&${successQuery}`)?.outcome).toBe('success');
    expect(parseRedirectResult('https://app.example.com/cb?x=1')).toBeNull();
    expect(parseRedirectResult(`/cb?${successQuery}&state=again`)).toBeNull();
  });
});

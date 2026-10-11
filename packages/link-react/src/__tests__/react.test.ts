import { StrictMode, createElement, useEffect, useRef } from 'react';
import type { ReactElement } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CredConnect, useCredLink } from '../index.js';
import type { UseCredLinkOptions, UseCredLinkResult } from '../index.js';

const TOKEN = `urn:cred:link:${'a'.repeat(43)}`;
const ORIGIN = 'https://link.cred.ninja';
const CODE = `cred_lac_${'b'.repeat(43)}`;

const successMessage = {
  type: 'cred.link.result',
  v: 1,
  outcome: 'success',
  connection_id: 'conn_abc123',
  code: CODE,
  grant_id: 'grt_abc123',
  provider: 'google',
  scopes: ['calendar.readonly'],
  state: 'dev-csrf-value',
};

interface FakePopup {
  closed: boolean;
  close: ReturnType<typeof vi.fn>;
  focus: ReturnType<typeof vi.fn>;
}

function fakePopup(): FakePopup {
  const popup: FakePopup = { closed: false, close: vi.fn(() => { popup.closed = true; }), focus: vi.fn() };
  return popup;
}

function post(source: unknown, data: unknown, origin = ORIGIN): void {
  const event = new MessageEvent('message', { data, origin });
  // jsdom only accepts real windows as `source` in the init dict; define it directly instead.
  Object.defineProperty(event, 'source', { value: source });
  act(() => {
    window.dispatchEvent(event);
  });
}

let popup: FakePopup;
let openSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  popup = fakePopup();
  // The fake popup stands in for a WindowProxy; only closed/close/focus are used.
  openSpy = vi.spyOn(window, 'open').mockImplementation(() => popup as unknown as Window);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function button(label = 'Connect'): ReactElement {
  return createElement('button', { type: 'button' }, label);
}

describe('CredConnect', () => {
  it('opens the popup from its child trigger and delivers onSuccess', () => {
    const onSuccess = vi.fn();
    const childClick = vi.fn();
    render(createElement(CredConnect, { token: TOKEN, onSuccess },
      createElement('button', { type: 'button', onClick: childClick }, 'Connect')));
    fireEvent.click(screen.getByText('Connect'));
    expect(childClick).toHaveBeenCalledTimes(1);
    expect(openSpy).toHaveBeenCalledTimes(1);
    const url = new URL(openSpy.mock.calls[0][0] as string);
    expect(url.origin).toBe(ORIGIN);
    expect(url.searchParams.get('mode')).toBe('popup');
    post(popup, successMessage);
    expect(onSuccess).toHaveBeenCalledTimes(1);
    expect(onSuccess.mock.calls[0][0]).toMatchObject({ connection_id: 'conn_abc123', state: 'dev-csrf-value' });
  });

  it('lets the child cancel with preventDefault', () => {
    render(createElement(CredConnect, { token: TOKEN },
      createElement('button', { type: 'button', onClick: (e: { preventDefault(): void }) => e.preventDefault() }, 'Connect')));
    fireEvent.click(screen.getByText('Connect'));
    expect(openSpy).not.toHaveBeenCalled();
  });

  it('uses the latest callbacks without re-creating the flow', () => {
    const first = vi.fn();
    const second = vi.fn();
    const { rerender } = render(createElement(CredConnect, { token: TOKEN, providers: ['google'], onSuccess: first }, button()));
    fireEvent.click(screen.getByText('Connect'));
    rerender(createElement(CredConnect, { token: TOKEN, providers: ['google'], theme: undefined, onSuccess: second }, button()));
    expect(popup.close).not.toHaveBeenCalled();
    post(popup, successMessage);
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
    expect(openSpy).toHaveBeenCalledTimes(1);
  });

  it('cleans up on unmount: popup closed, listener removed, no callbacks after', () => {
    const remove = vi.spyOn(window, 'removeEventListener');
    const onSuccess = vi.fn();
    const onExit = vi.fn();
    const { unmount } = render(createElement(CredConnect, { token: TOKEN, onSuccess, onExit }, button()));
    fireEvent.click(screen.getByText('Connect'));
    unmount();
    expect(popup.close).toHaveBeenCalled();
    expect(remove).toHaveBeenCalledWith('message', expect.any(Function));
    post(popup, successMessage);
    expect(onSuccess).not.toHaveBeenCalled();
    expect(onExit).not.toHaveBeenCalled();
  });

  it('does not open two flows under strict mode', () => {
    const add = vi.spyOn(window, 'addEventListener');
    const onSuccess = vi.fn();
    render(createElement(StrictMode, null, createElement(CredConnect, { token: TOKEN, onSuccess }, button())));
    fireEvent.click(screen.getByText('Connect'));
    expect(openSpy).toHaveBeenCalledTimes(1);
    expect(add.mock.calls.filter(([type]) => type === 'message')).toHaveLength(1);
    post(popup, successMessage);
    expect(onSuccess).toHaveBeenCalledTimes(1);
  });

  it('wraps non-element children in a button that waits for a token', () => {
    const { rerender } = render(createElement(CredConnect, { token: null }, 'Link account'));
    const el = screen.getByRole('button', { name: 'Link account' });
    expect((el as HTMLButtonElement).disabled).toBe(true);
    rerender(createElement(CredConnect, { token: TOKEN }, 'Link account'));
    expect((el as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(el);
    expect(openSpy).toHaveBeenCalledTimes(1);
  });

  it('logs a programming error instead of throwing when the popup is blocked', () => {
    openSpy.mockImplementation(() => null);
    const log = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    render(createElement(CredConnect, { token: TOKEN }, button()));
    expect(() => fireEvent.click(screen.getByText('Connect'))).not.toThrow();
    expect(log).toHaveBeenCalledWith(expect.stringContaining('popup_blocked'));
  });
});

describe('useCredLink', () => {
  function Probe(props: { options: UseCredLinkOptions; onResult: (r: UseCredLinkResult) => void }): null {
    const result = useCredLink(props.options);
    props.onResult(result);
    return null;
  }

  function renderHook(options: UseCredLinkOptions) {
    let latest: UseCredLinkResult | undefined;
    const onResult = (r: UseCredLinkResult) => {
      latest = r;
    };
    const utils = render(createElement(Probe, { options, onResult }));
    return {
      get current(): UseCredLinkResult {
        if (!latest) throw new Error('not rendered');
        return latest;
      },
      rerender: (next: UseCredLinkOptions) => utils.rerender(createElement(Probe, { options: next, onResult })),
      unmount: utils.unmount,
    };
  }

  it('is not ready without a token and becomes ready when one arrives', () => {
    const hook = renderHook({ token: undefined });
    expect(hook.current.ready).toBe(false);
    act(() => hook.current.open());
    expect(openSpy).not.toHaveBeenCalled();
    hook.rerender({ token: TOKEN });
    expect(hook.current.ready).toBe(true);
    expect(hook.current.error).toBeNull();
    act(() => hook.current.open());
    expect(openSpy).toHaveBeenCalledTimes(1);
  });

  it('keeps open stable across renders', () => {
    const hook = renderHook({ token: TOKEN, onSuccess: vi.fn() });
    const first = hook.current.open;
    hook.rerender({ token: TOKEN, onSuccess: vi.fn() });
    expect(hook.current.open).toBe(first);
  });

  it('reports invalid options and popup blocking through error', () => {
    const bad = renderHook({ token: 'nope' });
    expect(bad.current.ready).toBe(false);
    expect(bad.current.error?.code).toBe('invalid_token');
    bad.unmount();

    openSpy.mockImplementation(() => null);
    const hook = renderHook({ token: TOKEN });
    act(() => hook.current.open());
    expect(hook.current.error?.code).toBe('popup_blocked');
    openSpy.mockImplementation(() => popup as unknown as Window);
    act(() => hook.current.open());
    expect(hook.current.error).toBeNull();
  });

  it('renders one embedded iframe when opened from an effect under strict mode, and removes it on unmount', () => {
    function Embedded(): ReactElement {
      const ref = useRef<HTMLDivElement>(null);
      const { open, ready } = useCredLink({ token: TOKEN, mode: 'embedded', container: ref });
      useEffect(() => {
        if (ready) open();
      }, [ready, open]);
      return createElement('div', { ref, 'data-testid': 'host' });
    }
    const { unmount } = render(createElement(StrictMode, null, createElement(Embedded)));
    const host = screen.getByTestId('host');
    expect(host.querySelectorAll('iframe')).toHaveLength(1);
    const iframe = host.querySelector('iframe') as HTMLIFrameElement;
    expect(new URL(iframe.src).searchParams.get('mode')).toBe('embedded');
    post(iframe.contentWindow, { type: 'cred.link.resize', v: 1, height: 300 });
    expect(iframe.style.height).toBe('300px');
    unmount();
    expect(host.querySelectorAll('iframe')).toHaveLength(0);
  });
});

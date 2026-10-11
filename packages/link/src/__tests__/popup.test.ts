import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseLinkAuthorizeQuery } from '@credninja/protocol';
import { CredLinkError, LINK_POPUP_HEIGHT, LINK_POPUP_WIDTH, link } from '../index.js';
import type { CredLinkOptions } from '../index.js';
import {
  ORIGIN,
  TOKEN,
  errorMessage,
  exitMessage,
  expectedSuccessPayload,
  fakePopup,
  post,
  successMessage,
} from './helpers.js';
import type { FakePopup } from './helpers.js';

let popup: FakePopup;
let openSpy: ReturnType<typeof vi.spyOn>;

function callbacks() {
  return { onSuccess: vi.fn(), onError: vi.fn(), onExit: vi.fn() };
}

function create(extra: Partial<CredLinkOptions> = {}) {
  const cbs = callbacks();
  const handle = link({ token: TOKEN, ...cbs, ...extra });
  return { handle, ...cbs };
}

function totalCalls(cbs: ReturnType<typeof callbacks>): number {
  return cbs.onSuccess.mock.calls.length + cbs.onError.mock.calls.length + cbs.onExit.mock.calls.length;
}

beforeEach(() => {
  vi.useFakeTimers();
  popup = fakePopup();
  // The fake popup stands in for a WindowProxy; only closed/close/focus are used.
  openSpy = vi.spyOn(window, 'open').mockImplementation(() => popup as unknown as Window);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('popup mode', () => {
  it('opens the authorize URL in a centered popup sized by the widget', () => {
    const { handle } = create();
    handle.open();
    expect(openSpy).toHaveBeenCalledTimes(1);
    const [url, target, features] = openSpy.mock.calls[0] as [string, string, string];
    expect(target).toBe('_blank');
    expect(features).toContain(`width=${LINK_POPUP_WIDTH}`);
    expect(features).toContain(`height=${LINK_POPUP_HEIGHT}`);
    expect(features).toMatch(/left=-?\d+/);
    expect(features).toMatch(/top=-?\d+/);
    expect(features).not.toContain('noopener');
    expect(new URL(url).origin).toBe(ORIGIN);
    expect(parseLinkAuthorizeQuery(new URL(url).search)).toEqual({ request_uri: TOKEN, mode: 'popup' });
    handle.destroy();
  });

  it('delivers onSuccess with the echoed state, closes the popup and stops listening', () => {
    const remove = vi.spyOn(window, 'removeEventListener');
    const cbs = create();
    cbs.handle.open();
    post(popup, successMessage);
    expect(cbs.onSuccess).toHaveBeenCalledTimes(1);
    expect(cbs.onSuccess).toHaveBeenCalledWith(expectedSuccessPayload);
    expect(popup.close).toHaveBeenCalled();
    expect(remove).toHaveBeenCalledWith('message', expect.any(Function));
    expect(vi.getTimerCount()).toBe(0);
  });

  it('delivers onError and server-reported onExit with state', () => {
    const a = create();
    a.handle.open();
    post(popup, errorMessage);
    expect(a.onError).toHaveBeenCalledWith({ error: 'access_denied', request_id: 'req_123', state: 'dev-csrf-value' });

    popup = fakePopup();
    const b = create();
    b.handle.open();
    post(popup, exitMessage);
    expect(b.onExit).toHaveBeenCalledWith({ step: 'confirm', provider: 'slack', state: 'dev-csrf-value' });
    expect(totalCalls(a)).toBe(1);
    expect(totalCalls(b)).toBe(1);
  });

  describe('origin pinning', () => {
    it('ignores a well-formed result from another origin', () => {
      const cbs = create();
      cbs.handle.open();
      post(popup, successMessage, 'https://evil.example');
      post(popup, successMessage, 'https://link.cred.ninja.evil.example');
      post(popup, successMessage, 'http://link.cred.ninja');
      expect(totalCalls(cbs)).toBe(0);
      post(popup, successMessage);
      expect(cbs.onSuccess).toHaveBeenCalledTimes(1);
    });

    it('ignores a message from the right origin but a different window', () => {
      const cbs = create();
      cbs.handle.open();
      post(fakePopup(), successMessage);
      post(window, successMessage);
      post(null, successMessage);
      expect(totalCalls(cbs)).toBe(0);
      post(popup, successMessage);
      expect(cbs.onSuccess).toHaveBeenCalledTimes(1);
    });

    it('ignores malformed messages', () => {
      const cbs = create();
      cbs.handle.open();
      post(popup, 'cred.link.result');
      post(popup, JSON.stringify(successMessage));
      post(popup, { ...successMessage, v: 2 });
      post(popup, { ...successMessage, code: 'not-a-code' });
      post(popup, { ...successMessage, connection_id: 'abc' });
      post(popup, { ...errorMessage, error: 'made_up' });
      post(popup, { ...exitMessage, step: 'done' });
      post(popup, { type: 'cred.link.step', v: 1, step: 'nowhere' });
      expect(totalCalls(cbs)).toBe(0);
    });

    it('ignores step messages from the wrong origin or window', () => {
      const cbs = create();
      cbs.handle.open();
      post(popup, { type: 'cred.link.step', v: 1, step: 'confirm', provider: 'github' }, 'https://evil.example');
      post(fakePopup(), { type: 'cred.link.step', v: 1, step: 'confirm', provider: 'github' });
      cbs.handle.close();
      expect(cbs.onExit).toHaveBeenCalledWith({ step: 'picker' });
    });
  });

  it('delivers exactly one terminal callback per open()', () => {
    const cbs = create();
    cbs.handle.open();
    post(popup, successMessage);
    post(popup, errorMessage);
    post(popup, exitMessage);
    popup.closed = true;
    vi.advanceTimersByTime(5000);
    cbs.handle.close();
    expect(totalCalls(cbs)).toBe(1);
    expect(cbs.onSuccess).toHaveBeenCalledTimes(1);
  });

  it('reports onExit with the last reported step when the popup is closed without a result', () => {
    const cbs = create();
    cbs.handle.open();
    post(popup, { type: 'cred.link.step', v: 1, step: 'picker' });
    post(popup, { type: 'cred.link.step', v: 1, step: 'provider', provider: 'google' });
    popup.closed = true;
    vi.advanceTimersByTime(500);
    expect(cbs.onExit).not.toHaveBeenCalled();
    vi.advanceTimersByTime(300);
    expect(cbs.onExit).toHaveBeenCalledTimes(1);
    expect(cbs.onExit).toHaveBeenCalledWith({ step: 'provider', provider: 'google' });
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(5000);
    expect(totalCalls(cbs)).toBe(1);
  });

  it('defaults the exit step to picker when no step was reported', () => {
    const cbs = create();
    cbs.handle.open();
    popup.closed = true;
    vi.advanceTimersByTime(1000);
    expect(cbs.onExit).toHaveBeenCalledWith({ step: 'picker' });
  });

  it('lets a result posted just before the popup closed win over the exit', () => {
    const cbs = create();
    cbs.handle.open();
    popup.closed = true;
    vi.advanceTimersByTime(500);
    post(popup, successMessage);
    vi.advanceTimersByTime(1000);
    expect(cbs.onSuccess).toHaveBeenCalledTimes(1);
    expect(cbs.onExit).not.toHaveBeenCalled();
  });

  it('allows a new attempt after a widget-detected exit, but not after a server result', () => {
    const cbs = create();
    cbs.handle.open();
    popup.closed = true;
    vi.advanceTimersByTime(1000);
    expect(cbs.onExit).toHaveBeenCalledTimes(1);

    popup = fakePopup();
    cbs.handle.open();
    expect(openSpy).toHaveBeenCalledTimes(2);
    post(popup, successMessage);
    expect(cbs.onSuccess).toHaveBeenCalledTimes(1);

    let code: string | undefined;
    try {
      cbs.handle.open();
    } catch (err) {
      code = (err as CredLinkError).code;
    }
    expect(code).toBe('token_spent');
    expect(openSpy).toHaveBeenCalledTimes(2);
  });

  it('does not start a second flow when open() is called twice; it focuses the popup', () => {
    const add = vi.spyOn(window, 'addEventListener');
    const cbs = create();
    cbs.handle.open();
    cbs.handle.open();
    expect(openSpy).toHaveBeenCalledTimes(1);
    expect(add.mock.calls.filter(([type]) => type === 'message')).toHaveLength(1);
    expect(popup.focus).toHaveBeenCalledTimes(1);
    post(popup, successMessage);
    expect(cbs.onSuccess).toHaveBeenCalledTimes(1);
  });

  describe('popup blocked', () => {
    it('throws popup_blocked when window.open returns null, leaving nothing behind', () => {
      openSpy.mockImplementation(() => null);
      const add = vi.spyOn(window, 'addEventListener');
      const cbs = create();
      let error: unknown;
      try {
        cbs.handle.open();
      } catch (err) {
        error = err;
      }
      expect(error).toBeInstanceOf(CredLinkError);
      expect((error as CredLinkError).code).toBe('popup_blocked');
      expect(add).not.toHaveBeenCalled();
      expect(vi.getTimerCount()).toBe(0);
      expect(totalCalls(cbs)).toBe(0);

      // The handle is still usable: a later click can try again.
      openSpy.mockImplementation(() => popup as unknown as Window);
      cbs.handle.open();
      post(popup, successMessage);
      expect(cbs.onSuccess).toHaveBeenCalledTimes(1);
    });

    it('treats a popup that is already closed as blocked', () => {
      popup.closed = true;
      const cbs = create();
      expect(() => cbs.handle.open()).toThrow(CredLinkError);
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  it('close() closes the popup and reports onExit once', () => {
    const cbs = create();
    cbs.handle.open();
    post(popup, { type: 'cred.link.step', v: 1, step: 'confirm', provider: 'google' });
    cbs.handle.close();
    cbs.handle.close();
    expect(popup.close).toHaveBeenCalled();
    expect(cbs.onExit).toHaveBeenCalledTimes(1);
    expect(cbs.onExit).toHaveBeenCalledWith({ step: 'confirm', provider: 'google' });
    expect(vi.getTimerCount()).toBe(0);
    post(popup, successMessage);
    expect(cbs.onSuccess).not.toHaveBeenCalled();
  });

  it('destroy() tears down silently and the handle cannot be reopened', () => {
    const remove = vi.spyOn(window, 'removeEventListener');
    const cbs = create();
    cbs.handle.open();
    cbs.handle.destroy();
    expect(popup.close).toHaveBeenCalled();
    expect(remove).toHaveBeenCalledWith('message', expect.any(Function));
    expect(vi.getTimerCount()).toBe(0);
    post(popup, successMessage);
    vi.advanceTimersByTime(5000);
    expect(totalCalls(cbs)).toBe(0);
    expect(() => cbs.handle.open()).toThrow(/destroy/);
    cbs.handle.close();
    cbs.handle.destroy();
  });

  it('a throwing callback still leaves the widget torn down', () => {
    const cbs = create({
      onSuccess: () => {
        throw new Error('developer bug');
      },
    });
    // The browser reports a listener exception as an error event; swallow it for this test.
    const reported: unknown[] = [];
    const onError = (event: ErrorEvent) => {
      reported.push(event.error);
      event.preventDefault();
    };
    window.addEventListener('error', onError);
    cbs.handle.open();
    post(popup, successMessage);
    window.removeEventListener('error', onError);
    expect(reported).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0);
    expect(popup.close).toHaveBeenCalled();
    expect(() => cbs.handle.open()).toThrow(/new token/);
  });
});

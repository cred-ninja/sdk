import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseLinkAuthorizeQuery } from '@credninja/protocol';
import { LINK_IFRAME_SANDBOX, link } from '../index.js';
import { TOKEN, expectedSuccessPayload, fakePopup, post, successMessage } from './helpers.js';

let container: HTMLDivElement;

function setup() {
  const cbs = { onSuccess: vi.fn(), onError: vi.fn(), onExit: vi.fn() };
  const handle = link({ token: TOKEN, mode: 'embedded', container, theme: { appName: 'Acme', accent: '#123456' }, ...cbs });
  return { handle, ...cbs };
}

function frame(): HTMLIFrameElement {
  const el = container.querySelector('iframe');
  if (!el) throw new Error('no iframe');
  return el;
}

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  vi.restoreAllMocks();
});

describe('embedded mode', () => {
  it('renders the picker iframe into the container with a tight sandbox', () => {
    const open = vi.spyOn(window, 'open');
    const { handle } = setup();
    handle.open();
    const iframe = frame();
    expect(open).not.toHaveBeenCalled();
    const src = new URL(iframe.src);
    expect(src.origin).toBe('https://link.cred.ninja');
    expect(src.pathname).toBe('/link/v1/authorize');
    expect(parseLinkAuthorizeQuery(src.search)).toEqual({ request_uri: TOKEN, mode: 'embedded', theme: { accent: '#123456' } });
    expect(src.searchParams.has('app_name')).toBe(false);

    const tokens = (iframe.getAttribute('sandbox') ?? '').split(' ').sort();
    expect(tokens).toEqual(
      ['allow-forms', 'allow-popups', 'allow-popups-to-escape-sandbox', 'allow-same-origin', 'allow-scripts'],
    );
    expect(iframe.getAttribute('sandbox')).toBe(LINK_IFRAME_SANDBOX);
    expect(tokens.some((t) => t.startsWith('allow-top-navigation'))).toBe(false);
    expect(iframe.getAttribute('title')).toBeTruthy();
    expect(iframe.getAttribute('referrerpolicy')).toBe('strict-origin');
    handle.destroy();
  });

  it('honors resize messages from its own iframe only', () => {
    const { handle } = setup();
    handle.open();
    const iframe = frame();
    post(iframe.contentWindow, { type: 'cred.link.resize', v: 1, height: 412.4 });
    expect(iframe.style.height).toBe('413px');
    post(iframe.contentWindow, { type: 'cred.link.resize', v: 1, height: 900 }, 'https://evil.example');
    post(window, { type: 'cred.link.resize', v: 1, height: 900 });
    post(fakePopup(), { type: 'cred.link.resize', v: 1, height: 900 });
    post(iframe.contentWindow, { type: 'cred.link.resize', v: 1, height: 1e9 });
    expect(iframe.style.height).toBe('413px');
    handle.destroy();
  });

  it('receives the relayed result from the iframe, then removes the iframe', () => {
    const cbs = setup();
    cbs.handle.open();
    const iframe = frame();
    post(window, successMessage);
    post(iframe.contentWindow, successMessage, 'https://evil.example');
    expect(cbs.onSuccess).not.toHaveBeenCalled();
    post(iframe.contentWindow, successMessage);
    post(iframe.contentWindow, successMessage);
    expect(cbs.onSuccess).toHaveBeenCalledTimes(1);
    expect(cbs.onSuccess).toHaveBeenCalledWith(expectedSuccessPayload);
    expect(container.querySelector('iframe')).toBeNull();
  });

  it('does not render a second iframe when open() is called twice', () => {
    const { handle } = setup();
    handle.open();
    handle.open();
    expect(container.querySelectorAll('iframe')).toHaveLength(1);
    handle.destroy();
  });

  it('close() removes the iframe and reports onExit with the last step', () => {
    const cbs = setup();
    cbs.handle.open();
    post(frame().contentWindow, { type: 'cred.link.step', v: 1, step: 'picker' });
    cbs.handle.close();
    expect(container.querySelector('iframe')).toBeNull();
    expect(cbs.onExit).toHaveBeenCalledTimes(1);
    expect(cbs.onExit).toHaveBeenCalledWith({ step: 'picker' });
  });

  it('destroy() removes the iframe and the listener without callbacks', () => {
    const remove = vi.spyOn(window, 'removeEventListener');
    const cbs = setup();
    cbs.handle.open();
    const iframe = frame();
    const source = iframe.contentWindow;
    cbs.handle.destroy();
    expect(container.querySelector('iframe')).toBeNull();
    expect(remove).toHaveBeenCalledWith('message', expect.any(Function));
    post(source, successMessage);
    expect(cbs.onSuccess).not.toHaveBeenCalled();
    expect(cbs.onExit).not.toHaveBeenCalled();
  });
});

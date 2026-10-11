import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  LINK_TRANSACTION_TTL_SECONDS,
  appendLinkRedirectResult,
  linkResultMessage,
  parseLinkAuthorizeQuery,
} from '@credninja/protocol';
import type { LinkResult } from '@credninja/protocol';
import {
  CredLinkError,
  LINK_OPENER_LOSS_WINDOW_MS,
  LINK_RELAY_CHANNEL,
  LINK_RELAY_CLAIM_TIMEOUT_MS,
  LINK_RELAY_RECEIPT_GRACE_MS,
  LINK_RELAY_RECEIPT_TIMEOUT_MS,
  handleRedirect,
  link,
} from '../index.js';
import type { CredLinkOptions } from '../index.js';
import {
  CODE,
  FakeBroadcastChannel,
  ORIGIN,
  TOKEN,
  errorMessage,
  expectedSuccessPayload,
  fakePopup,
  flowIdOf,
  flush,
  post,
  settle,
  successMessage,
} from './helpers.js';
import type { FakePopup } from './helpers.js';

const OTHER_TOKEN = `urn:cred:link:${'c'.repeat(43)}`;
const successResult: LinkResult = {
  outcome: 'success',
  connection_id: 'conn_abc123',
  code: CODE,
  grant_id: 'grt_abc123',
  provider: 'google',
  scopes: ['calendar.readonly'],
  state: 'dev-csrf-value',
};
const forged: LinkResult = {
  outcome: 'success',
  connection_id: 'conn_attacker1',
  code: `cred_lac_${'Z'.repeat(43)}`,
  grant_id: 'grt_attacker1',
  provider: 'github',
  scopes: ['repo'],
  state: 'attacker-state',
};
const ACK = { type: 'cred.link.ack', v: 1 };
const providerStep = { type: 'cred.link.step', v: 1, step: 'provider', provider: 'google' };
const handoffStep = { ...providerStep, handoff: 'redirect' };

let popup: FakePopup;
let openSpy: ReturnType<typeof vi.spyOn>;
let FLOW: string;
let OTHER_FLOW: string;

function callbacks() {
  return { onSuccess: vi.fn(), onError: vi.fn(), onExit: vi.fn() };
}
type Cbs = ReturnType<typeof callbacks>;
function total(cbs: Cbs): number {
  return cbs.onSuccess.mock.calls.length + cbs.onError.mock.calls.length + cbs.onExit.mock.calls.length;
}

function popupWidget(extra: Partial<CredLinkOptions> = {}) {
  const cbs = callbacks();
  const handle = link({ token: TOKEN, ...cbs, ...extra });
  return { handle, ...cbs };
}

function embeddedWidget(token = TOKEN) {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const cbs = callbacks();
  const handle = link({ token, mode: 'embedded', container, ...cbs });
  handle.open();
  return { handle, container, ...cbs };
}

/** A popup-fallback return URL bound to `flow` (the server's request_uri hash). */
function returnUrl(result: LinkResult = successResult, flow: string | null = FLOW, extraQuery = ''): string {
  return appendLinkRedirectResult(`/cred/return${extraQuery}`, result, flow ? { via: 'popup', flow_id: flow } : { via: 'popup' });
}

/** Put the popup into a suspected opener loss: provider step, then the popup reads closed right away. */
function suspect(): void {
  post(popup, providerStep);
  popup.closed = true;
  vi.advanceTimersByTime(500);
}

function postedTypes(): string[] {
  return FakeBroadcastChannel.posted.map((p) => (p.data as { type: string }).type);
}

/** A same-origin peer on the relay channel that records what it sees. */
function peer() {
  const ch = new FakeBroadcastChannel(LINK_RELAY_CHANNEL);
  const seen: Array<Record<string, unknown>> = [];
  ch.addEventListener('message', (e) => seen.push(e.data as Record<string, unknown>));
  return { ch, seen };
}

beforeEach(async () => {
  FLOW = await flowIdOf(TOKEN);
  OTHER_FLOW = await flowIdOf(OTHER_TOKEN);
  vi.useFakeTimers();
  FakeBroadcastChannel.reset();
  vi.stubGlobal('BroadcastChannel', FakeBroadcastChannel);
  popup = fakePopup();
  // The fake popup stands in for a WindowProxy; only closed/close/focus/postMessage are used.
  openSpy = vi.spyOn(window, 'open').mockImplementation(() => popup as unknown as Window);
  window.history.replaceState(null, '', '/');
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  document.body.innerHTML = '';
});

describe('ack', () => {
  it('acks a valid result to its source window and origin before any callback', () => {
    const order: string[] = [];
    popup.postMessage.mockImplementation(() => order.push('ack'));
    const w = popupWidget({ onSuccess: () => order.push('onSuccess') });
    w.handle.open();
    post(popup, successMessage);
    expect(popup.postMessage).toHaveBeenCalledTimes(1);
    expect(popup.postMessage).toHaveBeenCalledWith(ACK, ORIGIN);
    expect(order).toEqual(['ack', 'onSuccess']);
  });

  it('acks error and exit results too, but never anything that failed validation', () => {
    const w = popupWidget();
    w.handle.open();
    const stranger = fakePopup();
    post(popup, successMessage, 'https://evil.example');
    post(stranger, successMessage);
    post(popup, { ...successMessage, code: 'nope' });
    post(popup, providerStep);
    post(popup, { type: 'cred.link.resize', v: 1, height: 10 });
    expect(popup.postMessage).not.toHaveBeenCalled();
    expect(stranger.postMessage).not.toHaveBeenCalled();
    post(popup, errorMessage);
    expect(popup.postMessage).toHaveBeenCalledWith(ACK, ORIGIN);
    expect(w.onError).toHaveBeenCalledTimes(1);
  });

  it('acks to the iframe in embedded mode', () => {
    const w = embeddedWidget();
    const frameWindow = (w.container.querySelector('iframe') as HTMLIFrameElement).contentWindow as Window;
    const ack = vi.spyOn(frameWindow, 'postMessage').mockImplementation(() => undefined);
    post(frameWindow, successMessage);
    expect(ack).toHaveBeenCalledWith(ACK, ORIGIN);
    expect(w.onSuccess).toHaveBeenCalledTimes(1);
  });
});

describe('handoff to redirect', () => {
  function fakeTopWindow() {
    const listeners: Array<(event: unknown) => void> = [];
    const top = { location: { href: 'https://app.example.com/settings' } };
    const win = {
      top,
      open: vi.fn(() => popup),
      addEventListener: vi.fn((type: string, fn: (event: unknown) => void) => {
        if (type === 'message') listeners.push(fn);
      }),
      removeEventListener: vi.fn(),
    };
    vi.stubGlobal('window', win);
    const send = (data: unknown, source: unknown = popup, origin = ORIGIN) => {
      for (const fn of [...listeners]) fn({ data, source, origin });
    };
    return { win, top, send };
  }

  it('closes the popup and navigates the top window to a redirect-mode authorize URL, with no callback', () => {
    const { win, top, send } = fakeTopWindow();
    const w = popupWidget({ providers: ['google', 'slack'], theme: { accent: '#123456' } });
    w.handle.open();
    expect(win.open).toHaveBeenCalledTimes(1);
    send(handoffStep);
    expect(popup.close).toHaveBeenCalled();
    const url = new URL(top.location.href);
    expect(url.origin + url.pathname).toBe(`${ORIGIN}/link/v1/authorize`);
    expect(parseLinkAuthorizeQuery(url.search)).toEqual({
      request_uri: TOKEN,
      mode: 'redirect',
      providers: ['google', 'slack'],
      theme: { accent: '#123456' },
    });
    expect(total(w)).toBe(0);
    expect(FakeBroadcastChannel.open.size).toBe(0);
    w.handle.open();
    expect(win.open).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ignores a malformed handoff', () => {
    const { top, send } = fakeTopWindow();
    const w = popupWidget();
    w.handle.open();
    send({ type: 'cred.link.step', v: 1, step: 'picker', provider: 'google', handoff: 'redirect' });
    send({ ...handoffStep, handoff: 'popup' });
    send({ type: 'cred.link.step', v: 1, step: 'provider', handoff: 'redirect' });
    send(handoffStep, popup, 'https://evil.example');
    send(handoffStep, fakePopup());
    expect(top.location.href).toBe('https://app.example.com/settings');
    expect(popup.close).not.toHaveBeenCalled();
    w.handle.close();
    expect(w.onExit).toHaveBeenCalledWith({ step: 'picker' });
  });

  it('reports navigation_blocked through onExit and the listener error when the top window refuses', () => {
    const { top, send } = fakeTopWindow();
    Object.defineProperty(top.location, 'href', {
      get: () => 'https://app.example.com/settings',
      set: () => {
        throw new DOMException('blocked', 'SecurityError');
      },
    });
    const w = popupWidget();
    w.handle.open();
    let thrown: unknown;
    try {
      send(handoffStep);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(CredLinkError);
    expect((thrown as CredLinkError).code).toBe('navigation_blocked');
    expect(w.onExit).toHaveBeenCalledWith({ step: 'provider', provider: 'google' });
    expect(total(w)).toBe(1);
  });

  it('is ignored in embedded mode', () => {
    const w = embeddedWidget();
    const iframe = w.container.querySelector('iframe') as HTMLIFrameElement;
    const before = window.location.href;
    post(iframe.contentWindow, handoffStep);
    expect(window.location.href).toBe(before);
    expect(w.container.querySelector('iframe')).toBe(iframe);
    expect(total(w)).toBe(0);
    w.handle.close();
    expect(w.onExit).toHaveBeenCalledWith({ step: 'provider', provider: 'google' });
  });
});

describe('suspected opener loss', () => {
  it('fires no exit, then a relayed success delivers onSuccess exactly once; the return page calls onRelayed and closes', async () => {
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const w = popupWidget();
    w.handle.open();
    await settle();
    suspect();
    vi.advanceTimersByTime(60_000);
    expect(total(w)).toBe(0);

    window.history.replaceState(null, '', returnUrl());
    const here = { ...callbacks(), onRelayed: vi.fn() };
    const returned = handleRedirect(here);
    expect(returned?.outcome).toBe('success');
    expect(window.location.search).toBe('');
    await flush();

    expect(w.onSuccess).toHaveBeenCalledTimes(1);
    expect(w.onSuccess).toHaveBeenCalledWith(expectedSuccessPayload);
    expect(here.onRelayed).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
    expect(total(here)).toBe(0);
    expect(postedTypes()).toEqual(['cred.link.relay.offer', 'cred.link.relay.claim', 'cred.link.relay.deliver', 'cred.link.relay.receipt']);
    vi.advanceTimersByTime(LINK_TRANSACTION_TTL_SECONDS * 1000);
    await flush();
    expect(total(w)).toBe(1);
    expect(total(here)).toBe(0);
    expect(FakeBroadcastChannel.open.size).toBe(0);
  });

  it('a popup closed outside the window after the provider step still exits as before', () => {
    const w = popupWidget();
    w.handle.open();
    post(popup, providerStep);
    vi.advanceTimersByTime(LINK_OPENER_LOSS_WINDOW_MS + 500);
    popup.closed = true;
    vi.advanceTimersByTime(800);
    expect(w.onExit).toHaveBeenCalledTimes(1);
    expect(w.onExit).toHaveBeenCalledWith({ step: 'provider', provider: 'google' });
  });

  it('a later step clears the suspicion window', () => {
    const w = popupWidget();
    w.handle.open();
    post(popup, providerStep);
    post(popup, { type: 'cred.link.step', v: 1, step: 'confirm', provider: 'google' });
    popup.closed = true;
    vi.advanceTimersByTime(800);
    expect(w.onExit).toHaveBeenCalledWith({ step: 'confirm', provider: 'google' });
  });

  it('times out to onExit at the transaction TTL', () => {
    const w = popupWidget();
    w.handle.open();
    suspect();
    vi.advanceTimersByTime(LINK_TRANSACTION_TTL_SECONDS * 1000 - 1);
    expect(w.onExit).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(w.onExit).toHaveBeenCalledTimes(1);
    expect(w.onExit).toHaveBeenCalledWith({ step: 'provider', provider: 'google' });
    expect(vi.getTimerCount()).toBe(0);
    expect(FakeBroadcastChannel.open.size).toBe(0);
  });

  it('close() during the suspicion exits immediately', () => {
    const w = popupWidget();
    w.handle.open();
    suspect();
    w.handle.close();
    expect(w.onExit).toHaveBeenCalledWith({ step: 'provider', provider: 'google' });
    expect(vi.getTimerCount()).toBe(0);
    expect(FakeBroadcastChannel.open.size).toBe(0);
  });

  it('open() during the suspicion ends that attempt with onExit and starts a new popup', () => {
    const w = popupWidget();
    w.handle.open();
    suspect();
    popup = fakePopup();
    w.handle.open();
    expect(w.onExit).toHaveBeenCalledTimes(1);
    expect(openSpy).toHaveBeenCalledTimes(2);
    post(popup, successMessage);
    expect(w.onSuccess).toHaveBeenCalledTimes(1);
  });

  it('open() during the suspicion returns quietly when onExit destroyed the handle', () => {
    let handle: ReturnType<typeof link> | null = null;
    handle = link({ token: TOKEN, onExit: () => handle?.destroy() });
    handle.open();
    suspect();
    expect(() => handle?.open()).not.toThrow();
    expect(openSpy).toHaveBeenCalledTimes(1);
  });

  it('destroy() closes the relay channel', () => {
    const w = popupWidget();
    w.handle.open();
    expect(FakeBroadcastChannel.open.size).toBe(1);
    suspect();
    w.handle.destroy();
    expect(FakeBroadcastChannel.open.size).toBe(0);
    expect(total(w)).toBe(0);
  });
});

describe('relay is bound to the flow', () => {
  it('a crafted URL without a flow id reaches no widget and is delivered here exactly like a plain redirect result', async () => {
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const victim = embeddedWidget();
    await settle();
    window.history.replaceState(null, '', returnUrl(forged, null));
    const here = { ...callbacks(), onRelayed: vi.fn() };
    handleRedirect(here);
    // Synchronous, no channel: same as a plain redirect result.
    expect(here.onSuccess).toHaveBeenCalledTimes(1);
    expect(here.onSuccess.mock.calls[0][0]).toMatchObject({ connection_id: 'conn_attacker1' });
    expect(FakeBroadcastChannel.posted).toHaveLength(0);
    await flush();
    vi.advanceTimersByTime(5000);
    expect(total(victim)).toBe(0);
    expect(victim.container.querySelector('iframe')).not.toBeNull();
    expect(here.onRelayed).not.toHaveBeenCalled();
    expect(close).not.toHaveBeenCalled();
  });

  it('a crafted URL with a wrong flow id is offered but claimed by nobody, then delivered here; the widgets keep their flows', async () => {
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const victim = embeddedWidget();
    const suspicious = popupWidget();
    suspicious.handle.open();
    await settle();
    suspect();
    window.history.replaceState(null, '', returnUrl(forged, OTHER_FLOW));
    const here = callbacks();
    handleRedirect(here);
    await flush();
    expect(postedTypes()).toEqual(['cred.link.relay.offer']);
    vi.advanceTimersByTime(LINK_RELAY_CLAIM_TIMEOUT_MS);
    expect(here.onSuccess).toHaveBeenCalledTimes(1);
    expect(total(victim)).toBe(0);
    expect(total(suspicious)).toBe(0);
    expect(victim.container.querySelector('iframe')).not.toBeNull();
    expect(close).not.toHaveBeenCalled();
    victim.handle.destroy();
    suspicious.handle.destroy();
  });

  it('with two widgets on different tokens, only the matching one claims and receives the result', async () => {
    vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const mine = embeddedWidget(TOKEN);
    const theirs = embeddedWidget(OTHER_TOKEN);
    await settle();
    window.history.replaceState(null, '', returnUrl());
    const here = { ...callbacks(), onRelayed: vi.fn() };
    handleRedirect(here);
    await flush();
    vi.advanceTimersByTime(LINK_RELAY_CLAIM_TIMEOUT_MS + LINK_RELAY_RECEIPT_TIMEOUT_MS);
    await flush();
    expect(postedTypes().filter((t) => t === 'cred.link.relay.claim')).toHaveLength(1);
    expect(mine.onSuccess).toHaveBeenCalledTimes(1);
    expect(total(theirs)).toBe(0);
    expect(theirs.container.querySelector('iframe')).not.toBeNull();
    expect(here.onRelayed).toHaveBeenCalledTimes(1);
    expect(total(here)).toBe(0);
    theirs.handle.destroy();
  });

  it('a widget without Web Crypto has no flow id and does not claim', async () => {
    vi.stubGlobal('crypto', { getRandomValues: (a: Uint8Array) => a });
    const w = embeddedWidget();
    await settle();
    window.history.replaceState(null, '', returnUrl());
    const here = callbacks();
    handleRedirect(here);
    await flush();
    vi.advanceTimersByTime(LINK_RELAY_CLAIM_TIMEOUT_MS);
    expect(here.onSuccess).toHaveBeenCalledTimes(1);
    expect(total(w)).toBe(0);
    w.handle.destroy();
  });
});

describe('relay receipt', () => {
  it('a receipt queued behind the receipt timer (busy return page) is still a handover: exactly one delivery', async () => {
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const w = popupWidget();
    w.handle.open();
    await settle();
    suspect();
    // Force the ordering: the return page's receipt timer runs before the receipt message reaches it,
    // as when a long task (for example hydration) delays the page past the timeout.
    const realPost = FakeBroadcastChannel.prototype.postMessage;
    vi.spyOn(FakeBroadcastChannel.prototype, 'postMessage').mockImplementation(function (this: FakeBroadcastChannel, data: unknown) {
      if ((data as { type?: string }).type === 'cred.link.relay.receipt') vi.advanceTimersByTime(LINK_RELAY_RECEIPT_TIMEOUT_MS);
      return realPost.call(this, data);
    });
    window.history.replaceState(null, '', returnUrl());
    const here = { ...callbacks(), onRelayed: vi.fn() };
    handleRedirect(here);
    await flush();
    vi.advanceTimersByTime(LINK_RELAY_RECEIPT_GRACE_MS * 10);
    await flush();
    expect(w.onSuccess).toHaveBeenCalledTimes(1);
    expect(here.onSuccess).not.toHaveBeenCalled();
    expect(here.onRelayed).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
  });

  it('known limit (same-origin trust): a script on the origin can claim first and forge a receipt, so the window closes and the waiting widget gets nothing', async () => {
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    // Registered before the widget, so it hears the offer first.
    const rogue = new FakeBroadcastChannel(LINK_RELAY_CHANNEL);
    rogue.addEventListener('message', (e) => {
      const d = e.data as { type: string; offer_id: string; claim_id?: string };
      if (d.type === 'cred.link.relay.offer') {
        rogue.postMessage({ type: 'cred.link.relay.claim', v: 2, offer_id: d.offer_id, claim_id: 'r'.repeat(32) });
      }
      if (d.type === 'cred.link.relay.deliver' && d.claim_id === 'r'.repeat(32)) {
        rogue.postMessage({ type: 'cred.link.relay.receipt', v: 2, offer_id: d.offer_id, claim_id: d.claim_id });
      }
    });
    const w = popupWidget();
    w.handle.open();
    await settle();
    suspect();
    window.history.replaceState(null, '', returnUrl());
    const here = { ...callbacks(), onRelayed: vi.fn() };
    handleRedirect(here);
    await flush();
    vi.advanceTimersByTime(LINK_RELAY_RECEIPT_TIMEOUT_MS * 2);
    await flush();
    // Documented in the README: the relay channel trusts every script on the page's origin.
    expect(here.onRelayed).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
    expect(total(here)).toBe(0);
    expect(total(w)).toBe(0);
    w.handle.destroy();
    rogue.close();
  });

  it('a claimant destroyed before the delivery: no receipt, so the result is delivered here and the window stays open', async () => {
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const w = popupWidget();
    w.handle.open();
    await settle();
    suspect();
    window.history.replaceState(null, '', returnUrl());
    const here = { ...callbacks(), onRelayed: vi.fn() };
    handleRedirect(here);
    await Promise.resolve(); // the widget has seen the offer and posted its claim
    w.handle.destroy(); // e.g. React unmount or a route change on the widget page
    await flush();
    expect(postedTypes()).toEqual(['cred.link.relay.offer', 'cred.link.relay.claim', 'cred.link.relay.deliver']);
    expect(here.onSuccess).not.toHaveBeenCalled();
    vi.advanceTimersByTime(LINK_RELAY_RECEIPT_TIMEOUT_MS);
    // The receipt timer only starts the grace re-check; delivery waits for it.
    expect(here.onSuccess).not.toHaveBeenCalled();
    vi.advanceTimersByTime(LINK_RELAY_RECEIPT_GRACE_MS);
    expect(here.onSuccess).toHaveBeenCalledTimes(1);
    expect(here.onSuccess).toHaveBeenCalledWith(expectedSuccessPayload);
    expect(total(w)).toBe(0);
    expect(here.onRelayed).not.toHaveBeenCalled();
    expect(close).not.toHaveBeenCalled();
    expect(FakeBroadcastChannel.open.size).toBe(0);
  });

  it('a claimant that never sends a receipt (rejected payload, or any other listener) leads to local delivery and no close', async () => {
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const rogue = peer();
    rogue.ch.addEventListener('message', (e) => {
      const d = e.data as { type: string; offer_id: string };
      if (d.type === 'cred.link.relay.offer') {
        rogue.ch.postMessage({ type: 'cred.link.relay.claim', v: 2, offer_id: d.offer_id, claim_id: 'r'.repeat(32) });
      }
    });
    window.history.replaceState(null, '', returnUrl());
    const here = { ...callbacks(), onRelayed: vi.fn() };
    handleRedirect(here);
    await flush();
    expect(rogue.seen.map((m) => m.type)).toContain('cred.link.relay.deliver');
    vi.advanceTimersByTime(LINK_RELAY_RECEIPT_TIMEOUT_MS + LINK_RELAY_RECEIPT_GRACE_MS);
    expect(here.onSuccess).toHaveBeenCalledTimes(1);
    expect(here.onRelayed).not.toHaveBeenCalled();
    expect(close).not.toHaveBeenCalled();
    rogue.ch.close();
  });

  it('a receipt for a different claim does not count as a handover', async () => {
    const close = vi.spyOn(window, 'close').mockImplementation(() => undefined);
    const rogue = peer();
    rogue.ch.addEventListener('message', (e) => {
      const d = e.data as { type: string; offer_id: string };
      if (d.type === 'cred.link.relay.offer') {
        rogue.ch.postMessage({ type: 'cred.link.relay.claim', v: 2, offer_id: d.offer_id, claim_id: 'r'.repeat(32) });
        rogue.ch.postMessage({ type: 'cred.link.relay.receipt', v: 2, offer_id: d.offer_id, claim_id: 's'.repeat(32) });
      }
    });
    window.history.replaceState(null, '', returnUrl());
    const here = { ...callbacks(), onRelayed: vi.fn() };
    handleRedirect(here);
    await flush();
    vi.advanceTimersByTime(LINK_RELAY_RECEIPT_TIMEOUT_MS + LINK_RELAY_RECEIPT_GRACE_MS);
    expect(here.onSuccess).toHaveBeenCalledTimes(1);
    expect(here.onRelayed).not.toHaveBeenCalled();
    expect(close).not.toHaveBeenCalled();
    rogue.ch.close();
  });

  it('the widget drops an invalid payload, a delivery for someone else and a late delivery, without a receipt', async () => {
    const w = embeddedWidget();
    await settle();
    const page = peer();
    const offer = (offer_id: string) => page.ch.postMessage({ type: 'cred.link.relay.offer', v: 2, offer_id, flow_id: FLOW });
    const claimFor = (offer_id: string) =>
      page.seen.find((m) => m.type === 'cred.link.relay.claim' && m.offer_id === offer_id)?.claim_id as string;
    const deliver = (offer_id: string, claim_id: string, message: unknown, deadline = Date.now() + 500) =>
      page.ch.postMessage({ type: 'cred.link.relay.deliver', v: 2, offer_id, claim_id, deadline, message });

    const a = 'a'.repeat(32);
    offer(a);
    await flush();
    deliver(a, 'x'.repeat(32), linkResultMessage(successResult));
    deliver(a, claimFor(a), { ...linkResultMessage(successResult), code: 'nope' });
    await flush();

    const b = 'b'.repeat(32);
    offer(b);
    await flush();
    deliver(b, claimFor(b), linkResultMessage(successResult), Date.now() - 1);
    await flush();

    expect(page.seen.filter((m) => m.type === 'cred.link.relay.receipt')).toHaveLength(0);
    expect(total(w)).toBe(0);
    expect(w.container.querySelector('iframe')).not.toBeNull();

    // Still waiting: a valid, timely delivery for a fresh claim is accepted, with a receipt first.
    const c = 'c'.repeat(32);
    offer(c);
    await flush();
    deliver(c, claimFor(c), linkResultMessage(successResult));
    await flush();
    expect(page.seen.filter((m) => m.type === 'cred.link.relay.receipt')).toHaveLength(1);
    expect(w.onSuccess).toHaveBeenCalledTimes(1);
    page.ch.close();
  });
});

describe('handleRedirect and the via marker', () => {
  it('without the via marker behaves exactly as before: no channel, synchronous delivery', () => {
    window.history.replaceState(null, '', appendLinkRedirectResult('/cred/return?tab=1', successResult));
    const here = callbacks();
    handleRedirect(here);
    expect(here.onSuccess).toHaveBeenCalledTimes(1);
    expect(FakeBroadcastChannel.created).toBe(0);
    expect(window.location.search).toBe('?tab=1');
  });

  it('strips the via and flow parameters from the URL', () => {
    window.history.replaceState(null, '', returnUrl(successResult, FLOW, '?tab=1'));
    expect(window.location.search).toContain('cred_link_via=popup');
    expect(window.location.search).toContain(`cred_link_flow=${FLOW}`);
    handleRedirect(callbacks());
    expect(window.location.search).toBe('?tab=1');
  });

  it('relay: false delivers locally and synchronously without a channel', () => {
    window.history.replaceState(null, '', returnUrl());
    const here = callbacks();
    handleRedirect({ ...here, relay: false });
    expect(here.onSuccess).toHaveBeenCalledTimes(1);
    expect(FakeBroadcastChannel.created).toBe(0);
    expect(window.location.search).toBe('');
  });

  it('without BroadcastChannel delivers locally, and widgets still work', () => {
    vi.stubGlobal('BroadcastChannel', undefined);
    const w = popupWidget();
    w.handle.open();
    post(popup, successMessage);
    expect(w.onSuccess).toHaveBeenCalledTimes(1);

    window.history.replaceState(null, '', returnUrl());
    const here = callbacks();
    handleRedirect(here);
    expect(here.onSuccess).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['a repeated via marker', (u: string) => `${u}&cred_link_via=popup`],
    ['another via value', (u: string) => u.replace('cred_link_via=popup', 'cred_link_via=tab')],
    ['a malformed via marker', (u: string) => u.replace('cred_link_via=popup', 'cred_link_via=%zz')],
    ['a malformed flow id', (u: string) => u.replace(/cred_link_flow=[0-9a-f]+/, 'cred_link_flow=XYZ')],
    ['a flow id without the via marker', (u: string) => u.replace('cred_link_via=popup&', '')],
  ])('%s is not delivered and the URL is left untouched', (_label, mutate) => {
    const path = mutate(returnUrl());
    window.history.replaceState(null, '', path);
    const replace = vi.spyOn(window.history, 'replaceState');
    const here = callbacks();
    expect(handleRedirect(here)).toBeNull();
    expect(total(here)).toBe(0);
    expect(replace).not.toHaveBeenCalled();
    expect(window.location.pathname + window.location.search).toBe(path);
    expect(FakeBroadcastChannel.created).toBe(0);
  });
});

import { createElement } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CredConnect, useCredLink } from '../index.js';
import type { UseCredLinkOptions, UseCredLinkResult } from '../index.js';

const TOKEN = `urn:cred:link:${'a'.repeat(43)}`;
const ORIGIN = 'https://link.cred.ninja';
const CODE = `cred_lac_${'b'.repeat(43)}`;
const RELAY = 'cred.link.relay.v2';
// Captured before timers are faked: Web Crypto digests resolve on the real event loop.
const realSetTimeout = globalThis.setTimeout;

async function flowIdOf(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

const resultMessage = {
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

/** Minimal in-memory BroadcastChannel: async delivery to other open instances with the same name. */
class FakeChannel {
  static open = new Set<FakeChannel>();
  closed = false;
  private readonly listeners = new Set<(event: MessageEvent) => void>();
  constructor(readonly name: string) {
    FakeChannel.open.add(this);
  }
  postMessage(data: unknown): void {
    const copy: unknown = structuredClone(data);
    for (const other of FakeChannel.open) {
      if (other !== this && other.name === this.name) void Promise.resolve().then(() => other.emit(copy));
    }
  }
  addEventListener(_type: string, fn: (event: MessageEvent) => void): void {
    this.listeners.add(fn);
  }
  removeEventListener(_type: string, fn: (event: MessageEvent) => void): void {
    this.listeners.delete(fn);
  }
  close(): void {
    this.closed = true;
    FakeChannel.open.delete(this);
  }
  private emit(data: unknown): void {
    // Only `data` is read by the code under test.
    if (!this.closed) for (const fn of [...this.listeners]) fn({ data } as MessageEvent);
  }
}

interface FakePopup {
  closed: boolean;
  close: ReturnType<typeof vi.fn>;
  focus: ReturnType<typeof vi.fn>;
  postMessage: ReturnType<typeof vi.fn>;
}

let popup: FakePopup;
let openSpy: ReturnType<typeof vi.spyOn>;

function post(data: unknown): void {
  const event = new MessageEvent('message', { data, origin: ORIGIN });
  // jsdom only accepts real windows as `source` in the init dict; define it directly instead.
  Object.defineProperty(event, 'source', { value: popup });
  act(() => {
    window.dispatchEvent(event);
  });
}

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 3; i++) {
      await new Promise<void>((resolve) => realSetTimeout(resolve, 0));
      for (let j = 0; j < 20; j++) await Promise.resolve();
    }
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  FakeChannel.open.clear();
  vi.stubGlobal('BroadcastChannel', FakeChannel);
  popup = { closed: false, close: vi.fn(() => { popup.closed = true; }), focus: vi.fn(), postMessage: vi.fn() };
  // The fake popup stands in for a WindowProxy.
  openSpy = vi.spyOn(window, 'open').mockImplementation(() => popup as unknown as Window);
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function Probe(props: { options: UseCredLinkOptions; onResult: (r: UseCredLinkResult) => void }): null {
  props.onResult(useCredLink(props.options));
  return null;
}

describe('popup fallback in React', () => {
  it('unmount closes the relay channel, also during a suspected opener loss', () => {
    const onExit = vi.fn();
    const { unmount } = render(createElement(CredConnect, { token: TOKEN, onExit }, createElement('button', null, 'Connect')));
    fireEvent.click(screen.getByText('Connect'));
    expect(FakeChannel.open.size).toBe(1);
    post({ type: 'cred.link.step', v: 1, step: 'provider', provider: 'google' });
    popup.closed = true;
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(FakeChannel.open.size).toBe(1);
    unmount();
    expect(FakeChannel.open.size).toBe(0);
    expect(onExit).not.toHaveBeenCalled();
  });

  it('keeps ready and error steady through a suspected opener loss, then delivers a relayed result to the latest callback', async () => {
    let latest: UseCredLinkResult | undefined;
    const onResult = (r: UseCredLinkResult) => {
      latest = r;
    };
    const first = vi.fn();
    const second = vi.fn();
    const { rerender } = render(createElement(Probe, { options: { token: TOKEN, onSuccess: first }, onResult }));
    act(() => latest?.open());
    post({ type: 'cred.link.step', v: 1, step: 'provider', provider: 'google' });
    popup.closed = true;
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(latest?.ready).toBe(true);
    expect(latest?.error).toBeNull();
    rerender(createElement(Probe, { options: { token: TOKEN, onSuccess: second }, onResult }));

    // Play the return page by hand: offer for this flow, read the claim, deliver, expect the receipt.
    await flush(); // let the widget finish hashing its token
    const page = new FakeChannel(RELAY);
    const seen: Array<{ type: string; claim_id: string }> = [];
    page.addEventListener('message', (e) => seen.push(e.data as { type: string; claim_id: string }));
    const offer_id = 'f'.repeat(32);
    page.postMessage({ type: 'cred.link.relay.offer', v: 2, offer_id, flow_id: await flowIdOf(TOKEN) });
    await flush();
    expect(seen.map((m) => m.type)).toEqual(['cred.link.relay.claim']);
    page.postMessage({
      type: 'cred.link.relay.deliver',
      v: 2,
      offer_id,
      claim_id: seen[0].claim_id,
      deadline: Date.now() + 500,
      message: resultMessage,
    });
    await flush();
    expect(seen.map((m) => m.type)).toEqual(['cred.link.relay.claim', 'cred.link.relay.receipt']);
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
    expect(latest?.ready).toBe(true);
    expect(latest?.error).toBeNull();
    page.close();
  });

  it('a handoff closes the popup, fires no callback and leaves ready and error unchanged', () => {
    let latest: UseCredLinkResult | undefined;
    const cbs = { onSuccess: vi.fn(), onError: vi.fn(), onExit: vi.fn() };
    render(createElement(Probe, { options: { token: TOKEN, ...cbs }, onResult: (r: UseCredLinkResult) => { latest = r; } }));
    act(() => latest?.open());
    // jsdom cannot navigate; the assignment to top.location is what the widget does here.
    const navigate = vi.fn();
    vi.spyOn(window, 'top', 'get').mockReturnValue({ location: { set href(v: string) { navigate(v); } } } as unknown as Window);
    post({ type: 'cred.link.step', v: 1, step: 'provider', provider: 'google', handoff: 'redirect' });
    expect(popup.close).toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledTimes(1);
    expect(new URL(navigate.mock.calls[0][0] as string).searchParams.get('mode')).toBe('redirect');
    expect(cbs.onSuccess).not.toHaveBeenCalled();
    expect(cbs.onError).not.toHaveBeenCalled();
    expect(cbs.onExit).not.toHaveBeenCalled();
    expect(latest?.ready).toBe(true);
    expect(latest?.error).toBeNull();
    expect(FakeChannel.open.size).toBe(0);
    act(() => latest?.open());
    expect(openSpy).toHaveBeenCalledTimes(1);
  });
});

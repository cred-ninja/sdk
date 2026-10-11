import { vi } from 'vitest';

// Captured before any test fakes timers: Web Crypto digests resolve on the real event loop.
const realSetTimeout = globalThis.setTimeout;

export const TOKEN = `urn:cred:link:${'a'.repeat(43)}`;
export const ORIGIN = 'https://link.cred.ninja';
export const CODE = `cred_lac_${'b'.repeat(43)}`;

export interface FakePopup {
  closed: boolean;
  close: ReturnType<typeof vi.fn>;
  focus: ReturnType<typeof vi.fn>;
  postMessage: ReturnType<typeof vi.fn>;
}

export function fakePopup(): FakePopup {
  const popup: FakePopup = {
    closed: false,
    close: vi.fn(() => {
      popup.closed = true;
    }),
    focus: vi.fn(),
    postMessage: vi.fn(),
  };
  return popup;
}

/**
 * In-memory BroadcastChannel: delivers to every other open instance with the
 * same name, asynchronously (on a microtask), never to the sender, like the
 * real one. Install with vi.stubGlobal('BroadcastChannel', FakeBroadcastChannel).
 */
export class FakeBroadcastChannel {
  static open = new Set<FakeBroadcastChannel>();
  static created = 0;
  static posted: Array<{ name: string; data: unknown }> = [];

  static reset(): void {
    FakeBroadcastChannel.open.clear();
    FakeBroadcastChannel.created = 0;
    FakeBroadcastChannel.posted = [];
  }

  closed = false;
  private readonly listeners = new Set<(event: MessageEvent) => void>();

  constructor(readonly name: string) {
    FakeBroadcastChannel.created += 1;
    FakeBroadcastChannel.open.add(this);
  }

  postMessage(data: unknown): void {
    if (this.closed) throw new Error('InvalidStateError: channel is closed');
    const copy: unknown = structuredClone(data);
    FakeBroadcastChannel.posted.push({ name: this.name, data: copy });
    for (const other of FakeBroadcastChannel.open) {
      if (other === this || other.name !== this.name) continue;
      void Promise.resolve().then(() => other.dispatch(copy));
    }
  }

  addEventListener(type: string, listener: (event: MessageEvent) => void): void {
    if (type === 'message') this.listeners.add(listener);
  }

  removeEventListener(type: string, listener: (event: MessageEvent) => void): void {
    if (type === 'message') this.listeners.delete(listener);
  }

  close(): void {
    this.closed = true;
    FakeBroadcastChannel.open.delete(this);
  }

  /** Deliver as if another context posted `data`. */
  dispatch(data: unknown): void {
    if (this.closed) return;
    // Only `data` is read by the code under test.
    for (const listener of [...this.listeners]) listener({ data } as MessageEvent);
  }
}

/** Let pending microtasks (fake channel deliveries) run. */
export async function flush(): Promise<void> {
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

/** Dispatch a message event on the page window as if posted by `source` from `origin`. */
export function post(source: unknown, data: unknown, origin: string = ORIGIN): void {
  const event = new MessageEvent('message', { data, origin });
  // jsdom only accepts real windows as `source` in the init dict; define it directly instead.
  Object.defineProperty(event, 'source', { value: source });
  window.dispatchEvent(event);
}

export const successMessage = {
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

export const errorMessage = {
  type: 'cred.link.result',
  v: 1,
  outcome: 'error',
  error: 'access_denied',
  request_id: 'req_123',
  state: 'dev-csrf-value',
};

export const exitMessage = {
  type: 'cred.link.result',
  v: 1,
  outcome: 'exit',
  step: 'confirm',
  provider: 'slack',
  state: 'dev-csrf-value',
};

export const expectedSuccessPayload = {
  connection_id: 'conn_abc123',
  code: CODE,
  grant_id: 'grt_abc123',
  provider: 'google',
  scopes: ['calendar.readonly'],
  state: 'dev-csrf-value',
};

/** Let real async work (Web Crypto digests) and the microtasks after it finish, even under fake timers. */
export async function settle(): Promise<void> {
  for (let i = 0; i < 3; i++) {
    await new Promise<void>((resolve) => realSetTimeout(resolve, 0));
    await flush();
  }
}

/** The relay flow id of a token: lowercase hex SHA-256, as the server computes it. */
export async function flowIdOf(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

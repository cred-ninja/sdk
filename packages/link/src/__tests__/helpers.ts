import { vi } from 'vitest';

export const TOKEN = `urn:cred:link:${'a'.repeat(43)}`;
export const ORIGIN = 'https://link.cred.ninja';
export const CODE = `cred_lac_${'b'.repeat(43)}`;

export interface FakePopup {
  closed: boolean;
  close: ReturnType<typeof vi.fn>;
  focus: ReturnType<typeof vi.fn>;
}

export function fakePopup(): FakePopup {
  const popup: FakePopup = {
    closed: false,
    close: vi.fn(() => {
      popup.closed = true;
    }),
    focus: vi.fn(),
  };
  return popup;
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

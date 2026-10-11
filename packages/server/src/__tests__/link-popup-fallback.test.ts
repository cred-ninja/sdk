/**
 * Cred Link polish: the hosted side of the popup fallback.
 *
 * Supertest checks the served HTML, headers and page config; the page script
 * itself (LINK_PAGE_SCRIPT, the exact text served under the nonce) is then
 * executed against a jsdom document with a stubbed window (opener, parent,
 * storage, timers, location, fetch).
 */

import crypto from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  LINK_POPUP_ACK_TIMEOUT_MS,
  LINK_REDIRECT_ONLY_STORAGE_KEY,
  LINK_REDIRECT_ONLY_TTL_DAYS,
  parseLinkRedirectFlowId,
  parseLinkRedirectResult,
  parseLinkRedirectVia,
} from '@credninja/protocol';
import { LINK_PAGE_SCRIPT } from '../link/pages.js';
import {
  APP_ORIGIN,
  APP_REDIRECT,
  BASE,
  Browser,
  activate,
  authorizePath,
  callback,
  confirm,
  envelopeOf,
  makeHarness,
  pageConfig,
  par,
  registerClient,
  toProvider,
} from './link-harness.js';
import type { Harness } from './link-harness.js';
import type request from 'supertest';

let h: Harness | null = null;

afterEach(() => {
  h?.close();
  h = null;
});

async function harness(): Promise<Harness> {
  h = await makeHarness();
  return h;
}

const SELF_ORIGIN = new URL(BASE).origin;
const OPENER_COOKIE = '__Host-cred_link_op';

/** The flow id the widget recomputes from its own token: SHA-256 hex of the request_uri. */
function flowIdOf(requestUri: string): string {
  return crypto.createHash('sha256').update(requestUri).digest('hex');
}

/** Exactly one cred_link_via=popup and one cred_link_flow bound to this request_uri. */
function expectFallbackBinding(url: URL, requestUri: string): void {
  expect(url.searchParams.getAll('cred_link_via')).toEqual(['popup']);
  expect(url.searchParams.getAll('cred_link_flow')).toEqual([flowIdOf(requestUri)]);
  expect(parseLinkRedirectVia(url.search)).toBe('popup');
  expect(parseLinkRedirectFlowId(url.search)).toBe(flowIdOf(requestUri));
}
const DAY_MS = 24 * 60 * 60 * 1000;

function csp(res: request.Response): string {
  return String(res.headers['content-security-policy']);
}

/** A popup flow up to its result page. */
/**
 * A popup (or embedded top-window) flow up to its result page. `opener` is
 * what the picker page script reported at submit ('1' = the window had an
 * opener; the harness default for popup mode).
 */
async function popupResultPage(
  hx: Harness,
  outcome: 'success' | 'exit' | 'error' = 'success',
  mode: 'popup' | 'embedded' = 'popup',
  opener?: '0' | '1' | 'handoff',
) {
  const client = await registerClient(hx.app);
  const browser = new Browser();
  const requestUri = await par(hx.app, client);
  if (outcome === 'exit') {
    const picker = await browser.get(hx.app, authorizePath(requestUri, mode));
    const page = await browser.post(hx.app, '/link/v1/picker', [['e', envelopeOf(picker.text)], ['action', 'cancel']]);
    return { client, page, requestUri, browser };
  }
  const providerUrl = await toProvider(hx.app, browser, requestUri, { mode, ...(opener ? { opener } : {}) });
  if (outcome === 'error') hx.fake.googleExchangeStatus = 400;
  const confirmPage = await callback(hx.app, browser, providerUrl);
  if (outcome === 'error') return { client, page: confirmPage, requestUri, browser };
  const page = await confirm(hx.app, browser, confirmPage.text, ['calendar.readonly', 'gmail.send']);
  return { client, page, requestUri, browser };
}

// ── A stubbed window running the real page script ────────────────────────────

interface FakeStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  data: Map<string, string>;
}

function memoryStorage(initial: Record<string, string> = {}): FakeStorage {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => { data.set(k, v); },
  };
}

function throwingStorage(): FakeStorage {
  return {
    data: new Map(),
    getItem: () => { throw new Error('SecurityError'); },
    setItem: () => { throw new Error('SecurityError'); },
  };
}

interface PeerWindow {
  postMessage: ReturnType<typeof vi.fn>;
}

function peer(): PeerWindow {
  return { postMessage: vi.fn() };
}

interface RunOptions {
  opener?: PeerWindow | null;
  parent?: PeerWindow;
  storage?: FakeStorage | 'accessor-throws';
  fetch?: (url: string, init: Record<string, unknown>) => Promise<{ type: string; status: number }>;
}

function runPage(html: string, opts: RunOptions = {}) {
  const dom = new JSDOM(html, { url: `${BASE}/link/v1/authorize` });
  const submit = vi.fn();
  dom.window.HTMLFormElement.prototype.submit = submit;
  const listeners: Array<(ev: unknown) => void> = [];
  const timers: Array<{ id: number; fn: () => void; ms: number; cleared: boolean }> = [];
  const storage = opts.storage ?? memoryStorage();
  const win: Record<string, unknown> = {
    opener: opts.opener ?? null,
    location: { replace: vi.fn() },
    close: vi.fn(),
    addEventListener: (type: string, fn: (ev: unknown) => void) => { if (type === 'message') listeners.push(fn); },
  };
  win.parent = opts.parent ?? win;
  if (opts.fetch) win.fetch = vi.fn(opts.fetch);
  Object.defineProperty(win, 'localStorage', {
    get() {
      if (storage === 'accessor-throws') throw new Error('SecurityError');
      return storage;
    },
  });
  const setTimeoutStub = (fn: () => void, ms: number) => {
    const id = timers.length + 1;
    timers.push({ id, fn, ms, cleared: false });
    return id;
  };
  const clearTimeoutStub = (id: number) => {
    const t = timers.find((x) => x.id === id);
    if (t) t.cleared = true;
  };
  const run = new Function('window', 'document', 'setTimeout', 'clearTimeout', 'URLSearchParams', 'FormData', LINK_PAGE_SCRIPT);
  run(win, dom.window.document, setTimeoutStub, clearTimeoutStub, dom.window.URLSearchParams, dom.window.FormData);
  return {
    dom,
    win,
    submit,
    timers,
    replace: (win.location as { replace: ReturnType<typeof vi.fn> }).replace,
    close: win.close as ReturnType<typeof vi.fn>,
    fetch: win.fetch as ReturnType<typeof vi.fn> | undefined,
    message(ev: { origin: string; source: unknown; data: unknown }) {
      for (const fn of listeners) fn(ev);
    },
    fireTimers(ms: number) {
      for (const t of timers) if (!t.cleared && t.ms === ms) { t.cleared = true; t.fn(); }
    },
  };
}

const flush = () => new Promise((r) => setImmediate(r));
const ACK = { type: 'cred.link.ack', v: 1 };

function messagesOf(w: PeerWindow): Array<[Record<string, unknown>, string]> {
  return w.postMessage.mock.calls as Array<[Record<string, unknown>, string]>;
}

// ── Served HTML, headers, config ─────────────────────────────────────────────

describe('popup result page (served)', () => {
  it('carries a fallback URL to the registered redirect_uri with exactly one cred_link_via=popup and one cred_link_flow, for success, error and exit', async () => {
    const hx = await harness();
    for (const outcome of ['success', 'error', 'exit'] as const) {
      const { page, requestUri } = await popupResultPage(hx, outcome);
      expect(page.status).toBe(200);
      const cfg = pageConfig(page.text);
      expect(cfg.result.outcome).toBe(outcome);
      expect(cfg.context).toBe('top');
      expect(cfg.target).toBe(APP_ORIGIN);
      expect(cfg.ack_timeout_ms).toBe(LINK_POPUP_ACK_TIMEOUT_MS);
      expect(cfg.storage_key).toBe(LINK_REDIRECT_ONLY_STORAGE_KEY);
      expect(cfg.redirect_only_ttl_ms).toBe(LINK_REDIRECT_ONLY_TTL_DAYS * DAY_MS);
      const url = new URL(cfg.fallback_url);
      expect(`${url.origin}${url.pathname}`).toBe(APP_REDIRECT);
      expectFallbackBinding(url, requestUri);
      const { type: _t, v: _v, ...result } = cfg.result;
      expect(parseLinkRedirectResult(url.search)).toEqual(result);
      if (outcome === 'exit') expect(cfg.memory_provider).toBeUndefined();
      else expect(cfg.memory_provider).toBe('google');
      // No COOP on Link pages; no fetch from the result page.
      expect(page.headers['cross-origin-opener-policy']).toBeUndefined();
      expect(csp(page)).toContain("connect-src 'none'");
      expect(page.text).toContain(LINK_PAGE_SCRIPT);
      hx.fake.googleExchangeStatus = 200;
    }
  });

  it('the popup picker alone gets connect-src self and the handoff flag', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const popup = await new Browser().get(hx.app, authorizePath(await par(hx.app, client), 'popup'));
    expect(csp(popup)).toContain("connect-src 'self'");
    expect(pageConfig(popup.text).handoff).toBe(true);
    expect(popup.headers['cross-origin-opener-policy']).toBeUndefined();

    const redirect = await new Browser().get(hx.app, authorizePath(await par(hx.app, client), 'redirect'));
    expect(csp(redirect)).toContain("connect-src 'none'");
    expect(pageConfig(redirect.text).handoff).toBeUndefined();

    const embedded = await new Browser().get(hx.app, authorizePath(await par(hx.app, client), 'embedded'));
    expect(csp(embedded)).toContain("connect-src 'none'");
    expect(pageConfig(embedded.text).handoff).toBeUndefined();
    expect(pageConfig(embedded.text).context).toBe('iframe');

    // The popup's confirm page does not get it either.
    const b = new Browser();
    const confirmPage = await callback(hx.app, b, await toProvider(hx.app, b, await par(hx.app, client), { mode: 'popup' }));
    expect(csp(confirmPage)).toContain("connect-src 'none'");
  });

  it('the embedded iframe result page posts to its parent with no fallback; the embedded top window falls back', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const browser = new Browser();
    const picker = await browser.get(hx.app, authorizePath(await par(hx.app, client), 'embedded'));
    const iframeCancel = await new Browser().post(hx.app, '/link/v1/picker?frame=iframe', [['e', envelopeOf(picker.text)], ['action', 'cancel']]);
    const cfg = pageConfig(iframeCancel.text);
    expect(cfg.context).toBe('iframe');
    expect(cfg.fallback_url).toBeUndefined();

    const top = await popupResultPage(hx, 'success', 'embedded');
    const topCfg = pageConfig(top.page.text);
    expect(topCfg.context).toBe('top');
    expect(topCfg.target).toBe(SELF_ORIGIN);
    expectFallbackBinding(new URL(topCfg.fallback_url), top.requestUri);
    // The window the iframe opened always starts with an opener.
    expect(topCfg.memory_provider).toBe('google');
  });
});

// ── The page script, executed ────────────────────────────────────────────────

describe('result page script', () => {
  it('without an opener (lost after starting with one) replaces the location with the fallback URL at once and remembers the provider', async () => {
    const hx = await harness();
    const { page, requestUri } = await popupResultPage(hx);
    const cfg = pageConfig(page.text);
    const storage = memoryStorage();
    const before = Date.now();
    const p = runPage(page.text, { opener: null, storage });
    expect(p.replace).toHaveBeenCalledTimes(1);
    const target = p.replace.mock.calls[0][0] as string;
    expect(target).toBe(cfg.fallback_url);
    expectFallbackBinding(new URL(target), requestUri);
    expect(p.close).not.toHaveBeenCalled();
    const memory = JSON.parse(storage.data.get(LINK_REDIRECT_ONLY_STORAGE_KEY)!);
    expect(Object.keys(memory)).toEqual(['google']);
    expect(memory.google).toBeGreaterThanOrEqual(before);
    expect(memory.google).toBeLessThanOrEqual(Date.now());
  });

  it('with an opener posts the result and closes on a valid ack, without fallback or memory', async () => {
    const hx = await harness();
    const { page } = await popupResultPage(hx);
    const opener = peer();
    const storage = memoryStorage();
    const p = runPage(page.text, { opener, storage });
    const sent = messagesOf(opener);
    expect(sent).toHaveLength(1);
    expect(sent[0][0].type).toBe('cred.link.result');
    expect(sent[0][1]).toBe(APP_ORIGIN);
    expect(p.timers.map((t) => t.ms)).toEqual([LINK_POPUP_ACK_TIMEOUT_MS]);

    p.message({ origin: APP_ORIGIN, source: opener, data: ACK });
    expect(p.close).toHaveBeenCalledTimes(1);
    expect(p.timers[0].cleared).toBe(true);
    p.fireTimers(LINK_POPUP_ACK_TIMEOUT_MS);
    expect(p.replace).not.toHaveBeenCalled();
    expect(storage.data.size).toBe(0);
  });

  it('with an opener and no ack falls back after the timeout, without memory', async () => {
    const hx = await harness();
    const { page } = await popupResultPage(hx);
    const storage = memoryStorage();
    const p = runPage(page.text, { opener: peer(), storage });
    expect(p.replace).not.toHaveBeenCalled();
    p.fireTimers(LINK_POPUP_ACK_TIMEOUT_MS);
    expect(p.replace).toHaveBeenCalledTimes(1);
    expect(p.replace.mock.calls[0][0]).toBe(pageConfig(page.text).fallback_url);
    expect(p.close).not.toHaveBeenCalled();
    expect(storage.data.size).toBe(0);
  });

  it('ignores an ack from the wrong origin, the wrong source or with the wrong shape', async () => {
    const hx = await harness();
    const { page } = await popupResultPage(hx);
    const opener = peer();
    const p = runPage(page.text, { opener });
    p.message({ origin: 'https://evil.example', source: opener, data: ACK });
    p.message({ origin: APP_ORIGIN, source: peer(), data: ACK });
    p.message({ origin: APP_ORIGIN, source: opener, data: { type: 'cred.link.ack', v: 2 } });
    p.message({ origin: APP_ORIGIN, source: opener, data: 'cred.link.ack' });
    expect(p.close).not.toHaveBeenCalled();
    p.fireTimers(LINK_POPUP_ACK_TIMEOUT_MS);
    expect(p.replace).toHaveBeenCalledTimes(1);
    // A late ack after the fallback does nothing.
    p.message({ origin: APP_ORIGIN, source: opener, data: ACK });
    expect(p.close).not.toHaveBeenCalled();
  });

  it('a throwing storage does not break the fallback', async () => {
    const hx = await harness();
    const { page } = await popupResultPage(hx);
    for (const storage of [throwingStorage(), 'accessor-throws' as const]) {
      const p = runPage(page.text, { opener: null, storage });
      expect(p.replace).toHaveBeenCalledTimes(1);
    }
  });

  it('the embedded top window waits for the ack from its iframe opener at the Link origin', async () => {
    const hx = await harness();
    const { page } = await popupResultPage(hx, 'success', 'embedded');
    const iframe = peer();
    const p = runPage(page.text, { opener: iframe });
    expect(messagesOf(iframe)[0][1]).toBe(SELF_ORIGIN);
    p.message({ origin: APP_ORIGIN, source: iframe, data: ACK });
    expect(p.close).not.toHaveBeenCalled();
    p.message({ origin: SELF_ORIGIN, source: iframe, data: ACK });
    expect(p.close).toHaveBeenCalledTimes(1);
  });
});

describe('embedded iframe relay', () => {
  it('relays the result to the parent and forwards only the parent ack to the window that posted it', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const picker = await new Browser().get(hx.app, authorizePath(await par(hx.app, client), 'embedded'));
    const parent = peer();
    const p = runPage(picker.text, { parent });
    parent.postMessage.mockClear();
    const popupWin = peer();

    // An ack before any result has nowhere to go.
    p.message({ origin: APP_ORIGIN, source: parent, data: ACK });
    expect(popupWin.postMessage).not.toHaveBeenCalled();

    const result = { type: 'cred.link.result', v: 1, outcome: 'exit', step: 'picker' };
    p.message({ origin: 'https://evil.example', source: popupWin, data: result });
    expect(parent.postMessage).not.toHaveBeenCalled();
    p.message({ origin: SELF_ORIGIN, source: popupWin, data: result });
    expect(messagesOf(parent)).toEqual([[result, APP_ORIGIN]]);

    // Wrong origin or not from the parent: not forwarded.
    p.message({ origin: 'https://evil.example', source: parent, data: ACK });
    p.message({ origin: APP_ORIGIN, source: peer(), data: ACK });
    expect(popupWin.postMessage).not.toHaveBeenCalled();
    p.message({ origin: APP_ORIGIN, source: parent, data: ACK });
    expect(messagesOf(popupWin)).toEqual([[ACK, SELF_ORIGIN]]);
  });
});

describe('popup picker redirect-only handoff', () => {
  function submitGoogle(p: ReturnType<typeof runPage>) {
    const form = p.dom.window.document.querySelector('form[data-cred-provider="google"]')!;
    const ev = new p.dom.window.Event('submit', { cancelable: true });
    form.dispatchEvent(ev);
    return ev;
  }

  const remembered = (at: number) => memoryStorage({ [LINK_REDIRECT_ONLY_STORAGE_KEY]: JSON.stringify({ google: at }) });

  it('a remembered provider with an opener submits by fetch, then posts the redirect handoff and does not navigate', async () => {
    const hx = await harness();
    const { picker } = await popupPicker(hx);
    const opener = peer();
    const fetchImpl = vi.fn(async () => ({ type: 'opaqueredirect', status: 0 }));
    const p = runPage(picker.text, { opener, storage: remembered(Date.now() - DAY_MS), fetch: fetchImpl });
    opener.postMessage.mockClear();
    const ev = submitGoogle(p);
    expect(ev.defaultPrevented).toBe(true);
    await flush();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, Record<string, unknown>];
    expect(url).toBe(`${BASE}/link/v1/picker`);
    expect(init).toMatchObject({ method: 'POST', credentials: 'include', redirect: 'manual' });
    const body = new URLSearchParams(String(init.body));
    expect(body.get('action')).toBe('continue');
    expect(body.get('opener')).toBe('handoff');
    expect(body.get('provider')).toBe('google');
    expect(body.get('e')).toBe(envelopeOf(picker.text));
    expect(messagesOf(opener)).toEqual([[{ type: 'cred.link.step', v: 1, step: 'provider', provider: 'google', handoff: 'redirect' }, APP_ORIGIN]]);
    expect(p.submit).not.toHaveBeenCalled();
    expect(p.replace).not.toHaveBeenCalled();
  });

  it('submits normally when not remembered, expired, without an opener, or with unreadable storage', async () => {
    const hx = await harness();
    const { picker } = await popupPicker(hx);
    const cases: Array<[string, RunOptions]> = [
      ['not remembered', { opener: peer(), storage: memoryStorage() }],
      ['expired', { opener: peer(), storage: remembered(Date.now() - (LINK_REDIRECT_ONLY_TTL_DAYS + 1) * DAY_MS) }],
      ['no opener', { opener: null, storage: remembered(Date.now()) }],
      ['storage throws', { opener: peer(), storage: throwingStorage() }],
      ['storage accessor throws', { opener: peer(), storage: 'accessor-throws' }],
    ];
    for (const [name, opts] of cases) {
      const fetchImpl = vi.fn(async () => ({ type: 'opaqueredirect', status: 0 }));
      const p = runPage(picker.text, { ...opts, fetch: fetchImpl });
      const ev = submitGoogle(p);
      await flush();
      expect({ name, prevented: ev.defaultPrevented, fetched: fetchImpl.mock.calls.length }).toEqual({ name, prevented: false, fetched: 0 });
      // The native submission reports whether this window had an opener.
      const field = p.dom.window.document.querySelector('form[data-cred-provider="google"] input[name="opener"]') as HTMLInputElement;
      expect({ name, opener: field.value }).toEqual({ name, opener: opts.opener ? '1' : '0' });
      if (opts.opener) {
        const steps = messagesOf(opts.opener).map((m) => m[0]).filter((m) => m.step === 'provider');
        expect(steps).toEqual([{ type: 'cred.link.step', v: 1, step: 'provider', provider: 'google' }]);
      }
    }
  });

  it('falls back to a normal submit when the fetch fails or does not redirect', async () => {
    const hx = await harness();
    const { picker } = await popupPicker(hx);
    for (const fetchImpl of [
      vi.fn(async () => { throw new TypeError('network'); }),
      vi.fn(async () => ({ type: 'basic', status: 200 })),
    ]) {
      const opener = peer();
      const p = runPage(picker.text, { opener, storage: remembered(Date.now()), fetch: fetchImpl as never });
      const ev = submitGoogle(p);
      expect(ev.defaultPrevented).toBe(true);
      await flush();
      expect(p.submit).toHaveBeenCalledTimes(1);
      const form = p.dom.window.document.querySelector('form[data-cred-provider="google"]')!;
      expect(form.querySelector('input[type="hidden"][name="action"][value="continue"]')).not.toBeNull();
      const steps = messagesOf(opener).map((m) => m[0]).filter((m) => m.step === 'provider');
      expect(steps).toEqual([{ type: 'cred.link.step', v: 1, step: 'provider', provider: 'google' }]);
    }
  });
});

describe('redirect-only memory guard', () => {
  it('a popup-mode URL opened without an opener never enables the memory write', async () => {
    const hx = await harness();
    const { page, browser } = await popupResultPage(hx, 'success', 'popup', '0');
    expect(browser.jar.has(OPENER_COOKIE)).toBe(false);
    expect(pageConfig(page.text).memory_provider).toBeUndefined();
    const storage = memoryStorage();
    const p = runPage(page.text, { opener: null, storage });
    expect(p.replace).toHaveBeenCalledTimes(1);
    expect(storage.data.size).toBe(0);
  });

  it('the opener record is a short-lived HttpOnly cookie bound to the transaction, cleared by the result page', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const browser = new Browser();
    const requestUri = await par(hx.app, client);
    const picker = await browser.get(hx.app, authorizePath(requestUri, 'popup'));
    const res = await browser.post(hx.app, '/link/v1/picker', [
      ['e', envelopeOf(picker.text)], ['action', 'continue'], ['provider', 'google'], ['opener', '1'], ['scope', 'calendar.readonly'],
    ]);
    expect(res.status).toBe(303);
    const set = (res.headers['set-cookie'] as unknown as string[]).find((c) => c.startsWith(`${OPENER_COOKIE}=`))!;
    expect(set).toMatch(/; HttpOnly/);
    expect(set).toMatch(/; Secure/);
    expect(set).toMatch(/; SameSite=Lax/);
    expect(set).toMatch(/; Path=\//);
    const maxAge = Number(/Max-Age=(\d+)/.exec(set)![1]);
    expect(maxAge).toBeGreaterThan(0);
    expect(maxAge).toBeLessThanOrEqual(600);

    // A cookie from another transaction does not enable it.
    const other = new Browser();
    const otherUri = await par(hx.app, client);
    const providerUrl = await toProvider(hx.app, other, otherUri, { mode: 'popup', opener: '0' });
    other.jar.set(OPENER_COOKIE, browser.jar.get(OPENER_COOKIE)!);
    const otherConfirm = await callback(hx.app, other, providerUrl);
    const otherResult = await confirm(hx.app, other, otherConfirm.text, ['calendar.readonly', 'gmail.send']);
    expect(pageConfig(otherResult.text).memory_provider).toBeUndefined();

    // The matching transaction's result page enables it and clears the cookie.
    const confirmPage = await callback(hx.app, browser, new URL(res.headers.location));
    const result = await confirm(hx.app, browser, confirmPage.text, ['calendar.readonly']);
    expect(pageConfig(result.text).memory_provider).toBe('google');
    expect(browser.jar.has(OPENER_COOKIE)).toBe(false);
  });
});

describe('reconnect diff toggles', () => {
  it('moves a scope between kept and removed when its box is toggled', async () => {
    const hx = await harness();
    const client = await registerClient(hx.app);
    const first = new Browser();
    const firstConfirm = await callback(hx.app, first, await toProvider(hx.app, first, await par(hx.app, client)));
    const r = await confirm(hx.app, first, firstConfirm.text, ['calendar.readonly', 'gmail.send']);
    const location = new URL(r.headers.location);
    const result = parseLinkRedirectResult(location.search)!;
    if (result.outcome !== 'success') throw new Error('flow failed');
    await activate(hx.app, client, result.connection_id, result.code);

    const b = new Browser();
    const page = await callback(hx.app, b, await toProvider(hx.app, b, await par(hx.app, client, { required_scopes: {} })));
    const p = runPage(page.text);
    const doc = p.dom.window.document;
    const ids = (id: string) => Array.from(doc.querySelectorAll(`#${id} li[data-scope]`)).map((li) => li.getAttribute('data-scope'));
    expect(ids('cred-reconnect-kept')).toEqual(['calendar.readonly', 'gmail.send']);
    expect(ids('cred-reconnect-removed')).toEqual([]);

    const gmail = doc.querySelector('input[name="scope"][value="gmail.send"]') as HTMLInputElement;
    gmail.checked = false;
    gmail.dispatchEvent(new p.dom.window.Event('change', { bubbles: true }));
    expect(ids('cred-reconnect-kept')).toEqual(['calendar.readonly']);
    expect(ids('cred-reconnect-removed')).toEqual(['gmail.send']);
    expect(doc.querySelector('#cred-reconnect-removed li')!.textContent).toBe('Send email as you');
    expect(doc.querySelector('#cred-reconnect-added li')!.textContent).toBe('Nothing');

    gmail.checked = true;
    gmail.dispatchEvent(new p.dom.window.Event('change', { bubbles: true }));
    expect(ids('cred-reconnect-removed')).toEqual([]);
  });
});

// ── End to end: the app consumes the result from the fallback URL ────────────

describe('popup fallback end to end', () => {
  it('the app activates with the result read from the fallback URL', async () => {
    const hx = await harness();
    const { client, page, requestUri } = await popupResultPage(hx);
    const p = runPage(page.text, { opener: null });
    const landed = new URL(p.replace.mock.calls[0][0] as string);
    expectFallbackBinding(landed, requestUri);
    const result = parseLinkRedirectResult(landed.search)!;
    if (result.outcome !== 'success') throw new Error('expected success');
    const res = await activate(hx.app, client, result.connection_id, result.code);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('active');
  });

  it('after a handoff the top window re-enters with mode=redirect, finishes and falls back to redirect delivery', async () => {
    const hx = await harness();
    const { client, requestUri, browser, picker } = await popupPicker(hx);
    // What the popup's fetch did: advance the picker (sets the binding cookie).
    const advanced = await browser.post(hx.app, '/link/v1/picker', [
      ['e', envelopeOf(picker.text)], ['action', 'continue'], ['provider', 'google'], ['opener', 'handoff'], ['scope', 'calendar.readonly'], ['scope', 'gmail.send'],
    ]);
    expect(advanced.status).toBe(303);
    // A handoff never records "started with an opener".
    expect(browser.jar.has(OPENER_COOKIE)).toBe(false);
    // The widget navigates the top window to authorize with mode=redirect.
    // The stored mode stays popup (the store does not change it on
    // re-entry); the current step (provider) is re-rendered.
    const reentry = await browser.get(hx.app, authorizePath(requestUri, 'redirect'));
    expect(reentry.status).toBe(303);
    const providerUrl = new URL(reentry.headers.location);
    expect(providerUrl.origin).toBe('https://accounts.google.com');
    const confirmPage = await callback(hx.app, browser, providerUrl);
    const resultPage = await confirm(hx.app, browser, confirmPage.text, ['calendar.readonly', 'gmail.send']);
    expect(resultPage.status).toBe(200);
    // The top window has no opener: immediate fallback. It completes a
    // handoff, so it does not write (or refresh) the redirect-only memory.
    expect(pageConfig(resultPage.text).memory_provider).toBeUndefined();
    const storage = memoryStorage();
    const p = runPage(resultPage.text, { opener: null, storage });
    const landed = new URL(p.replace.mock.calls[0][0] as string);
    expectFallbackBinding(landed, requestUri);
    const result = parseLinkRedirectResult(landed.search)!;
    if (result.outcome !== 'success') throw new Error('expected success');
    expect((await activate(hx.app, client, result.connection_id, result.code)).status).toBe(200);
    expect(storage.data.size).toBe(0);
  });
});

async function popupPicker(hx: Harness) {
  const client = await registerClient(hx.app);
  const requestUri = await par(hx.app, client);
  const browser = new Browser();
  const picker = await browser.get(hx.app, authorizePath(requestUri, 'popup'));
  return { client, requestUri, browser, picker };
}

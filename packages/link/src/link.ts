import { LINK_MESSAGE_TYPES, parseLinkMessage } from '@credninja/protocol';
import type { LinkExitStep, LinkProviderSlug, LinkResult } from '@credninja/protocol';
import { CredLinkError } from './errors.js';
import { resolveLinkConfig } from './options.js';
import type { CredLinkCallbacks, CredLinkOptions, ResolvedLinkConfig } from './options.js';

/** The handle Cred.link() returns. */
export interface CredLink {
  /**
   * Start the flow. Call it directly inside a user gesture (a click
   * handler) so the browser allows the popup. While a flow is running a
   * second call does not start another one: in popup mode it focuses the
   * existing popup. Throws CredLinkError: 'popup_blocked',
   * 'navigation_blocked' (redirect mode inside a frame that may not
   * navigate the top window), 'no_window',
   * 'token_spent' (the Link service already returned a result for this
   * token), 'destroyed'.
   */
  open(): void;
  /**
   * End the running flow from the page: closes the popup or removes the
   * iframe and, if no result had arrived, calls onExit with the last
   * reported step. No-op when nothing is running. The handle stays usable.
   */
  close(): void;
  /**
   * Tear everything down without calling any callback, and make the handle
   * unusable. Call it when the component that owns the widget goes away.
   */
  destroy(): void;
}

/** Popup size in CSS px. */
export const LINK_POPUP_WIDTH = 500;
export const LINK_POPUP_HEIGHT = 720;
/** How often a popup is checked for having been closed. */
export const LINK_POPUP_POLL_MS = 500;
/**
 * After a closed popup is noticed, wait this long before reporting an exit,
 * so a result posted just before the hosted page closed itself still wins.
 */
export const LINK_POPUP_CLOSE_GRACE_MS = 300;
/** Iframe height before the picker reports its own. */
export const LINK_IFRAME_INITIAL_HEIGHT = 560;

/**
 * Sandbox for the embedded picker iframe, as tight as the flow allows:
 *   allow-scripts                     the picker posts step and resize messages
 *   allow-forms                       the picker form submits
 *   allow-same-origin                 keeps the Link origin (an opaque origin
 *                                     would post as "null" and fail origin
 *                                     pinning); safe because the iframe is
 *                                     cross-origin to the embedding page
 *   allow-popups                      the picker submits into a new top-level
 *                                     window (form target=_blank)
 *   allow-popups-to-escape-sandbox    that window runs the provider hop and
 *                                     confirm unsandboxed, as providers require
 * Not granted: any top navigation, modals, downloads, pointer lock,
 * presentation, orientation lock, storage access.
 */
export const LINK_IFRAME_SANDBOX = 'allow-scripts allow-forms allow-same-origin allow-popups allow-popups-to-escape-sandbox';

type HandleState = 'idle' | 'active' | 'navigating' | 'spent' | 'destroyed';

interface Session {
  /** The window that must be event.source: the popup, or the iframe's contentWindow. */
  source(): unknown;
  /** Listener registered on the developer's window. */
  onMessage: (event: MessageEvent) => void;
  win: Window;
  popup: Window | null;
  iframe: HTMLIFrameElement | null;
  pollTimer: ReturnType<typeof setInterval> | null;
  graceTimer: ReturnType<typeof setTimeout> | null;
  lastStep: LinkExitStep;
  lastProvider: LinkProviderSlug | undefined;
}

function currentWindow(): Window | undefined {
  return typeof window === 'undefined' ? undefined : window;
}

function popupFeatures(win: Window): string {
  const width = LINK_POPUP_WIDTH;
  const height = LINK_POPUP_HEIGHT;
  const outerWidth = Number.isFinite(win.outerWidth) && win.outerWidth > 0 ? win.outerWidth : width;
  const outerHeight = Number.isFinite(win.outerHeight) && win.outerHeight > 0 ? win.outerHeight : height;
  const screenX = Number.isFinite(win.screenX) ? win.screenX : 0;
  const screenY = Number.isFinite(win.screenY) ? win.screenY : 0;
  const left = Math.round(screenX + Math.max(0, (outerWidth - width) / 2));
  const top = Math.round(screenY + Math.max(0, (outerHeight - height) / 2));
  return `popup=yes,width=${width},height=${height},left=${left},top=${top}`;
}

function isPopupUnusable(popup: Window | null): boolean {
  if (!popup) return true;
  try {
    return popup.closed === true || typeof popup.closed === 'undefined';
  } catch {
    return true;
  }
}

function isPopupClosed(popup: Window): boolean {
  try {
    return popup.closed;
  } catch {
    return false;
  }
}

class LinkHandle implements CredLink {
  private state: HandleState = 'idle';
  private session: Session | null = null;

  constructor(
    private readonly config: ResolvedLinkConfig,
    private readonly callbacks: CredLinkCallbacks,
  ) {}

  open(): void {
    switch (this.state) {
      case 'destroyed':
        throw new CredLinkError('destroyed', 'open() was called after destroy()');
      case 'spent':
        throw new CredLinkError('token_spent', 'this token already produced a result; request a new token from your backend');
      case 'navigating':
        return;
      case 'active':
        this.focusActive();
        return;
      case 'idle':
        break;
    }
    const win = currentWindow();
    if (!win) throw new CredLinkError('no_window', 'open() needs a browser window; call it from a user gesture, not during server-side rendering');
    switch (this.config.mode) {
      case 'popup':
        this.openPopup(win);
        return;
      case 'redirect':
        this.openRedirect(win);
        return;
      case 'embedded':
        this.openEmbedded(win);
        return;
    }
  }

  close(): void {
    if (this.state !== 'active' || !this.session) return;
    this.endWithDetectedExit();
  }

  destroy(): void {
    if (this.state === 'destroyed') return;
    this.teardown();
    this.state = 'destroyed';
  }

  // ── modes ────────────────────────────────────────────────────────────────

  private openPopup(win: Window): void {
    // Must stay synchronous: window.open is only allowed inside the user gesture.
    const popup = win.open(this.config.authorizeUrl, '_blank', popupFeatures(win));
    if (isPopupUnusable(popup)) {
      try {
        popup?.close();
      } catch {
        // Ignore: nothing else to clean up.
      }
      throw new CredLinkError('popup_blocked', 'the browser blocked the Link popup; call open() directly inside a click handler');
    }
    const session = this.startSession(win, () => popup);
    session.popup = popup;
    session.pollTimer = setInterval(() => this.checkPopup(session), LINK_POPUP_POLL_MS);
  }

  private openRedirect(win: Window): void {
    this.state = 'navigating';
    try {
      const target = win.top ?? win;
      target.location.href = this.config.authorizeUrl;
    } catch (err) {
      // A cross-origin or sandboxed frame may not navigate the top window. Stay retryable.
      this.state = 'idle';
      // DOMException is not an Error subclass in every environment; read its name structurally.
      const name = typeof err === 'object' && err !== null ? (err as { name?: unknown }).name : undefined;
      const reason = typeof name === 'string' && name !== '' ? ` (${name})` : '';
      throw new CredLinkError(
        'navigation_blocked',
        `the browser refused to navigate the top window to Link${reason}; call open() inside a user gesture, allow top navigation for this frame, or use popup mode`,
      );
    }
  }

  private openEmbedded(win: Window): void {
    const container = this.config.container;
    if (!container) throw new CredLinkError('invalid_options', "mode 'embedded' requires container");
    const doc = container.ownerDocument ?? win.document;
    const iframe = doc.createElement('iframe');
    iframe.setAttribute('sandbox', LINK_IFRAME_SANDBOX);
    iframe.setAttribute('referrerpolicy', 'strict-origin');
    iframe.setAttribute('title', 'Connect an account');
    iframe.setAttribute('data-cred-link', '');
    iframe.style.display = 'block';
    iframe.style.width = '100%';
    iframe.style.border = '0';
    iframe.style.height = `${LINK_IFRAME_INITIAL_HEIGHT}px`;
    iframe.src = this.config.authorizeUrl;
    const session = this.startSession(win, () => iframe.contentWindow);
    session.iframe = iframe;
    container.appendChild(iframe);
  }

  // ── session lifecycle ────────────────────────────────────────────────────

  private startSession(win: Window, source: () => unknown): Session {
    const session: Session = {
      source,
      onMessage: (event: MessageEvent) => this.handleMessage(session, event),
      win,
      popup: null,
      iframe: null,
      pollTimer: null,
      graceTimer: null,
      lastStep: 'picker',
      lastProvider: undefined,
    };
    this.session = session;
    this.state = 'active';
    win.addEventListener('message', session.onMessage);
    return session;
  }

  private handleMessage(session: Session, event: MessageEvent): void {
    // Security boundary: right origin, right window, well-formed. Anything else is dropped silently.
    if (this.session !== session || this.state !== 'active') return;
    if (event.origin !== this.config.origin) return;
    const expected = session.source();
    if (expected === null || expected === undefined || event.source !== expected) return;
    const message = parseLinkMessage(event.data);
    if (!message) return;

    switch (message.type) {
      case LINK_MESSAGE_TYPES.step:
        session.lastStep = message.step;
        session.lastProvider = message.provider;
        return;
      case LINK_MESSAGE_TYPES.resize:
        if (session.iframe) session.iframe.style.height = `${Math.ceil(message.height)}px`;
        return;
      case LINK_MESSAGE_TYPES.result: {
        // Strip the envelope fields; deliver the result fields only.
        const { type: _type, v: _v, ...result } = message;
        this.teardown();
        this.state = 'spent';
        this.deliver(result);
        return;
      }
    }
  }

  private checkPopup(session: Session): void {
    if (this.session !== session || !session.popup || session.graceTimer !== null) return;
    if (!isPopupClosed(session.popup)) return;
    if (session.pollTimer !== null) clearInterval(session.pollTimer);
    session.pollTimer = null;
    session.graceTimer = setTimeout(() => {
      session.graceTimer = null;
      if (this.session === session && this.state === 'active') this.endWithDetectedExit();
    }, LINK_POPUP_CLOSE_GRACE_MS);
  }

  /** Popup closed or close() called: report an exit the widget observed, keep the token reusable. */
  private endWithDetectedExit(): void {
    const session = this.session;
    if (!session) return;
    const step = session.lastStep;
    const provider = session.lastProvider;
    this.teardown();
    this.state = 'idle';
    this.deliver(provider ? { outcome: 'exit', step, provider } : { outcome: 'exit', step });
  }

  private focusActive(): void {
    const popup = this.session?.popup;
    if (!popup) return;
    try {
      popup.focus();
    } catch {
      // Ignore: focusing is best effort.
    }
  }

  /** Remove the listener, stop timers, close the popup or remove the iframe. Idempotent. */
  private teardown(): void {
    const session = this.session;
    this.session = null;
    if (!session) return;
    session.win.removeEventListener('message', session.onMessage);
    if (session.pollTimer !== null) clearInterval(session.pollTimer);
    if (session.graceTimer !== null) clearTimeout(session.graceTimer);
    session.pollTimer = null;
    session.graceTimer = null;
    if (session.popup) {
      try {
        if (!session.popup.closed) session.popup.close();
      } catch {
        // Ignore: the popup may already be gone.
      }
    }
    if (session.iframe) session.iframe.remove();
  }

  /** Call exactly one developer callback. Runs after teardown, so a throwing callback leaves no state behind. */
  private deliver(result: LinkResult): void {
    deliverResult(result, this.callbacks);
  }
}

/** Route a result to the matching callback. Shared with handleRedirect. */
export function deliverResult(result: LinkResult, callbacks: CredLinkCallbacks): void {
  switch (result.outcome) {
    case 'success': {
      const { outcome: _o, ...payload } = result;
      callbacks.onSuccess?.(payload);
      return;
    }
    case 'error': {
      const { outcome: _o, ...payload } = result;
      callbacks.onError?.(payload);
      return;
    }
    case 'exit': {
      const { outcome: _o, ...payload } = result;
      callbacks.onExit?.(payload);
      return;
    }
  }
}

/**
 * Create a Link widget (spec section 1). Validates options and throws
 * CredLinkError on bad input; touches no browser API until open().
 */
export function link(options: CredLinkOptions): CredLink {
  const config = resolveLinkConfig(options);
  const callbacks: CredLinkCallbacks = {
    onSuccess: options.onSuccess,
    onError: options.onError,
    onExit: options.onExit,
  };
  return new LinkHandle(config, callbacks);
}

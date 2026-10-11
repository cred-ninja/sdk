import {
  LINK_MESSAGE_TYPES,
  LINK_TRANSACTION_TTL_SECONDS,
  linkAckMessage,
  parseLinkMessage,
} from '@credninja/protocol';
import type { LinkExitStep, LinkMessage, LinkProviderSlug, LinkResult } from '@credninja/protocol';
import { CredLinkError } from './errors.js';
import { resolveLinkConfig } from './options.js';
import type { CredLinkCallbacks, CredLinkOptions, ResolvedLinkConfig } from './options.js';
import {
  LINK_OPENER_LOSS_WINDOW_MS,
  LINK_RELAY_MESSAGE_TYPES,
  LINK_RELAY_RECEIPT_TIMEOUT_MS,
  LINK_RELAY_VERSION,
  closeRelayChannel,
  computeFlowId,
  openRelayChannel,
  parseRelayMessage,
  relayId,
} from './relay.js';

/** The handle Cred.link() returns. */
export interface CredLink {
  /**
   * Start the flow. Call it directly inside a user gesture (a click
   * handler) so the browser allows the popup. While a flow is running a
   * second call does not start another one: in popup mode it focuses the
   * existing popup. The exception is a popup flow waiting on a suspected
   * opener loss (see the README, "Popup fallback"): then open() ends that
   * attempt with onExit and starts a new one. Throws CredLinkError: 'popup_blocked',
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
  /** When step 'provider' was last received (Date.now()), for opener-loss detection. */
  providerStepAt: number | null;
  /** The popup read closed right after the provider step: waiting for a relayed result. */
  suspected: boolean;
  /** Popup fallback relay listener (popup and embedded modes), when BroadcastChannel exists. */
  channel: BroadcastChannel | null;
  onRelay: ((event: MessageEvent) => void) | null;
  /** Claims this widget made: offer_id to claim_id. */
  claims: Map<string, string>;
  /** SHA-256 of the token, once computed; null until then or when Web Crypto is unavailable. */
  flowId: string | null;
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
  /** The relay flow id of this handle's token, computed once on the first session. */
  private flowIdPromise: Promise<string | null> | null = null;

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
        if (this.session?.suspected) {
          // The user is starting over; end the attempt that was waiting on a relayed result.
          this.endWithDetectedExit();
          // The onExit callback may have destroyed the handle (or opened it again): then there is nothing to start.
          if (this.isDestroyedOrBusy()) return;
          this.open();
          return;
        }
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
        this.openRedirect(win, this.config.authorizeUrl);
        return;
      case 'embedded':
        this.openEmbedded(win);
        return;
    }
  }

  /** Read the state without the narrowing of the surrounding switch. */
  private isDestroyedOrBusy(): boolean {
    return this.state !== 'idle';
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

  private openRedirect(win: Window, url: string): void {
    this.state = 'navigating';
    try {
      const target = win.top ?? win;
      target.location.href = url;
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
      providerStepAt: null,
      suspected: false,
      channel: null,
      onRelay: null,
      claims: new Map(),
      flowId: null,
    };
    this.session = session;
    this.state = 'active';
    win.addEventListener('message', session.onMessage);
    const channel = openRelayChannel();
    if (channel) {
      session.channel = channel;
      session.onRelay = (event: MessageEvent) => this.handleRelay(session, event.data);
      channel.addEventListener('message', session.onRelay);
      // The relay is bound to this flow: offers name SHA-256(token). Until the digest is known
      // (or if Web Crypto is missing) this widget does not claim anything.
      if (!this.flowIdPromise) this.flowIdPromise = computeFlowId(this.config.token);
      void this.flowIdPromise.then((flowId) => {
        if (this.session === session) session.flowId = flowId;
      });
    }
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
        session.providerStepAt = message.step === 'provider' ? Date.now() : null;
        // handoff is honored in popup mode only; elsewhere the step is recorded and the field ignored.
        if (message.handoff === 'redirect' && this.config.mode === 'popup' && message.provider) {
          this.handoffToRedirect(session, message.provider);
        }
        return;
      case LINK_MESSAGE_TYPES.resize:
        if (session.iframe) session.iframe.style.height = `${Math.ceil(message.height)}px`;
        return;
      case LINK_MESSAGE_TYPES.result:
        // Ack first, before teardown and callbacks, so the hosted page does not fall back to redirect.
        try {
          // event.source passed the source check above, so it is the popup or iframe window.
          (event.source as Window).postMessage(linkAckMessage(), this.config.origin);
        } catch {
          // Ignore: the window may be gone; the hosted page then falls back on its own.
        }
        this.finishWithResult(message);
        return;
    }
  }

  /** The single finish path for a validated result, from postMessage or from the relay. */
  private finishWithResult(message: Extract<LinkMessage, { type: 'cred.link.result' }>): void {
    // Strip the envelope fields; deliver the result fields only.
    const { type: _type, v: _v, ...result } = message;
    this.teardown();
    this.state = 'spent';
    this.deliver(result);
  }

  /**
   * The picker asked to continue in redirect mode (this browser lost the
   * opener with this provider before): close the popup and navigate the top
   * window to the same flow in redirect mode. No callback fires here; the
   * result arrives on the return page.
   */
  private handoffToRedirect(session: Session, provider: LinkProviderSlug): void {
    const win = session.win;
    this.teardown();
    this.state = 'idle';
    try {
      this.openRedirect(win, this.config.handoffUrl);
    } catch (err) {
      // The page cannot navigate its top window: this attempt is over here, so say so, then surface why.
      this.deliver({ outcome: 'exit', step: 'provider', provider });
      throw err;
    }
  }

  /**
   * Popup fallback relay. Claim an offer only for this flow (its flow id is
   * SHA-256 of our token) and only while eligible; accept only the delivery
   * for our own claim, within its deadline, after the same validation as a
   * postMessage result; send the receipt, then finish.
   */
  private handleRelay(session: Session, data: unknown): void {
    if (this.session !== session || this.state !== 'active' || !session.channel) return;
    const message = parseRelayMessage(data);
    if (!message) return;
    switch (message.type) {
      case LINK_RELAY_MESSAGE_TYPES.offer: {
        if (session.flowId === null || message.flow_id !== session.flowId) return;
        if (!this.isRelayEligible(session) || session.claims.has(message.offer_id)) return;
        const claim_id = relayId();
        session.claims.set(message.offer_id, claim_id);
        try {
          session.channel.postMessage({ type: LINK_RELAY_MESSAGE_TYPES.claim, v: LINK_RELAY_VERSION, offer_id: message.offer_id, claim_id });
        } catch {
          session.claims.delete(message.offer_id);
        }
        return;
      }
      case LINK_RELAY_MESSAGE_TYPES.deliver: {
        if (session.claims.get(message.offer_id) !== message.claim_id) return;
        session.claims.delete(message.offer_id);
        // Late delivery: the return page may already have handled the result itself. Drop it unanswered.
        const now = Date.now();
        if (now > message.deadline || message.deadline - now > LINK_RELAY_RECEIPT_TIMEOUT_MS) return;
        // Same validation as a postMessage result.
        const result = parseLinkMessage(message.message);
        if (!result || result.type !== LINK_MESSAGE_TYPES.result) return;
        if (!this.isRelayEligible(session)) return;
        try {
          session.channel.postMessage({
            type: LINK_RELAY_MESSAGE_TYPES.receipt,
            v: LINK_RELAY_VERSION,
            offer_id: message.offer_id,
            claim_id: message.claim_id,
          });
        } catch {
          // No receipt means the return page delivers the result itself; do not deliver it here too.
          return;
        }
        this.finishWithResult(result);
        return;
      }
      case LINK_RELAY_MESSAGE_TYPES.claim:
      case LINK_RELAY_MESSAGE_TYPES.receipt:
        return;
    }
  }

  /** Eligible for a relayed result: flow open, and embedded, or a popup that reads closed or lost. The flow id is checked separately. */
  private isRelayEligible(session: Session): boolean {
    if (this.config.mode === 'embedded') return true;
    if (this.config.mode !== 'popup' || !session.popup) return false;
    return session.suspected || isPopupClosed(session.popup);
  }

  private checkPopup(session: Session): void {
    if (this.session !== session || !session.popup || session.graceTimer !== null) return;
    if (!isPopupClosed(session.popup)) return;
    if (session.pollTimer !== null) clearInterval(session.pollTimer);
    session.pollTimer = null;
    const sinceProvider = session.providerStepAt === null ? Infinity : Date.now() - session.providerStepAt;
    if (sinceProvider <= LINK_OPENER_LOSS_WINDOW_MS) {
      // Suspected opener loss: the provider's pages likely cut the popup off and the result will come by
      // redirect. Stay open and eligible for the relay until it does, or the transaction can no longer finish.
      session.suspected = true;
      session.lastStep = 'provider';
      session.graceTimer = setTimeout(() => {
        session.graceTimer = null;
        if (this.session === session && this.state === 'active') this.endWithDetectedExit();
      }, LINK_TRANSACTION_TTL_SECONDS * 1000);
      return;
    }
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
    if (session.channel) {
      if (session.onRelay) session.channel.removeEventListener('message', session.onRelay);
      closeRelayChannel(session.channel);
      session.channel = null;
      session.onRelay = null;
    }
    session.claims.clear();
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

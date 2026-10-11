import {
  LINK_REDIRECT_PARAMS,
  linkResultMessage,
  parseLinkRedirectFlowId,
  parseLinkRedirectResult,
} from '@credninja/protocol';
import type { LinkResult } from '@credninja/protocol';
import { deliverResult } from './link.js';
import type { CredLinkCallbacks } from './options.js';
import {
  LINK_RELAY_ACCEPT_WINDOW_MS,
  LINK_RELAY_CLAIM_TIMEOUT_MS,
  LINK_RELAY_MESSAGE_TYPES,
  LINK_RELAY_RECEIPT_GRACE_MS,
  LINK_RELAY_RECEIPT_TIMEOUT_MS,
  LINK_RELAY_VERSION,
  closeRelayChannel,
  openRelayChannel,
  parseRelayMessage,
  relayId,
} from './relay.js';

/** Options for handleRedirect(). */
export interface HandleRedirectOptions extends CredLinkCallbacks {
  /**
   * Read the result from this URL (absolute, path-relative or a bare query
   * string) instead of window.location. When given, the browser URL is left
   * untouched.
   */
  url?: string;
  /**
   * Popup fallback relay (default true). When the result arrived with
   * `cred_link_via=popup` and a valid `cred_link_flow`, offer it to the
   * widget for that flow if it is still waiting on another page of this
   * origin, before handling it here. false always handles it here.
   */
  relay?: boolean;
  /**
   * Called instead of onSuccess, onError and onExit when the result was
   * handed over to the waiting widget on another page (popup fallback).
   * This page then tries window.close(), which the browser may refuse (for
   * example for a window the user opened); use this to show "Connected, you
   * can close this window".
   */
  onRelayed?(): void;
}

const REDIRECT_KEYS: ReadonlySet<string> = new Set(Object.values(LINK_REDIRECT_PARAMS));

function safeDecode(value: string): string | null {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return null;
  }
}

/** The query string (no leading '?', no fragment) of a URL, a path, a query string or a Location. */
function queryOf(input: string | { search: string }): string {
  let raw: string;
  if (typeof input === 'string') {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input) || input.startsWith('/')) {
      try {
        raw = new URL(input, 'http://localhost').search;
      } catch {
        return '';
      }
    } else {
      raw = input;
    }
  } else {
    raw = typeof input.search === 'string' ? input.search : '';
  }
  const hash = raw.indexOf('#');
  if (hash !== -1) raw = raw.slice(0, hash);
  return raw.startsWith('?') ? raw.slice(1) : raw;
}

/** Decoded key of one `k=v` query part, or null when the key has a malformed escape. */
function keyOf(part: string): string | null {
  const eq = part.indexOf('=');
  return safeDecode(eq === -1 ? part : part.slice(0, eq));
}

function isLinkPart(part: string): boolean {
  const key = keyOf(part);
  return key !== null && REDIRECT_KEYS.has(key);
}

/**
 * Only the Link result parameters of a query, raw. The contracts helper
 * rejects a whole query if any part has a malformed percent-escape, so
 * unrelated parameters are removed before it sees the query.
 */
function linkPartsOf(query: string): string {
  return query.split('&').filter(isLinkPart).join('&');
}

function hasOutcomeParam(query: string): boolean {
  return query.split('&').some((part) => keyOf(part) === LINK_REDIRECT_PARAMS.outcome);
}

/** Remove every Link redirect parameter, keeping the developer's own parameters byte for byte. */
function stripLinkParams(query: string): string {
  return query
    .split('&')
    .filter((part) => part !== '' && !isLinkPart(part))
    .join('&');
}

/**
 * Parse a redirect-mode result without side effects. Accepts an absolute
 * URL, a path with a query, a bare query string, or a Location-like object.
 * Returns null when there is no Link result or it is malformed. Uses the
 * contracts helper parseLinkRedirectResult.
 */
export function parseRedirectResult(input: string | { search: string }): LinkResult | null {
  return parseLinkRedirectResult(linkPartsOf(queryOf(input)));
}

/**
 * Call this on the page your registered redirect_uri points to. Reads the
 * Link result from the query string, removes the Link parameters from the
 * address bar with history.replaceState (so the one-time code does not stay
 * in history, bookmarks or Referer headers), then calls the matching
 * callback at most once. Returns the result, or null when the page was not
 * reached from a Link redirect. Unrelated parameters, even malformed ones,
 * do not affect parsing and are kept as they are. A malformed Link result is
 * not delivered and the URL is left untouched, so nothing is cleaned away
 * that was not delivered. Safe during server-side rendering (returns null
 * without a window).
 *
 * Popup fallback: when the result carries `cred_link_via=popup` and
 * `cred_link_flow` (a popup or embedded flow lost its opener and the Link
 * service redirected here instead), the result is first offered on a
 * BroadcastChannel to the widget for that flow, if it is still waiting on
 * another page of this origin. If that widget takes it (claim, then a
 * receipt), onRelayed runs instead of the result callbacks and this window
 * is asked to close; otherwise this page's callbacks run. In the relay case
 * the callbacks run asynchronously, after the relay decision; the return
 * value and the URL cleanup stay synchronous. Use the callbacks, not the
 * return value, to trigger activation: when the result is handed over, the
 * other page activates it.
 */
export function handleRedirect(options: HandleRedirectOptions = {}): LinkResult | null {
  if (options.url !== undefined) {
    const result = parseRedirectResult(options.url);
    if (result) deliverResult(result, options);
    return result;
  }
  if (typeof window === 'undefined') return null;
  const win = window;
  const query = queryOf(win.location);
  if (!hasOutcomeParam(query)) return null;

  const result = parseLinkRedirectResult(linkPartsOf(query));
  // Never clean away a result that is not delivered: a malformed result is left in place for the developer to inspect.
  if (!result) return null;

  // Clean before calling back, so a throwing callback still leaves a clean URL.
  const remaining = stripLinkParams(query);
  const cleaned = `${win.location.pathname}${remaining === '' ? '' : `?${remaining}`}${win.location.hash}`;
  try {
    win.history.replaceState(win.history.state, '', cleaned);
  } catch {
    // Ignore: some sandboxed documents refuse history changes; the result is still delivered once.
  }

  // Relay only for a popup fallback that names its flow; a via marker without a flow id is delivered here.
  const flowId = parseLinkRedirectFlowId(linkPartsOf(query));
  if (flowId !== null && options.relay !== false) {
    relayOrDeliver(win, result, flowId, options);
  } else {
    deliverResult(result, options);
  }
  return result;
}

/**
 * Offer, claim, deliver, receipt. The offer names the flow, so only the
 * widget holding that token claims. The first claim gets the delivery; the
 * result counts as handed over only once its receipt arrives, and then
 * onRelayed runs and this window is asked to close. No claim, no receipt in
 * time, or no BroadcastChannel: the result is delivered here, and this
 * window is never closed.
 */
function relayOrDeliver(win: Window, result: LinkResult, flowId: string, options: HandleRedirectOptions): void {
  const channel = openRelayChannel();
  if (!channel) {
    deliverResult(result, options);
    return;
  }
  const offer_id = relayId();
  let claimId: string | null = null;
  let decided = false;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const decide = (): boolean => {
    if (decided) return false;
    decided = true;
    if (timer !== null) clearTimeout(timer);
    channel.removeEventListener('message', onMessage);
    closeRelayChannel(channel);
    return true;
  };
  const deliverHere = (): void => {
    if (decide()) deliverResult(result, options);
  };
  const handedOver = (): void => {
    if (!decide()) return;
    options.onRelayed?.();
    try {
      win.close();
    } catch {
      // Ignore: the browser may refuse to close a window it did not open by script.
    }
  };
  const onMessage = (event: MessageEvent): void => {
    if (decided) return;
    const message = parseRelayMessage(event.data);
    if (!message || message.offer_id !== offer_id) return;
    if (message.type === LINK_RELAY_MESSAGE_TYPES.claim && claimId === null) {
      claimId = message.claim_id;
      if (timer !== null) clearTimeout(timer);
      timer = setTimeout(() => {
        // Do not deliver yet: a receipt may already be queued behind this timer if the page was busy.
        // One more short timer lets queued messages run first; a receipt then still takes the handover branch.
        timer = setTimeout(deliverHere, LINK_RELAY_RECEIPT_GRACE_MS);
      }, LINK_RELAY_RECEIPT_TIMEOUT_MS);
      try {
        channel.postMessage({
          type: LINK_RELAY_MESSAGE_TYPES.deliver,
          v: LINK_RELAY_VERSION,
          offer_id,
          claim_id: claimId,
          deadline: Date.now() + LINK_RELAY_ACCEPT_WINDOW_MS,
          message: linkResultMessage(result),
        });
      } catch {
        deliverHere();
      }
      return;
    }
    if (message.type === LINK_RELAY_MESSAGE_TYPES.receipt && claimId !== null && message.claim_id === claimId) {
      handedOver();
    }
  };

  timer = setTimeout(deliverHere, LINK_RELAY_CLAIM_TIMEOUT_MS);
  channel.addEventListener('message', onMessage);
  try {
    channel.postMessage({ type: LINK_RELAY_MESSAGE_TYPES.offer, v: LINK_RELAY_VERSION, offer_id, flow_id: flowId });
  } catch {
    deliverHere();
  }
}

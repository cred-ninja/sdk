import { isLinkFlowId } from '@credninja/protocol';

/**
 * Popup fallback relay (widget to widget, on the developer's own origin).
 *
 * When a popup or embedded flow loses its opener, the hosted result page
 * redirects to the registered redirect_uri with `cred_link_via=popup` and
 * `cred_link_flow=<flow id>`, where the flow id is the lowercase hex SHA-256
 * of the widget's token. That return page runs handleRedirect(), which
 * offers the result on this BroadcastChannel to the one widget, on another
 * page of the same origin, that holds that token:
 *
 *   return page -> offer   {type:'cred.link.relay.offer',   v:2, offer_id, flow_id}
 *   widget      -> claim   {type:'cred.link.relay.claim',   v:2, offer_id, claim_id}
 *                  (only while waiting, and only if SHA-256(own token) === flow_id)
 *   return page -> deliver {type:'cred.link.relay.deliver', v:2, offer_id, claim_id, deadline, message}
 *                  (to the first claim only; deadline is epoch ms)
 *   widget      -> receipt {type:'cred.link.relay.receipt', v:2, offer_id, claim_id}
 *                  (after validating `message` with parseLinkMessage and checking
 *                  the deadline, before running any callback)
 *
 * The return page treats the result as handed over only after the receipt;
 * otherwise it delivers the result itself. These shapes are not part of the
 * protocol package: both ends are this package.
 */
export const LINK_RELAY_CHANNEL = 'cred.link.relay.v2';

/** How long the return page waits for a claim before handling the result itself. */
export const LINK_RELAY_CLAIM_TIMEOUT_MS = 700;

/**
 * After delivering to a claimant, how long the return page waits for its
 * receipt before handling the result itself.
 */
export const LINK_RELAY_RECEIPT_TIMEOUT_MS = 1000;

/**
 * When the receipt timer fires, the return page waits this much longer
 * before delivering locally, so a receipt already queued behind the timer
 * (the page was busy with a long task) is still handled first and the
 * result is not delivered twice.
 */
export const LINK_RELAY_RECEIPT_GRACE_MS = 50;

/**
 * The claimant accepts a delivery only until `deadline` = sent time plus
 * this, half the receipt timeout, so a receipt it sends is still in time on
 * the return page. A delivery that arrives later is dropped unanswered.
 */
export const LINK_RELAY_ACCEPT_WINDOW_MS = 500;

/**
 * A popup that starts reading closed within this long after the picker
 * reported step 'provider' is treated as a suspected opener loss (the
 * provider's pages cut the popup off), not as the user closing it.
 */
export const LINK_OPENER_LOSS_WINDOW_MS = 3000;

/** Relay message type strings. */
export const LINK_RELAY_MESSAGE_TYPES = {
  offer: 'cred.link.relay.offer',
  claim: 'cred.link.relay.claim',
  deliver: 'cred.link.relay.deliver',
  receipt: 'cred.link.relay.receipt',
} as const;

/** Relay message version, carried as `v`. */
export const LINK_RELAY_VERSION = 2;

/** Return page to widgets: a result for flow `flow_id` is available. */
export interface LinkRelayOffer {
  type: 'cred.link.relay.offer';
  v: 2;
  offer_id: string;
  flow_id: string;
}
/** Widget to return page: the widget holding the flow's token asks for the result. */
export interface LinkRelayClaim {
  type: 'cred.link.relay.claim';
  v: 2;
  offer_id: string;
  claim_id: string;
}
/** Return page to the first claimant. `message` is validated by the receiver with parseLinkMessage. */
export interface LinkRelayDeliver {
  type: 'cred.link.relay.deliver';
  v: 2;
  offer_id: string;
  claim_id: string;
  /** Epoch ms after which the claimant must drop the delivery. */
  deadline: number;
  message: unknown;
}
/** Claimant to return page: the delivery was valid and is being delivered here. */
export interface LinkRelayReceipt {
  type: 'cred.link.relay.receipt';
  v: 2;
  offer_id: string;
  claim_id: string;
}
/** Any relay message. */
export type LinkRelayMessage = LinkRelayOffer | LinkRelayClaim | LinkRelayDeliver | LinkRelayReceipt;

const RELAY_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;

function isRelayId(value: unknown): value is string {
  return typeof value === 'string' && RELAY_ID_PATTERN.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Validate untrusted channel data. Returns a fresh object with only the known fields, or null. */
export function parseRelayMessage(data: unknown): LinkRelayMessage | null {
  if (!isRecord(data) || data.v !== LINK_RELAY_VERSION || !isRelayId(data.offer_id)) return null;
  const offer_id = data.offer_id;
  switch (data.type) {
    case LINK_RELAY_MESSAGE_TYPES.offer:
      return isLinkFlowId(data.flow_id) ? { type: 'cred.link.relay.offer', v: 2, offer_id, flow_id: data.flow_id } : null;
    case LINK_RELAY_MESSAGE_TYPES.claim:
      return isRelayId(data.claim_id) ? { type: 'cred.link.relay.claim', v: 2, offer_id, claim_id: data.claim_id } : null;
    case LINK_RELAY_MESSAGE_TYPES.deliver: {
      const { claim_id, deadline } = data;
      if (!isRelayId(claim_id) || typeof deadline !== 'number' || !Number.isFinite(deadline)) return null;
      return { type: 'cred.link.relay.deliver', v: 2, offer_id, claim_id, deadline, message: data.message };
    }
    case LINK_RELAY_MESSAGE_TYPES.receipt:
      return isRelayId(data.claim_id) ? { type: 'cred.link.relay.receipt', v: 2, offer_id, claim_id: data.claim_id } : null;
    default:
      return null;
  }
}

/**
 * The relay flow id of a token: lowercase hex SHA-256 of its UTF-8 bytes,
 * the same value the server stores as the transaction's request_uri hash.
 * Resolves null when Web Crypto is unavailable (for example on a page that
 * is not a secure context); the widget is then simply not relay-eligible.
 */
export async function computeFlowId(token: string): Promise<string | null> {
  try {
    const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
    if (!subtle || typeof subtle.digest !== 'function' || typeof TextEncoder !== 'function') return null;
    const digest = await subtle.digest('SHA-256', new TextEncoder().encode(token));
    const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
    return isLinkFlowId(hex) ? hex : null;
  } catch {
    return null;
  }
}

/** A random relay id: 32 hex characters. Not a secret, only a correlation id. */
export function relayId(): string {
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  const bytes = new Uint8Array(16);
  if (c && typeof c.getRandomValues === 'function') {
    c.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Open the relay channel, or null when BroadcastChannel is unavailable. Called only inside widget calls, never at import. */
export function openRelayChannel(): BroadcastChannel | null {
  const Ctor = (globalThis as { BroadcastChannel?: typeof BroadcastChannel }).BroadcastChannel;
  if (typeof Ctor !== 'function') return null;
  try {
    return new Ctor(LINK_RELAY_CHANNEL);
  } catch {
    return null;
  }
}

/** Close a channel, ignoring errors. */
export function closeRelayChannel(channel: BroadcastChannel | null): void {
  if (!channel) return;
  try {
    channel.close();
  } catch {
    // Ignore: already closed.
  }
}

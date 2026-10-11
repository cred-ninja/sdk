/**
 * @credninja/link: the Cred Link account-connection widget (vanilla JS).
 *
 * Importing this module has no side effects and touches no browser API, so
 * it is safe to import during server-side rendering. Browser APIs are used
 * only inside open(), close(), destroy() and handleRedirect(); the popup
 * fallback BroadcastChannel is opened only while a flow is running or a
 * relayed result is being offered.
 */
import { link } from './link.js';
import { handleRedirect, parseRedirectResult } from './redirect.js';
import { buildAuthorizeUrl } from './options.js';

export { link, LINK_IFRAME_SANDBOX, LINK_POPUP_WIDTH, LINK_POPUP_HEIGHT } from './link.js';
export { handleRedirect, parseRedirectResult } from './redirect.js';
export { buildAuthorizeUrl } from './options.js';
export {
  LINK_RELAY_CHANNEL,
  LINK_RELAY_CLAIM_TIMEOUT_MS,
  LINK_RELAY_RECEIPT_TIMEOUT_MS,
  LINK_RELAY_RECEIPT_GRACE_MS,
  LINK_RELAY_ACCEPT_WINDOW_MS,
  LINK_RELAY_MESSAGE_TYPES,
  LINK_RELAY_VERSION,
  LINK_OPENER_LOSS_WINDOW_MS,
} from './relay.js';
export { CredLinkError, isCredLinkError } from './errors.js';

export type { CredLink } from './link.js';
export type { CredLinkOptions, CredLinkCallbacks, CredLinkUrlOptions } from './options.js';
export type { HandleRedirectOptions } from './redirect.js';
export type { LinkRelayClaim, LinkRelayDeliver, LinkRelayMessage, LinkRelayOffer, LinkRelayReceipt } from './relay.js';
export type { CredLinkErrorCode } from './errors.js';
export type {
  LinkErrorCode,
  LinkErrorPayload,
  LinkExitPayload,
  LinkExitStep,
  LinkProviderSlug,
  LinkResult,
  LinkScopeMap,
  LinkSuccessPayload,
  LinkTheme,
  LinkWidgetMode,
} from '@credninja/protocol';

/**
 * Namespace object matching the spec's `Cred.link(options)` call style.
 * `Cred.handleRedirect()` is the redirect-mode return-page helper.
 */
export const Cred = Object.freeze({
  link,
  handleRedirect,
  parseRedirectResult,
  buildAuthorizeUrl,
});

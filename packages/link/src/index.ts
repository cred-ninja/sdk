/**
 * @credninja/link: the Cred Link account-connection widget (vanilla JS).
 *
 * Importing this module has no side effects and touches no browser API, so
 * it is safe to import during server-side rendering. Browser APIs are used
 * only inside open(), close(), destroy() and handleRedirect().
 */
import { link } from './link.js';
import { handleRedirect, parseRedirectResult } from './redirect.js';
import { buildAuthorizeUrl } from './options.js';

export { link, LINK_IFRAME_SANDBOX, LINK_POPUP_WIDTH, LINK_POPUP_HEIGHT } from './link.js';
export { handleRedirect, parseRedirectResult } from './redirect.js';
export { buildAuthorizeUrl } from './options.js';
export { CredLinkError, isCredLinkError } from './errors.js';

export type { CredLink } from './link.js';
export type { CredLinkOptions, CredLinkCallbacks, CredLinkUrlOptions } from './options.js';
export type { HandleRedirectOptions } from './redirect.js';
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

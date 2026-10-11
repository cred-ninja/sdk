'use client';

/**
 * @credninja/link-react: React bindings for the Cred Link widget.
 * Importing has no side effects and is safe during server-side rendering.
 */
export { CredConnect } from './cred-connect.js';
export { useCredLink } from './use-cred-link.js';
export type { CredConnectProps } from './cred-connect.js';
export type { ContainerRef, UseCredLinkOptions, UseCredLinkResult } from './use-cred-link.js';

export { CredLinkError, handleRedirect, parseRedirectResult } from '@credninja/link';
export type {
  CredLinkErrorCode,
  HandleRedirectOptions,
  LinkErrorCode,
  LinkErrorPayload,
  LinkExitPayload,
  LinkProviderSlug,
  LinkResult,
  LinkScopeMap,
  LinkSuccessPayload,
  LinkTheme,
  LinkWidgetMode,
} from '@credninja/link';

/**
 * Errors the widget throws synchronously to the developer. These are
 * programming or environment problems detected in the browser. Flow
 * outcomes reported by the Link service (access_denied, provider_error and
 * so on) never throw: they arrive through onError.
 */
export type CredLinkErrorCode =
  /** The options object is malformed, or carries a field the browser must not supply. */
  | 'invalid_options'
  /** `token` is not a Link request_uri (urn:cred:link:...). */
  | 'invalid_token'
  /** The browser refused to open the popup (open() was not called inside a user gesture, or a blocker is active). */
  | 'popup_blocked'
  /** Redirect mode could not navigate the top window (for example from a cross-origin or sandboxed frame). open() can be retried. */
  | 'navigation_blocked'
  /** open() was called where there is no `window` (for example during server-side rendering). */
  | 'no_window'
  /** open() was called after the Link service returned a result for this token. Request a new token from your backend. */
  | 'token_spent'
  /** open() was called after destroy(). */
  | 'destroyed';

/** Typed error thrown by Cred.link() and CredLink.open(). */
export class CredLinkError extends Error {
  readonly code: CredLinkErrorCode;

  constructor(code: CredLinkErrorCode, message: string) {
    super(message);
    this.name = 'CredLinkError';
    this.code = code;
    Object.setPrototypeOf(this, CredLinkError.prototype);
  }
}

/** Type guard for CredLinkError, safe across bundle copies. */
export function isCredLinkError(value: unknown): value is CredLinkError {
  if (value instanceof CredLinkError) return true;
  // Widening to an optional unknown field only, so the property can be inspected.
  return value instanceof Error && value.name === 'CredLinkError' && typeof (value as { code?: unknown }).code === 'string';
}

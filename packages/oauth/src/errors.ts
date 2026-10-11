/**
 * @credninja/oauth: typed token endpoint errors and the raw token response.
 *
 * Both are additive. Adapters keep their existing error messages, so code
 * that matched on message text keeps working, while new callers can branch
 * on `OAuthTokenError.status` and `OAuthTokenError.error` (the OAuth `error`
 * code from the response body, for example `invalid_grant`).
 */

/** Which token endpoint call failed. */
export type OAuthTokenOperation = 'exchange' | 'refresh';

/**
 * Thrown by the adapters' code exchange and refresh paths when the token
 * endpoint rejects the request: a non-2xx status, or a 2xx body that
 * carries an OAuth `error` and no access token (GitHub and Slack answer
 * errors with 200). `message` stays the adapter's existing text.
 *
 * `error` is the body's `error` member only when it is a short token
 * (RFC 6749 5.2 grammar); `error_description` is never copied, because it
 * is provider prose that callers must not render.
 */
export class OAuthTokenError extends Error {
  readonly status: number;
  readonly error?: string;
  readonly operation: OAuthTokenOperation;

  constructor(message: string, init: { status: number; error?: string; operation: OAuthTokenOperation }) {
    super(message);
    this.name = 'OAuthTokenError';
    this.status = init.status;
    this.operation = init.operation;
    if (init.error !== undefined) this.error = init.error;
  }
}

/** Type guard that also works across duplicated module instances. */
export function isOAuthTokenError(value: unknown): value is OAuthTokenError {
  return value instanceof OAuthTokenError
    || (typeof value === 'object' && value !== null && (value as { name?: unknown }).name === 'OAuthTokenError'
      && typeof (value as { status?: unknown }).status === 'number');
}

const OAUTH_ERROR_CODE_PATTERN = /^[\x21\x23-\x5B\x5D-\x7E]{1,64}$/;

/** The OAuth `error` code of a parsed response body, when it is a well-formed short token. */
export function oauthErrorCode(body: unknown): string | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
  const code = (body as Record<string, unknown>).error;
  return typeof code === 'string' && OAUTH_ERROR_CODE_PATTERN.test(code) ? code : undefined;
}

/** Parse a failed response body as JSON when possible. Never throws. */
export async function readErrorBody(response: { json?: () => Promise<unknown> }): Promise<unknown> {
  if (typeof response.json !== 'function') return undefined;
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

/**
 * True when a 2xx token endpoint body is really an error: it names an OAuth
 * `error` and carries no access token.
 */
export function isErrorTokenBody(body: Record<string, unknown>): boolean {
  const hasToken = typeof body.access_token === 'string' && body.access_token !== '';
  const nestedUser = body.authed_user as Record<string, unknown> | undefined;
  const hasUserToken = typeof nestedUser?.access_token === 'string' && nestedUser.access_token !== '';
  return !hasToken && !hasUserToken && oauthErrorCode(body) !== undefined;
}

const RAW_TOKEN_RESPONSES = new WeakMap<object, Readonly<Record<string, unknown>>>();

/** Remember the parsed provider body a normalized token response came from. Adapter-internal. */
export function attachRawTokenResponse<T extends object>(tokens: T, raw: Record<string, unknown>): T {
  RAW_TOKEN_RESPONSES.set(tokens, Object.freeze({ ...raw }));
  return tokens;
}

/**
 * The provider's token endpoint body, as parsed, for a TokenResponse
 * returned by an adapter's code exchange, or a RefreshResponse returned by
 * a refresh through the shared refresh path (for example a refresh `scope`). Use it for provider-specific
 * fields the normalized shape drops (Slack `team` and `bot_user_id`, Notion
 * `workspace_id` and `bot_id`). It contains the tokens: never log or
 * serialize it. Returns undefined for objects an adapter did not produce.
 * Kept out of the TokenResponse shape on purpose, so existing callers that
 * serialize token responses do not start emitting extra provider data.
 */
export function getRawTokenResponse(tokens: object): Readonly<Record<string, unknown>> | undefined {
  return RAW_TOKEN_RESPONSES.get(tokens);
}

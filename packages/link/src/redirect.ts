import { LINK_REDIRECT_PARAMS, parseLinkRedirectResult } from '@credninja/protocol';
import type { LinkResult } from '@credninja/protocol';
import { deliverResult } from './link.js';
import type { CredLinkCallbacks } from './options.js';

/** Options for handleRedirect(). */
export interface HandleRedirectOptions extends CredLinkCallbacks {
  /**
   * Read the result from this URL (absolute, path-relative or a bare query
   * string) instead of window.location. When given, the browser URL is left
   * untouched.
   */
  url?: string;
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

  deliverResult(result, options);
  return result;
}

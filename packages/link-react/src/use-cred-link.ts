'use client';

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { isCredLinkError, link } from '@credninja/link';
import type { CredLink, CredLinkCallbacks, CredLinkError, CredLinkOptions } from '@credninja/link';

/** A React ref holding the embedded-mode container. */
export interface ContainerRef {
  readonly current: HTMLElement | null;
}

/**
 * Options for useCredLink and props of CredConnect. Same as Cred.link()
 * options, with two React conveniences: `token` may be empty while your
 * backend call is in flight (the widget is simply not ready), and
 * `container` may be a ref.
 */
export interface UseCredLinkOptions extends Omit<CredLinkOptions, 'token' | 'container'> {
  token: string | null | undefined;
  container?: HTMLElement | null | ContainerRef;
}

/** What useCredLink returns. */
export interface UseCredLinkResult {
  /** Start the flow. Call it from a click handler. A no-op until `ready`. Never throws: problems land in `error`. */
  open: () => void;
  /** True once a valid token is loaded in the browser. Always false during server-side rendering. */
  ready: boolean;
  /**
   * Invalid options ('invalid_options', 'invalid_token') or a failed open()
   * ('popup_blocked', 'navigation_blocked', 'token_spent'). Flow outcomes from the Link service
   * arrive through onError, not here.
   */
  error: CredLinkError | null;
}

// useLayoutEffect on the client so callbacks are current before any event; useEffect on the server, where neither runs.
const useIsomorphicLayoutEffect = typeof window === 'undefined' ? useEffect : useLayoutEffect;

function stableKey(value: unknown): string {
  return value === undefined || value === null ? '' : JSON.stringify(value);
}

function fromKey<T>(key: string): T | undefined {
  // The key was produced by stableKey from a value of type T.
  return key === '' ? undefined : (JSON.parse(key) as T);
}

function isContainerRef(value: unknown): value is ContainerRef {
  return typeof value === 'object' && value !== null && 'current' in value && !('nodeType' in value);
}

/**
 * React hook around Cred.link(). The widget is created after mount and
 * re-created only when the token, mode, baseUrl, container, providers,
 * scopes or theme change by value. Callbacks always use the latest props
 * without re-creating anything. The widget is destroyed on unmount, so no
 * callback fires after it. Safe in strict mode (the double effect creates
 * and destroys an idle widget; nothing opens until open() is called) and
 * during server-side rendering.
 */
export function useCredLink(options: UseCredLinkOptions): UseCredLinkResult {
  const callbacksRef = useRef<CredLinkCallbacks>({});
  useIsomorphicLayoutEffect(() => {
    callbacksRef.current = { onSuccess: options.onSuccess, onError: options.onError, onExit: options.onExit };
  });

  const linkRef = useRef<CredLink | null>(null);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<CredLinkError | null>(null);

  const { token, mode, baseUrl, container } = options;
  const providersKey = stableKey(options.providers);
  const scopesKey = stableKey(options.scopes);
  const themeKey = stableKey(options.theme);

  useEffect(() => {
    if (!token) {
      setReady(false);
      setError(null);
      return undefined;
    }
    let instance: CredLink;
    try {
      instance = link({
        token,
        mode,
        baseUrl,
        container: isContainerRef(container) ? container.current : container,
        providers: fromKey<CredLinkOptions['providers']>(providersKey),
        scopes: fromKey<CredLinkOptions['scopes']>(scopesKey),
        theme: fromKey<CredLinkOptions['theme']>(themeKey),
        onSuccess: (result) => callbacksRef.current.onSuccess?.(result),
        onError: (result) => callbacksRef.current.onError?.(result),
        onExit: (result) => callbacksRef.current.onExit?.(result),
      });
    } catch (err) {
      if (!isCredLinkError(err)) throw err;
      setReady(false);
      setError(err);
      return undefined;
    }
    linkRef.current = instance;
    setError(null);
    setReady(true);
    return () => {
      instance.destroy();
      if (linkRef.current === instance) linkRef.current = null;
      setReady(false);
    };
  }, [token, mode, baseUrl, container, providersKey, scopesKey, themeKey]);

  const open = useCallback(() => {
    const instance = linkRef.current;
    if (!instance) return;
    try {
      instance.open();
      setError(null);
    } catch (err) {
      if (!isCredLinkError(err)) throw err;
      setError(err);
    }
  }, []);

  return { open, ready, error };
}

'use client';

import { cloneElement, createElement, isValidElement, useEffect } from 'react';
import type { MouseEvent as ReactMouseEvent, ReactElement, ReactNode } from 'react';
import { useCredLink } from './use-cred-link.js';
import type { UseCredLinkOptions } from './use-cred-link.js';

/** Props of CredConnect: the widget options plus the trigger child. */
export interface CredConnectProps extends UseCredLinkOptions {
  /**
   * The trigger. A single element (for example your own button) gets an
   * onClick that opens the widget; its own onClick runs first and can call
   * event.preventDefault() to cancel. Anything else (text, or nothing) is
   * wrapped in a plain button that is disabled until the widget is ready.
   */
  children?: ReactNode;
}

type ClickableProps = { onClick?: (event: ReactMouseEvent<HTMLElement>) => void };

/**
 * Drop-in Cred Link trigger (spec section 1):
 *
 *   <CredConnect token={token} onSuccess={...}><button>Connect</button></CredConnect>
 *
 * Problems that are programming errors (bad token, popup blocked) are
 * logged with console.error; use the useCredLink hook to handle them in UI.
 */
export function CredConnect(props: CredConnectProps): ReactElement {
  const { children, ...options } = props;
  const { open, ready, error } = useCredLink(options);

  useEffect(() => {
    if (error) console.error(`[@credninja/link-react] ${error.code}: ${error.message}`);
  }, [error]);

  if (isValidElement(children)) {
    // The trigger is any element; only its onClick prop is read and replaced.
    const child = children as ReactElement<ClickableProps>;
    return cloneElement(child, {
      onClick: (event: ReactMouseEvent<HTMLElement>) => {
        child.props.onClick?.(event);
        if (!event.defaultPrevented) open();
      },
    });
  }
  return createElement(
    'button',
    { type: 'button', onClick: () => open(), disabled: !ready },
    children ?? 'Connect an account',
  );
}

// @vitest-environment node
import { createElement } from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { CredConnect, useCredLink } from '../index.js';

const TOKEN = `urn:cred:link:${'a'.repeat(43)}`;

describe('server-side rendering', () => {
  it('renders CredConnect and useCredLink without a window', () => {
    expect(typeof (globalThis as { window?: unknown }).window).toBe('undefined');
    const html = renderToString(createElement(CredConnect, { token: TOKEN }, createElement('button', null, 'Connect')));
    expect(html).toContain('Connect');

    let seen: { ready: boolean } | undefined;
    function Probe(): null {
      seen = useCredLink({ token: TOKEN });
      return null;
    }
    renderToString(createElement(Probe));
    expect(seen?.ready).toBe(false);
  });

  it('renders the fallback trigger disabled', () => {
    const html = renderToString(createElement(CredConnect, { token: TOKEN }));
    expect(html).toMatch(/<button[^>]*disabled/);
  });
});

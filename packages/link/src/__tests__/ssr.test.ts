// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { Cred, CredLinkError, handleRedirect } from '../index.js';
import { TOKEN } from './helpers.js';

describe('server-side rendering', () => {
  it('imports and creates a handle without a window', () => {
    expect(typeof (globalThis as { window?: unknown }).window).toBe('undefined');
    const handle = Cred.link({ token: TOKEN });
    let code: string | undefined;
    try {
      handle.open();
    } catch (err) {
      code = err instanceof CredLinkError ? err.code : undefined;
    }
    expect(code).toBe('no_window');
    handle.close();
    handle.destroy();
  });

  it('handleRedirect returns null without a window', () => {
    expect(handleRedirect()).toBeNull();
  });
});

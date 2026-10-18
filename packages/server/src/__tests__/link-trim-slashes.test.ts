import { describe, expect, it } from 'vitest';
import { trimTrailingSlashes } from '../link/util.js';

describe('trimTrailingSlashes', () => {
  it('drops every trailing slash and nothing else', () => {
    expect(trimTrailingSlashes('https://cred.example/')).toBe('https://cred.example');
    expect(trimTrailingSlashes('https://cred.example///')).toBe('https://cred.example');
    expect(trimTrailingSlashes('https://cred.example/a//b')).toBe('https://cred.example/a//b');
    expect(trimTrailingSlashes('https://cred.example')).toBe('https://cred.example');
    expect(trimTrailingSlashes('///')).toBe('');
    expect(trimTrailingSlashes('')).toBe('');
  });

  it('stays linear on a long run of slashes that is not at the end', () => {
    const hostile = `${'/'.repeat(200_000)}x`;
    const started = performance.now();
    expect(trimTrailingSlashes(hostile)).toBe(hostile);
    expect(performance.now() - started).toBeLessThan(100);
  });
});

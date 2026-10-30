import { describe, it, expect } from 'vitest';
import { countItems, destinationWithinPrefix, meterSide } from '../metering.js';

describe('countItems', () => {
  it('counts listings under any member name, nested through objects', () => {
    expect(countItems([1, 2, 3], true)).toBe(3);
    expect(countItems({ files: [1, 2] }, true)).toBe(2);
    expect(countItems({ messages: [1, 2, 3, 4], nextPageToken: 'x' }, true)).toBe(4); // Gmail
    expect(countItems({ ok: true, messages: [1, 2] }, true)).toBe(2); // Slack
    expect(countItems({ data: { issues: { nodes: [1, 2, 3] } } }, true)).toBe(3); // GraphQL
    expect(countItems({ changes: [1], newStartPageToken: 't' }, true)).toBe(1); // Drive changes
  });

  it('does not count arrays inside the records themselves', () => {
    expect(countItems([{ labels: [1, 2, 3] }, { labels: [4] }], true)).toBe(2);
  });

  it('counts a resource with no arrays as one, an empty body as none, and cannot measure text', () => {
    expect(countItems({ id: 'abc', name: 'x' }, true)).toBe(1);
    expect(countItems(undefined, false, true)).toBe(0);
    expect(countItems('<html>', false)).toBeNull();
  });
});

describe('destinationWithinPrefix', () => {
  it('holds only at a URL boundary', () => {
    const prefix = 'https://www.googleapis.com/drive/v3/files/abc';
    expect(destinationWithinPrefix(prefix, prefix)).toBe(true);
    expect(destinationWithinPrefix(`${prefix}?fields=id`, prefix)).toBe(true);
    expect(destinationWithinPrefix(`${prefix}/export`, prefix)).toBe(true);
    expect(destinationWithinPrefix(`${prefix}XYZ`, prefix)).toBe(false);
    expect(destinationWithinPrefix('https://api.github.com/repos/acme-evil/x', 'https://api.github.com/repos/acme')).toBe(false);
    expect(destinationWithinPrefix('https://api.github.com/repos/acme/x', 'https://api.github.com/repos/acme/')).toBe(true);
  });
});

describe('meterSide', () => {
  it('names a side for metered keys only', () => {
    expect(meterSide('calls')).toBe('request');
    expect(meterSide('max_rows')).toBe('response');
    expect(meterSide('max_spend')).toBeNull();
    expect(meterSide('constructor')).toBeNull();
  });
});

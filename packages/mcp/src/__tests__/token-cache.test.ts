import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TokenCache, TokenEntry } from '../token-cache.js';

function makeEntry(overrides?: Partial<TokenEntry>): TokenEntry {
  return {
    accessToken: 'ya29.test-token',
    service: 'google',
    userId: 'user_abc',
    expiresAt: Date.now() + 3600_000,
    ...overrides,
  };
}

describe('TokenCache', () => {
  let cache: TokenCache;

  beforeEach(() => { cache = new TokenCache(); });
  afterEach(() => { cache.destroy(); });

  // ── Store & retrieve ────────────────────────────────────────────────────────

  it('stores and retrieves a token', () => {
    const id = cache.store(makeEntry());
    expect(id).toMatch(/^del_[0-9a-f]{20}$/);
    const entry = cache.get(id);
    expect(entry?.accessToken).toBe('ya29.test-token');
  });

  it('returns undefined for unknown handle', () => {
    expect(cache.get('del_doesnotexist')).toBeUndefined();
  });

  it('returns undefined for expired entry', () => {
    const id = cache.store(makeEntry({ expiresAt: Date.now() - 1 }));
    expect(cache.get(id)).toBeUndefined();
  });

  it('deletes an entry', () => {
    const id = cache.store(makeEntry());
    expect(cache.delete(id)).toBe(true);
    expect(cache.get(id)).toBeUndefined();
  });

  it('returns a copy — mutations do not affect stored entry', () => {
    const id = cache.store(makeEntry());
    const entry = cache.get(id)!;
    entry.accessToken = 'mutated';
    expect(cache.get(id)?.accessToken).toBe('ya29.test-token');
  });

  // ── SSRF protection — isAllowedUrl ─────────────────────────────────────────

  describe('isAllowedUrl', () => {
    it('allows known Google API bases', () => {
      expect(cache.isAllowedUrl('google', 'https://www.googleapis.com/calendar/v3/calendars')).toBe(true);
      expect(cache.isAllowedUrl('google', 'https://gmail.googleapis.com/gmail/v1/users/me/messages')).toBe(true);
      expect(cache.isAllowedUrl('google', 'https://drive.googleapis.com/drive/v3/files')).toBe(true);
    });

    it('allows GitHub API', () => {
      expect(cache.isAllowedUrl('github', 'https://api.github.com/repos/org/repo/issues')).toBe(true);
    });

    it('allows Slack API', () => {
      expect(cache.isAllowedUrl('slack', 'https://slack.com/api/conversations.list')).toBe(true);
    });

    it('allows Notion API', () => {
      expect(cache.isAllowedUrl('notion', 'https://api.notion.com/v1/pages')).toBe(true);
    });

    it('allows Salesforce *.salesforce.com', () => {
      expect(cache.isAllowedUrl('salesforce', 'https://myorg.salesforce.com/services/data/v58.0/sobjects')).toBe(true);
    });

    it('allows Salesforce *.force.com', () => {
      expect(cache.isAllowedUrl('salesforce', 'https://myorg.force.com/services/data/v58.0/query')).toBe(true);
    });

    it('rejects HTTP (non-HTTPS)', () => {
      expect(cache.isAllowedUrl('github', 'http://api.github.com/repos/org/repo')).toBe(false);
    });

    it('rejects attacker domain that looks like a known base', () => {
      // Attacker registers googleapis.com.evil.com
      expect(cache.isAllowedUrl('google', 'https://googleapis.com.evil.com/steal')).toBe(false);
      // Attacker uses a URL that starts with the right string but wrong domain
      expect(cache.isAllowedUrl('github', 'https://api.github.com.evil.com/steal')).toBe(false);
    });

    it('rejects unknown service', () => {
      expect(cache.isAllowedUrl('unknownservice', 'https://api.github.com/repos')).toBe(false);
    });

    it('rejects non-Salesforce domains for Salesforce service', () => {
      expect(cache.isAllowedUrl('salesforce', 'https://attacker.com/steal')).toBe(false);
    });

    it('rejects cross-service URLs', () => {
      // Google token cannot be used to call GitHub API
      expect(cache.isAllowedUrl('google', 'https://api.github.com/repos')).toBe(false);
    });
  });
});

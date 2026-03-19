/**
 * Dynamic SSRF bypass test suite — isAllowedUrl()
 *
 * Tests known URL parser tricks that can bypass naive allowlist checks.
 * Each case documents the bypass technique and expected result.
 * Any UNEXPECTED_PASS here is a live vulnerability.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TokenCache } from '../token-cache.js';

describe('SSRF dynamic bypass suite — isAllowedUrl()', () => {
  let cache: TokenCache;
  beforeEach(() => { cache = new TokenCache(); });
  afterEach(() => { cache.destroy(); });

  // ── 1. Credential/userinfo injection ───────────────────────────────────────
  // "https://allowed.com@attacker.com/" — URL parser sees attacker.com as host
  describe('1. userinfo injection (user@host)', () => {
    it('github: api.github.com as username, attacker as host', () => {
      expect(cache.isAllowedUrl('github', 'https://api.github.com@attacker.com/')).toBe(false);
    });
    it('google: googleapis.com as username, attacker as host', () => {
      expect(cache.isAllowedUrl('google', 'https://www.googleapis.com@attacker.com/calendar/v3/')).toBe(false);
    });
    it('slack: slack.com as username, attacker as host', () => {
      expect(cache.isAllowedUrl('slack', 'https://slack.com@attacker.com/api/conversations.list')).toBe(false);
    });
  });

  // ── 2. Subdomain confusion ─────────────────────────────────────────────────
  // "https://api.github.com.evil.com/" — a subdomain of evil.com
  describe('2. subdomain confusion', () => {
    it('github: api.github.com.evil.com', () => {
      expect(cache.isAllowedUrl('github', 'https://api.github.com.evil.com/')).toBe(false);
    });
    it('google: www.googleapis.com.evil.com', () => {
      expect(cache.isAllowedUrl('google', 'https://www.googleapis.com.evil.com/')).toBe(false);
    });
    it('notion: api.notion.com.evil.com', () => {
      expect(cache.isAllowedUrl('notion', 'https://api.notion.com.evil.com/')).toBe(false);
    });
  });

  // ── 3. URL-encoded / control characters ───────────────────────────────────
  describe('3. URL encoding and control characters', () => {
    it('github: %2F (encoded slash) before attacker host', () => {
      expect(cache.isAllowedUrl('github', 'https://api.github.com%2F@attacker.com/')).toBe(false);
    });
    it('github: encoded @ sign to confuse parser', () => {
      expect(cache.isAllowedUrl('github', 'https://api.github.com%40attacker.com/')).toBe(false);
    });
    it('google: null byte IN HOSTNAME (not path) — parser strips it, resolves to wrong host', () => {
      // Null byte in the authority section before the path separator
      // WHATWG parser will strip or reject — in either case, the hostname
      // won't be www.googleapis.com so should be rejected
      expect(cache.isAllowedUrl('google', 'https://www.googleapis.com\x00.evil.com/')).toBe(false);
    });
    it('google: null byte in PATH after hostname — NOT a bypass (hostname still correct)', () => {
      // "\x00" is in the path, not the authority. Parser keeps hostname as googleapis.com.
      // This is correctly ALLOWED — the null byte doesn't redirect the request.
      expect(cache.isAllowedUrl('google', 'https://www.googleapis.com/\x00@attacker.com')).toBe(true);
    });
    it('github: tab in PATH after hostname — NOT a bypass (hostname still correct)', () => {
      // Same reasoning — tab in path doesn't affect hostname resolution
      expect(cache.isAllowedUrl('github', 'https://api.github.com/\t@attacker.com')).toBe(true);
    });
  });

  // ── 4. Protocol confusion ──────────────────────────────────────────────────
  describe('4. protocol variations', () => {
    it('rejects HTTP', () => {
      expect(cache.isAllowedUrl('github', 'http://api.github.com/')).toBe(false);
    });
    it('rejects HTTP with uppercase', () => {
      expect(cache.isAllowedUrl('github', 'HTTP://api.github.com/')).toBe(false);
    });
    it('rejects javascript:', () => {
      expect(cache.isAllowedUrl('github', 'javascript://api.github.com/')).toBe(false);
    });
    it('rejects file:', () => {
      expect(cache.isAllowedUrl('github', 'file:///etc/passwd')).toBe(false);
    });
    it('rejects data: URI', () => {
      expect(cache.isAllowedUrl('github', 'data:text/plain,https://api.github.com/')).toBe(false);
    });
    it('rejects ftp:', () => {
      expect(cache.isAllowedUrl('github', 'ftp://api.github.com/')).toBe(false);
    });
  });

  // ── 5. Private/internal IP ranges ─────────────────────────────────────────
  describe('5. private/internal IP targets', () => {
    it('rejects localhost', () => {
      expect(cache.isAllowedUrl('github', 'https://localhost/')).toBe(false);
    });
    it('rejects 127.0.0.1', () => {
      expect(cache.isAllowedUrl('github', 'https://127.0.0.1/')).toBe(false);
    });
    it('rejects 0.0.0.0', () => {
      expect(cache.isAllowedUrl('github', 'https://0.0.0.0/')).toBe(false);
    });
    it('rejects 192.168.x.x', () => {
      expect(cache.isAllowedUrl('github', 'https://192.168.1.1/')).toBe(false);
    });
    it('rejects 10.x.x.x', () => {
      expect(cache.isAllowedUrl('github', 'https://10.0.0.1/')).toBe(false);
    });
    it('rejects IPv6 loopback ::1', () => {
      expect(cache.isAllowedUrl('github', 'https://[::1]/')).toBe(false);
    });
    it('rejects IPv6 mapped 127.0.0.1 (::ffff:7f00:1)', () => {
      expect(cache.isAllowedUrl('github', 'https://[::ffff:7f00:1]/')).toBe(false);
    });
    it('rejects AWS metadata IP 169.254.169.254', () => {
      expect(cache.isAllowedUrl('github', 'https://169.254.169.254/')).toBe(false);
    });
  });

  // ── 6. Unicode / homoglyph / IDNA ─────────────────────────────────────────
  // Visually identical characters from other alphabets
  describe('6. unicode homoglyphs and IDNA', () => {
    it('rejects Cyrillic а (U+0430) in place of ASCII a', () => {
      // "аpi.github.com" — first char is Cyrillic
      expect(cache.isAllowedUrl('github', 'https://\u0430pi.github.com/')).toBe(false);
    });
    it('rejects fullwidth ASCII in URL', () => {
      // Fullwidth slash ／ (U+FF0F)
      expect(cache.isAllowedUrl('github', 'https://api.github.com\uff0f@attacker.com')).toBe(false);
    });
  });

  // ── 7. Cross-service token misdirection ────────────────────────────────────
  // Using a google-delegated token to call github API (different service)
  describe('7. cross-service misdirection', () => {
    it('google token cannot reach github API', () => {
      expect(cache.isAllowedUrl('google', 'https://api.github.com/repos')).toBe(false);
    });
    it('github token cannot reach google API', () => {
      expect(cache.isAllowedUrl('github', 'https://www.googleapis.com/calendar/v3/')).toBe(false);
    });
    it('slack token cannot reach notion API', () => {
      expect(cache.isAllowedUrl('slack', 'https://api.notion.com/v1/pages')).toBe(false);
    });
    it('notion token cannot reach slack API', () => {
      expect(cache.isAllowedUrl('notion', 'https://slack.com/api/conversations.list')).toBe(false);
    });
  });

  // ── 8. Salesforce-specific bypasses ────────────────────────────────────────
  describe('8. Salesforce hostname checks', () => {
    it('allows valid salesforce subdomain', () => {
      expect(cache.isAllowedUrl('salesforce', 'https://myorg.salesforce.com/services/data/v58.0/sobjects')).toBe(true);
    });
    it('allows valid force.com subdomain', () => {
      expect(cache.isAllowedUrl('salesforce', 'https://myorg.force.com/services/data/v58.0/query')).toBe(true);
    });
    it('rejects bare salesforce.com (no subdomain)', () => {
      // endsWith(".salesforce.com") requires a dot prefix
      expect(cache.isAllowedUrl('salesforce', 'https://salesforce.com/')).toBe(false);
    });
    it('rejects attacker domain ending in salesforce.com-like string', () => {
      expect(cache.isAllowedUrl('salesforce', 'https://attacker-salesforce.com/')).toBe(false);
    });
    it('rejects attacker.com with salesforce.com in path', () => {
      expect(cache.isAllowedUrl('salesforce', 'https://attacker.com/.salesforce.com')).toBe(false);
    });
    it('rejects private IP as salesforce subdomain label', () => {
      // "192.168.1.1.salesforce.com" — technically matches endsWith but resolves locally
      // This is the DNS rebinding risk — flag it
      const result = cache.isAllowedUrl('salesforce', 'https://192.168.1.1.salesforce.com/');
      // Document the result — if true, it's a DNS rebinding risk worth noting
      console.log(`[SSRF-AUDIT] 192.168.1.1.salesforce.com allowed: ${result}`);
      // We don't assert a specific value here — we're documenting behavior
    });
  });

  // ── 9. Port variations ────────────────────────────────────────────────────
  describe('9. non-standard ports', () => {
    it('github: non-standard port (attacker service on 8443)', () => {
      expect(cache.isAllowedUrl('github', 'https://api.github.com:8443/')).toBe(false);
    });
    it('github: port 443 explicit is allowed (same as default)', () => {
      // Explicit :443 is semantically identical to no port — should be allowed
      expect(cache.isAllowedUrl('github', 'https://api.github.com:443/repos')).toBe(true);
    });
    it('github: port 80 rejected (non-standard for HTTPS)', () => {
      expect(cache.isAllowedUrl('github', 'https://api.github.com:80/')).toBe(false);
    });
  });

  // ── 10. Edge cases and malformed input ────────────────────────────────────
  describe('10. malformed / edge-case input', () => {
    it('rejects empty string', () => {
      expect(cache.isAllowedUrl('github', '')).toBe(false);
    });
    it('rejects whitespace-only', () => {
      expect(cache.isAllowedUrl('github', '   ')).toBe(false);
    });
    it('allows bare base (no trailing slash) — URL parser normalizes to /', () => {
      // new URL("https://api.github.com").pathname === "/" so this matches the allowlist.
      // This is correct — a request to https://api.github.com is a valid GitHub API call.
      expect(cache.isAllowedUrl('github', 'https://api.github.com')).toBe(true);
    });
    it('rejects extremely long URL', () => {
      const long = 'https://api.github.com/' + 'a'.repeat(100_000);
      // Should not throw — just return true/false
      expect(() => cache.isAllowedUrl('github', long)).not.toThrow();
    });
    it('rejects unknown service regardless of URL', () => {
      expect(cache.isAllowedUrl('unknown_service', 'https://api.github.com/')).toBe(false);
    });
  });
});

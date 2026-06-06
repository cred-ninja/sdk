/**
 * @credninja/guard — URL Allowlist Policy
 *
 * For cred_use: restrict which API endpoints the agent can call.
 * SKIP for delegation requests (no targetUrl).
 */

import type { CredPolicy, GuardContext, PolicyResult, UrlAllowlistPolicyConfig } from '../types.js';

export class UrlAllowlistPolicy implements CredPolicy {
  readonly name = 'url-allowlist';
  private readonly config: UrlAllowlistPolicyConfig;

  constructor(config: UrlAllowlistPolicyConfig) {
    this.config = config;
  }

  evaluate(ctx: GuardContext): PolicyResult {
    const { provider, targetUrl } = ctx;

    // SKIP if no targetUrl (this is a delegation, not a cred_use)
    if (!targetUrl) {
      return {
        decision: 'SKIP',
        policy: this.name,
        reason: 'No targetUrl — not a cred_use request',
      };
    }

    // SKIP if provider not in config
    const allowedPatterns = this.config.allowedUrls[provider];
    if (!allowedPatterns || allowedPatterns.length === 0) {
      return {
        decision: 'SKIP',
        policy: this.name,
        reason: `No URL restrictions for provider: ${provider}`,
      };
    }

    // Check if targetUrl matches any pattern
    for (const pattern of allowedPatterns) {
      if (this.matchesPattern(targetUrl, pattern)) {
        return {
          decision: 'ALLOW',
          policy: this.name,
          reason: `URL matches allowed pattern: ${this.patternToString(pattern)}`,
        };
      }
    }

    // No pattern matched — DENY
    return {
      decision: 'DENY',
      policy: this.name,
      reason: `URL ${targetUrl} does not match any allowed pattern`,
    };
  }

  private matchesPattern(url: string, pattern: string | RegExp): boolean {
    if (pattern instanceof RegExp) {
      return pattern.test(url);
    }
    // String patterns are treated as path prefixes scoped to a single origin.
    // A raw `url.startsWith(pattern)` check is unsafe: an allowlist entry of
    // `https://api.github.com/` would also match `https://api.github.com.evil.com/`
    // (attacker-controlled subdomain) or `https://api.github.com@evil.com/`
    // (userinfo trick, where the request actually targets evil.com). We instead
    // parse both URLs and require an exact origin match before comparing paths.
    return this.matchesStringPrefix(url, pattern);
  }

  private matchesStringPrefix(url: string, pattern: string): boolean {
    let target: URL;
    let allowed: URL;
    try {
      target = new URL(url);
      allowed = new URL(pattern);
    } catch {
      // Unparseable target or pattern — fail closed.
      return false;
    }

    // Reject embedded credentials (e.g. https://api.github.com@evil.com or
    // https://user:pass@host); these are a common allowlist-bypass vector.
    if (target.username || target.password) {
      return false;
    }

    // Scheme + host + port must match exactly. This closes subdomain-suffix and
    // userinfo bypasses while preserving same-origin path-prefix matching.
    if (target.origin !== allowed.origin || target.protocol !== allowed.protocol) {
      return false;
    }

    // Within the same origin, keep the documented prefix semantics on path+query.
    const targetPathRef = target.pathname + target.search;
    const allowedPathRef = allowed.pathname + allowed.search;
    return targetPathRef.startsWith(allowedPathRef);
  }

  private patternToString(pattern: string | RegExp): string {
    if (pattern instanceof RegExp) {
      return pattern.toString();
    }
    return pattern;
  }
}

/**
 * Factory function to create a URL allowlist policy.
 */
export function urlAllowlistPolicy(config: UrlAllowlistPolicyConfig): UrlAllowlistPolicy {
  return new UrlAllowlistPolicy(config);
}

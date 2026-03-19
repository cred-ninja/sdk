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
    // String patterns are treated as prefixes
    return url.startsWith(pattern);
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

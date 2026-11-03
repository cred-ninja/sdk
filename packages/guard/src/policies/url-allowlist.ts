/**
 * @credninja/guard — URL Allowlist Policy
 *
 * For cred_use: restrict which API endpoints the agent can call.
 * SKIP for delegation requests (no targetUrl).
 */

import type {
  CredPolicy,
  GuardContext,
  ParameterValue,
  PolicyDescriptor,
  PolicyResult,
  UrlAllowlistPolicyConfig,
} from '../types.js';
import {
  OPAQUE,
  decodeRegExp,
  encodeRegExp,
  escapePointerSegment,
  isEncodedRegExp,
  isOpaqueMarker,
  isPlainObject,
  isStringArray,
} from '../policy-diagnostics/params.js';

export class UrlAllowlistPolicy implements CredPolicy {
  readonly name = 'url-allowlist';
  private readonly config: UrlAllowlistPolicyConfig;

  constructor(config: UrlAllowlistPolicyConfig) {
    this.config = config;
  }

  evaluate(ctx: GuardContext): PolicyResult {
    const { provider, targetUrl, requestedScopes } = ctx;

    // SKIP if no targetUrl (this is a delegation, not a cred_use)
    if (!targetUrl) {
      return {
        decision: 'SKIP',
        policy: this.name,
        reason: 'No targetUrl — not a cred_use request',
      };
    }

    const allowedPatterns = this.config.allowedUrls[provider];
    const wildcardSuffixes = this.config.wildcardSubdomains?.[provider];
    const hasPatterns = Boolean(allowedPatterns && allowedPatterns.length > 0);
    const hasWildcards = Boolean(wildcardSuffixes && wildcardSuffixes.length > 0);

    // SKIP if provider has neither fixed patterns nor wildcard suffixes configured
    if (!hasPatterns && !hasWildcards) {
      return {
        decision: 'SKIP',
        policy: this.name,
        reason: `No URL restrictions for provider: ${provider}`,
      };
    }

    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      return { decision: 'DENY', policy: this.name, reason: 'Target URL could not be parsed' };
    }
    if (parsed.protocol !== 'https:') {
      return { decision: 'DENY', policy: this.name, reason: 'Target URL must use HTTPS' };
    }
    if (parsed.username || parsed.password) {
      return { decision: 'DENY', policy: this.name, reason: 'Target URL must not contain userinfo' };
    }
    if (parsed.port !== '' && parsed.port !== '443') {
      return { decision: 'DENY', policy: this.name, reason: 'Target URL must use the default HTTPS port' };
    }

    // Wildcard-subdomain match (e.g. Salesforce's per-tenant origin)
    if (hasWildcards) {
      const hostname = parsed.hostname.toLowerCase();
      const looksLikeNumericSubdomain = /^(\d{1,3}\.){3}\d{1,3}\./.test(hostname);
      if (!looksLikeNumericSubdomain) {
        for (const suffix of wildcardSuffixes!) {
          if (hostname.endsWith(suffix.toLowerCase())) {
            return {
              decision: 'ALLOW',
              policy: this.name,
              reason: `Hostname matches wildcard suffix: ${suffix}`,
            };
          }
        }
      }
    }

    // Fixed-pattern match, gated by an optional per-provider scope predicate
    if (hasPatterns) {
      for (const pattern of allowedPatterns!) {
        if (this.matchesPattern(targetUrl, pattern)) {
          const scopeGate = this.config.scopeGate?.[provider];
          if (scopeGate && !scopeGate(requestedScopes, targetUrl)) {
            return {
              decision: 'DENY',
              policy: this.name,
              reason: `Target URL does not match an allowed scope for provider: ${provider}`,
            };
          }
          return {
            decision: 'ALLOW',
            policy: this.name,
            reason: `URL matches allowed pattern: ${this.patternToString(pattern)}`,
          };
        }
      }
    }

    // No pattern or wildcard suffix matched — DENY
    return {
      decision: 'DENY',
      policy: this.name,
      reason: `URL ${targetUrl} does not match any allowed pattern`,
    };
  }

  /**
   * The configuration as a parameter tree. RegExp patterns are encoded as
   * `{ "$regex": source, "flags": flags }`; `scopeGate` predicates are
   * functions, so each is shown as `{ "$opaque": true }`, listed in
   * `opaquePaths`, and carried over by reference by `withParameters`.
   */
  describe(): PolicyDescriptor {
    const allowedUrls: Record<string, ParameterValue[]> = {};
    for (const [provider, patterns] of Object.entries(this.config.allowedUrls)) {
      allowedUrls[provider] = patterns.map((pattern) => (pattern instanceof RegExp ? encodeRegExp(pattern) : pattern));
    }
    const parameters: Record<string, ParameterValue> = { allowedUrls };
    if (this.config.wildcardSubdomains) {
      parameters.wildcardSubdomains = Object.fromEntries(
        Object.entries(this.config.wildcardSubdomains).map(([provider, suffixes]) => [provider, [...suffixes]]),
      );
    }
    const opaquePaths: string[] = [];
    if (this.config.scopeGate) {
      const scopeGate: Record<string, ParameterValue> = {};
      for (const provider of Object.keys(this.config.scopeGate)) {
        scopeGate[provider] = OPAQUE;
        opaquePaths.push(`/scopeGate/${escapePointerSegment(provider)}`);
      }
      parameters.scopeGate = scopeGate;
    }
    return { kind: this.name, parameters, ...(opaquePaths.length > 0 ? { opaquePaths } : {}) };
  }

  withParameters(parameters: Record<string, ParameterValue>): UrlAllowlistPolicy {
    return new UrlAllowlistPolicy(UrlAllowlistPolicy.parseParameters(parameters, this.config.scopeGate));
  }

  /**
   * Parse an edited parameter tree. `previousScopeGate` supplies the function
   * behind each `{ "$opaque": true }` marker; a marker for a provider that
   * had no gate before, or a non-marker value under `scopeGate`, is refused,
   * since a patch can neither invent nor rewrite a predicate.
   */
  static parseParameters(
    parameters: Record<string, ParameterValue>,
    previousScopeGate?: UrlAllowlistPolicyConfig['scopeGate'],
  ): UrlAllowlistPolicyConfig {
    if (!isPlainObject(parameters)) throw new Error('url-allowlist parameters must be an object');
    if (!isPlainObject(parameters.allowedUrls)) throw new Error('url-allowlist.allowedUrls must be an object');
    const allowedUrls: Record<string, (string | RegExp)[]> = {};
    for (const [provider, patterns] of Object.entries(parameters.allowedUrls)) {
      if (!Array.isArray(patterns)) throw new Error(`url-allowlist.allowedUrls.${provider} must be an array`);
      allowedUrls[provider] = patterns.map((pattern, index) => {
        if (typeof pattern === 'string') {
          let parsed: URL;
          try {
            parsed = new URL(pattern);
          } catch {
            throw new Error(`url-allowlist.allowedUrls.${provider}[${index}] is not an absolute URL`);
          }
          if (parsed.protocol !== 'https:') throw new Error(`url-allowlist.allowedUrls.${provider}[${index}] must use https`);
          return pattern;
        }
        if (isEncodedRegExp(pattern)) {
          try {
            return decodeRegExp(pattern);
          } catch {
            throw new Error(`url-allowlist.allowedUrls.${provider}[${index}] is not a valid regular expression`);
          }
        }
        throw new Error(`url-allowlist.allowedUrls.${provider}[${index}] must be a string or { "$regex", "flags" }`);
      });
    }
    const config: UrlAllowlistPolicyConfig = { allowedUrls };
    if (parameters.wildcardSubdomains !== undefined && parameters.wildcardSubdomains !== null) {
      if (!isPlainObject(parameters.wildcardSubdomains)) throw new Error('url-allowlist.wildcardSubdomains must be an object');
      config.wildcardSubdomains = {};
      for (const [provider, suffixes] of Object.entries(parameters.wildcardSubdomains)) {
        if (!isStringArray(suffixes)) throw new Error(`url-allowlist.wildcardSubdomains.${provider} must be an array of strings`);
        config.wildcardSubdomains[provider] = [...suffixes];
      }
    }
    if (parameters.scopeGate !== undefined && parameters.scopeGate !== null) {
      if (!isPlainObject(parameters.scopeGate)) throw new Error('url-allowlist.scopeGate must be an object');
      config.scopeGate = {};
      for (const [provider, marker] of Object.entries(parameters.scopeGate)) {
        const gate = previousScopeGate?.[provider];
        if (!isOpaqueMarker(marker) || typeof gate !== 'function') {
          throw new Error(`url-allowlist.scopeGate.${provider} cannot be set by a patch; it is a predicate kept by reference`);
        }
        config.scopeGate[provider] = gate;
      }
    }
    return config;
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

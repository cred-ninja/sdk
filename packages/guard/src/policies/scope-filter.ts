/**
 * @credninja/guard — Scope Filter Policy
 *
 * Restrict which scopes an agent can request, beyond what the user consented to.
 * Default: DENY unlisted scopes. Opt-in: narrow instead of deny.
 */

import type { CredPolicy, GuardContext, PolicyResult, ScopeFilterPolicyConfig } from '../types.js';

export class ScopeFilterPolicy implements CredPolicy {
  readonly name = 'scope-filter';
  private readonly config: ScopeFilterPolicyConfig;

  constructor(config: ScopeFilterPolicyConfig) {
    this.config = config;
  }

  evaluate(ctx: GuardContext): PolicyResult {
    const { provider, requestedScopes } = ctx;

    // SKIP if provider not in config
    const allowedScopes = this.config.allowedScopes[provider];
    if (!allowedScopes) {
      return {
        decision: 'SKIP',
        policy: this.name,
        reason: `No scope restrictions for provider: ${provider}`,
      };
    }

    // Find disallowed scopes
    const allowedSet = new Set(allowedScopes);
    const disallowed = requestedScopes.filter((scope) => !allowedSet.has(scope));

    if (disallowed.length === 0) {
      return {
        decision: 'ALLOW',
        policy: this.name,
        reason: 'All requested scopes are allowed',
      };
    }

    // If narrowInsteadOfDeny is enabled, narrow scopes and allow
    if (this.config.narrowInsteadOfDeny) {
      const narrowedScopes = requestedScopes.filter((scope) => allowedSet.has(scope));
      return {
        decision: 'ALLOW',
        policy: this.name,
        reason: `Narrowed scopes: removed ${disallowed.join(', ')}`,
        narrowedScopes,
      };
    }

    // Default: DENY
    return {
      decision: 'DENY',
      policy: this.name,
      reason: `Disallowed scopes requested: ${disallowed.join(', ')}`,
    };
  }
}

/**
 * Factory function to create a scope filter policy.
 */
export function scopeFilterPolicy(config: ScopeFilterPolicyConfig): ScopeFilterPolicy {
  return new ScopeFilterPolicy(config);
}

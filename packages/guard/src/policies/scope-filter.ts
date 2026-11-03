/**
 * @credninja/guard — Scope Filter Policy
 *
 * Restrict which scopes an agent can request, beyond what the user consented to.
 * Default: DENY unlisted scopes. Opt-in: narrow instead of deny.
 */

import type {
  CredPolicy,
  GuardContext,
  ParameterValue,
  PolicyDescriptor,
  PolicyResult,
  ScopeFilterPolicyConfig,
} from '../types.js';
import {
  cloneParameters,
  isPlainObject,
  requireOptionalBoolean,
  requireStringArrayRecord,
} from '../weightspace/params.js';

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

  /** The configuration as a parameter tree (see CredPolicy.describe). */
  describe(): PolicyDescriptor {
    return { kind: this.name, parameters: cloneParameters(this.config) as Record<string, ParameterValue> };
  }

  withParameters(parameters: Record<string, ParameterValue>): ScopeFilterPolicy {
    return new ScopeFilterPolicy(ScopeFilterPolicy.parseParameters(parameters));
  }

  static parseParameters(parameters: Record<string, ParameterValue>): ScopeFilterPolicyConfig {
    if (!isPlainObject(parameters)) throw new Error('scope-filter parameters must be an object');
    const config: ScopeFilterPolicyConfig = {
      allowedScopes: requireStringArrayRecord(parameters.allowedScopes, 'scope-filter.allowedScopes'),
    };
    const narrow = requireOptionalBoolean(parameters.narrowInsteadOfDeny, 'scope-filter.narrowInsteadOfDeny');
    if (narrow !== undefined) config.narrowInsteadOfDeny = narrow;
    return config;
  }
}

/**
 * Factory function to create a scope filter policy.
 */
export function scopeFilterPolicy(config: ScopeFilterPolicyConfig): ScopeFilterPolicy {
  return new ScopeFilterPolicy(config);
}

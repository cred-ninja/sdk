import type {
  ValidateSubDelegationInput,
  ValidateSubDelegationResult,
} from './types.js';

export class DelegationChainError extends Error {
  constructor(
    message: string,
    public readonly code:
      | 'invalid_parent'
      | 'self_delegation'
      | 'service_mismatch'
      | 'user_mismatch'
      | 'app_mismatch'
      | 'delegation_not_allowed'
      | 'depth_exceeded'
      | 'scope_escalation_denied'
      | 'no_scopes_granted',
  ) {
    super(message);
    this.name = 'DelegationChainError';
  }
}

const WILDCARD_SUFFIX = '.*';

/**
 * A scope is a non-empty string with at most one wildcard, and that wildcard
 * must be a trailing ".*" segment ("crm.*"). A bare "*", a mid-string star
 * ("cr*m"), or a star without a dot ("crm*") is malformed. A malformed scope
 * matches only itself (exact literal equality, preserving pre-wildcard
 * behavior for legacy scopes), and never covers or is covered by anything
 * else, so it can be carried through a chain unchanged but never expanded.
 */
export function isValidScope(scope: unknown): scope is string {
  if (typeof scope !== 'string' || scope.trim().length === 0) return false;
  const star = scope.indexOf('*');
  if (star === -1) return true;
  return scope.endsWith(WILDCARD_SUFFIX)
    && star === scope.length - 1
    && scope.length > WILDCARD_SUFFIX.length;
}

/**
 * Does `granted` cover `requested`?
 *
 * Rules (these match the wire subsumption relation in
 * draft-asor-wimse-agent-delegation-chain section 4.2, rule 1):
 * - exact match covers;
 * - a trailing-wildcard scope "p.*" covers any scope that begins with "p."
 *   and has at least one character after it, at any depth ("crm.*" covers
 *   "crm.read" and "crm.contacts.read"), including a longer wildcard
 *   ("crm.*" covers "crm.contacts.*");
 * - "crm.*" does not cover "crm", "crm.", "crmx.read", or "crm.*" spelled
 *   with a different prefix;
 * - a malformed scope matches only itself: exact equality covers ("read:*"
 *   covers "read:*"), but a malformed scope never covers, and is never
 *   covered by, anything else.
 */
export function scopeCovers(granted: string, requested: string): boolean {
  if (typeof granted !== 'string' || granted.trim().length === 0) return false;
  if (granted === requested) return true;
  if (!isValidScope(granted) || !isValidScope(requested)) return false;
  if (!granted.endsWith(WILDCARD_SUFFIX)) return false;
  const prefix = granted.slice(0, -1); // keep the dot: "crm."
  return requested.length > prefix.length && requested.startsWith(prefix);
}

/** True when at least one scope in `granted` covers `requested`. */
export function scopeCoveredBy(granted: readonly string[], requested: string): boolean {
  return granted.some((g) => scopeCovers(g, requested));
}

export function validateSubDelegation(
  input: ValidateSubDelegationInput,
): ValidateSubDelegationResult {
  const { parent, childAgentDid, service, userId, appClientId, requestedScopes, permission } = input;

  if (!parent.agentDid || !parent.delegationId) {
    throw new DelegationChainError('Parent delegation is missing required identity fields', 'invalid_parent');
  }

  if (parent.agentDid === childAgentDid) {
    throw new DelegationChainError('Child agent must differ from parent agent', 'self_delegation');
  }

  if (parent.service !== service) {
    throw new DelegationChainError('Child delegation service must match parent delegation', 'service_mismatch');
  }

  if (parent.userId !== userId) {
    throw new DelegationChainError('Child delegation user must match parent delegation', 'user_mismatch');
  }

  if (parent.appClientId !== appClientId) {
    throw new DelegationChainError('Child delegation app must match parent delegation', 'app_mismatch');
  }

  if (!permission.delegatable) {
    throw new DelegationChainError('Permission is not delegatable', 'delegation_not_allowed');
  }

  const nextDepth = parent.chainDepth + 1;
  if (nextDepth > permission.maxDelegationDepth) {
    throw new DelegationChainError('Sub-delegation exceeds max delegation depth', 'depth_exceeded');
  }

  const requested = requestedScopes && requestedScopes.length > 0
    ? requestedScopes
    : parent.scopesGranted;

  // Coverage is wildcard-aware in one direction only: a granted "crm.*"
  // covers a requested "crm.read", never the reverse. A malformed scope
  // matches only itself, so a legacy literal scope carries through a chain
  // unchanged but can never expand it.
  const grantedScopes = requested.filter((scope) => (
    scopeCoveredBy(parent.scopesGranted, scope) && scopeCoveredBy(permission.allowedScopes, scope)
  ));

  if (grantedScopes.length === 0) {
    throw new DelegationChainError('Sub-delegation would grant no scopes', 'no_scopes_granted');
  }

  const widenedScopes = requested.filter((scope) => !scopeCoveredBy(parent.scopesGranted, scope));
  if (widenedScopes.length > 0) {
    throw new DelegationChainError(
      `Requested scopes exceed parent delegation: ${widenedScopes.join(', ')}`,
      'scope_escalation_denied',
    );
  }

  return {
    parentDelegationId: parent.delegationId,
    chainDepth: nextDepth,
    grantedScopes,
  };
}

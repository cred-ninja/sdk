import type {
  ValidateSubDelegationInput,
  ValidateSubDelegationResult,
} from './types.js';
import { constraintsSubsume } from './constraints.js';

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
      | 'no_scopes_granted'
      | 'constraint_escalation_denied',
  ) {
    super(message);
    this.name = 'DelegationChainError';
  }
}

/**
 * Scope classes, following the scope grammar proposed for
 * draft-asor-wimse-agent-delegation-chain-02 (list thread, Oct 2026) and
 * the -01 Section 4.1 productions it keeps intact:
 *
 *   scope          = literal-scope / wildcard-scope / opaque-scope
 *   segment        = lower *(lower / digit / "_" / "-")
 *   literal-scope  = segment "." segment *("." segment)        ; -01 4.1
 *   wildcard-scope = segment *("." segment) ".*"               ; -01 4.1
 *   opaque-scope   = 1*( %x21 / %x23-29 / %x2B-5B / %x5D-7E )  ; RFC 6749 scope-token minus "*"
 *
 * The alternatives overlap, so classification is by precedence: literal,
 * then wildcard, then opaque; anything else (a "*" anywhere but as the
 * trailing ".*" segment, whitespace, control or non-ASCII bytes) is
 * malformed. Classification is a function of the string alone: a provider
 * scope that happens to be lowercase and dotted is a literal and gets
 * wildcard coverage; one with uppercase, a colon, a slash, or a single
 * segment is opaque and matches only itself.
 */
export type ScopeClass = 'literal' | 'wildcard' | 'opaque' | 'malformed';

const SEGMENT = '[a-z][a-z0-9_-]*';
const LITERAL_SCOPE = new RegExp(`^${SEGMENT}(?:\\.${SEGMENT})+$`);
const WILDCARD_SCOPE = new RegExp(`^${SEGMENT}(?:\\.${SEGMENT})*\\.\\*$`);
const OPAQUE_SCOPE = /^[\x21\x23-\x29\x2B-\x5B\x5D-\x7E]+$/;

export function classifyScope(scope: unknown): ScopeClass {
  if (typeof scope !== 'string' || scope.length === 0) return 'malformed';
  if (LITERAL_SCOPE.test(scope)) return 'literal';
  if (WILDCARD_SCOPE.test(scope)) return 'wildcard';
  if (OPAQUE_SCOPE.test(scope)) return 'opaque';
  return 'malformed';
}

/**
 * A scope is valid when it is a literal, a wildcard, or an opaque
 * provider-native string. A bare "*", a mid-string star ("cr*m"), or a star
 * without a dot ("crm*") is malformed. A malformed scope matches only itself
 * (exact equality, preserving pre-wildcard behavior for legacy receipts) and
 * never covers, and is never covered by, anything else.
 */
export function isValidScope(scope: unknown): scope is string {
  return classifyScope(scope) !== 'malformed';
}

/**
 * Does `granted` cover `requested`?
 *
 * Rules (the wire subsumption relation in
 * draft-asor-wimse-agent-delegation-chain-01 section 4.1, plus the opaque
 * class proposed for -02):
 * - exact match covers, whatever the class;
 * - a wildcard "p.*" covers any LITERAL that begins with "p." at any depth
 *   ("crm.*" covers "crm.read" and "crm.contacts.read"), and any longer
 *   wildcard under the same prefix ("crm.*" covers "crm.contacts.*");
 * - "crm.*" does not cover "crm", "crm.", "crmx.read", or "crm.*" spelled
 *   with a different prefix;
 * - a wildcard never covers an opaque scope, and an opaque scope never
 *   covers anything but a byte-identical opaque scope: "drive.*" does not
 *   cover "drive.Read" (uppercase makes it opaque), "repo:status" matches
 *   only "repo:status";
 * - a malformed scope matches only itself: exact equality covers ("read:*"
 *   covers "read:*"), but a malformed scope never covers, and is never
 *   covered by, anything else.
 */
export function scopeCovers(granted: string, requested: string): boolean {
  if (typeof granted !== 'string' || granted.trim().length === 0) return false;
  if (granted === requested) return true;
  if (classifyScope(granted) !== 'wildcard') return false;
  const requestedClass = classifyScope(requested);
  if (requestedClass !== 'literal' && requestedClass !== 'wildcard') return false;
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

  // Constraint ceilings (asor-01 section 4.3): a child either inherits the
  // parent's ceilings unchanged, or restates every one of them at least as
  // tight (it may also add new ones). Anything looser is escalation.
  const parentConstraints = parent.constraints ?? [];
  const { requestedConstraints } = input;
  let grantedConstraints;
  if (requestedConstraints === undefined) {
    grantedConstraints = parentConstraints;
  } else {
    const check = constraintsSubsume(parentConstraints, requestedConstraints, { rankOrderings: input.rankOrderings });
    if (!check.ok) {
      throw new DelegationChainError(
        `Requested constraints exceed parent delegation: ${check.message}`,
        'constraint_escalation_denied',
      );
    }
    grantedConstraints = requestedConstraints;
  }

  return {
    parentDelegationId: parent.delegationId,
    chainDepth: nextDepth,
    grantedScopes,
    grantedConstraints,
  };
}

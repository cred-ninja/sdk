/**
 * Inputs and outputs of validateSubDelegation(). Plain data, no storage.
 */
import type { DelegationConstraint, RankOrderings } from './constraints.js';

export interface DelegationAuthority {
  delegationId: string;
  agentDid: string;
  service: string;
  userId: string;
  appClientId: string;
  scopesGranted: string[];
  chainDepth: number;
  /**
   * Constraint ceilings carried by the parent's receipt, already validated
   * (parseConstraints). Absent or empty means the parent carries none.
   */
  constraints?: DelegationConstraint[];
  /**
   * When the parent stops being valid, in Unix seconds. Absent means the
   * caller bounds the child's expiry itself.
   */
  expiresAt?: number;
}

export interface DelegationValidationPermission {
  allowedScopes: string[];
  delegatable: boolean;
  maxDelegationDepth: number;
}

/**
 * The delegating (grantor) agent's delegation gate: the fields of the
 * grantor's own Permission that say whether it may pass a delegation on,
 * and how deep the chain may go when it does. A Permission belongs to one
 * agent, and its `delegatable` / `maxDelegationDepth` describe what THAT
 * agent may do with a delegation it holds — so at a sub-delegation hop the
 * gate is the grantor's Permission, never the recipient's. The recipient's
 * Permission (the `permission` input) decides only which scopes the
 * recipient may hold; the recipient's own delegatable/depth are consulted
 * at the next hop, when the recipient is the grantor.
 */
export interface DelegationGrantorPermission {
  delegatable: boolean;
  maxDelegationDepth: number;
}

export interface ValidateSubDelegationInput {
  parent: DelegationAuthority;
  childAgentDid: string;
  service: string;
  userId: string;
  appClientId: string;
  requestedScopes?: string[];
  /**
   * Ceilings requested for the child, already validated (parseConstraints).
   * Absent means inherit the parent's ceilings unchanged. When present,
   * every parent ceiling must be restated at least as tight (asor-01 4.3),
   * or validation throws 'constraint_escalation_denied'.
   */
  requestedConstraints?: DelegationConstraint[];
  /**
   * Orderings for `rank` constraint labels (see constraints.ts). Merged over
   * DEFAULT_RANK_ORDERINGS.
   */
  rankOrderings?: RankOrderings;
  /**
   * Expiry requested for the child, in Unix seconds. Later than
   * `parent.expiresAt` throws 'expiry_escalation_denied': a child can never
   * outlive the delegation it was derived from.
   */
  requestedExpiresAt?: number;
  /**
   * The RECEIVING agent's Permission. Only its `allowedScopes` is consulted
   * (which scopes the recipient may hold) when `grantorPermission` is
   * supplied; its `delegatable` / `maxDelegationDepth` then govern the next
   * hop, not this one.
   */
  permission: DelegationValidationPermission;
  /**
   * The DELEGATING agent's Permission gate (see DelegationGrantorPermission).
   * When supplied, `delegatable` / `maxDelegationDepth` are read from it
   * instead of from `permission`. When omitted, the legacy single-Permission
   * behaviour is kept and `permission` is treated as the grantor's — callers
   * that hold both agents' Permissions must supply it, or the check runs
   * against the wrong agent.
   */
  grantorPermission?: DelegationGrantorPermission;
}

export interface ValidateSubDelegationResult {
  parentDelegationId: string;
  chainDepth: number;
  grantedScopes: string[];
  /** Ceilings the child receipt must carry. */
  grantedConstraints: DelegationConstraint[];
}

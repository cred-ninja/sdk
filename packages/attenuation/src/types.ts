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
}

export interface DelegationValidationPermission {
  allowedScopes: string[];
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
  permission: DelegationValidationPermission;
}

export interface ValidateSubDelegationResult {
  parentDelegationId: string;
  chainDepth: number;
  grantedScopes: string[];
  /** Ceilings the child receipt must carry. */
  grantedConstraints: DelegationConstraint[];
}

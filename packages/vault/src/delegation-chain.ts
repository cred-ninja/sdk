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

  const allowedByPermission = new Set(permission.allowedScopes);
  const allowedByParent = new Set(parent.scopesGranted);
  const requested = requestedScopes && requestedScopes.length > 0
    ? requestedScopes
    : parent.scopesGranted;

  const grantedScopes = requested.filter((scope) => (
    allowedByParent.has(scope) && allowedByPermission.has(scope)
  ));

  if (grantedScopes.length === 0) {
    throw new DelegationChainError('Sub-delegation would grant no scopes', 'no_scopes_granted');
  }

  const widenedScopes = requested.filter((scope) => !allowedByParent.has(scope));
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

/**
 * @credninja/attenuation: delegation attenuation with no runtime dependencies.
 *
 * - Scope grammar and covering relation (literal, wildcard, opaque).
 * - Constraint ceilings: parsing, subsumption, producer rules.
 * - validateSubDelegation(): the per-hop issuance check.
 * - verifyDelegationChain(): offline chain verification over plain hop records.
 * - parseStrictJson(): duplicate-member and unsafe-integer rejecting JSON.
 * - Compact JWS behind a signer interface (EdDSA, ES256), with a verifier
 *   that holds its own accepted-algorithm list.
 * - The draft-asor-wimse-agent-delegation-chain-02 Delegation Chain format:
 *   verifyAgentDelegationChain() and mintAgentDelegationToken().
 *
 * @credninja/vault re-exports everything here except the JWS and
 * agent_delegation modules, so existing imports keep working.
 */
export { validateSubDelegation, DelegationChainError, scopeCovers, scopeCoveredBy, isValidScope, classifyScope } from './delegation-chain.js';
export type { ScopeClass } from './delegation-chain.js';
export { verifyDelegationChain } from './chain-verify.js';
export type { DelegationChainHop, ChainVerifyReason, ChainVerifyResult, VerifyDelegationChainOptions } from './chain-verify.js';
export {
  parseConstraints,
  constraintsSubsume,
  constraintTypeOf,
  unresolvableRankLabels,
  cumulativeConstraints,
  producerConstraintViolations,
  DEFAULT_RANK_ORDERINGS,
  DEFAULT_RUNNING_COUNT_KEYS,
  DELEGATION_CONSTRAINT_TYPES,
  CUMULATIVE_CONSTRAINT_TYPES,
  CUMULATIVE_CONSTRAINT_UNENFORCEABLE,
} from './constraints.js';
export type {
  DelegationConstraint,
  DelegationConstraintType,
  MaxConstraint,
  MinConstraint,
  OneOfConstraint,
  NotOneOfConstraint,
  PrefixConstraint,
  RankConstraint,
  MaxLifetimeConstraint,
  MaxSubtreeConstraint,
  ProducerConstraintOptions,
  ConstraintSetMember,
  RankOrderings,
  ConstraintSubsumptionOptions,
  ConstraintParseResult,
  ConstraintSubsumptionResult,
} from './constraints.js';
export type {
  DelegationAuthority,
  DelegationValidationPermission,
  ValidateSubDelegationInput,
  ValidateSubDelegationResult,
} from './types.js';
export { parseStrictJson, StrictJsonError } from './strict-json.js';
export type { StrictJsonErrorCode } from './strict-json.js';
export { canonicalJson, CanonicalJsonError } from './jcs.js';
export {
  JWS_ALGORITHMS,
  base64urlEncode,
  base64urlDecode,
  jwkThumbprint,
  createKeySigner,
  createVerificationKey,
  createHs256Key,
  staticKeyResolver,
  signCompactJws,
  checkJwsSignature,
} from './jws.js';
export type { JwsAlgorithm, JwsSigner, JwsVerificationKey, JwsKeyResolver, JwsHeaderRef, JwsSignatureFailure } from './jws.js';
export {
  AGENT_DELEGATION_TYPE,
  CNF_MEMBERS,
  verifyAgentDelegationChain,
  mintAgentDelegationToken,
  parseAgentDelegationDetail,
  agentDelegationCommitment,
  AgentDelegationMintError,
} from './agent-delegation.js';
export type {
  AgentDelegationReason,
  AgentDelegationClaims,
  AgentDelegationChainResult,
  VerifiedAgentDelegationToken,
  VerifyAgentDelegationChainOptions,
  MintAgentDelegationTokenInput,
  ParsedAgentDelegationDetail,
  UnknownConstraint,
} from './agent-delegation.js';

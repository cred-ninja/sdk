/**
 * @credninja/vault — Local-first encrypted token vault
 *
 * AES-256-GCM encryption with PBKDF2-SHA256 key derivation.
 * Works offline. No cloud required.
 *
 * The delegation attenuation code (scopes, constraint ceilings, chain
 * verification, strict JSON) lives in @credninja/attenuation, which has no
 * native dependencies; it is re-exported here unchanged.
 */

export { CredVault, createVault } from './vault.js';
export { SQLiteAuditBackend, NoopAuditBackend, hmacAuditField } from './audit.js';
export type { AuditEvent, AuditActor, AuditResource, AuditBackend, AuditFilter } from './audit.js';
export { RotationEngine } from './rotation.js';
export type { RotationResult as RotationEngineResult, RefreshAdapter as RotationRefreshAdapter } from './rotation.js';
export { PermissionStore } from './permissions.js';
export type { CreatePermissionInput } from './permissions.js';
export { validateSubDelegation, DelegationChainError, scopeCovers, scopeCoveredBy, isValidScope, classifyScope } from '@credninja/attenuation';
export type { ScopeClass } from '@credninja/attenuation';
export { verifyDelegationChain } from '@credninja/attenuation';
export {
  collectDelegationSubtree,
  MemoryDelegationStore,
  DelegationRevokedError,
  DEFAULT_MAX_REVOCATION_DEPTH,
} from './delegation-revocation.js';
export type {
  DelegationRecord,
  DelegationStatus,
  RecordDelegationInput,
  DelegationRevocationSeed,
  DelegationRevocationOptions,
  DelegationRevocationResult,
  RevokedDelegation,
} from './delegation-revocation.js';
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
} from '@credninja/attenuation';
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
} from '@credninja/attenuation';
export type { DelegationChainHop, ChainVerifyReason, ChainVerifyResult, VerifyDelegationChainOptions } from '@credninja/attenuation';

export { encrypt, decrypt, encryptWithKey, decryptWithKey, deriveKey, generateSalt, maskToken } from './crypto.js';

export { SQLiteBackend } from './storage/sqlite.js';
export { FileBackend } from './storage/file.js';
export type { StorageBackend } from './storage/interface.js';

export type {
  VaultEntry,
  VaultOptions,
  StoreInput,
  GetInput,
  DeleteInput,
  ListInput,
  RefreshAdapter,
  StoredRow,
  EncryptedPayload,
  AgentRecord,
  AgentRow,
  AgentStatus,
  Permission,
  UpdatePermissionInput,
  PermissionRateLimit,
  PermissionRow,
  PermissionRowUpdate,
  DelegationAuthority,
  DelegationValidationPermission,
  ValidateSubDelegationInput,
  ValidateSubDelegationResult,
  Rotation,
  RotationRow,
  RotationStrategy,
  RotationState,
  RotationFailureAction,
} from './types.js';
export { parseStrictJson, StrictJsonError } from '@credninja/attenuation';
export type { StrictJsonErrorCode } from '@credninja/attenuation';

// Cred Link Phase 1 storage (LinkStore on SQLite, LinkSecretStore over CredVault).
export {
  SqliteLinkStore,
  LinkStoreError,
  VaultLinkSecretStore,
  createLinkStorage,
  LINK_VAULT_USER_ID_PREFIX,
  LINK_STAGED_VAULT_USER_ID_PREFIX,
  linkVaultUserId,
  linkStagedVaultUserId,
  isReservedLinkVaultUserId,
  ReservedVaultUserIdError,
  LINK_SCHEMA_VERSION,
} from './link/index.js';
export type {
  SqliteLinkStoreOptions,
  LinkStoreErrorCode,
  VaultLinkSecretStoreOptions,
  LinkSecretStoreLookup,
  CreateLinkStorageOptions,
  LinkStorage,
} from './link/index.js';

// Running totals for cumulative constraints (max_lifetime, max_subtree).
export { SqliteCumulativeLedger } from './cumulative-ledger.js';
export type { CumulativeLedger, CumulativeLedgerRegistration, CumulativeDebitResult, SqliteCumulativeLedgerOptions } from './cumulative-ledger.js';

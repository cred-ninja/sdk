/**
 * @credninja/vault — Local-first encrypted token vault
 *
 * AES-256-GCM encryption with PBKDF2-SHA256 key derivation.
 * Works offline. No cloud required.
 */

export { CredVault, createVault } from './vault.js';
export { SQLiteAuditBackend, NoopAuditBackend, hmacAuditField } from './audit.js';
export type { AuditEvent, AuditActor, AuditResource, AuditBackend, AuditFilter } from './audit.js';
export { RotationEngine } from './rotation.js';
export type { RotationResult as RotationEngineResult, RefreshAdapter as RotationRefreshAdapter } from './rotation.js';
export { PermissionStore } from './permissions.js';
export type { CreatePermissionInput } from './permissions.js';
export { validateSubDelegation, DelegationChainError, scopeCovers, scopeCoveredBy, isValidScope, classifyScope } from './delegation-chain.js';
export type { ScopeClass } from './delegation-chain.js';
export { verifyDelegationChain } from './chain-verify.js';
export { parseConstraints, constraintsSubsume, constraintTypeOf, unresolvableRankLabels, DEFAULT_RANK_ORDERINGS, DELEGATION_CONSTRAINT_TYPES } from './constraints.js';
export type {
  DelegationConstraint,
  DelegationConstraintType,
  MaxConstraint,
  MinConstraint,
  OneOfConstraint,
  NotOneOfConstraint,
  PrefixConstraint,
  RankConstraint,
  ConstraintSetMember,
  RankOrderings,
  ConstraintSubsumptionOptions,
  ConstraintParseResult,
  ConstraintSubsumptionResult,
} from './constraints.js';
export type { DelegationChainHop, ChainVerifyReason, ChainVerifyResult, VerifyDelegationChainOptions } from './chain-verify.js';

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
export { parseStrictJson, StrictJsonError } from './strict-json.js';
export type { StrictJsonErrorCode } from './strict-json.js';

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

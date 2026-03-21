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
export { validateSubDelegation, DelegationChainError } from './delegation-chain.js';

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
  PermissionRateLimit,
  PermissionRow,
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

/**
 * @credninja/vault — Local-first encrypted token vault
 *
 * AES-256-GCM encryption with PBKDF2-SHA256 key derivation.
 * Works offline. No cloud required.
 */

export { CredVault, createVault } from './vault.js';
export { AgentVault, createAgentVault } from './agent-vault.js';

export { encrypt, decrypt, encryptWithKey, decryptWithKey, deriveKey, generateSalt, maskToken } from './crypto.js';

export { SQLiteBackend } from './storage/sqlite.js';
export { FileBackend } from './storage/file.js';
export type { StorageBackend, AgentIdentityStoredRow } from './storage/interface.js';

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
  AgentIdentityRow,
  RegisterAgentInput,
  ClaimAgentInput,
} from './types.js';

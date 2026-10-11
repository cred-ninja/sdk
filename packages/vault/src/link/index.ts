/**
 * Cred Link Phase 1 storage: SQLite LinkStore and a vault-backed
 * LinkSecretStore, implementing the contracts in @credninja/protocol.
 */
export { SqliteLinkStore, LinkStoreError } from './sqlite-store.js';
export type { SqliteLinkStoreOptions, LinkStoreErrorCode } from './sqlite-store.js';
export { VaultLinkSecretStore } from './secret-store.js';
export type { VaultLinkSecretStoreOptions, LinkSecretStoreLookup } from './secret-store.js';
export { createLinkStorage } from './factory.js';
export type { CreateLinkStorageOptions, LinkStorage } from './factory.js';
export {
  LINK_VAULT_USER_ID_PREFIX,
  LINK_STAGED_VAULT_USER_ID_PREFIX,
  linkVaultUserId,
  linkStagedVaultUserId,
  isReservedLinkVaultUserId,
  ReservedVaultUserIdError,
} from './vault-ids.js';
export { LINK_SCHEMA_VERSION } from './schema.js';

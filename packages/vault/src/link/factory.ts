import type { CredVault } from '../vault.js';
import { SqliteLinkStore } from './sqlite-store.js';
import type { SqliteLinkStoreOptions } from './sqlite-store.js';
import { VaultLinkSecretStore } from './secret-store.js';

export interface CreateLinkStorageOptions {
  /** The vault Link tokens are encrypted into. */
  vault: CredVault;
  /** Path of the Link SQLite database file (separate from the vault's). ':memory:' for tests. */
  path: string;
  /** Passed through to SqliteLinkStore. */
  storeOptions?: SqliteLinkStoreOptions;
}

export interface LinkStorage {
  store: SqliteLinkStore;
  secrets: VaultLinkSecretStore;
}

/** Opens the Link store at `path` and a secret store over `vault` that looks providers up in it. */
export function createLinkStorage(options: CreateLinkStorageOptions): LinkStorage {
  const store = new SqliteLinkStore(options.path, options.storeOptions);
  const secrets = new VaultLinkSecretStore({ vault: options.vault, store });
  return { store, secrets };
}

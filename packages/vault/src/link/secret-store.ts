import { LINK_PROVIDERS, isConnectionId, isTransactionId } from '@credninja/protocol';
import type { ConnectionId, LinkSecretStore, LinkStore, LinkTokenSet, TransactionId } from '@credninja/protocol';
import { CredVault, isGenuineCredVault } from '../vault.js';
import { linkStagedVaultUserId, linkVaultUserId } from './vault-ids.js';
import { LINK_VAULT_ACCESS } from './vault-access.js';

/*
 * CredVault's own methods, captured when this module loads. The secret store
 * always calls these on a genuine CredVault, so the LINK_VAULT_ACCESS symbol
 * is only ever handed to CredVault's code: never to a Proxy, a look-alike, a
 * subclass override, or a method replaced on the instance or prototype later.
 */
const vaultGetStored = CredVault.prototype.getStored;
const vaultStore = CredVault.prototype.store;
const vaultDelete = CredVault.prototype.delete;

/** The LinkStore lookups the secret store needs to find a provider slug. */
export type LinkSecretStoreLookup = Pick<LinkStore, 'getConnection' | 'getTransaction'>;

export interface VaultLinkSecretStoreOptions {
  /** The vault Link tokens are stored in (AES-256-GCM per field). */
  vault: CredVault;
  /** Where to look up a connection's or transaction's provider. */
  store: LinkSecretStoreLookup;
}

/** A decrypted vault entry, kept internal to this file. */
interface StoredTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: Date;
  scopes?: string[];
}

/**
 * Reads a vault entry as stored, including when its access token has
 * expired, without refreshing it (CredVault.getStored). Plain get() would
 * return null for an expired entry when no adapter is passed.
 */
async function readStored(vault: CredVault, provider: string, userId: string): Promise<StoredTokens | null> {
  const entry = await vaultGetStored.call(vault, { provider, userId }, LINK_VAULT_ACCESS);
  if (!entry) return null;
  return {
    accessToken: entry.accessToken,
    refreshToken: entry.refreshToken,
    expiresAt: entry.expiresAt,
    scopes: entry.scopes,
  };
}

function toTokenSet(stored: StoredTokens): LinkTokenSet {
  const set: LinkTokenSet = { access_token: stored.accessToken };
  if (stored.refreshToken !== undefined) set.refresh_token = stored.refreshToken;
  if (stored.expiresAt !== undefined && !Number.isNaN(stored.expiresAt.getTime())) {
    set.expires_at = stored.expiresAt.toISOString();
  }
  return set;
}

function validateTokens(tokens: LinkTokenSet): { accessToken: string; refreshToken?: string; expiresAt?: Date } {
  if (!tokens || typeof tokens.access_token !== 'string' || tokens.access_token === '') {
    throw new TypeError('LinkTokenSet.access_token must be a non-empty string');
  }
  if (tokens.refresh_token !== undefined && (typeof tokens.refresh_token !== 'string' || tokens.refresh_token === '')) {
    throw new TypeError('LinkTokenSet.refresh_token must be a non-empty string when present');
  }
  let expiresAt: Date | undefined;
  if (tokens.expires_at !== undefined) {
    expiresAt = new Date(tokens.expires_at);
    if (typeof tokens.expires_at !== 'string' || Number.isNaN(expiresAt.getTime())) {
      throw new TypeError('LinkTokenSet.expires_at must be an ISO-8601 timestamp');
    }
  }
  return { accessToken: tokens.access_token, refreshToken: tokens.refresh_token, expiresAt };
}

/**
 * LinkSecretStore over an existing CredVault.
 *
 * Vault layout (see vault-ids.ts):
 *   connection tokens: provider = connection.provider, userId = `link:<connection_id>`
 *   staged tokens:     provider = transaction.provider, userId = `link-staged:<tid>`
 * The vault entry's `scopes` is the provider-granted scope set (the server's
 * delegation code reads entry.scopes as the stored provider consent).
 * LinkTokenSet.token_type is not persisted: the vault has no column for it.
 */
export class VaultLinkSecretStore implements LinkSecretStore {
  private readonly vault: CredVault;
  private readonly store: LinkSecretStoreLookup;

  constructor(options: VaultLinkSecretStoreOptions) {
    if (!options || !options.store) {
      throw new TypeError('VaultLinkSecretStore needs { vault, store }');
    }
    // instanceof alone accepts a Proxy around a real vault; the brand check does not.
    if (!(options.vault instanceof CredVault) || !isGenuineCredVault(options.vault)) {
      throw new TypeError('VaultLinkSecretStore needs a genuine CredVault instance');
    }
    this.vault = options.vault;
    this.store = options.store;
  }

  async putStaged(tid: TransactionId, tokens: LinkTokenSet): Promise<void> {
    const userId = linkStagedVaultUserId(tid);
    const t = validateTokens(tokens);
    const tx = await this.store.getTransaction(tid);
    if (!tx) throw new Error('VaultLinkSecretStore.putStaged: unknown transaction');
    if (!tx.provider) throw new Error('VaultLinkSecretStore.putStaged: transaction has no provider yet');
    // Replace any earlier staged set, including one under a different provider.
    for (const p of LINK_PROVIDERS) {
      if (p !== tx.provider) await vaultDelete.call(this.vault, { provider: p, userId }, LINK_VAULT_ACCESS);
    }
    await vaultStore.call(this.vault, {
      provider: tx.provider,
      userId,
      accessToken: t.accessToken,
      refreshToken: t.refreshToken,
      expiresAt: t.expiresAt,
      scopes: tx.provider_granted_scopes,
    }, LINK_VAULT_ACCESS);
  }

  async getStaged(tid: TransactionId): Promise<LinkTokenSet | null> {
    if (!isTransactionId(tid)) return null;
    const tx = await this.store.getTransaction(tid);
    if (!tx || !tx.provider) return null;
    const stored = await readStored(this.vault, tx.provider, linkStagedVaultUserId(tid));
    return stored ? toTokenSet(stored) : null;
  }

  async deleteStaged(tid: TransactionId): Promise<void> {
    const userId = linkStagedVaultUserId(tid);
    for (const p of LINK_PROVIDERS) {
      await vaultDelete.call(this.vault, { provider: p, userId }, LINK_VAULT_ACCESS);
    }
  }

  /**
   * Called after LinkStore.commitActivation. Phase 1 limitation: the two are
   * separate writes, so a crash between them leaves the staged tokens under
   * `link-staged:<tid>` (the transaction is already terminal, so no sweep
   * returns it) and the connection with no tokens. The server treats a
   * connection with no tokens as needs_reauth.
   */
  async commitStaged(tid: TransactionId, connection_id: ConnectionId): Promise<boolean> {
    const stagedUserId = linkStagedVaultUserId(tid);
    const userId = linkVaultUserId(connection_id);
    const [tx, conn] = await Promise.all([this.store.getTransaction(tid), this.store.getConnection(connection_id)]);
    if (!tx || !tx.provider) return false;
    if (!conn) throw new Error('VaultLinkSecretStore.commitStaged: unknown connection');
    if (conn.status === 'revoked') throw new Error('VaultLinkSecretStore.commitStaged: connection is revoked');
    if (tx.connection_id !== undefined && tx.connection_id !== conn.id) {
      throw new Error('VaultLinkSecretStore.commitStaged: transaction belongs to a different connection');
    }
    if (tx.provider !== conn.provider) {
      throw new Error('VaultLinkSecretStore.commitStaged: transaction provider differs from the connection provider');
    }
    const staged = await readStored(this.vault, tx.provider, stagedUserId);
    if (!staged) return false;
    const existing = staged.refreshToken === undefined
      ? await readStored(this.vault, conn.provider, userId)
      : null;
    await vaultStore.call(this.vault, {
      provider: conn.provider,
      userId,
      accessToken: staged.accessToken,
      refreshToken: staged.refreshToken ?? existing?.refreshToken,
      expiresAt: staged.expiresAt,
      scopes: tx.provider_granted_scopes ?? conn.provider_scopes,
    }, LINK_VAULT_ACCESS);
    await this.deleteStaged(tid);
    return true;
  }

  async get(connection_id: ConnectionId): Promise<LinkTokenSet | null> {
    if (!isConnectionId(connection_id)) return null;
    const conn = await this.store.getConnection(connection_id);
    if (!conn) return null;
    const stored = await readStored(this.vault, conn.provider, linkVaultUserId(connection_id));
    return stored ? toTokenSet(stored) : null;
  }

  /**
   * Write rotated tokens after a refresh. Keeps the stored refresh_token when
   * the new set has none (most providers do not rotate it), and writes the
   * connection's current provider_scopes as the entry's scopes.
   */
  async put(connection_id: ConnectionId, tokens: LinkTokenSet): Promise<void> {
    const userId = linkVaultUserId(connection_id);
    const t = validateTokens(tokens);
    const conn = await this.store.getConnection(connection_id);
    if (!conn) throw new Error('VaultLinkSecretStore.put: unknown connection');
    if (conn.status === 'revoked') throw new Error('VaultLinkSecretStore.put: connection is revoked');
    const existing = t.refreshToken === undefined
      ? await readStored(this.vault, conn.provider, userId)
      : null;
    await vaultStore.call(this.vault, {
      provider: conn.provider,
      userId,
      accessToken: t.accessToken,
      refreshToken: t.refreshToken ?? existing?.refreshToken,
      expiresAt: t.expiresAt,
      scopes: conn.provider_scopes,
    }, LINK_VAULT_ACCESS);
  }

  /** Deletes the connection's tokens under every Link provider slug (idempotent, needs no lookup). */
  async delete(connection_id: ConnectionId): Promise<void> {
    const userId = linkVaultUserId(connection_id);
    for (const p of LINK_PROVIDERS) {
      await vaultDelete.call(this.vault, { provider: p, userId }, LINK_VAULT_ACCESS);
    }
  }
}

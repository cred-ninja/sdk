import { isConnectionId, isTransactionId } from '@credninja/protocol';

/**
 * Reserved vault userId namespace for Cred Link.
 *
 * A Link connection's tokens live in the vault under
 * (provider = connection.provider, userId = `link:<connection_id>`), so the
 * server's existing delegation path (vault.get with an adapter, which
 * auto-refreshes) can serve them unchanged. Tokens staged during a hosted
 * flow live under `link-staged:<tid>` until activation.
 *
 * Legacy entry points that take a caller-supplied userId must reject any id
 * for which isReservedLinkVaultUserId returns true.
 */
export const LINK_VAULT_USER_ID_PREFIX = 'link:';

/** Prefix of the vault userId holding a transaction's staged tokens. */
export const LINK_STAGED_VAULT_USER_ID_PREFIX = 'link-staged:';

/** Vault userId for a Link connection's tokens. Throws on a malformed connection id. */
export function linkVaultUserId(connection_id: string): string {
  if (!isConnectionId(connection_id)) {
    throw new TypeError('linkVaultUserId: expected a conn_ connection id');
  }
  return `${LINK_VAULT_USER_ID_PREFIX}${connection_id}`;
}

/** Vault userId for a transaction's staged tokens. Throws on a malformed transaction id. */
export function linkStagedVaultUserId(tid: string): string {
  if (!isTransactionId(tid)) {
    throw new TypeError('linkStagedVaultUserId: expected an ltx_ transaction id');
  }
  return `${LINK_STAGED_VAULT_USER_ID_PREFIX}${tid}`;
}

/**
 * True when `userId` is in the reserved Link namespace: it starts with
 * exactly `link:` or `link-staged:` (case-sensitive, no trimming). A bare
 * prefix with nothing after it is also reserved. Non-strings return false.
 */
export function isReservedLinkVaultUserId(userId: string): boolean {
  if (typeof userId !== 'string') return false;
  return userId.startsWith(LINK_VAULT_USER_ID_PREFIX)
    || userId.startsWith(LINK_STAGED_VAULT_USER_ID_PREFIX);
}

/**
 * Thrown by CredVault when a public method is called with a reserved Link
 * user id and without the internal Link capability. Local SDK and MCP modes
 * call CredVault directly with caller-supplied ids, so the vault refuses
 * these itself rather than relying on the server's route guards.
 */
export class ReservedVaultUserIdError extends Error {
  readonly code = 'reserved_user_id' as const;

  constructor(method: string) {
    super(`CredVault.${method}: this userId is reserved for Cred Link`);
    this.name = 'ReservedVaultUserIdError';
  }
}

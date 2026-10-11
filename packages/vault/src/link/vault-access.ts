/**
 * Internal capability that lets code inside @credninja/vault reach vault
 * entries under the reserved Link user ids (`link:`, `link-staged:`).
 *
 * It is a Symbol, so it can never come from request data (JSON, query
 * strings, form fields). This module is deliberately not re-exported from
 * link/index.ts or the package entry point, and the package's "exports"
 * map exposes only ".", so code outside this package cannot import it.
 * VaultLinkSecretStore passes it as the last argument of CredVault's
 * userId-taking methods, for example `vault.get(input, LINK_VAULT_ACCESS)`.
 */
export const LINK_VAULT_ACCESS: unique symbol = Symbol('credninja.vault.linkAccess');

/** The type of the capability argument CredVault accepts. */
export type LinkVaultAccess = typeof LINK_VAULT_ACCESS;

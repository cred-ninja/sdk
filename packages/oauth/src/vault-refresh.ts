/**
 * @credninja/oauth — adapter for @credninja/vault's refresh contract.
 *
 * The vault refreshes an expired row through a structural adapter:
 * `refreshAccessToken(refreshToken, clientId, clientSecret)` resolving to
 * `{ accessToken, refreshToken?, expiresIn?, scopes? }`. A native
 * ServiceAdapter takes one params object and resolves to the provider's
 * snake_case shape, so handing one to the vault directly sends no refresh
 * token at all. This wraps a native adapter into the vault's shape.
 *
 * No dependency on @credninja/vault: the shape is structural.
 */
import type { ServiceAdapter } from './types.js';
import { getRawTokenResponse } from './errors.js';

export interface VaultRefreshResult {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  /**
   * The scopes the provider stated for the refreshed token. Undefined when the
   * provider stated none, which under RFC 6749 section 5.1 means they are the
   * scopes already granted: the vault keeps the stored list.
   */
  scopes?: string[];
}

export interface VaultRefreshAdapter {
  refreshAccessToken(refreshToken: string, clientId: string, clientSecret: string): Promise<VaultRefreshResult>;
}

/** Wrap a native ServiceAdapter into the refresh contract @credninja/vault calls. */
export function toVaultRefreshAdapter(adapter: Pick<ServiceAdapter, 'refreshAccessToken'>): VaultRefreshAdapter {
  return {
    async refreshAccessToken(refreshToken, clientId, clientSecret) {
      const result = await adapter.refreshAccessToken({ refreshToken, clientId, clientSecret });
      if (typeof result.access_token !== 'string' || result.access_token === '') {
        // Storing an empty token over a working refresh token would lose the
        // connection for nothing; refuse the refresh instead.
        throw new Error('Token refresh returned no access token');
      }
      const scopes = statedScopes(result);
      return {
        accessToken: result.access_token,
        ...(result.refresh_token ? { refreshToken: result.refresh_token } : {}),
        ...(typeof result.expires_in === 'number' ? { expiresIn: result.expires_in } : {}),
        ...(scopes ? { scopes } : {}),
      };
    },
  };
}

/**
 * The scope the provider's refresh body stated, as a list. Providers separate
 * scopes with spaces (RFC 6749) or commas (GitHub, Linear). An absent or empty
 * scope is treated as not stated, so the stored list is kept.
 */
function statedScopes(result: object): string[] | undefined {
  const scope = getRawTokenResponse(result)?.scope;
  const scopes = Array.isArray(scope)
    ? scope.filter((value): value is string => typeof value === 'string')
    : typeof scope === 'string' ? scope.split(/[\s,]+/) : [];
  const named = scopes.map((value) => value.trim()).filter(Boolean);
  return named.length > 0 ? named : undefined;
}

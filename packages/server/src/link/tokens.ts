/**
 * Cred Link server: loading a connection's provider token (decision 7).
 *
 * Never uses vault.get's silent auto-refresh. Reads with secrets.get (which
 * returns expired sets), refreshes through the adapter when the token is
 * expired (or a refresh is forced) under an in-process per-connection lock
 * with a re-check inside the lock, so concurrent callers refresh once, and
 * writes the rotated set back with secrets.put.
 *
 * A provider `invalid_grant` moves the connection to needs_reauth with a
 * typed reason. Any other refresh failure is transient and changes nothing.
 *
 * The lock is per process (ConnectionLocks): Phase 1 runs one server
 * process per SQLite file.
 */

import { getRawTokenResponse } from '@credninja/oauth';
import { LINK_MACHINE_CODE_FOR_CONNECTION_STATUS } from '@credninja/protocol';
import type { Connection, ConnectionId, LinkMachineErrorCode, LinkSecretStore, LinkStore, LinkTokenSet } from '@credninja/protocol';
import { LinkProviderRuntime, classifyRefreshError, refreshedTokenSet } from './providers.js';
import { parseGrantedScopeString } from './scopes.js';
import { nowIso } from './util.js';

/** Seconds before expiry at which a token is treated as expired. */
export const LINK_TOKEN_EXPIRY_SKEW_SECONDS = 60;

/** Reason recorded on the connection when a refresh returns invalid_grant (spec 7). */
export const LINK_INVALID_GRANT_REASON: LinkMachineErrorCode = 'grant_revoked';

export type LinkTokenLoadResult =
  | { ok: true; tokens: LinkTokenSet; refreshed: boolean }
  /** The grant is gone at the provider; the connection is now needs_reauth. */
  | { ok: false; kind: 'reauth'; code: LinkMachineErrorCode }
  /** Transient provider or network failure; nothing changed. */
  | { ok: false; kind: 'unavailable' }
  /** No tokens are stored for the connection. */
  | { ok: false; kind: 'missing' };

/**
 * In-process per-connection mutual exclusion. Every path that writes or
 * deletes a connection's tokens (refresh, activation's commitStaged,
 * connection deletion, transaction cleanup) runs under the same lock, so a
 * refresh in flight can never write tokens back after a delete or clobber
 * tokens a reauth just committed. Phase 1 runs one process per SQLite file.
 */
export class ConnectionLocks {
  private readonly locks = new Map<string, Promise<unknown>>();

  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(key) ?? Promise.resolve();
    const run = previous.then(fn, fn);
    const tail = run.then(() => undefined, () => undefined);
    this.locks.set(key, tail);
    try {
      return await run;
    } finally {
      if (this.locks.get(key) === tail) this.locks.delete(key);
    }
  }
}

export interface LinkTokenLoaderOptions {
  store: LinkStore;
  secrets: LinkSecretStore;
  providers: LinkProviderRuntime;
  locks: ConnectionLocks;
  /** Called after a connection moved to needs_reauth (for audit). Must not throw. */
  onReauthRequired?: (connection: Connection, code: LinkMachineErrorCode) => void;
  /**
   * Called (under the lock) when a refresh response reported a scope set.
   * The implementation applies it to the connection and narrows the grant
   * (spec 7 provider_scope_changed). Errors are ignored.
   */
  onProviderScopes?: (connection: Connection, scopes: string[]) => Promise<void>;
}

function isExpired(tokens: LinkTokenSet, nowMs: number): boolean {
  if (!tokens.expires_at) return false;
  const expiresMs = Date.parse(tokens.expires_at);
  if (Number.isNaN(expiresMs)) return true;
  return expiresMs - LINK_TOKEN_EXPIRY_SKEW_SECONDS * 1000 <= nowMs;
}

/** The typed code for a connection that is not usable (no state change). */
function unusableCode(connection: Connection | null): LinkMachineErrorCode {
  if (!connection) return 'grant_revoked';
  return connection.status_reason ?? LINK_MACHINE_CODE_FOR_CONNECTION_STATUS[connection.status] ?? 'grant_revoked';
}

export class LinkTokenLoader {
  private readonly lastRefreshAt = new Map<string, number>();
  /** Number of refresh calls made to providers (for tests and metrics). */
  refreshCount = 0;

  constructor(private readonly options: LinkTokenLoaderOptions) {}

  /**
   * The connection's current token, refreshed when expired (or when
   * `force` is set and the provider supports refresh).
   *
   * Only the fast path (a usable stored token) runs outside the lock.
   * Every decision that changes state (refresh, write-back, scope
   * narrowing, marking needs_reauth for a missing or unrefreshable token)
   * is made inside the connection's lock, which activation also holds from
   * its database commit through its token commit. An active connection
   * without stored tokens then really is broken (for example a crash
   * between those two steps) and moves to needs_reauth.
   */
  async load(connection: Connection, options: { force?: boolean } = {}): Promise<LinkTokenLoadResult> {
    const { secrets, providers, store } = this.options;
    const calledAt = Date.now();
    const id = connection.id as ConnectionId;
    const needsRefresh = (tokens: LinkTokenSet, nowMs: number): boolean => isExpired(tokens, nowMs)
      || (options.force === true && (this.lastRefreshAt.get(id) ?? 0) < calledAt);
    const refreshable = (tokens: LinkTokenSet): boolean => providers.supportsRefresh(connection.provider)
      && typeof tokens.refresh_token === 'string' && tokens.refresh_token !== '';

    const current = await secrets.get(id);
    if (current && !needsRefresh(current, calledAt)) return { ok: true, tokens: current, refreshed: false };
    if (current && !refreshable(current) && !isExpired(current, calledAt)) {
      return { ok: true, tokens: current, refreshed: false };
    }

    return this.options.locks.run(id, async (): Promise<LinkTokenLoadResult> => {
      const conn = await store.getConnection(id);
      if (!conn || conn.status !== 'active') return { ok: false, kind: 'reauth', code: unusableCode(conn) };
      const latest = await secrets.get(id);
      if (!latest) return this.noTokens(conn);
      if (!needsRefresh(latest, Date.now())) return { ok: true, tokens: latest, refreshed: false };
      if (!refreshable(latest)) {
        if (!isExpired(latest, Date.now())) return { ok: true, tokens: latest, refreshed: false };
        return this.markReauth(conn, 'grant_expired');
      }
      const startedFrom = latest.refresh_token as string;
      const startedVersion = conn.version;

      let next: LinkTokenSet;
      let reportedScopes: string[] | null = null;
      try {
        this.refreshCount++;
        const refreshed = await providers.refresh(conn.provider, startedFrom);
        if (typeof refreshed.access_token !== 'string' || refreshed.access_token === '') {
          return { ok: false, kind: 'unavailable' };
        }
        next = refreshedTokenSet(latest, refreshed);
        const raw = getRawTokenResponse(refreshed);
        reportedScopes = raw ? parseGrantedScopeString(raw.scope) : null;
      } catch (error) {
        // A timeout lands here too: transient, nothing written.
        if (classifyRefreshError(error) === 'reauth') return this.markReauth(conn, LINK_INVALID_GRANT_REASON);
        return { ok: false, kind: 'unavailable' };
      }
      // Write back (and apply reported scopes) only onto the exact state the
      // refresh started from: same refresh token, same connection version,
      // still active. Otherwise the result is discarded.
      const after = await store.getConnection(id);
      if (!after || after.status !== 'active') return { ok: false, kind: 'reauth', code: unusableCode(after) };
      const stored = await secrets.get(id);
      if (!stored || stored.refresh_token !== startedFrom || after.version !== startedVersion) {
        return { ok: false, kind: 'unavailable' };
      }
      try {
        await secrets.put(id, next);
      } catch {
        return { ok: false, kind: 'unavailable' };
      }
      this.lastRefreshAt.set(id, Date.now());
      if (reportedScopes && reportedScopes.length > 0 && this.options.onProviderScopes) {
        try {
          await this.options.onProviderScopes(after, reportedScopes);
        } catch {
          // Narrowing is best effort; the access check still runs on every call.
        }
      }
      return { ok: true, tokens: next, refreshed: true };
    });
  }

  private async noTokens(connection: Connection): Promise<LinkTokenLoadResult> {
    if (connection.status === 'active') return this.markReauth(connection, 'reauth_required');
    return { ok: false, kind: 'missing' };
  }

  private async markReauth(connection: Connection, code: LinkMachineErrorCode): Promise<LinkTokenLoadResult> {
    try {
      const updated = await this.options.store.setConnectionStatus({
        connection_id: connection.id,
        status: 'needs_reauth',
        reason: code,
        now: nowIso(),
      });
      if (updated) {
        try {
          this.options.onReauthRequired?.(updated.connection, code);
        } catch {
          // Reporting must not change the result.
        }
      }
    } catch {
      return { ok: false, kind: 'unavailable' };
    }
    return { ok: false, kind: 'reauth', code };
  }
}

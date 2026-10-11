/**
 * Cred Link server: shared context, audit, transaction minting and cleanup.
 */

import type { CredVault } from '@credninja/vault';
import {
  LINK_AUTHORIZE_PARAMS,
  LINK_DEFAULT_ORG_ID,
  LINK_ID_PREFIXES,
  LINK_PATHS,
  LINK_REQUEST_URI_PREFIX,
  LINK_TRANSACTION_TTL_SECONDS,
} from '@credninja/protocol';
import type {
  ClientGrant,
  Connection,
  LinkClient,
  LinkGrantAuditMetadata,
  LinkHooks,
  LinkPermissionPort,
  LinkProviderSlug,
  LinkScopeMap,
  LinkSecretStore,
  LinkTokenSet,
  LinkTransaction,
  NewLinkTransaction,
  TransactionId,
} from '@credninja/protocol';
import type { SqliteLinkStore } from '@credninja/vault';
import type { LinkClientAuthenticator } from './client-auth.js';
import type { LinkProviderRuntime } from './providers.js';
import type { ConnectionLocks, ConnectionQuarantine, LinkTokenLoader } from './tokens.js';
import { alwaysRequiredScopes } from './scopes.js';
import { newId, newSecret, nowIso, sha256Hex } from './util.js';

/** Everything the Link routes share. */
export interface LinkContext {
  store: SqliteLinkStore;
  secrets: LinkSecretStore;
  hooks: LinkHooks;
  permissions: LinkPermissionPort;
  providers: LinkProviderRuntime;
  tokens: LinkTokenLoader;
  /** Per-connection lock shared by every path that writes or deletes a connection's tokens. */
  locks: ConnectionLocks;
  /** Connections whose failed activation could not record needs_reauth (see ConnectionQuarantine). */
  quarantine: ConnectionQuarantine;
  clientAuth: LinkClientAuthenticator;
  vault: CredVault;
  /** Public Link base URL, no trailing slash. */
  baseUrl: string;
  /** Origin of baseUrl. */
  selfOrigin: string;
}

// ── Audit ────────────────────────────────────────────────────────────────────

/**
 * Write a grant audit event (spec 5 "Silent grant changes"). Throws when
 * the audit backend cannot write: callers treat that as a failure of the
 * operation (fail closed).
 */
export function writeGrantAudit(
  ctx: LinkContext,
  input: {
    action: 'create' | 'update' | 'revoke';
    grant: Pick<ClientGrant, 'id' | 'connection_id' | 'client_id' | 'subject' | 'scopes' | 'status' | 'version'>;
    provider: LinkProviderSlug;
    before_scopes: string[] | null;
    before_status: ClientGrant['status'] | null;
    reason: LinkGrantAuditMetadata['reason'];
    tid?: TransactionId;
    actor?: string;
  },
): void {
  const metadata: LinkGrantAuditMetadata = {
    grant_id: input.grant.id,
    connection_id: input.grant.connection_id,
    client_id: input.grant.client_id,
    subject: input.grant.subject,
    provider: input.provider,
    before_scopes: input.before_scopes,
    after_scopes: [...input.grant.scopes],
    before_status: input.before_status,
    after_status: input.grant.status,
    version: input.grant.version,
    reason: input.reason,
    ...(input.tid ? { tid: input.tid } : {}),
  };
  ctx.vault.writeAuditEvent({
    id: newId(LINK_ID_PREFIXES.auditEvent),
    timestamp: new Date(),
    actor: { type: 'system', id: input.actor ?? `link:${input.grant.client_id}` },
    action: input.action,
    resource: { type: 'grant', id: input.grant.id },
    outcome: 'success',
    scopesGranted: [...input.grant.scopes],
    correlationId: input.tid ?? newId(LINK_ID_PREFIXES.request),
    metadata: metadata as unknown as Record<string, unknown>,
  });
}

/** Best-effort variant for cleanup paths where the state change already happened. */
export function writeGrantAuditBestEffort(ctx: LinkContext, input: Parameters<typeof writeGrantAudit>[1]): void {
  try {
    writeGrantAudit(ctx, input);
  } catch (error) {
    console.error('[link] grant audit write failed', { grant_id: input.grant.id, kind: error instanceof Error ? error.name : 'unknown' });
  }
}

// ── Transactions ─────────────────────────────────────────────────────────────

export interface MintTransactionInput {
  client: LinkClient;
  intent: NewLinkTransaction['intent'];
  subject: string;
  subject_type: NewLinkTransaction['subject_type'];
  providers: LinkProviderSlug[];
  requested_scopes: LinkScopeMap;
  required_scopes: LinkScopeMap;
  redirect_uri: string;
  origin: string;
  client_state?: string;
  agent_id?: string;
  connection_id?: Connection['id'];
  grant_id?: ClientGrant['id'];
}

/**
 * Create a transaction and return its request_uri. Always_required catalog
 * scopes are added to both requested and required scopes of every provider
 * (decision 10).
 */
export async function mintTransaction(ctx: LinkContext, input: MintTransactionInput, nowMs = Date.now()): Promise<{ request_uri: string; transaction: LinkTransaction }> {
  const requested: LinkScopeMap = {};
  const required: LinkScopeMap = {};
  for (const provider of input.providers) {
    const always = alwaysRequiredScopes(provider);
    const req = [...(input.required_scopes[provider] ?? []), ...always];
    requested[provider] = Array.from(new Set([...(input.requested_scopes[provider] ?? []), ...req])).sort();
    required[provider] = Array.from(new Set(req)).sort();
  }
  const requestUri = `${LINK_REQUEST_URI_PREFIX}${newSecret()}`;
  const tx: NewLinkTransaction = {
    tid: newId(LINK_ID_PREFIXES.transaction) as TransactionId,
    org_id: LINK_DEFAULT_ORG_ID,
    client_id: input.client.client_id,
    intent: input.intent,
    subject: input.subject,
    subject_type: input.subject_type,
    providers: input.providers,
    requested_scopes: requested,
    required_scopes: required,
    authorization_details: [],
    redirect_uri: input.redirect_uri,
    origin: input.origin,
    request_uri_hash: sha256Hex(requestUri),
    created_at: nowIso(nowMs),
    expires_at: nowIso(nowMs + LINK_TRANSACTION_TTL_SECONDS * 1000),
    ...(input.client_state !== undefined ? { client_state: input.client_state } : {}),
    ...(input.agent_id !== undefined ? { agent_id: input.agent_id } : {}),
    ...(input.connection_id !== undefined ? { connection_id: input.connection_id } : {}),
    ...(input.grant_id !== undefined ? { grant_id: input.grant_id } : {}),
  };
  const transaction = await ctx.store.createTransaction(tx);
  return { request_uri: requestUri, transaction };
}

/** GET /link/v1/authorize URL for a request_uri. */
export function authorizeUrl(ctx: LinkContext, input: { request_uri: string; client_id: string; mode: 'popup' | 'redirect' | 'embedded' }): string {
  const q = new URLSearchParams();
  q.set(LINK_AUTHORIZE_PARAMS.request_uri, input.request_uri);
  q.set(LINK_AUTHORIZE_PARAMS.client_id, input.client_id);
  q.set(LINK_AUTHORIZE_PARAMS.mode, input.mode);
  return `${ctx.baseUrl}${LINK_PATHS.authorize}?${q.toString()}`;
}

/**
 * Mint a reauth URL for an agent (spec 6 "Requests Cred mints itself for an
 * agent"): no session to draw on, so the transaction is fixed to the
 * connection's own subject and rests on the same-account rule and on
 * activation by the client's backend. Uses the client's first registered
 * redirect_uri and origin, and redirect mode (a human opens it directly).
 */
export async function mintAgentReauthUrl(ctx: LinkContext, connection: Connection): Promise<string | null> {
  const client = await ctx.store.getClient(connection.client_id);
  if (!client || client.status !== 'active') return null;
  const redirectUri = client.redirect_uris[0];
  const origin = client.origins[0];
  if (!redirectUri || !origin) return null;
  const grant = await ctx.store.getGrantForConnection(connection.id);
  if (!grant || grant.status === 'revoked') return null;
  const { request_uri } = await mintTransaction(ctx, {
    client,
    intent: 'reauth',
    subject: connection.subject,
    subject_type: connection.subject_type,
    providers: [connection.provider],
    requested_scopes: { [connection.provider]: grant.scopes },
    required_scopes: {},
    redirect_uri: redirectUri,
    origin,
    connection_id: connection.id,
    grant_id: grant.id,
  });
  return authorizeUrl(ctx, { request_uri, client_id: client.client_id, mode: 'redirect' });
}

// ── Cleanup ──────────────────────────────────────────────────────────────────

/**
 * The provider revocation rule (every place Link revokes at a provider).
 *
 * Every client on this server shares the server's provider OAuth app, and
 * at Google, Salesforce and Slack one revocation ends the whole
 * authorization for that account. So tokens are revoked at the provider
 * only when nothing else on this server still depends on that account: no
 * other non-revoked connection for (provider, provider_account_id), on any
 * client or subject (pending rows of other flows included), and no other
 * open transaction with staged tokens for it. Otherwise only the local
 * tokens are deleted. An unknown account is never revoked. Legacy /connect
 * vault rows carry no account id and cannot be seen here.
 */
export async function mayRevokeAccountAtProvider(
  ctx: LinkContext,
  input: {
    provider: LinkProviderSlug;
    provider_account_id?: string | null;
    /** The connection being removed, and pending rows the ending transaction created. */
    exclude_connection_ids?: string[];
    /** The transaction whose tokens are being discarded. */
    exclude_tid?: string;
  },
): Promise<boolean> {
  if (!input.provider_account_id) return false;
  const excluded = new Set(input.exclude_connection_ids ?? []);
  try {
    const account = { provider: input.provider, provider_account_id: input.provider_account_id };
    const connections = await ctx.store.listAccountConnections(account);
    if (connections.some((c) => c.status !== 'revoked' && !excluded.has(c.id))) return false;
    const open = await ctx.store.listOpenAccountTransactions(account);
    return !open.some((t) => t.tid !== input.exclude_tid);
  } catch {
    return false;
  }
}

/** Revoke at the provider when the rule allows it. Returns whether it revoked. */
export async function revokeAtProviderIfSafe(
  ctx: LinkContext,
  tokens: LinkTokenSet,
  input: Parameters<typeof mayRevokeAccountAtProvider>[1],
): Promise<boolean> {
  if (!(await mayRevokeAccountAtProvider(ctx, input))) return false;
  return ctx.providers.revoke(input.provider, tokens);
}

/**
 * After endTransaction, the sweep, a failed claim or a refused activation:
 * revoke the staged tokens at the provider (when the rule allows it), delete
 * them, delete the secrets of the pending connection the transaction
 * created (under that connection's lock), and audit the revoked pending
 * grant. Never throws.
 */
export async function cleanupEndedTransaction(ctx: LinkContext, tx: LinkTransaction): Promise<void> {
  try {
    const ownPending = tx.creates_connection === true && tx.connection_id && !tx.activated_at ? tx.connection_id : null;
    if (tx.provider) {
      const staged = await ctx.secrets.getStaged(tx.tid).catch(() => null);
      if (staged) {
        await revokeAtProviderIfSafe(ctx, staged, {
          provider: tx.provider,
          provider_account_id: tx.provider_account_id,
          exclude_connection_ids: ownPending ? [ownPending] : [],
          exclude_tid: tx.tid,
        });
      }
    }
    await ctx.secrets.deleteStaged(tx.tid);
    if (ownPending) {
      await ctx.locks.run(ownPending, () => ctx.secrets.delete(ownPending as Connection['id']));
      if (tx.grant_id && tx.provider) {
        const grant = await ctx.store.getGrant(tx.grant_id);
        if (grant && (grant.status === 'revoked' || grant.status === 'expired')) {
          writeGrantAuditBestEffort(ctx, {
            action: 'revoke',
            grant,
            provider: tx.provider,
            before_scopes: grant.scopes,
            before_status: 'pending',
            reason: tx.outcome === 'expired' ? 'expire' : 'revoke',
            tid: tx.tid,
          });
        }
      }
    }
  } catch (error) {
    console.error('[link] transaction cleanup failed', { tid: tx.tid, kind: error instanceof Error ? error.name : 'unknown' });
  }
}

/**
 * One sweep: end expired transactions and clean each up, in batches of
 * `limit`, at most `maxBatches` batches. Returns how many ended.
 */
export async function sweepExpired(ctx: LinkContext, nowMs = Date.now(), limit = 100, maxBatches = 10): Promise<number> {
  let total = 0;
  for (let batch = 0; batch < maxBatches; batch++) {
    const ended = await ctx.store.sweepExpiredTransactions({ now: nowIso(nowMs), limit });
    for (const tx of ended) {
      await cleanupEndedTransaction(ctx, tx);
    }
    total += ended.length;
    if (ended.length < limit) break;
  }
  ctx.clientAuth.prune(nowMs);
  return total;
}

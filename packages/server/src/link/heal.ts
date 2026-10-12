/**
 * Cred Link server: the startup heal for unfinished activations (spec 10).
 *
 * Activation commits the database (store.commitActivation) before it moves
 * the staged tokens (LinkSecretStore.commitStaged), then marks the move
 * settled (store.settleActivation). A process that dies between those steps
 * leaves an activated transaction without tokens_settled_at. For a new
 * connection that means an active connection without tokens; for update
 * and reauth it means a live connection whose database row describes the
 * new consent while it still holds the old tokens. A lazy check on first
 * use cannot see the second case, so every such transaction is resolved
 * once at service start.
 *
 * Two phases. Phase 1 runs before Link serves any request (the gate) and
 * makes only the state changes, each under the connection's token lock.
 * Phase 2 runs after the gate opens, in the background, one transaction at
 * a time: provider revocation (bounded by the provider call timeout),
 * staged-token deletion, then settle. A reverted or stale transaction stays
 * unsettled until its phase 2 is done, so a process that dies first finds
 * it again on the next start (see the stale rule for what that start then
 * does). A transaction whose move finished is settled in phase 1; deleting
 * its leftover staged copy in phase 2 is best effort, and a copy left
 * behind is an orphan that never changes a connection again (nothing reads
 * the staged copy of a settled, terminal transaction).
 *
 * Stale rule. commitActivation writes the connection and the transaction
 * in one store write with the same timestamp, and every later write to a
 * connection row sets its updated_at (and version). So a connection whose
 * status is still 'active' and whose updated_at still equals the
 * transaction's activated_at is exactly as this activation left it.
 * Anything else means something happened afterwards (the in-process
 * needs_reauth after a failed move, a later reauth or update, a provider
 * scope change, DELETE, or this heal's own phase 1 on an earlier start):
 * the transaction is stale and must not touch the connection. Its staged
 * copy is deleted locally, never revoked at the provider (the same account
 * may now hold newer, live tokens), and it is settled.
 *
 * In every branch where the connection exists, the permission intersect
 * with its current grant (whatever its status) runs first, under the lock,
 * because the grant change was committed whatever happened to the tokens.
 * It stands in for the activation's own call, so its previous_scopes are
 * the transaction's grant_scopes_at_confirm (the grant's scopes just before
 * the commit, as commitActivation verified) when the transaction has them,
 * else the grant's own scopes (a transaction that created its connection,
 * or a version 1 row). It never widens. If it fails, nothing else happens
 * and the transaction stays unsettled. Known cost, failing closed: a
 * Permission the app set for a newly added scope between a failed-hook
 * response and the restart is stripped of that scope.
 *
 * Per transaction:
 *   connection gone                 settle; delete any staged copy in
 *                                   phase 2 (best effort)
 *   no staged tokens left           the move finished: settle; an active
 *                                   connection with no stored tokens at all
 *                                   becomes needs_reauth (settled_reauth)
 *   staged equal to stored tokens   the move finished except the cleanup:
 *                                   settle now, delete the staged copy in
 *                                   phase 2 (best effort) (cleaned)
 *   stale (rule above)              phase 2: delete the staged copy, never
 *                                   revoke, settle
 *   created the connection, and     the move finished and a refresh rotated
 *   the connection holds tokens     the tokens since (no other tokens were
 *                                   ever stored there; a refresh writes only
 *                                   the secret, never the connection row):
 *                                   settle now, delete the staged copy in
 *                                   phase 2 (cleaned)
 *   a refresh token was staged and  moved then refreshed, or never moved and
 *   the stored one equals it        the provider re-issued the same refresh
 *                                   token on re-consent: indistinguishable.
 *                                   Write the staged refresh token onto the
 *                                   connection with expires_at now
 *                                   (secrets.put; the access token kept is
 *                                   the one of the two with the later
 *                                   expiry), so the next use refreshes with
 *                                   that refresh token, the same credential
 *                                   in both
 *                                   cases, and gets tokens for the current
 *                                   consent; a refresh that fails with
 *                                   invalid_grant moves the connection to
 *                                   needs_reauth as usual. Settle now,
 *                                   delete the staged copy in phase 2; the
 *                                   connection stays active (reapplied)
 *   otherwise                       the move never happened: needs_reauth
 *                                   (reason reauth_required) and an audit
 *                                   record now; then, in phase 2, provider
 *                                   revocation rule on the staged tokens,
 *                                   delete them, settle (reverted)
 *
 * After an upgrade from a version 1 Link database the store returns every
 * activation that build recorded (it cannot tell a crash from a healthy
 * one), so the first start re-checks all of them once. Phase 1 stays local
 * (store and vault reads and writes, at most a status change, the
 * permission intersect, and the settle); provider calls only ever happen in
 * phase 2, and only for an activation whose move never happened.
 * A connection's stored tokens are never deleted here, and the staged
 * tokens are never revoked at the provider while the connection holds
 * tokens (phase 2 excludes the connection from the account check only when
 * it holds none). A transaction that cannot be healed is logged and left
 * unsettled for the next start.
 *
 * Known limits (both fail closed: a working connection ends needs_reauth
 * and the user reconnects):
 *   - an update or reauth on a provider that rotates refresh tokens, a
 *     crash inside the token move, and a refresh before the next start
 *     leave stored tokens that match no rule above;
 *   - when no refresh token was staged and the access token was refreshed
 *     before the heal decided (which needs an earlier start whose phase 1
 *     failed for that transaction, or a version 1 leftover), the stored
 *     tokens match no rule above either.
 * Also: two missed intersects in a row (a store failure during a
 * narrowing, then a store failure, not a crash, during the next widening)
 * leave the stale Permission usable until the next start; and
 * setAgentPermission racing a widening activation can have its new scope
 * stripped (fails closed).
 */

import type { Connection, LinkTokenSet, LinkTransaction } from '@credninja/protocol';
import type { LinkContext } from './core.js';
import { revokeAtProviderIfSafe, writeGrantAuditBestEffort } from './core.js';
import { nowIso } from './util.js';

/** Outcome of phase 1 for one transaction (for logs and tests). */
export type LinkHealOutcome = 'settled' | 'settled_reauth' | 'cleaned' | 'reapplied' | 'reverted' | 'stale' | 'failed';

/** Outcome of phase 2 for one transaction. */
export type LinkHealFollowUpOutcome = 'revoked' | 'not_revoked' | 'skipped_stale' | 'deleted' | 'failed';

export interface LinkHealReport {
  /** Phase 1, complete when the gate opens. */
  outcomes: Array<{ tid: string; outcome: LinkHealOutcome }>;
}

export interface LinkHealFollowUpReport {
  /** Phase 2, complete when LinkService.healed resolves. */
  follow_ups: Array<{ tid: string; outcome: LinkHealFollowUpOutcome }>;
}

export interface LinkHealRun {
  /** Resolves when phase 1 is done: Link may serve requests. Never rejects. */
  ready: Promise<LinkHealReport>;
  /** Resolves when phase 2 is done too. Never rejects. */
  done: Promise<LinkHealFollowUpReport>;
}

type FollowUp = (ctx: LinkContext) => Promise<LinkHealFollowUpOutcome>;

interface PhaseOne {
  outcome: LinkHealOutcome;
  followUp?: FollowUp;
}

function sameTokens(stored: LinkTokenSet, staged: LinkTokenSet): boolean {
  // commitStaged keeps the connection's refresh token when the staged set
  // has none, so the refresh token only counts when one was staged.
  return stored.access_token === staged.access_token
    && (stored.expires_at ?? null) === (staged.expires_at ?? null)
    && (staged.refresh_token === undefined || stored.refresh_token === staged.refresh_token);
}

/** True when the connection is exactly as this activation left it (module comment). */
function untouchedSinceActivation(connection: Connection, tx: LinkTransaction): boolean {
  return connection.status === 'active'
    && typeof tx.activated_at === 'string'
    && connection.updated_at === tx.activated_at;
}

async function markReauth(ctx: LinkContext, connection: Connection, tx: LinkTransaction): Promise<Connection | null> {
  if (connection.status !== 'active') return null;
  const updated = await ctx.store.setConnectionStatus({
    connection_id: connection.id,
    status: 'needs_reauth',
    reason: 'reauth_required',
    now: nowIso(),
  });
  if (updated?.grant) {
    writeGrantAuditBestEffort(ctx, {
      action: 'update',
      grant: updated.grant,
      provider: connection.provider,
      before_scopes: updated.grant.scopes,
      before_status: 'active',
      reason: 'reauth_required',
      tid: tx.tid,
      actor: 'link:startup-heal',
    });
  }
  return updated?.connection ?? null;
}

/**
 * The permission intersect the activation runs after its database commit,
 * re-run with the connection's current grant (whatever its status). It
 * stands in for the activation's own call, so previous_scopes is that
 * call's previous scopes when the transaction carries them:
 * grant_scopes_at_confirm, which commitActivation verified equal to the
 * grant's scopes before its commit. A transaction that created its
 * connection, or a version 1 row, has none; then previous_scopes =
 * grant.scopes, the plain re-apply. Never widens. Local only: no network
 * call. onActivate is not re-run: it overwrites the requesting agent's
 * permission, which could undo a later change by the app; a missing agent
 * permission fails closed instead.
 */
async function reconcile(ctx: LinkContext, connectionId: string, tx: LinkTransaction): Promise<void> {
  const grant = await ctx.store.getGrantForConnection(connectionId);
  if (!grant) return;
  const previous = Array.isArray(tx.grant_scopes_at_confirm) ? tx.grant_scopes_at_confirm : grant.scopes;
  await ctx.hooks.onGrantUpdated({ grant, previous_scopes: previous, reason: 'activate' });
}

/** The access token with the later expiry (staged when either has none). */
function laterAccessToken(stored: LinkTokenSet, staged: LinkTokenSet): string {
  const storedMs = stored.expires_at ? Date.parse(stored.expires_at) : NaN;
  const stagedMs = staged.expires_at ? Date.parse(staged.expires_at) : NaN;
  if (Number.isNaN(storedMs) || Number.isNaN(stagedMs)) return staged.access_token;
  return storedMs > stagedMs ? stored.access_token : staged.access_token;
}

/** Phase 2 for a settled transaction: delete the leftover staged copy (best effort). */
function deleteOrphan(tx: LinkTransaction): FollowUp {
  return async (ctx) => {
    await ctx.secrets.deleteStaged(tx.tid);
    return 'deleted';
  };
}

/** Phase 2 without the provider: delete the staged copy locally, settle. */
function deleteAndSettle(tx: LinkTransaction, outcome: LinkHealFollowUpOutcome): FollowUp {
  return async (ctx) => {
    await ctx.secrets.deleteStaged(tx.tid);
    await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
    return outcome;
  };
}

/**
 * Phase 2 for a reverted activation. Under the connection's lock again: if
 * the connection changed after phase 1 left it needs_reauth (a reauth went
 * through meanwhile), the stale rule applies and nothing is revoked.
 * Otherwise the revocation rule runs on the staged tokens, excluding this
 * connection only when it holds no stored tokens.
 */
function revertFollowUp(tx: LinkTransaction, connectionId: string, staged: LinkTokenSet, leftAt: string | null): FollowUp {
  return (ctx) => ctx.locks.run(connectionId, async (): Promise<LinkHealFollowUpOutcome> => {
    const connection = await ctx.store.getConnection(connectionId);
    let outcome: LinkHealFollowUpOutcome = 'skipped_stale';
    if (connection && leftAt !== null && connection.updated_at === leftAt) {
      const stored = await ctx.secrets.get(connection.id);
      const revoked = await revokeAtProviderIfSafe(ctx, staged, {
        provider: connection.provider,
        provider_account_id: tx.provider_account_id ?? connection.provider_account_id,
        exclude_connection_ids: stored ? [] : [connection.id],
        exclude_tid: tx.tid,
      });
      outcome = revoked ? 'revoked' : 'not_revoked';
    }
    await ctx.secrets.deleteStaged(tx.tid);
    await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
    return outcome;
  });
}

async function phaseOne(ctx: LinkContext, tx: LinkTransaction): Promise<PhaseOne> {
  if (!tx.connection_id) {
    await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
    return { outcome: 'settled' };
  }
  const connectionId = tx.connection_id;
  return ctx.locks.run(connectionId, async (): Promise<PhaseOne> => {
    const connection = await ctx.store.getConnection(connectionId);
    const staged = tx.provider ? await ctx.secrets.getStaged(tx.tid) : null;
    if (!connection) {
      await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
      return staged ? { outcome: 'cleaned', followUp: deleteOrphan(tx) } : { outcome: 'cleaned' };
    }

    // The grant change was committed whatever happened to the tokens, so
    // the permission intersect runs first in every branch (it never widens,
    // so it is safe on a connection touched since). If it fails, nothing
    // else happens and the transaction stays unsettled for the next start.
    await reconcile(ctx, connection.id, tx);

    if (!staged) {
      const stored = await ctx.secrets.get(connection.id);
      const reauth = !stored ? (await markReauth(ctx, connection, tx)) !== null : false;
      await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
      return { outcome: reauth ? 'settled_reauth' : 'settled' };
    }

    const stored = await ctx.secrets.get(connection.id);
    if (stored && sameTokens(stored, staged)) {
      await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
      return { outcome: 'cleaned', followUp: deleteOrphan(tx) };
    }

    if (!untouchedSinceActivation(connection, tx)) {
      // Stale: something happened to the connection after this activation.
      return { outcome: 'stale', followUp: deleteAndSettle(tx, 'skipped_stale') };
    }

    if (stored && tx.creates_connection === true) {
      // The transaction created the connection, so no other tokens were ever
      // stored there: the move finished and a refresh rotated them since.
      await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
      return { outcome: 'cleaned', followUp: deleteOrphan(tx) };
    }

    if (stored && staged.refresh_token !== undefined && stored.refresh_token === staged.refresh_token) {
      // Moved then refreshed, or never moved and the provider answered the
      // re-consent with the same refresh token string: the two cannot be
      // told apart. Write the staged refresh token with expires_at now, so
      // the next use refreshes with it (the same credential in both cases)
      // and gets tokens for the current consent. The access token kept is
      // the one with the later expiry, so a revocation before that refresh
      // targets the newest token.
      await ctx.secrets.put(connection.id, { ...staged, access_token: laterAccessToken(stored, staged), expires_at: nowIso() });
      await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
      return { outcome: 'reapplied', followUp: deleteOrphan(tx) };
    }

    // The move never happened: never half-active.
    const left = await markReauth(ctx, connection, tx);
    return { outcome: 'reverted', followUp: revertFollowUp(tx, connection.id, staged, left?.updated_at ?? null) };
  });
}

function kindOf(error: unknown): string {
  return error instanceof Error ? error.name : 'unknown';
}

/**
 * Resolve every unsettled activation. Phase 1 resolves `ready`; phase 2
 * starts once it has and resolves `done`. Neither rejects; one failure does
 * not stop the rest.
 */
export function healUnsettledActivations(ctx: LinkContext): LinkHealRun {
  const followUps: Array<{ tx: LinkTransaction; run: FollowUp }> = [];
  const ready = (async (): Promise<LinkHealReport> => {
    const report: LinkHealReport = { outcomes: [] };
    let pending: LinkTransaction[];
    try {
      pending = await ctx.store.listUnsettledActivations();
    } catch (error) {
      console.error('[link] startup heal could not list unsettled activations', { kind: kindOf(error) });
      return report;
    }
    for (const tx of pending) {
      let outcome: LinkHealOutcome;
      try {
        const result = await phaseOne(ctx, tx);
        outcome = result.outcome;
        if (result.followUp) followUps.push({ tx, run: result.followUp });
      } catch (error) {
        console.error('[link] startup heal failed for a transaction; left unsettled', { tid: tx.tid, kind: kindOf(error) });
        outcome = 'failed';
      }
      report.outcomes.push({ tid: tx.tid, outcome });
    }
    if (report.outcomes.length > 0) {
      console.warn('[link] startup heal resolved unfinished activations', {
        count: report.outcomes.length,
        failed: report.outcomes.filter((o) => o.outcome === 'failed').length,
        follow_ups: followUps.length,
      });
    }
    return report;
  })();

  const done = ready.then(async (): Promise<LinkHealFollowUpReport> => {
    const report: LinkHealFollowUpReport = { follow_ups: [] };
    for (const { tx, run } of followUps) {
      let outcome: LinkHealFollowUpOutcome;
      try {
        outcome = await run(ctx);
      } catch (error) {
        // Left unsettled: the next start finds it again.
        console.error('[link] startup heal follow-up failed; left unsettled', { tid: tx.tid, kind: kindOf(error) });
        outcome = 'failed';
      }
      report.follow_ups.push({ tid: tx.tid, outcome });
    }
    return report;
  }, (): LinkHealFollowUpReport => ({ follow_ups: [] }));

  return { ready, done };
}

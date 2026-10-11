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
 * Per transaction (not stale):
 *   no staged tokens left           the move finished: settle; an active
 *                                   connection with no stored tokens at all
 *                                   becomes needs_reauth
 *   staged equal to stored tokens   the move finished except the cleanup:
 *                                   settle now, delete the staged copy in
 *                                   phase 2 (best effort)
 *   stored tokens that can only     the move finished and a refresh rotated
 *   have come from this             the tokens since (a refresh writes only
 *   transaction                     the secret, never the connection row):
 *                                   settle now, delete the staged copy in
 *                                   phase 2. That is: the transaction created
 *                                   the connection and the connection holds
 *                                   tokens at all, or a refresh token was
 *                                   staged and the stored refresh token
 *                                   equals it
 *   otherwise                       the move never happened: needs_reauth
 *                                   (reason reauth_required) and an audit
 *                                   record now; then, in phase 2, provider
 *                                   revocation rule on the staged tokens,
 *                                   delete them, settle
 * A connection left active that is still untouched since this activation
 * also gets the permission intersect with its current grant re-run, since
 * activation's hooks may not have run. A connection written since then had
 * its hooks run by whatever wrote it (or by this activation before it), so
 * it is left alone.
 *
 * After an upgrade from a version 1 Link database the store returns every
 * activation that build recorded (it cannot tell a crash from a healthy
 * one), so the first start re-checks all of them once. Phase 1 stays local
 * (store and vault reads, at most a status change, a permission intersect
 * for an untouched connection, and the settle); provider calls only ever
 * happen in phase 2, and only for an activation whose move never happened.
 * A connection's stored tokens are never deleted here, and the staged
 * tokens are never revoked at the provider while the connection holds
 * tokens (phase 2 excludes the connection from the account check only when
 * it holds none). A transaction that cannot be healed is logged and left
 * unsettled for the next start.
 *
 * Known limit (fails closed): an update or reauth on a provider that
 * rotates refresh tokens, a crash inside the token move, and a refresh
 * before the next start leave stored tokens that match neither rule above;
 * the connection then ends needs_reauth although its tokens work, and the
 * user reconnects.
 */

import type { Connection, LinkTokenSet, LinkTransaction } from '@credninja/protocol';
import type { LinkContext } from './core.js';
import { revokeAtProviderIfSafe, writeGrantAuditBestEffort } from './core.js';
import { nowIso } from './util.js';

/** Outcome of phase 1 for one transaction (for logs and tests). */
export type LinkHealOutcome = 'settled' | 'settled_reauth' | 'cleaned' | 'reverted' | 'stale' | 'failed';

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

/**
 * Stored tokens that differ from the staged ones but can only have come
 * from this transaction's move (then rotated by a refresh): it created the
 * connection, so no other tokens were ever stored there, or a refresh token
 * was staged and the stored one is still it.
 */
function movedHere(tx: LinkTransaction, stored: LinkTokenSet, staged: LinkTokenSet): boolean {
  if (tx.creates_connection === true) return true;
  return staged.refresh_token !== undefined && stored.refresh_token === staged.refresh_token;
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
 * A connection the heal leaves active may have missed activation's
 * post-commit hooks. Re-run only the permission intersect with the current
 * grant (idempotent, never widens). onActivate is not re-run: it overwrites
 * the requesting agent's permission, which could undo a later change by
 * the app; a missing agent permission fails closed instead.
 */
async function reconcileActive(ctx: LinkContext, connectionId: string): Promise<void> {
  const connection = await ctx.store.getConnection(connectionId);
  if (!connection || connection.status !== 'active') return;
  const grant = await ctx.store.getGrantForConnection(connectionId);
  if (!grant || grant.status !== 'active') return;
  await ctx.hooks.onGrantUpdated({ grant, previous_scopes: grant.scopes, reason: 'activate' });
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

    if (!staged) {
      const stored = await ctx.secrets.get(connection.id);
      const reauth = !stored ? (await markReauth(ctx, connection, tx)) !== null : false;
      if (!reauth && untouchedSinceActivation(connection, tx)) await reconcileActive(ctx, connection.id);
      await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
      return { outcome: reauth ? 'settled_reauth' : 'settled' };
    }

    const stored = await ctx.secrets.get(connection.id);
    if (stored && sameTokens(stored, staged)) {
      if (untouchedSinceActivation(connection, tx)) await reconcileActive(ctx, connection.id);
      await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
      return { outcome: 'cleaned', followUp: deleteOrphan(tx) };
    }

    if (!untouchedSinceActivation(connection, tx)) {
      // Stale: something happened to the connection after this activation.
      return { outcome: 'stale', followUp: deleteAndSettle(tx, 'skipped_stale') };
    }

    if (stored && movedHere(tx, stored, staged)) {
      // The move finished and a refresh rotated the tokens since.
      await reconcileActive(ctx, connection.id);
      await ctx.store.settleActivation({ tid: tx.tid, now: nowIso() });
      return { outcome: 'cleaned', followUp: deleteOrphan(tx) };
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

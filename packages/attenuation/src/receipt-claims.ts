/**
 * Who a Cred delegation receipt names, in both claim layouts.
 *
 * draft-sweeney-wimse-credential-delegation-02 "Delegation Token Format":
 * `sub` is the Subject (the user on whose behalf delegation occurs),
 * `client_id` and `act.sub` both name the current Acting Agent and MUST
 * agree, and prior actors MAY be carried as nested `act` (RFC 8693 Section
 * 4.1) for attribution only. Receipts minted before that layout put the
 * agent DID in `sub` (and in `client_id`) and the user in a `userId` claim.
 * Readers accept both; a receipt carrying `act` is read only as the -02
 * layout, so the two can never be confused.
 */

export interface ActorClaim {
  sub: string;
  act?: ActorClaim;
}

export interface ReceiptActorClaims {
  sub: string;
  client_id: string;
  act: ActorClaim;
}

/**
 * The -02 actor claims for a receipt issued to `agentDid` on behalf of
 * `principal`. `priorActors` are the ancestor agent DIDs, root first; the
 * immediate delegator becomes `act.act`, its delegator `act.act.act`, and so on.
 */
export function receiptActorClaims(input: { principal: string; agentDid: string; priorActors?: readonly string[] }): ReceiptActorClaims {
  let act: ActorClaim | undefined;
  for (const did of input.priorActors ?? []) act = act ? { sub: did, act } : { sub: did };
  return { sub: input.principal, client_id: input.agentDid, act: act ? { sub: input.agentDid, act } : { sub: input.agentDid } };
}

export type ReceiptActorResult =
  | { ok: true; agentDid: string; principal: string; layout: 'draft-02' | 'legacy' }
  | { ok: false; message: string };

function nonEmpty(v: unknown): v is string {
  return typeof v === 'string' && v.trim() !== '';
}

/**
 * Read the current agent and the principal from a receipt payload.
 *
 * - -02 layout (has `act`): `act.sub` and `client_id` must be the same
 *   non-empty string; `sub` is the principal; a `userId` claim, if
 *   present, must equal `sub`.
 * - Legacy layout (no `act`): `sub` is the agent; `client_id`, if present,
 *   must equal it; the principal is `userId`, defaulting to `default` as
 *   receipts without the claim always have.
 */
export function readReceiptActor(payload: Record<string, unknown>): ReceiptActorResult {
  if (Object.prototype.hasOwnProperty.call(payload, 'act')) {
    const act = payload.act;
    if (typeof act !== 'object' || act === null || Array.isArray(act) || !nonEmpty((act as Record<string, unknown>).sub)) {
      return { ok: false, message: 'act must be an object naming the current actor in act.sub' };
    }
    const agentDid = (act as Record<string, unknown>).sub as string;
    if (payload.client_id !== agentDid) return { ok: false, message: 'client_id and act.sub must name the same agent' };
    if (!nonEmpty(payload.sub)) return { ok: false, message: 'sub must name the principal' };
    if (payload.userId !== undefined && payload.userId !== payload.sub) {
      return { ok: false, message: 'userId must equal sub' };
    }
    return { ok: true, agentDid, principal: payload.sub, layout: 'draft-02' };
  }
  if (!nonEmpty(payload.sub)) return { ok: false, message: 'sub must name the agent' };
  if (payload.client_id !== undefined && payload.client_id !== payload.sub) {
    return { ok: false, message: 'client_id must equal sub on a receipt without act' };
  }
  const principal = payload.userId ?? 'default';
  if (!nonEmpty(principal)) return { ok: false, message: 'userId must be a non-empty string' };
  return { ok: true, agentDid: payload.sub, principal, layout: 'legacy' };
}

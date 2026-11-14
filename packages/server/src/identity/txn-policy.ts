/**
 * Txn-Token policy on the final hop (draft-ietf-oauth-transaction-tokens-11):
 * which routes a required Txn-Token gates, which agents must carry one, and
 * whether a request's Txn-Token is acceptable. Pure decisions: the server
 * turns a refusal into its audit event and response, and records an accepted
 * token for the request.
 */
import type { ExternalIdentityMapping, VerifiedExternalIdentity } from './types.js';
import { TxnTokenRefusal, verifyTxnToken, type TxnTokenTrust, type VerifiedTxnToken } from './txn-token.js';
import { validateWorkloadIdentifier } from './wimse.js';

/** Routes that issue or exercise credentials: the ones a required Txn-Token gates. */
export function isCredentialRoute(path: string): boolean {
  const p = path.split('?')[0].replace(/\/+$/, '').toLowerCase();
  return p === '/api/v1/delegate' || p === '/api/v1/subdelegate' || p === '/api/v1/token' || p === '/bc-authorize'
    || p === '/api/v1/use' || p.startsWith('/api/token/');
}

/** The trust domain configuration whose Txn-Tokens `agentDid` must present, if any. */
export function txnTrustRequiredFor(
  trustByDomain: Readonly<Record<string, TxnTokenTrust>> | undefined,
  mappings: readonly ExternalIdentityMapping[],
  agentDid: string,
): TxnTokenTrust | undefined {
  if (!trustByDomain) return undefined;
  for (const m of mappings) {
    if (m.kind !== 'wimse' || m.agentDid !== agentDid) continue;
    try {
      const trust = trustByDomain[validateWorkloadIdentifier(m.subject).trustDomain];
      if (trust && trust.required !== false) return trust;
    } catch {
      // A mapping whose subject is not a Workload Identifier maps nothing.
    }
  }
  return undefined;
}

export type TxnTokenDecision =
  | { ok: true; accepted?: { token: VerifiedTxnToken; trust: TxnTokenTrust } }
  | { ok: false; code: string; detail: string };

/**
 * Decide on a request's Txn-Token once the request is authenticated.
 * `identity` is null when no WIMSE workload authenticated it. A token must
 * come from a WIMSE workload whose proof bound it (WPT `tth`, or the HTTP
 * signature covering it), verify under that workload's trust domain, and is
 * required on credential routes when that domain, or any other domain the
 * agent is mapped from (`requiredElsewhere`), says so.
 */
export function decideTxnToken(input: {
  trustByDomain: Readonly<Record<string, TxnTokenTrust>>;
  identity: VerifiedExternalIdentity | null;
  header: string | string[] | undefined;
  credentialRoute: boolean;
  requiredElsewhere: boolean;
}): TxnTokenDecision {
  const { trustByDomain, identity, header, credentialRoute, requiredElsewhere } = input;
  const present = header !== undefined;
  const refuse = (code: string, detail: string): TxnTokenDecision => ({ ok: false, code, detail });
  if (!identity || identity.kind !== 'wimse') {
    return present ? refuse('txn_token_unbound', 'Txn-Token without a WIMSE proof that binds it') : { ok: true };
  }
  const trust = trustByDomain[identity.trustDomain];
  // The strictest requirement of any trust domain this agent is mapped from
  // applies, so presenting the workload of a laxer domain does not shed it.
  const mustCarry = credentialRoute && ((trust !== undefined && trust.required !== false) || requiredElsewhere);
  if (!trust) {
    if (present) return refuse('txn_token_untrusted', 'no Txn-Token trust for this trust domain');
    return mustCarry ? refuse('txn_token_required', "this agent's trust domain requires a Txn-Token") : { ok: true };
  }
  if (!present) return mustCarry ? refuse('txn_token_required', 'this trust domain requires a Txn-Token') : { ok: true };
  // The binding: the WPT source has already required a matching tth; an
  // HTTP signature must cover the header.
  if (identity.proof === 'http-sig') {
    const covered = identity.attributes.covered;
    if (!Array.isArray(covered) || !covered.includes('txn-token')) return refuse('txn_token_unbound', 'signature does not cover Txn-Token');
  } else if (identity.proof !== 'wpt') {
    return refuse('txn_token_unbound', 'proof cannot bind a Txn-Token');
  }
  if (Array.isArray(header) || String(header).includes(',')) return refuse('txn_token_invalid', 'more than one Txn-Token');
  try {
    return { ok: true, accepted: { token: verifyTxnToken(String(header), trust), trust } };
  } catch (err) {
    if (err instanceof TxnTokenRefusal) return refuse(`txn_token_${err.code}`, err.detail);
    throw err;
  }
}

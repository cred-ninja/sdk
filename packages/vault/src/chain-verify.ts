/**
 * Offline verification of a whole delegation chain.
 *
 * This is the Cred analog of the Offline Verification Algorithm in
 * draft-asor-wimse-agent-delegation-chain-00 section 6. It is deliberately
 * independent of any token encoding: the caller parses each hop, verifies its
 * signature with whatever primitive the format uses, computes the hash the
 * format commits to, and hands this function plain records. The function then
 * checks everything that is a property of the chain rather than of a single
 * token: linkage, depth, scope subsumption, and expiry ordering.
 *
 * Callers:
 * - @credninja/server wraps it as verifyReceiptChain() for Ed25519 receipts,
 *   where selfHash is SHA-256 hex over the full compact receipt and parentHash
 *   is the child's `parentReceiptHash` claim.
 * - The conformance runner in cred-ninja/protocol feeds it the draft-asor
 *   HS256 interop vectors, where selfHash is base64url SHA-256 over the JWS
 *   Signing Input and parentHash is the child's `par_hash` claim.
 *
 * Hash conventions differ between those two callers. This function never
 * computes a hash; it only compares the strings it is given, so both callers
 * exercise the same linkage check.
 */
import { scopeCoveredBy } from './delegation-chain.js';

export interface DelegationChainHop {
  /** Subject of this hop (the delegate). */
  agentDid: string;
  /** Unique id of this hop's delegation. */
  delegationId: string;
  /** 0 for the root, incrementing by exactly one per hop. */
  chainDepth: number;
  /** Scopes held at this hop. Each must be covered by the parent's scopes. */
  scopes: string[];
  /** Unix seconds. Optional for legacy receipts. */
  iat?: number;
  exp?: number;
  /** Result of the caller's signature check over this hop's bytes. */
  signatureValid: boolean;
  /** Hash the caller computed over this hop's bytes, in the format's convention. */
  selfHash?: string;
  /** Commitment this hop carries to its parent, as written in the token. */
  parentHash?: string;
}

export type ChainVerifyReason =
  | 'empty_chain'
  | 'malformed'
  | 'signature_invalid'
  | 'expired'
  | 'exp_not_monotonic'
  | 'depth_invalid'
  | 'parent_hash_mismatch'
  | 'not_narrower'
  | 'self_delegation';

export type ChainVerifyResult =
  | { ok: true; depth: number; leaf: DelegationChainHop }
  | { ok: false; reason: ChainVerifyReason; hop: number; message: string };

export interface VerifyDelegationChainOptions {
  /** Unix seconds to evaluate `exp` against. Defaults to the current time. */
  now?: number;
  /** Seconds past `exp` a hop is still accepted. Defaults to 0. */
  clockSkewSeconds?: number;
  /**
   * Largest chainDepth the leaf may have. Undefined means unbounded here;
   * callers that know the policy ceiling should pass it.
   */
  maxDepth?: number;
  /**
   * When true (the default), every non-root hop must carry a parentHash and
   * every hop except the leaf must carry a selfHash, and they must line up.
   * Set false only for legacy chains whose receipts predate the commitment.
   */
  requireParentHash?: boolean;
}

function fail(reason: ChainVerifyReason, hop: number, message: string): ChainVerifyResult {
  return { ok: false, reason, hop, message };
}

export function verifyDelegationChain(
  hops: readonly DelegationChainHop[],
  options: VerifyDelegationChainOptions = {},
): ChainVerifyResult {
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const skew = options.clockSkewSeconds ?? 0;
  const requireParentHash = options.requireParentHash ?? true;

  if (hops.length === 0) {
    return fail('empty_chain', 0, 'Chain has no hops');
  }

  // Per-hop checks first, root to leaf, so a broken token is reported before
  // any relationship involving it.
  for (let i = 0; i < hops.length; i++) {
    const hop = hops[i];
    if (!hop || typeof hop.agentDid !== 'string' || hop.agentDid.trim() === ''
      || typeof hop.delegationId !== 'string' || hop.delegationId.trim() === ''
      || !Array.isArray(hop.scopes) || !Number.isInteger(hop.chainDepth)) {
      return fail('malformed', i, `Hop ${i} is missing required fields`);
    }
    if (hop.signatureValid !== true) {
      return fail('signature_invalid', i, `Hop ${i} signature did not verify`);
    }
    if (typeof hop.exp === 'number' && now > hop.exp + skew) {
      return fail('expired', i, `Hop ${i} expired at ${hop.exp}, now is ${now}`);
    }
    if (hop.chainDepth !== i) {
      return fail('depth_invalid', i, `Hop ${i} declares chainDepth ${hop.chainDepth}`);
    }
  }

  const leafDepth = hops.length - 1;
  if (typeof options.maxDepth === 'number' && leafDepth > options.maxDepth) {
    return fail('depth_invalid', leafDepth, `Chain depth ${leafDepth} exceeds maximum ${options.maxDepth}`);
  }

  // Pairwise checks, parent to child.
  for (let i = 1; i < hops.length; i++) {
    const parent = hops[i - 1];
    const child = hops[i];

    if (requireParentHash) {
      if (typeof child.parentHash !== 'string' || child.parentHash === '') {
        return fail('parent_hash_mismatch', i, `Hop ${i} carries no parent commitment`);
      }
      if (typeof parent.selfHash !== 'string' || parent.selfHash === '') {
        return fail('parent_hash_mismatch', i, `Hop ${i - 1} has no computed hash to compare against`);
      }
      if (child.parentHash !== parent.selfHash) {
        return fail('parent_hash_mismatch', i, `Hop ${i} commits to a different parent than the one presented`);
      }
    } else if (typeof child.parentHash === 'string' && typeof parent.selfHash === 'string'
      && child.parentHash !== parent.selfHash) {
      // Even when not required, a commitment that is present must be right.
      return fail('parent_hash_mismatch', i, `Hop ${i} commits to a different parent than the one presented`);
    }

    if (child.agentDid === parent.agentDid) {
      return fail('self_delegation', i, `Hop ${i} delegates to the same agent as hop ${i - 1}`);
    }

    const widened = child.scopes.filter((scope) => !scopeCoveredBy(parent.scopes, scope));
    if (widened.length > 0) {
      return fail('not_narrower', i, `Hop ${i} holds scopes its parent does not cover: ${widened.join(', ')}`);
    }

    if (typeof parent.exp === 'number' && typeof child.exp === 'number' && child.exp > parent.exp) {
      return fail('exp_not_monotonic', i, `Hop ${i} expires at ${child.exp}, after its parent at ${parent.exp}`);
    }
  }

  return { ok: true, depth: leafDepth, leaf: hops[leafDepth] };
}

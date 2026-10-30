/**
 * Sub-Delegation Exchange (draft-sweeney-wimse-credential-delegation-02,
 * "Delegation Chain Integrity", "Sub-Delegation Exchange").
 *
 * A hop has two steps, so that the token is requested by the agent it names:
 *
 * 1. Authorization: the delegating agent calls POST /api/v1/subdelegate
 *    with `exchange: "grant"`. The server runs every check it runs for a
 *    direct sub-delegation, signs the child receipt, and returns a
 *    single-use delegation grant bound to the receiving agent's DID, the
 *    receipt, and a short expiry. No handle exists yet.
 * 2. Issuance: the receiving agent calls POST /api/v1/token, an RFC 8693
 *    token exchange with the grant as `subject_token` and an RFC 7523 JWT
 *    it signed with its own did:key as `actor_token`. The server checks the
 *    actor token names the DID the grant names, then consumes the grant
 *    (a second redemption is rejected) and issues the child.
 *
 * Grants are 256-bit random strings; the store keeps only their SHA-256.
 * Redemption is check-and-delete in one synchronous step, so two concurrent
 * redemptions in one process cannot both succeed.
 */
import { createHash, randomBytes } from 'node:crypto';
import {
  checkJwsSignature,
  createVerificationKey,
  parseStrictJson,
  publicKeyFromDidKey,
} from '@credninja/attenuation';
import type { DelegationConstraint } from '@credninja/vault';

export const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const DELEGATION_GRANT_TOKEN_TYPE = 'urn:credninja:params:oauth:token-type:delegation-grant';
export const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';

/** Longest lifetime an RFC 7523 assertion may claim (draft "Agent Authentication": exp at most iat + 300). */
const MAX_ASSERTION_LIFETIME_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 60;

export interface PendingDelegationGrant {
  agentDid: string;
  delegatorDid: string;
  service: string;
  userId: string;
  appClientId: string;
  scopes: string[];
  constraints: DelegationConstraint[];
  delegationId: string;
  parentDelegationId: string;
  chainDepth: number;
  receipt: string;
  /** Ancestor DIDs above the receiving agent, root first (re-checked at redemption). */
  lineage: string[];
  /** Chain-Verifiable Profile token minted at authorization, if one was requested. */
  agentDelegationToken?: string;
  /** Unix milliseconds. */
  expiresAt: number;
}

export interface DelegationGrantStore {
  issue(grant: PendingDelegationGrant): string;
  /** The grant, without consuming it, or undefined when unknown or expired. */
  peek(grant: string): PendingDelegationGrant | undefined;
  /** Consume the grant. Undefined when it is unknown, expired, or already redeemed. */
  redeem(grant: string): PendingDelegationGrant | undefined;
}

function grantKey(grant: string): string {
  return createHash('sha256').update(grant).digest('hex');
}

export function createDelegationGrantStore(now: () => number = Date.now): DelegationGrantStore {
  const grants = new Map<string, PendingDelegationGrant>();
  const prune = () => {
    const t = now();
    for (const [key, g] of grants) if (g.expiresAt <= t) grants.delete(key);
  };
  return {
    issue(grant) {
      prune();
      const value = randomBytes(32).toString('base64url');
      grants.set(grantKey(value), grant);
      return value;
    },
    peek(grant) {
      if (typeof grant !== 'string') return undefined;
      const g = grants.get(grantKey(grant));
      return g && g.expiresAt > now() ? g : undefined;
    },
    redeem(grant) {
      if (typeof grant !== 'string') return undefined;
      const key = grantKey(grant);
      const g = grants.get(key);
      grants.delete(key);
      return g && g.expiresAt > now() ? g : undefined;
    },
  };
}

export type ActorTokenResult = { ok: true; jti: string; exp: number } | { ok: false; message: string };

/**
 * Verify an RFC 7523 JWT assertion signed by `agentDid`'s own did:key:
 * `iss` and `sub` are the DID, `aud` names `audience`, `exp` is at most 300
 * seconds after `iat` and not past, `jti` is present and not seen before
 * (`seenJti` returns true for a replay). EdDSA or ES256, by the DID's key.
 */
export function verifyActorToken(
  token: unknown,
  agentDid: string,
  audience: string,
  seenJti: (jti: string, exp: number) => boolean,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): ActorTokenResult {
  if (typeof token !== 'string') return { ok: false, message: 'actor_token is required' };
  const publicKey = publicKeyFromDidKey(agentDid);
  if (!publicKey) return { ok: false, message: 'the grant names an agent that is not a did:key; it cannot prove possession' };
  const key = createVerificationKey(publicKey);
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, message: 'actor_token is not a compact JWS' };
  let header: unknown;
  let claims: unknown;
  try {
    header = parseStrictJson(Buffer.from(parts[0]!, 'base64url').toString('utf8'));
    claims = parseStrictJson(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, message: 'actor_token is not valid JSON' };
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) return { ok: false, message: 'actor_token header is not an object' };
  if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) return { ok: false, message: 'actor_token claims are not an object' };
  const failure = checkJwsSignature(
    header as Record<string, unknown>,
    Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'),
    Buffer.from(parts[2]!, 'base64url'),
    ['EdDSA', 'ES256'],
    () => key,
  );
  if (failure) return { ok: false, message: `actor_token signature did not verify under ${agentDid} (${failure})` };
  const c = claims as Record<string, unknown>;
  if (c.iss !== agentDid || c.sub !== agentDid) return { ok: false, message: 'actor_token iss and sub must be the agent DID the grant names' };
  const aud = c.aud;
  if (!(aud === audience || (Array.isArray(aud) && aud.includes(audience)))) return { ok: false, message: `actor_token aud must name ${audience}` };
  if (typeof c.iat !== 'number' || typeof c.exp !== 'number') return { ok: false, message: 'actor_token needs numeric iat and exp' };
  if (c.exp - c.iat > MAX_ASSERTION_LIFETIME_SECONDS) return { ok: false, message: 'actor_token exp is more than 300 seconds after iat' };
  if (nowSeconds > c.exp + CLOCK_SKEW_SECONDS || c.iat > nowSeconds + CLOCK_SKEW_SECONDS) return { ok: false, message: 'actor_token is expired or not yet valid' };
  if (typeof c.jti !== 'string' || c.jti === '') return { ok: false, message: 'actor_token needs a jti' };
  if (seenJti(c.jti, c.exp)) return { ok: false, message: 'actor_token jti was already used' };
  return { ok: true, jti: c.jti, exp: c.exp };
}

/** A replay cache for assertion `jti`s, pruned as entries expire. */
export function createJtiReplayCache(nowSeconds: () => number = () => Math.floor(Date.now() / 1000)): (jti: string, exp: number) => boolean {
  const seen = new Map<string, number>();
  let lastSweep = -1;
  return (jti, exp) => {
    const t = nowSeconds();
    // Prune expired entries at most once per second, so the per-request
    // cost does not grow with the number of retained entries.
    if (t !== lastSweep) {
      lastSweep = t;
      for (const [k, e] of seen) if (e + CLOCK_SKEW_SECONDS < t) seen.delete(k);
    }
    if (seen.has(jti)) return true;
    seen.set(jti, exp);
    return false;
  };
}

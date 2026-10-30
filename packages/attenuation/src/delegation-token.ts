/**
 * Delegation Token: the DPoP-bound JWT a Delegation Server issues to one
 * agent (draft-sweeney-wimse-credential-delegation-02 Section 5). It carries
 * the subject, the acting agent, its capabilities as RFC 9396
 * `authorization_details`, any constraint ceilings, the key it is bound to,
 * the consent it traces to, an opaque reference to the stored credential,
 * and the content identifiers of the delegation receipts behind it (`prf`).
 *
 * Exercise presents it as `Authorization: DPoP <token>` with a DPoP proof
 * whose `ath` is the SHA-256 of the token (RFC 9449 Section 4.2).
 */
import { createHash } from 'node:crypto';
import { checkJwsSignature, signCompactJws, base64urlDecode } from './jws.js';
import type { JwsKeyResolver, JwsSigner } from './jws.js';
import { parseStrictJson } from './strict-json.js';
import type { ActorClaim } from './receipt-claims.js';

/** JWS `typ` of a Delegation Token, so it is never confused with a receipt. */
export const DELEGATION_TOKEN_TYP = 'dt+jwt';
/** RFC 9396 detail type of a Cred capability. */
export const CRED_DELEGATION_TYPE = 'cred_delegation';
/** Section 9.6: a Delegation Token lives at most an hour. */
export const DELEGATION_TOKEN_MAX_LIFETIME_SECONDS = 3600;
const DEFAULT_CLOCK_SKEW_SECONDS = 60;

/**
 * One capability. An operation is an OAuth scope string or the name of an
 * operation in the provider's catalogue; resources narrow it further.
 */
export interface CredDelegationDetail {
  type: typeof CRED_DELEGATION_TYPE;
  provider: string;
  operations: string[];
  resources?: string[];
}

export interface DelegationTokenClaims {
  iss: string;
  sub: string;
  client_id: string;
  act: ActorClaim;
  authorization_details: CredDelegationDetail[];
  delegation_constraints?: unknown[];
  cnf: { jkt: string };
  iat: number;
  exp: number;
  jti: string;
  consent_id: string;
  credential_handle: string;
  /** Receipt content identifiers, root hop first. */
  prf: string[];
}

export type DelegationTokenFailure =
  | 'malformed'
  | 'wrong_type'
  | 'bad_signature'
  | 'malformed_claims'
  | 'wrong_issuer'
  | 'expired';

export type DelegationTokenResult =
  | { ok: true; claims: DelegationTokenClaims }
  | { ok: false; reason: DelegationTokenFailure };

/** base64url SHA-256 of a compact JWS: `ath` of a token, a receipt's id in `prf`. */
function sha256Id(compact: string): string {
  return createHash('sha256').update(compact, 'ascii').digest('base64url');
}

/** The DPoP `ath` for a Delegation Token. */
export function delegationTokenAth(token: string): string {
  return sha256Id(token);
}

/** A delegation receipt's content identifier, as listed in `prf`. */
export function receiptContentId(receipt: string): string {
  return sha256Id(receipt);
}

const nonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const stringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every(nonEmptyString);

function isActor(value: unknown, depth = 0): value is ActorClaim {
  if (depth > 32 || typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const { sub, act, ...rest } = value as Record<string, unknown>;
  if (!nonEmptyString(sub) || Object.keys(rest).length > 0) return false;
  return act === undefined || isActor(act, depth + 1);
}

function isDetail(value: unknown): value is CredDelegationDetail {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const d = value as Record<string, unknown>;
  return d.type === CRED_DELEGATION_TYPE
    && nonEmptyString(d.provider)
    && stringArray(d.operations) && d.operations.length > 0
    && (d.resources === undefined || stringArray(d.resources));
}

/** The claim-set rules shared by minting and verification; null when valid. */
function claimProblem(c: Record<string, unknown>): string | null {
  for (const name of ['iss', 'sub', 'client_id', 'jti', 'consent_id', 'credential_handle'] as const) {
    if (!nonEmptyString(c[name])) return `${name} must be a non-empty string`;
  }
  if (!isActor(c.act)) return 'act must be an actor claim';
  if ((c.act as ActorClaim).sub !== c.client_id) return 'client_id and act.sub must name the same agent';
  if (!Array.isArray(c.authorization_details) || c.authorization_details.length === 0 || !c.authorization_details.every(isDetail)) {
    return 'authorization_details must be a non-empty array of cred_delegation details';
  }
  if (c.delegation_constraints !== undefined && !Array.isArray(c.delegation_constraints)) {
    return 'delegation_constraints must be an array';
  }
  const cnf = c.cnf as Record<string, unknown> | undefined;
  if (typeof cnf !== 'object' || cnf === null || !nonEmptyString(cnf.jkt)) return 'cnf.jkt must name the bound key';
  if (!Number.isSafeInteger(c.iat) || !Number.isSafeInteger(c.exp)) return 'iat and exp must be integers';
  const lifetime = (c.exp as number) - (c.iat as number);
  if (lifetime <= 0 || lifetime > DELEGATION_TOKEN_MAX_LIFETIME_SECONDS) {
    return `lifetime must be between 1 and ${DELEGATION_TOKEN_MAX_LIFETIME_SECONDS} seconds`;
  }
  if (!stringArray(c.prf) || c.prf.length === 0) return 'prf must list at least one receipt';
  return null;
}

/** Sign a Delegation Token. Throws when the claims break the token's rules. */
export function mintDelegationToken(claims: DelegationTokenClaims, signer: JwsSigner): string {
  const problem = claimProblem(claims as unknown as Record<string, unknown>);
  if (problem) throw new Error(`Invalid Delegation Token: ${problem}`);
  return signCompactJws({ ...claims }, signer, { typ: DELEGATION_TOKEN_TYP });
}

function decodeSegment(segment: string): Record<string, unknown> | null {
  const bytes = base64urlDecode(segment);
  if (!bytes) return null;
  try {
    const value = parseStrictJson(bytes.toString('utf8'));
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * Verify a Delegation Token: compact form, `typ`, signature under an
 * accepted algorithm and a key the issuer holds, the claim set, the issuer,
 * and expiry. Revocation and the DPoP binding are the caller's to check.
 */
export function verifyDelegationToken(
  token: string,
  opts: {
    issuer: string;
    acceptedAlgs: readonly string[];
    resolveKey: JwsKeyResolver;
    nowSeconds?: number;
    clockSkewSeconds?: number;
  },
): DelegationTokenResult {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3) return { ok: false, reason: 'malformed' };
  const header = decodeSegment(parts[0]!);
  const payload = decodeSegment(parts[1]!);
  const signature = base64urlDecode(parts[2]!);
  if (!header || !payload || !signature) return { ok: false, reason: 'malformed' };
  if (header.typ !== DELEGATION_TOKEN_TYP) return { ok: false, reason: 'wrong_type' };
  if (checkJwsSignature(header, Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), signature, opts.acceptedAlgs, opts.resolveKey) !== null) {
    return { ok: false, reason: 'bad_signature' };
  }
  if (claimProblem(payload) !== null) return { ok: false, reason: 'malformed_claims' };
  const claims = payload as unknown as DelegationTokenClaims;
  if (claims.iss !== opts.issuer) return { ok: false, reason: 'wrong_issuer' };
  const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
  // RFC 7519 Section 4.1.4: not accepted on or after exp.
  if (now >= claims.exp + (opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS)) return { ok: false, reason: 'expired' };
  return { ok: true, claims };
}

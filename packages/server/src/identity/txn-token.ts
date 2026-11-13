/**
 * Transaction Tokens (draft-ietf-oauth-transaction-tokens-11) at the last hop
 * of a trust domain.
 *
 * Trust is configured per WIMSE trust domain, out of band: the expected `aud`
 * (the trust domain the token is valid in, §9.2), the Txn-Token Service's
 * public keys, how to read a user subject, and how the token's `scope` maps
 * to provider-native scopes. The caller selects that configuration by the
 * presenting workload's verified trust domain; nothing in the Txn-Token
 * (`iss`, header keys) chooses its own verification key.
 *
 * Checks (§9, §12.2): compact JWS; `typ` txntoken+jwt; asymmetric `alg`;
 * `kid` among the configured keys; signature; `aud` equal to the configured
 * value; `iat` and `exp` present, not expired, not issued in the future, and a
 * bounded lifetime; `txn`, `sub`, `scope` and `req_wl` present as strings.
 * Unknown claims are ignored (§9.2).
 *
 * Only node:crypto is used. Error details name the failed check, never token
 * contents.
 */
import { createHash } from 'node:crypto';
import { keyFitsAlg, sigAlg, verifySignature } from './wimse.js';
import type { TrustAnchorKeys } from './trust-bundle.js';

export class TxnTokenRefusal extends Error {
  readonly code: string;
  readonly detail: string;
  constructor(code: string, detail: string) {
    super(`txn-token: ${code}`);
    this.name = 'TxnTokenRefusal';
    this.code = code;
    this.detail = detail;
  }
}

/** How a user subject is read from a verified Txn-Token (draft SPEC note: the format cannot tell users from workloads). */
export interface TxnUserSubjectRule {
  /** Claim path, dot-separated: `sub`, or `tctx.user_id`. */
  claim: string;
  /**
   * Optional full-string pattern with exactly one capture group, which yields
   * the Cred user id, e.g. `^user:([A-Za-z0-9._@-]{1,128})$`. Must start with
   * `^` and end with `$`. Without it the whole claim value is the user id.
   */
  pattern?: string;
}

export interface TxnTokenTrust {
  /** The `aud` value that names this trust domain (§9.2). */
  aud: string;
  /** The Txn-Token Service's public keys, selected by `kid`. */
  keys: TrustAnchorKeys;
  /** No rule: every token is autonomous (no user), so none can use a user-delegated credential. */
  userSubject?: TxnUserSubjectRule;
  /** `scope` value → provider-native scopes, per service: `{ google: { 'calendar.read': ['calendar.readonly'] } }`. */
  scopeMap: Readonly<Record<string, Readonly<Record<string, readonly string[]>>>>;
  /** Refuse WIMSE requests from this trust domain that carry no Txn-Token. Default true. */
  required?: boolean;
  /** Cap on exp - iat. Default 3600. */
  maxLifetimeSec?: number;
  /** Allowed clock skew. Default 60. */
  clockSkewSec?: number;
  now?: () => number;
}

export interface VerifiedTxnToken {
  txn: string;
  sub: string;
  /** `scope`, split on spaces. */
  scopes: readonly string[];
  reqWl: string;
  exp: number;
  /** The Cred user id, or undefined for an autonomous transaction. */
  userId?: string;
  /** base64url SHA-256 of the token as presented, for logs (never the token). */
  hash: string;
  claims: Readonly<Record<string, unknown>>;
}

const MAX_TOKEN_LENGTH = 16_384;
const MAX_SUBJECT_LENGTH = 256;
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const EMBEDDED_KEY_HEADERS = ['jwk', 'jku', 'x5u', 'x5c'];

function refuse(code: string, detail: string): never {
  throw new TxnTokenRefusal(code, detail);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Validate a trust configuration once, at startup. Throws on a bad one. */
export function checkTxnTokenTrust(trust: TxnTokenTrust): void {
  if (!trust || typeof trust.aud !== 'string' || trust.aud.length === 0) throw new Error('txn-token: aud is required');
  if (!trust.keys || trust.keys.size === 0) throw new Error('txn-token: keys are required');
  if (!isPlainObject(trust.scopeMap)) throw new Error('txn-token: scopeMap is required');
  const rule = trust.userSubject;
  if (rule) {
    if (typeof rule.claim !== 'string' || !/^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$/.test(rule.claim)) {
      throw new Error('txn-token: userSubject.claim must be a dot-separated claim path');
    }
    if (rule.pattern !== undefined) {
      if (!rule.pattern.startsWith('^') || !rule.pattern.endsWith('$')) {
        throw new Error('txn-token: userSubject.pattern must be anchored with ^ and $');
      }
      // Exactly one capture group: "pattern|" always matches "", and the
      // match array has one slot per group plus the whole match.
      const groups = new RegExp(`${rule.pattern}|`).exec('')!.length - 1;
      if (groups !== 1) throw new Error('txn-token: userSubject.pattern must have exactly one capture group');
    }
  }
}

function claimAt(claims: Record<string, unknown>, path: string): unknown {
  let v: unknown = claims;
  for (const part of path.split('.')) {
    if (!isPlainObject(v)) return undefined;
    v = v[part];
  }
  return v;
}

/** The user id a verified token names, or undefined when it is autonomous. */
function userIdFrom(claims: Record<string, unknown>, rule: TxnUserSubjectRule | undefined): string | undefined {
  if (!rule) return undefined;
  const v = claimAt(claims, rule.claim);
  if (typeof v !== 'string' || v.length === 0 || v.length > MAX_SUBJECT_LENGTH) return undefined;
  if (rule.pattern === undefined) return v;
  const m = new RegExp(rule.pattern).exec(v);
  return m && typeof m[1] === 'string' && m[1].length > 0 ? m[1] : undefined;
}

export function verifyTxnToken(token: string, trust: TxnTokenTrust): VerifiedTxnToken {
  const now = (trust.now ?? (() => Math.floor(Date.now() / 1000)))();
  const skew = trust.clockSkewSec ?? 60;
  if (typeof token !== 'string') refuse('malformed', 'not a string');
  const t = token.trim();
  // §12.1: "The value of this header MUST be exactly one Txn-Token."
  if (t.length > MAX_TOKEN_LENGTH || !COMPACT_JWS.test(t)) refuse('malformed', 'not one compact JWS');
  const [h, p, s] = t.split('.');
  let header: unknown;
  let claims: unknown;
  try {
    header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  } catch {
    refuse('malformed', 'header or payload is not JSON');
  }
  if (!isPlainObject(header) || !isPlainObject(claims)) refuse('malformed', 'header or payload is not an object');
  const hd = header as Record<string, unknown>;
  const c = claims as Record<string, unknown>;

  // §9.1: typ MUST be txntoken+jwt (RFC 8725 §3.11 explicit typing).
  const typ = typeof hd.typ === 'string' ? hd.typ.toLowerCase() : '';
  if (typ !== 'txntoken+jwt' && typ !== 'application/txntoken+jwt') refuse('typ', 'typ is not txntoken+jwt');
  if ('crit' in hd) refuse('crit', 'crit present');
  for (const k of EMBEDDED_KEY_HEADERS) if (k in hd) refuse('embedded_key', `header carries ${k}`);
  if (typeof hd.alg !== 'string' || hd.alg === 'none' || /^HS/i.test(hd.alg)) refuse('alg', 'alg is none, symmetric or missing');
  const alg = sigAlg(hd.alg);
  if (!alg) refuse('alg', 'alg is not supported');
  if (typeof hd.kid !== 'string' || hd.kid.length === 0) refuse('kid', 'kid missing');
  const anchor = trust.keys.get(hd.kid as string);
  if (!anchor) refuse('kid', 'kid is not among the configured keys');
  if (anchor!.alg !== undefined && sigAlg(anchor!.alg) !== alg) refuse('alg', 'alg differs from the key alg');
  if (!keyFitsAlg(anchor!.key, alg!)) refuse('alg', 'alg does not fit the key');
  if (!verifySignature(alg!, anchor!.key, Buffer.from(`${h}.${p}`, 'ascii'), Buffer.from(s, 'base64url'))) refuse('signature', 'signature invalid');

  // §9.2 aud: "MUST identify the Trust Domain"; "MUST NOT be accepted outside" it.
  const aud = Array.isArray(c.aud) && c.aud.length === 1 ? c.aud[0] : c.aud;
  if (aud !== trust.aud) refuse('aud', 'aud does not name this trust domain');

  const num = (n: string): number => {
    const v = c[n];
    if (typeof v !== 'number' || !Number.isFinite(v)) refuse(n, `${n} missing`);
    return v as number;
  };
  const iat = num('iat');
  const exp = num('exp');
  if (exp + skew <= now) refuse('expired', 'exp has passed');
  if (iat > now + skew) refuse('iat', 'iat is in the future');
  if (exp <= iat) refuse('lifetime', 'exp is not after iat');
  if (exp - iat > (trust.maxLifetimeSec ?? 3600)) refuse('lifetime', 'lifetime exceeds the configured maximum');
  const str = (n: string): string => {
    const v = c[n];
    if (typeof v !== 'string' || v.length === 0) refuse(n, `${n} missing`);
    return v as string;
  };
  const txn = str('txn');
  const sub = str('sub');
  const scope = str('scope');
  const reqWl = str('req_wl');
  const userId = userIdFrom(c, trust.userSubject);
  return {
    txn,
    sub,
    scopes: scope.split(' ').filter((x) => x.length > 0),
    reqWl,
    exp,
    ...(userId !== undefined ? { userId } : {}),
    hash: createHash('sha256').update(t, 'ascii').digest('base64url'),
    claims: c,
  };
}

/**
 * The provider scopes a verified token allows for `service`: the union of the
 * mapped values of each of its scopes. Null when the service has no mapping
 * or any token scope is unmapped (an unmapped scope is refused, not ignored).
 */
export function mappedProviderScopes(trust: TxnTokenTrust, service: string, scopes: readonly string[]): string[] | null {
  const table = trust.scopeMap[service];
  if (!table || scopes.length === 0) return null;
  const out = new Set<string>();
  for (const s of scopes) {
    if (!Object.prototype.hasOwnProperty.call(table, s)) return null;
    for (const p of table[s]) out.add(p);
  }
  return [...out];
}

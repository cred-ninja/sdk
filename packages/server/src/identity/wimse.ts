/**
 * WIMSE workload authentication: a Workload Identity Token (WIT) in the
 * `Workload-Identity-Token` header plus a Workload Proof Token (WPT) in
 * `Authorization: WPT <jws>`.
 *
 * Sources:
 *   - draft-ietf-wimse-workload-creds-03 (WIT: §3 trust anchors, §5.1 format,
 *     §5.1.3 validation, §9.3.1 lifetime)
 *   - draft-ietf-wimse-wpt-02 (WPT: §2 format and validation, §2.2 the WPT
 *     Authorization scheme, §3.1.4 replay, §3.1.7 audience)
 *   - draft-ietf-wimse-identifier-04 (Workload Identifier syntax, §4.1, §4.3)
 *
 * A WIT is never accepted on its own: workload-creds-03 §5.1 (cnf) says it
 * "MUST NOT be used as a bearer token". Every request must also carry a WPT
 * signed by the WIT's confirmation key.
 *
 * Only node:crypto is used. Error details name the failed check and claim,
 * never token contents.
 */
import { constants, createHash, createPublicKey, timingSafeEqual, verify, type JsonWebKey, type KeyObject } from 'node:crypto';
import {
  IdentityRefusal,
  type ExternalIdentitySource,
  type IdentityRequest,
  type ReplayCache,
  type VerifiedExternalIdentity,
} from './types.js';
import type { TrustAnchorKeys } from './trust-bundle.js';

export interface WimseSourceConfig {
  /** Allowlist: exactly these trust domains, each with its own anchors (workload-creds-03 §3). */
  trustDomains: Record<string, TrustAnchorKeys>;
  replay: ReplayCache;
  /** Cap on WIT lifetime: exp - iat if iat is present, else exp - now. Default 86400. */
  maxWitLifetimeSec?: number;
  /** Cap on exp - now for a WPT (wpt-02 §2 "lifetimes MUST be short"). Default 300. */
  maxWptLifetimeSec?: number;
  /** Allowed clock skew for exp/nbf/iat. Default 60. */
  clockSkewSec?: number;
  /** Current time in seconds since the epoch; for tests. */
  now?: () => number;
}

/** The configuration the pure verifiers need (no replay cache). */
export type WimseVerifyConfig = Omit<WimseSourceConfig, 'replay'>;

export interface WorkloadIdentifier {
  /** The identifier after RFC 3986 §6.2.2 syntax-based normalization (identifier-04 §4.3). */
  identifier: string;
  /** The lower-cased authority component. */
  trustDomain: string;
}

export interface VerifiedWit {
  /** The WIT exactly as presented, for the WPT `wth` hash. */
  token: string;
  subject: string;
  trustDomain: string;
  exp: number;
  /** `cnf.jwk.alg` as presented. */
  cnfAlg: string;
  cnfKey: KeyObject;
  /** RFC 7638 thumbprint of `cnf.jwk`. */
  cnfJkt: string;
  claims: Readonly<Record<string, unknown>>;
}

export interface VerifiedWpt {
  jti: string;
  exp: number;
  claims: Readonly<Record<string, unknown>>;
}

const DEFAULT_MAX_WIT_LIFETIME = 86_400;
const DEFAULT_MAX_WPT_LIFETIME = 300;
const DEFAULT_SKEW = 60;
/** identifier-04 §4.1: "Workload Identifiers SHOULD NOT exceed 2048 bytes". */
const MAX_IDENTIFIER_BYTES = 2048;
/** wpt-02 §2: jti carries ~128 bits of randomness; 16 base64url chars is 96 bits, the floor accepted. */
const MIN_JTI_LENGTH = 16;
/** Bounds replay-cache memory per entry. */
const MAX_JTI_LENGTH = 256;
/** Bounds work done on attacker-supplied input before any signature check. */
const MAX_TOKEN_LENGTH = 16_384;

/** workload-creds-03 §5.1.1 ABNF: JWT = base64url "." base64url "." base64url. */
const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
/** RFC 9110 §11.2 token68, used by the WPT scheme (wpt-02 §2 Figure 1). */
const TOKEN68 = /^[A-Za-z0-9\-._~+/]+=*$/;

/** Header members that would let the token choose its own verification key. */
const EMBEDDED_KEY_HEADERS = ['jwk', 'jku', 'x5u', 'x5c'] as const;
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

type SigAlg = 'ES256' | 'ES384' | 'RS256' | 'PS256' | 'EdDSA';

interface ResolvedConfig {
  trustDomains: Map<string, TrustAnchorKeys>;
  maxWitLifetimeSec: number;
  maxWptLifetimeSec: number;
  clockSkewSec: number;
  now: () => number;
}

function refuse(code: string, detail: string): never {
  throw new IdentityRefusal('wimse', code, detail);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function resolveConfig(cfg: WimseVerifyConfig): ResolvedConfig {
  const trustDomains = new Map<string, TrustAnchorKeys>();
  for (const [td, anchors] of Object.entries(cfg.trustDomains ?? {})) {
    trustDomains.set(td.toLowerCase(), anchors);
  }
  const num = (v: number | undefined, d: number, name: string): number => {
    const n = v ?? d;
    if (!Number.isFinite(n) || n < 0) throw new Error(`wimse: ${name} must be a non-negative number`);
    return n;
  };
  return {
    trustDomains,
    maxWitLifetimeSec: num(cfg.maxWitLifetimeSec, DEFAULT_MAX_WIT_LIFETIME, 'maxWitLifetimeSec'),
    maxWptLifetimeSec: num(cfg.maxWptLifetimeSec, DEFAULT_MAX_WPT_LIFETIME, 'maxWptLifetimeSec'),
    clockSkewSec: num(cfg.clockSkewSec, DEFAULT_SKEW, 'clockSkewSec'),
    now: cfg.now ?? (() => Math.floor(Date.now() / 1000)),
  };
}

interface ParsedJws {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  signingInput: Buffer;
  signature: Buffer;
}

function parseCompactJws(token: string, which: 'wit' | 'wpt'): ParsedJws {
  if (token.length > MAX_TOKEN_LENGTH || !COMPACT_JWS.test(token)) {
    refuse(`malformed_${which}`, `${which} is not a compact JWS`);
  }
  const [h, p, s] = token.split('.');
  let header: unknown;
  let claims: unknown;
  try {
    header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  } catch {
    refuse(`malformed_${which}`, `${which} header or payload is not JSON`);
  }
  if (!isPlainObject(header) || !isPlainObject(claims)) {
    refuse(`malformed_${which}`, `${which} header or payload is not a JSON object`);
  }
  // RFC 7515 §4.1.11: no extensions are understood, so any crit must be refused.
  if ('crit' in header) refuse(`${which}_crit`, `${which} header carries crit`);
  return { header, claims, signingInput: Buffer.from(`${h}.${p}`, 'ascii'), signature: Buffer.from(s, 'base64url') };
}

/** Explicit typing (RFC 8725 §3.11): case-insensitive media type, optional "application/" prefix. */
function typIs(typ: unknown, expected: string): boolean {
  if (typeof typ !== 'string') return false;
  const t = typ.toLowerCase();
  return t === expected || t === `application/${expected}`;
}

/** Maps a JWS alg to the one this module verifies; "Ed25519" (RFC 9864) and "EdDSA" are one algorithm here. */
function sigAlg(alg: unknown): SigAlg | undefined {
  switch (alg) {
    case 'ES256':
    case 'ES384':
    case 'RS256':
    case 'PS256':
    case 'EdDSA':
      return alg;
    case 'Ed25519':
      return 'EdDSA';
    default:
      return undefined;
  }
}

/** Whether `key` is of the type and curve `alg` requires. */
function keyFitsAlg(key: KeyObject, alg: SigAlg): boolean {
  const type = key.asymmetricKeyType;
  const curve = key.asymmetricKeyDetails?.namedCurve;
  switch (alg) {
    case 'ES256':
      return type === 'ec' && curve === 'prime256v1';
    case 'ES384':
      return type === 'ec' && curve === 'secp384r1';
    case 'RS256':
      return type === 'rsa';
    case 'PS256':
      return type === 'rsa' || type === 'rsa-pss';
    case 'EdDSA':
      return type === 'ed25519';
  }
}

function verifySignature(alg: SigAlg, key: KeyObject, input: Buffer, sig: Buffer): boolean {
  try {
    switch (alg) {
      case 'ES256':
        // JOSE ECDSA signatures are raw r||s (RFC 7518 §3.4).
        return sig.length === 64 && verify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, sig);
      case 'ES384':
        return sig.length === 96 && verify('sha384', input, { key, dsaEncoding: 'ieee-p1363' }, sig);
      case 'RS256':
        return verify('sha256', input, key, sig);
      case 'PS256':
        return verify('sha256', input, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig);
      case 'EdDSA':
        return verify(null, input, key, sig);
    }
  } catch {
    return false;
  }
}

function sha256Digest(value: string): Buffer {
  // latin1 keeps the bytes Node decoded from the header; ASCII tokens hash identically.
  return createHash('sha256').update(value, 'latin1').digest();
}

/** Constant-time compare of a presented base64url SHA-256 against the expected digest. */
function hashMatches(presented: unknown, expectedDigest: Buffer): boolean {
  if (typeof presented !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(presented)) return false;
  const got = Buffer.from(presented, 'base64url');
  return got.length === expectedDigest.length && timingSafeEqual(got, expectedDigest);
}

const UNRESERVED = /[A-Za-z0-9\-._~]/;
const PCT = /%([0-9A-Fa-f]{2})/g;

/** Decode percent-encoded unreserved characters; upper-case the hex of the rest (RFC 3986 §6.2.2.1-2). */
function normalizePct(s: string): string {
  return s.replace(PCT, (m, hex: string) => {
    const ch = String.fromCharCode(parseInt(hex, 16));
    return UNRESERVED.test(ch) ? ch : `%${hex.toUpperCase()}`;
  });
}

/**
 * Validate a Workload Identifier (identifier-04 §4.1) and return its
 * normalized form and trust domain. Throws IdentityRefusal('invalid_subject').
 */
export function validateWorkloadIdentifier(uri: unknown): WorkloadIdentifier {
  const bad = (why: string): never => refuse('invalid_subject', `workload identifier ${why}`);
  if (typeof uri !== 'string' || uri.length === 0) bad('is not a non-empty string');
  const s = uri as string;
  if (Buffer.byteLength(s, 'utf8') > MAX_IDENTIFIER_BYTES) bad(`exceeds ${MAX_IDENTIFIER_BYTES} bytes`);
  // RFC 3986 characters only, and every "%" starts a valid pct-encoding.
  if (!/^[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/.test(s)) bad('contains characters outside RFC 3986');
  if (/%(?![0-9A-Fa-f]{2})/.test(s)) bad('contains an invalid percent-encoding');
  // §4.1: "MUST NOT contain a query component, a fragment component".
  if (s.includes('?')) bad('has a query component');
  if (s.includes('#')) bad('has a fragment component');

  // §4.1: absolute URI with a non-empty authority.
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/]*)(.*)$/.exec(s);
  if (!m) bad('is not an absolute URI with an authority');
  const [, scheme, authority, path] = m as RegExpExecArray;
  if (authority.length === 0) bad('has an empty authority (trust domain)');
  // §4.1: "MUST NOT contain ... user information, or a port component".
  if (authority.includes('@')) bad('has user information');
  let host: string;
  if (authority.startsWith('[')) {
    if (!/^\[[0-9A-Fa-f:.]+\]$/.test(authority)) bad('has an invalid IP literal or a port');
    host = authority;
  } else {
    if (authority.includes(':')) bad('has a port component');
    // §4.3: A-labels only; percent-encoded or other non-LDH hosts are refused.
    if (!/^[A-Za-z0-9.-]+$/.test(authority)) bad('has a trust domain that is not a DNS name or IP literal');
    host = authority;
  }

  // §4.1: non-empty path.
  if (path.length <= 1) bad('has an empty path');
  // §4.1: no "." or ".." segment, literally or after decoding percent-encoded unreserved characters.
  const segments = path.slice(1).split('/');
  for (const seg of segments) {
    const decoded = normalizePct(seg);
    if (decoded === '.' || decoded === '..') bad('has a dot segment');
  }

  const trustDomain = host.toLowerCase();
  return { identifier: `${scheme.toLowerCase()}://${trustDomain}${normalizePct(path)}`, trustDomain };
}

/** RFC 7638 thumbprint over the required members of an EC or OKP public key. */
function jwkThumbprint(jwk: JsonWebKey): string {
  const canonical =
    jwk.kty === 'EC'
      ? JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
      : JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

/**
 * workload-creds-03 §5.1 cnf: jwk with an alg member; no symmetric or
 * encryption algorithms. Accepted: ES256 on P-256, EdDSA/Ed25519 on Ed25519.
 */
function confirmationKey(cnf: unknown): { alg: string; key: KeyObject; jkt: string } {
  if (!isPlainObject(cnf) || !isPlainObject(cnf.jwk)) refuse('wit_cnf', 'cnf.jwk missing');
  const jwk = (cnf as { jwk: Record<string, unknown> }).jwk;
  for (const m of PRIVATE_JWK_MEMBERS) {
    if (m in jwk) refuse('wit_cnf', `cnf.jwk carries private or symmetric member "${m}"`);
  }
  if (jwk.kty === 'oct') refuse('wit_cnf', 'cnf.jwk is symmetric');
  if (typeof jwk.alg !== 'string') refuse('wit_cnf_alg', 'cnf.jwk.alg missing');
  const alg = jwk.alg as string;
  const str = (v: unknown) => typeof v === 'string' && v.length > 0;

  let pub: JsonWebKey;
  if (alg === 'ES256' && jwk.kty === 'EC' && jwk.crv === 'P-256' && str(jwk.x) && str(jwk.y)) {
    pub = { kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string };
  } else if ((alg === 'EdDSA' || alg === 'Ed25519') && jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && str(jwk.x)) {
    pub = { kty: 'OKP', crv: 'Ed25519', x: jwk.x as string };
  } else {
    refuse('wit_cnf_alg', 'cnf.jwk.alg is not ES256 (EC P-256) or EdDSA/Ed25519 (OKP Ed25519)');
  }
  let key: KeyObject;
  try {
    key = createPublicKey({ key: pub, format: 'jwk' });
  } catch {
    refuse('wit_cnf', 'cnf.jwk is not a valid public key');
  }
  return { alg, key, jkt: jwkThumbprint(pub) };
}

function optionalTime(claims: Record<string, unknown>, name: string, which: 'wit' | 'wpt'): number | undefined {
  const v = claims[name];
  if (v === undefined) return undefined;
  if (typeof v !== 'number' || !Number.isFinite(v)) refuse(`${which}_${name}`, `${which} ${name} is not a NumericDate`);
  return v as number;
}

/** Verify a WIT (workload-creds-03 §5.1.3). Throws IdentityRefusal on any failure. */
export function verifyWit(token: string, cfg: WimseVerifyConfig): VerifiedWit {
  const c = resolveConfig(cfg);
  const now = c.now();
  const { header, claims, signingInput, signature } = parseCompactJws(token, 'wit');

  if (!typIs(header.typ, 'wit+jwt')) refuse('wit_type', 'wit typ is not wit+jwt');
  // §5.1: asymmetric signature algorithm, never none; HS* refused explicitly.
  if (typeof header.alg !== 'string' || header.alg === 'none' || /^HS/i.test(header.alg)) {
    refuse('wit_alg', 'wit alg is none, symmetric, or missing');
  }
  const alg = sigAlg(header.alg);
  if (!alg) refuse('wit_alg', 'wit alg is not supported');
  for (const h of EMBEDDED_KEY_HEADERS) {
    if (h in header) refuse('wit_embedded_key', `wit header carries ${h}`);
  }
  // §3: kid selects among the trust domain's keys; with no single-key policy here, kid is required.
  if (typeof header.kid !== 'string' || header.kid.length === 0) refuse('wit_kid', 'wit kid missing');

  // §5.1.3: sub is one Workload Identifier; its trust domain selects the anchors.
  const id = validateWorkloadIdentifier(claims.sub);
  const anchors = c.trustDomains.get(id.trustDomain);
  if (!anchors) refuse('untrusted_trust_domain', 'wit sub trust domain is not configured');
  // §3: "A credential MUST be validated only against the anchors bound to the
  // trust domain named in its Workload Identifier."
  const anchor = (anchors as TrustAnchorKeys).get(header.kid as string);
  if (!anchor) refuse('unknown_kid', 'wit kid is not among the trust domain anchors');
  if (anchor!.alg !== undefined && sigAlg(anchor!.alg) !== alg) refuse('wit_alg', 'wit alg differs from anchor alg');
  if (!keyFitsAlg(anchor!.key, alg!)) refuse('wit_alg', 'wit alg does not fit the anchor key type');
  if (!verifySignature(alg!, anchor!.key, signingInput, signature)) refuse('wit_signature', 'wit signature invalid');

  // Time checks (§5.1 exp; §9.3.1 lifetime).
  const exp = claims.exp;
  if (typeof exp !== 'number' || !Number.isFinite(exp)) refuse('wit_exp', 'wit exp missing');
  if ((exp as number) + c.clockSkewSec <= now) refuse('wit_expired', 'wit exp has passed');
  const nbf = optionalTime(claims, 'nbf', 'wit');
  if (nbf !== undefined && nbf > now + c.clockSkewSec) refuse('wit_not_yet_valid', 'wit nbf is in the future');
  const iat = optionalTime(claims, 'iat', 'wit');
  if (iat !== undefined && iat > now + c.clockSkewSec) refuse('wit_iat_future', 'wit iat is in the future');
  const lifetime = iat !== undefined ? (exp as number) - iat : (exp as number) - now;
  if (lifetime > c.maxWitLifetimeSec) refuse('wit_lifetime', 'wit lifetime exceeds the configured maximum');

  const cnf = confirmationKey(claims.cnf);
  return {
    token,
    subject: id.identifier,
    trustDomain: id.trustDomain,
    exp: exp as number,
    cnfAlg: cnf.alg,
    cnfKey: cnf.key,
    cnfJkt: cnf.jkt,
    claims,
  };
}

function singleHeader(req: IdentityRequest, name: string): string | undefined {
  const v = req.headers[name];
  if (Array.isArray(v)) {
    if (v.length === 1) return v[0];
    refuse('multiple_headers', `${name} occurs more than once`);
  }
  return v as string | undefined;
}

/** Verify a WPT against an already-verified WIT (wpt-02 §2). Throws IdentityRefusal on any failure. */
export function verifyWpt(token: string, wit: VerifiedWit, req: IdentityRequest, cfg: WimseVerifyConfig): VerifiedWpt {
  const c = resolveConfig(cfg);
  const now = c.now();
  const { header, claims, signingInput, signature } = parseCompactJws(token, 'wpt');

  if (!typIs(header.typ, 'wpt+jwt')) refuse('wpt_type', 'wpt typ is not wpt+jwt');
  // §2: "The value MUST match the alg value of the jwk in the cnf claim of the WIT."
  // "EdDSA" and "Ed25519" name the same algorithm for an Ed25519 key.
  const alg = sigAlg(header.alg);
  const cnfAlg = sigAlg(wit.cnfAlg);
  if (typeof header.alg !== 'string' || !alg || alg !== cnfAlg) refuse('wpt_alg_mismatch', 'wpt alg does not match cnf.jwk.alg');
  if (!keyFitsAlg(wit.cnfKey, alg!)) refuse('wpt_alg_mismatch', 'wpt alg does not fit the cnf key');
  // §2: "The WPT signature is valid using the public key from the confirmation claim of the WIT."
  if (!verifySignature(alg!, wit.cnfKey, signingInput, signature)) refuse('wpt_signature', 'wpt signature invalid');

  // §2 / §3.1.7: aud compared to the configured target URI, never to Host.
  const aud = Array.isArray(claims.aud) && claims.aud.length === 1 ? claims.aud[0] : claims.aud;
  if (typeof aud !== 'string' || aud !== req.targetUri) refuse('wpt_audience', 'wpt aud does not match the target URI');

  const exp = claims.exp;
  if (typeof exp !== 'number' || !Number.isFinite(exp)) refuse('wpt_exp', 'wpt exp missing');
  if ((exp as number) + c.clockSkewSec <= now) refuse('wpt_expired', 'wpt exp has passed');
  // §2: "WPTs with an expiration time unreasonably far in the future SHOULD be rejected."
  if ((exp as number) - now > c.maxWptLifetimeSec + c.clockSkewSec) refuse('wpt_lifetime', 'wpt exp is too far in the future');
  const nbf = optionalTime(claims, 'nbf', 'wpt');
  if (nbf !== undefined && nbf > now + c.clockSkewSec) refuse('wpt_not_yet_valid', 'wpt nbf is in the future');
  const iat = optionalTime(claims, 'iat', 'wpt');
  if (iat !== undefined && iat > now + c.clockSkewSec) refuse('wpt_iat_future', 'wpt iat is in the future');

  const jti = claims.jti;
  if (typeof jti !== 'string' || jti.length < MIN_JTI_LENGTH || jti.length > MAX_JTI_LENGTH) {
    refuse('wpt_jti', `wpt jti missing or not ${MIN_JTI_LENGTH}..${MAX_JTI_LENGTH} characters`);
  }

  // §2 wth: SHA-256 of the ASCII WIT value.
  if (!hashMatches(claims.wth, sha256Digest(wit.token))) refuse('wpt_wth', 'wpt wth does not match the wit');

  // §2 tth: mandatory when a Txn-Token is in the request.
  const txn = singleHeader(req, 'txn-token');
  if (txn !== undefined) {
    if (claims.tth === undefined) refuse('wpt_tth_missing', 'txn-token present but wpt has no tth');
    if (!hashMatches(claims.tth, sha256Digest(txn))) refuse('wpt_tth', 'wpt tth does not match txn-token');
  } else if (claims.tth !== undefined) {
    refuse('wpt_tth_unexpected', 'wpt tth present but request has no txn-token');
  }

  // §2 oth: each key a lower-case header name present once in the request;
  // value = hash of the trimmed header value. Any entry not understood fails.
  if (claims.oth !== undefined) {
    if (!isPlainObject(claims.oth)) refuse('wpt_oth', 'wpt oth is not an object');
    for (const [name, hash] of Object.entries(claims.oth as Record<string, unknown>)) {
      if (name.length === 0 || name !== name.toLowerCase()) refuse('wpt_oth', 'wpt oth key is not a lower-case header name');
      const value = Object.prototype.hasOwnProperty.call(req.headers, name) ? singleHeader(req, name) : undefined;
      if (value === undefined) refuse('wpt_oth', 'wpt oth names a header absent from the request');
      if (!hashMatches(hash, sha256Digest((value as string).trim()))) refuse('wpt_oth', 'wpt oth hash does not match');
    }
  }

  return { jti: jti as string, exp: exp as number, claims };
}

export function createWimseIdentitySource(config: WimseSourceConfig): ExternalIdentitySource {
  if (!config || !config.replay) throw new Error('wimse: replay cache is required');
  if (!config.trustDomains || Object.keys(config.trustDomains).length === 0) {
    throw new Error('wimse: at least one trust domain is required');
  }
  for (const td of Object.keys(config.trustDomains)) {
    if (!/^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])$/.test(td)) throw new Error(`wimse: invalid trust domain "${td}"`);
  }
  // Validates numbers once at construction, so a bad config fails at startup.
  const resolved = resolveConfig(config);
  const verifyCfg: WimseVerifyConfig = { ...config, now: resolved.now };

  return {
    kind: 'wimse',
    async authenticate(req: IdentityRequest): Promise<VerifiedExternalIdentity | null> {
      const rawWit = req.headers['workload-identity-token'];
      if (rawWit === undefined) return null;
      if (Array.isArray(rawWit) || typeof rawWit !== 'string') {
        refuse('multiple_wit', 'workload-identity-token occurs more than once');
      }

      // wpt-02 §2.2: exactly one Authorization field using the WPT scheme;
      // a WIT alone, or with a Bearer token, is not accepted.
      const auth = req.headers['authorization'];
      if (Array.isArray(auth)) refuse('proof_required', 'more than one authorization header');
      // Node keeps only the first Authorization field; count the raw ones
      // (wpt-02 §2.2: a sender MUST NOT generate more than one).
      if (req.rawHeaders) {
        let fields = 0;
        for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() === 'authorization') fields++;
        if (fields > 1) refuse('proof_required', 'more than one authorization header');
      }
      if (typeof auth !== 'string') refuse('proof_required', 'no authorization header with the WPT scheme');
      const m = /^([A-Za-z0-9!#$%&'*+.^_`|~-]+) +(\S+)$/.exec((auth as string).trim());
      if (!m || m[1].toLowerCase() !== 'wpt') refuse('proof_required', 'authorization scheme is not WPT');
      const wptToken = (m as RegExpExecArray)[2];
      if (!TOKEN68.test(wptToken)) refuse('malformed_wpt', 'wpt credentials are not token68');

      const wit = verifyWit(rawWit as string, verifyCfg);
      const wpt = verifyWpt(wptToken, wit, req, verifyCfg);

      // Recorded only after both signatures and all claims pass, so a forged
      // proof cannot burn a legitimate jti (wpt-02 §3.1.4). The entry lives
      // until exp + skew: that is how long verifyWpt would still accept it.
      const replayUntil = wpt.exp + resolved.clockSkewSec;
      if (!config.replay.checkAndRecord(`wpt:${wpt.jti}`, replayUntil, resolved.now())) {
        refuse('replay', 'wpt jti already used');
      }

      return {
        kind: 'wimse',
        subject: wit.subject,
        trustDomain: wit.trustDomain,
        attributes: { cnfJkt: wit.cnfJkt },
        proof: 'wpt',
        expiresAt: Math.min(wit.exp, wpt.exp),
      };
    },
  };
}

/**
 * Cred Link server: client authentication for PAR and the connection API
 * (decision 3).
 *
 *   client_secret_basic  `Authorization: Basic base64(urlenc(id):urlenc(secret))`
 *                        (RFC 6749 2.3.1). The secret is compared as a
 *                        SHA-256 digest in constant time.
 *   private_key_jwt      RFC 7523 client assertion. On every route it may
 *                        travel as `Authorization: Bearer <jwt>`; on routes
 *                        with a body it may instead be sent as
 *                        `client_assertion_type` + `client_assertion` body
 *                        fields. iss = sub = client_id, aud = the server's
 *                        base URL (redirectBaseUri, or the Link base URL),
 *                        exp - iat at most LINK_CLIENT_ASSERTION_MAX_LIFETIME_SECONDS,
 *                        jti single use for the assertion's lifetime.
 *
 * Every failure returns null; the caller answers with the opaque failure.
 * Unknown clients still pay for a digest comparison.
 */

import crypto from 'node:crypto';
import type { Request } from 'express';
import {
  LINK_CLIENT_ASSERTION_MAX_LIFETIME_SECONDS,
  LINK_CLIENT_ASSERTION_TYPE,
  isLinkClientId,
} from '@credninja/protocol';
import type { LinkClient, LinkJwk, LinkStore } from '@credninja/protocol';
import { hexDigestsEqual, sha256Hex, trimTrailingSlashes } from './util.js';

/** Clock skew tolerated on assertion iat/exp/nbf, seconds. */
const ASSERTION_SKEW_SECONDS = 30;
const MAX_ASSERTION_LENGTH = 8192;
const MAX_JTI_LENGTH = 256;
const DUMMY_DIGEST = sha256Hex('cred-link-dummy-secret');

/** Algorithms accepted for client assertions, by JWK key type. */
const ALGORITHMS: Record<string, { kty: string; hash: string | null; pss?: boolean; curve?: string }> = {
  RS256: { kty: 'RSA', hash: 'sha256' },
  RS384: { kty: 'RSA', hash: 'sha384' },
  RS512: { kty: 'RSA', hash: 'sha512' },
  PS256: { kty: 'RSA', hash: 'sha256', pss: true },
  PS384: { kty: 'RSA', hash: 'sha384', pss: true },
  PS512: { kty: 'RSA', hash: 'sha512', pss: true },
  ES256: { kty: 'EC', hash: 'sha256', curve: 'P-256' },
  ES384: { kty: 'EC', hash: 'sha384', curve: 'P-384' },
  ES512: { kty: 'EC', hash: 'sha512', curve: 'P-521' },
  EdDSA: { kty: 'OKP', hash: null, curve: 'Ed25519' },
};

/** Smallest RSA modulus accepted for client keys. */
const MIN_RSA_MODULUS_BITS = 2048;

const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

/**
 * Validate a JWKS submitted at registration: 1 to 10 public RSA, EC or OKP
 * (Ed25519) keys that Node can import, no private members, unique kids,
 * RSA moduli of at least 2048 bits.
 */
export function validateClientJwks(value: unknown): { keys: LinkJwk[] } | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const keys = (value as { keys?: unknown }).keys;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 10) return null;
  const kids = new Set<string>();
  const out: LinkJwk[] = [];
  for (const candidate of keys) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null;
    const jwk = candidate as LinkJwk;
    if (jwk.kty !== 'RSA' && jwk.kty !== 'EC' && jwk.kty !== 'OKP') return null;
    if (PRIVATE_JWK_MEMBERS.some((m) => m in jwk)) return null;
    if (jwk.kid !== undefined) {
      if (typeof jwk.kid !== 'string' || jwk.kid === '' || jwk.kid.length > 128 || kids.has(jwk.kid)) return null;
      kids.add(jwk.kid);
    }
    if (jwk.alg !== undefined && (typeof jwk.alg !== 'string' || !ALGORITHMS[jwk.alg] || ALGORITHMS[jwk.alg].kty !== jwk.kty)) return null;
    if (jwk.kty === 'OKP' && jwk.crv !== 'Ed25519') return null;
    let key: crypto.KeyObject;
    try {
      key = crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' });
    } catch {
      return null;
    }
    if (jwk.kty === 'RSA' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_MODULUS_BITS) return null;
    out.push({ ...jwk });
  }
  return { keys: out };
}

/** Single-use jti tracking for client assertions (per process). */
export class AssertionReplayCache {
  private readonly seen = new Map<string, number>();

  /** Record (client, jti) until `expiresAtMs`; false when already seen. */
  remember(clientId: string, jti: string, expiresAtMs: number, nowMs = Date.now()): boolean {
    this.prune(nowMs);
    const key = `${clientId}\u0000${jti}`;
    if (this.seen.has(key)) return false;
    this.seen.set(key, expiresAtMs);
    return true;
  }

  prune(nowMs = Date.now()): void {
    for (const [key, expiresAt] of this.seen) {
      if (expiresAt <= nowMs) this.seen.delete(key);
    }
  }
}

function decodeSegment(segment: string): Record<string, unknown> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function verifyJwsSignature(alg: string, jwk: LinkJwk, signingInput: string, signature: Buffer): boolean {
  const spec = ALGORITHMS[alg];
  if (!spec || spec.kty !== jwk.kty) return false;
  if (jwk.alg !== undefined && jwk.alg !== alg) return false;
  if (spec.curve && jwk.crv !== spec.curve) return false;
  if (jwk.use !== undefined && jwk.use !== 'sig') return false;
  let key: crypto.KeyObject;
  try {
    key = crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: 'jwk' });
  } catch {
    return false;
  }
  const data = Buffer.from(signingInput, 'ascii');
  try {
    if (spec.kty === 'OKP') return crypto.verify(null, data, key, signature);
    if (spec.kty === 'EC') return crypto.verify(spec.hash, data, { key, dsaEncoding: 'ieee-p1363' }, signature);
    if (spec.pss) {
      return crypto.verify(spec.hash, data, {
        key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      }, signature);
    }
    return crypto.verify(spec.hash, data, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
  } catch {
    return false;
  }
}

export interface LinkClientAuthenticatorOptions {
  store: Pick<LinkStore, 'getClient'>;
  /** Accepted `aud` values (no trailing slash). */
  audiences: string[];
  replay?: AssertionReplayCache;
}

type CredentialSource =
  | { kind: 'basic'; clientId: string; secret: string }
  | { kind: 'assertion'; jwt: string }
  | { kind: 'none' };

function formDecode(value: string): string | null {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return null;
  }
}

/** Which credential the request carries. More than one, or a malformed one, is 'none'. */
function credentialOf(req: Request): CredentialSource {
  const header = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
  const body = req.body && typeof req.body === 'object' ? req.body as Record<string, unknown> : {};
  const bodyAssertion = body.client_assertion;
  const bodyAssertionType = body.client_assertion_type;
  const hasBodyAssertion = bodyAssertion !== undefined || bodyAssertionType !== undefined;

  // Auth schemes are case-insensitive (RFC 9110 11.1).
  const basicMatch = /^basic[ \t]+(\S+)[ \t]*$/i.exec(header);
  const bearerMatch = /^bearer[ \t]+(\S+)[ \t]*$/i.exec(header);
  if (basicMatch) {
    if (hasBodyAssertion) return { kind: 'none' };
    let decoded: string;
    try {
      decoded = Buffer.from(basicMatch[1], 'base64').toString('utf8');
    } catch {
      return { kind: 'none' };
    }
    const colon = decoded.indexOf(':');
    if (colon <= 0) return { kind: 'none' };
    const clientId = formDecode(decoded.slice(0, colon));
    const secret = formDecode(decoded.slice(colon + 1));
    if (!clientId || !secret) return { kind: 'none' };
    return { kind: 'basic', clientId, secret };
  }
  if (bearerMatch) {
    if (hasBodyAssertion) return { kind: 'none' };
    return { kind: 'assertion', jwt: bearerMatch[1] };
  }
  if (header !== '') return { kind: 'none' };
  if (bodyAssertionType === LINK_CLIENT_ASSERTION_TYPE && typeof bodyAssertion === 'string' && bodyAssertion !== '') {
    return { kind: 'assertion', jwt: bodyAssertion };
  }
  return { kind: 'none' };
}

/** Authenticates Link clients. */
export class LinkClientAuthenticator {
  private readonly replay: AssertionReplayCache;
  private readonly audiences: Set<string>;

  constructor(private readonly options: LinkClientAuthenticatorOptions) {
    this.replay = options.replay ?? new AssertionReplayCache();
    this.audiences = new Set(options.audiences.map(trimTrailingSlashes));
  }

  /** The authenticated, active client, or null for any failure. */
  async authenticate(req: Request, nowMs = Date.now()): Promise<LinkClient | null> {
    const credential = credentialOf(req);
    if (credential.kind === 'basic') return this.basic(credential.clientId, credential.secret);
    if (credential.kind === 'assertion') return this.assertion(credential.jwt, nowMs);
    return null;
  }

  private async basic(clientId: string, secret: string): Promise<LinkClient | null> {
    const presented = sha256Hex(secret);
    const client = isLinkClientId(clientId) ? await this.options.store.getClient(clientId) : null;
    const usable = client !== null && client.status === 'active' && client.token_endpoint_auth_method === 'client_secret_basic';
    const expected = usable ? client.client_secret_hash : DUMMY_DIGEST;
    const match = hexDigestsEqual(presented, expected);
    return usable && match ? client : null;
  }

  private async assertion(jwt: string, nowMs: number): Promise<LinkClient | null> {
    if (jwt.length > MAX_ASSERTION_LENGTH) return null;
    const parts = jwt.split('.');
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const header = decodeSegment(h);
    const payload = decodeSegment(p);
    if (!header || !payload || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
    const alg = header.alg;
    if (typeof alg !== 'string' || !ALGORITHMS[alg]) return null;
    if (header.crit !== undefined) return null;

    const iss = payload.iss;
    if (typeof iss !== 'string' || !isLinkClientId(iss) || payload.sub !== iss) return null;
    const client = await this.options.store.getClient(iss);
    if (!client || client.status !== 'active' || client.token_endpoint_auth_method !== 'private_key_jwt') return null;

    const kid = header.kid;
    if (kid !== undefined && typeof kid !== 'string') return null;
    const candidates = client.jwks.keys.filter((k) => (kid === undefined ? true : k.kid === kid));
    const signature = Buffer.from(s, 'base64url');
    const signingInput = `${h}.${p}`;
    if (!candidates.some((k) => verifyJwsSignature(alg, k, signingInput, signature))) return null;

    // Claims.
    const aud = payload.aud;
    const auds = Array.isArray(aud) ? aud : [aud];
    if (auds.length === 0 || !auds.every((a) => typeof a === 'string')) return null;
    if (!auds.some((a) => this.audiences.has(trimTrailingSlashes(a as string)))) return null;
    const exp = payload.exp;
    const iat = payload.iat;
    if (typeof exp !== 'number' || typeof iat !== 'number' || !Number.isFinite(exp) || !Number.isFinite(iat)) return null;
    const nowSec = nowMs / 1000;
    if (exp <= nowSec - ASSERTION_SKEW_SECONDS) return null;
    if (iat > nowSec + ASSERTION_SKEW_SECONDS) return null;
    if (exp <= iat || exp - iat > LINK_CLIENT_ASSERTION_MAX_LIFETIME_SECONDS) return null;
    if (payload.nbf !== undefined && (typeof payload.nbf !== 'number' || payload.nbf > nowSec + ASSERTION_SKEW_SECONDS)) return null;
    const jti = payload.jti;
    if (typeof jti !== 'string' || jti === '' || jti.length > MAX_JTI_LENGTH) return null;
    if (!this.replay.remember(client.client_id, jti, (exp + ASSERTION_SKEW_SECONDS) * 1000, nowMs)) return null;
    return client;
  }

  /** Drop expired jti entries (called by the sweep). */
  prune(nowMs = Date.now()): void {
    this.replay.prune(nowMs);
  }
}

/**
 * DPoP proofs (RFC 9449) that tie a Delegation Token to the key of the
 * agent it was issued to.
 *
 * A Delegation Token carries the RFC 7638 thumbprint of the agent's did:key
 * in `cnf.jkt`. Every exercise presents the token as `Authorization: DPoP
 * <token>` with a `DPoP` header: a JWS of type `dpop+jwt`, signed by that
 * key, naming the HTTP method and URL of the request, the token (`ath`, the
 * SHA-256 of the token, RFC 9449 Section 4.2) and, through `cred_req`, the
 * exact request body. A token copied out of a log or a prompt is useless
 * without the agent's private key.
 */
import { createHash, createPublicKey, type KeyObject } from 'node:crypto';
import {
  canonicalJson,
  checkJwsSignature,
  createVerificationKey,
  didKeyConfirmation,
  jwkThumbprint,
  parseStrictJson,
  publicKeyFromDidKey,
} from '@credninja/attenuation';

/** Algorithms a proof may use: the same list actor tokens accept. */
export const DPOP_ACCEPTED_ALGS = ['EdDSA', 'ES256'] as const;
/** How old a proof's `iat` may be. Proofs are made per request. */
export const DPOP_MAX_AGE_SECONDS = 120;
/** How far in the future a proof's `iat` may be (clock skew). */
export const DPOP_CLOCK_SKEW_SECONDS = 60;

export type DpopResult = { ok: true; jkt: string; jti: string } | { ok: false; message: string };

/** `ath` for an access token: base64url SHA-256 of the token (RFC 9449 Section 4.2). */
export function dpopAth(token: string): string {
  return createHash('sha256').update(token, 'ascii').digest('base64url');
}

/**
 * `cred_req` for a /api/v1/use request body: base64url SHA-256 of its RFC
 * 8785 serialization. Null when the body has no canonical JSON form.
 */
export function dpopRequestHash(requestBody: unknown): string | null {
  try {
    return createHash('sha256').update(canonicalJson(requestBody), 'utf8').digest('base64url');
  } catch {
    return null;
  }
}

/** The thumbprint a handle issued to `agentDid` is bound to, or null when the DID carries no key. */
export function dpopBindingFor(agentDid: string | undefined): string | null {
  if (!agentDid) return null;
  return didKeyConfirmation(agentDid)?.jkt ?? null;
}

/**
 * Read the single `DPoP` header of a request. Express joins repeated headers
 * with ", "; a compact JWS never contains a comma, so a comma means more than
 * one header, which RFC 9449 section 4.3 rejects.
 */
export function readDpopHeader(value: string | string[] | undefined): string | null | 'multiple' {
  if (value === undefined) return null;
  if (Array.isArray(value)) return value.length === 1 ? readDpopHeader(value[0]) : 'multiple';
  const trimmed = value.trim();
  if (trimmed === '') return null;
  return trimmed.includes(',') ? 'multiple' : trimmed;
}

function decodeJson(segment: string): Record<string, unknown> | null {
  try {
    const value = parseStrictJson(Buffer.from(segment, 'base64url').toString('utf8'));
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function publicKeyFromJwk(jwk: Record<string, unknown>): KeyObject | null {
  // A proof carries the public key only; a private member is a client bug
  // that would leak the key, and is refused.
  if ('d' in jwk) return null;
  try {
    const key = createPublicKey({ key: jwk as never, format: 'jwk' });
    return key.type === 'public' ? key : null;
  } catch {
    return null;
  }
}

/**
 * Verify a DPoP proof for one request.
 *
 * - `agentDid`: the did:key the handle (or the delegation being requested)
 *   names. The proof's `jwk` must be that key and the signature must verify
 *   under it.
 * - `htm` / `htu`: the method and the URL, without query or fragment, the
 *   proof must name.
 * - `ath`: when set, the proof must carry it (binds the proof to one handle).
 * - `seenJti`: replay cache; returns true when the key has been seen.
 */
export function verifyDpopProof(
  proof: unknown,
  opts: {
    agentDid: string;
    htm: string;
    htu: string;
    ath?: string;
    /** When set, the proof's `cred_req` must equal it (binds one request). */
    req?: string;
    seenJti: (key: string, exp: number) => boolean;
    nowSeconds?: number;
  },
): DpopResult {
  const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (typeof proof !== 'string' || proof === '') return { ok: false, message: 'a DPoP proof is required' };
  const expectedJkt = dpopBindingFor(opts.agentDid);
  const didKey = publicKeyFromDidKey(opts.agentDid);
  if (!expectedJkt || !didKey) return { ok: false, message: `${opts.agentDid} is not a did:key; no key to prove possession of` };

  const parts = proof.split('.');
  if (parts.length !== 3) return { ok: false, message: 'DPoP proof is not a compact JWS' };
  const header = decodeJson(parts[0]!);
  const claims = decodeJson(parts[1]!);
  if (!header || !claims) return { ok: false, message: 'DPoP proof header or claims are not JSON objects' };

  if (header.typ !== 'dpop+jwt') return { ok: false, message: 'DPoP proof typ must be dpop+jwt' };
  if (typeof header.jwk !== 'object' || header.jwk === null || Array.isArray(header.jwk)) {
    return { ok: false, message: 'DPoP proof header must carry the public jwk' };
  }
  const headerKey = publicKeyFromJwk(header.jwk as Record<string, unknown>);
  if (!headerKey) return { ok: false, message: 'DPoP proof jwk is not a usable public key' };
  let headerJkt: string;
  try {
    headerJkt = jwkThumbprint(headerKey);
  } catch {
    return { ok: false, message: 'DPoP proof jwk is not an Ed25519 or P-256 key' };
  }
  if (headerJkt !== expectedJkt) return { ok: false, message: `DPoP proof key is not the key of ${opts.agentDid}` };

  const verificationKey = createVerificationKey(didKey);
  const failure = checkJwsSignature(
    header,
    Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'),
    Buffer.from(parts[2]!, 'base64url'),
    DPOP_ACCEPTED_ALGS,
    () => verificationKey,
  );
  if (failure) return { ok: false, message: `DPoP proof signature did not verify (${failure})` };

  if (claims.htm !== opts.htm) return { ok: false, message: `DPoP proof htm must be ${opts.htm}` };
  if (typeof claims.htu !== 'string' || normalizeHtu(claims.htu) === null || normalizeHtu(claims.htu) !== normalizeHtu(opts.htu)) {
    return { ok: false, message: `DPoP proof htu must be ${opts.htu}` };
  }
  if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) return { ok: false, message: 'DPoP proof needs a numeric iat' };
  if (claims.iat > now + DPOP_CLOCK_SKEW_SECONDS) return { ok: false, message: 'DPoP proof iat is in the future' };
  if (claims.iat < now - DPOP_MAX_AGE_SECONDS) return { ok: false, message: 'DPoP proof is too old' };
  if (typeof claims.jti !== 'string' || claims.jti === '' || claims.jti.length > 256) {
    return { ok: false, message: 'DPoP proof needs a jti of at most 256 characters' };
  }
  if (opts.ath !== undefined && claims.ath !== opts.ath) return { ok: false, message: 'DPoP proof ath does not match the handle' };
  if (opts.req !== undefined && claims.cred_req !== opts.req) {
    return { ok: false, message: 'DPoP proof cred_req does not match this request (URL, method, body or headers)' };
  }
  // Keyed by thumbprint so two agents cannot collide on a jti.
  if (opts.seenJti(`${expectedJkt}:${claims.jti}`, claims.iat + DPOP_MAX_AGE_SECONDS)) {
    return { ok: false, message: 'DPoP proof jti was already used' };
  }
  return { ok: true, jkt: expectedJkt, jti: claims.jti };
}

/**
 * `htu` for comparison (RFC 9449 section 4.3): scheme and host
 * case-insensitive, default port dropped, query and fragment ignored. The
 * host is compared as written: localhost and 127.0.0.1 are different URLs.
 */
export function normalizeHtu(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
}

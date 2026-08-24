/**
 * Proof-of-possession (mandatory).
 *
 * A delegation receipt binds a subject: the agent's did:key (an Ed25519 public
 * key). Possession of the receipt alone is not enough to call the proxy. Every
 * credentialed request must also carry a PoP proof: a short-lived compact JWS,
 * signed by the agent's did:key *private* key, that binds this specific request
 * to this specific receipt. A stolen receipt without the private key is inert.
 *
 * The proof (a DPoP-style token, RFC 9449 in spirit) is sent in the
 * `X64dbg-PoP` header. Its payload binds:
 *   htm  HTTP method
 *   htu  request path (defence-in-depth against cross-endpoint replay)
 *   iat  issued-at (freshness window)
 *   jti  unique nonce (single-use, replay cache)
 *   ath  base64url(sha256(receipt))  -> ties the proof to THIS receipt
 *   bh   base64url(sha256(body))      -> ties the proof to THIS body (POST)
 *
 * The verifying key is taken from the *receipt's verified subject*, never from
 * the proof itself, so the proof cannot assert its own identity.
 */

import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(str: string): Uint8Array {
  const map = new Map<string, number>();
  for (let i = 0; i < BASE58_ALPHABET.length; i++) map.set(BASE58_ALPHABET[i], i);

  const bytes: number[] = [0];
  for (const ch of str) {
    const value = map.get(ch);
    if (value === undefined) throw new Error(`invalid base58 character: ${ch}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading '1's are leading zero bytes.
  for (let k = 0; k < str.length && str[k] === '1'; k++) bytes.push(0);
  return Uint8Array.from(bytes.reverse());
}

/** Decode a did:key (Ed25519) into a public KeyObject. Throws on anything else. */
export function didKeyToPublicKey(did: string): KeyObject {
  if (!did.startsWith('did:key:z')) throw new Error('subject is not a did:key');
  const decoded = base58Decode(did.slice('did:key:z'.length));
  // Multicodec prefix for Ed25519 public keys is 0xed 0x01.
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('did:key is not an Ed25519 key');
  }
  const raw = decoded.slice(2);
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
    format: 'der',
    type: 'spki',
  });
}

/** Single-use nonce cache with time-based eviction. In-process; a shared store is the production form. */
export class NonceStore {
  private readonly seen = new Map<string, number>();
  constructor(private readonly ttlMs: number) {}

  /** Returns true if jti is fresh (and records it); false if already seen. */
  checkAndRecord(jti: string, nowMs: number): boolean {
    this.prune(nowMs);
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, nowMs + this.ttlMs);
    return true;
  }

  private prune(nowMs: number): void {
    for (const [k, exp] of this.seen) {
      if (exp <= nowMs) this.seen.delete(k);
    }
  }
}

export function sha256Base64Url(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('base64url');
}

export interface PopVerifyParams {
  method: string;
  path: string;
  /** DID from the verified receipt subject. */
  subjectDid: string;
  /** The raw receipt JWS string, to bind via `ath`. */
  receipt: string;
  /** base64url(sha256(body)) for requests with a body; omit for GET. */
  bodyHashB64?: string;
  windowSeconds: number;
  nonceStore: NonceStore;
  nowMs: number;
}

export interface PopResult {
  ok: boolean;
  reason?: string;
}

interface PopPayload {
  htm?: string;
  htu?: string;
  iat?: number;
  jti?: string;
  ath?: string;
  bh?: string;
}

export function verifyPop(proof: string | undefined, p: PopVerifyParams): PopResult {
  if (!proof) return { ok: false, reason: 'missing_pop' };

  const parts = proof.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed_pop' };
  const [headerB64, payloadB64, sigB64] = parts;

  let header: { alg?: string; typ?: string };
  let payload: PopPayload;
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, reason: 'malformed_pop' };
  }
  if (header.alg !== 'EdDSA') return { ok: false, reason: 'pop_bad_alg' };

  // Verify the signature against the RECEIPT's subject key (not the proof's).
  let publicKey: KeyObject;
  try {
    publicKey = didKeyToPublicKey(p.subjectDid);
  } catch (err) {
    return { ok: false, reason: `pop_bad_subject:${(err as Error).message}` };
  }
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
  let signatureValid = false;
  try {
    signatureValid = verify(null, signingInput, publicKey, Buffer.from(sigB64, 'base64url'));
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return { ok: false, reason: 'pop_bad_signature' };

  // Bindings — only trusted after the signature checks out.
  if (payload.htm !== p.method) return { ok: false, reason: 'pop_method_mismatch' };
  if (payload.htu !== p.path) return { ok: false, reason: 'pop_path_mismatch' };
  if (payload.ath !== sha256Base64Url(p.receipt)) return { ok: false, reason: 'pop_receipt_mismatch' };
  if (p.bodyHashB64 !== undefined && payload.bh !== p.bodyHashB64) return { ok: false, reason: 'pop_body_mismatch' };

  const nowSec = Math.floor(p.nowMs / 1000);
  if (typeof payload.iat !== 'number' || Math.abs(nowSec - payload.iat) > p.windowSeconds) {
    return { ok: false, reason: 'pop_stale' };
  }
  if (typeof payload.jti !== 'string' || payload.jti.length === 0) return { ok: false, reason: 'pop_no_jti' };
  if (!p.nonceStore.checkAndRecord(payload.jti, p.nowMs)) return { ok: false, reason: 'pop_replayed' };

  return { ok: true };
}

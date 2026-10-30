/**
 * Agent Identity — DID:key generation and management
 *
 * Uses Ed25519 key pairs with did:key encoding (RFC draft-multiformats-multibase).
 * Zero external dependencies — Node.js crypto module only.
 */

import { generateKeyPair, KeyObject, verify, sign, randomUUID, createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { promisify } from 'node:util';

const generateKeyPairAsync = promisify(generateKeyPair);

// ── Cred Public Key (pinned at build time) ───────────────────────────────────

/**
 * Cred's Ed25519 public key for verifying delegation receipts.
 */
export const CRED_PUBLIC_KEY_HEX = 'ed50f12caeed3e3054be071c2884fda47752a02b5d98e37dfd79db5fd502699f';

// Default max age for legacy receipts (no `exp` claim), matching the
// server's default receipt TTL. Allowed clock skew when checking `exp`.
const DEFAULT_RECEIPT_MAX_AGE_SECONDS = 3600;
const RECEIPT_CLOCK_SKEW_SECONDS = 60;

// ── Types ────────────────────────────────────────────────────────────────────

export type AgentStatus = 'active' | 'suspended' | 'revoked';

export interface GenerateIdentityOptions {
  scopeCeiling?: string[];
  status?: AgentStatus;
}

export interface AgentIdentity {
  /** DID in did:key format: did:key:z6Mk<base58-encoded-public-key> */
  did: string;
  /** Raw 32-byte Ed25519 public key */
  publicKey: Uint8Array;
  /** Raw 32-byte Ed25519 private key (caller must persist securely) */
  privateKey: Uint8Array;
  /** Maximum scopes this agent can ever request (empty = uncapped) */
  scopeCeiling: string[];
  /** Agent status — revoked agents cannot receive delegations */
  status: AgentStatus;
  /** Export identity for persistence */
  export(): ExportedIdentity;
}

export interface ExportedIdentity {
  did: string;
  privateKeyHex: string;
  scopeCeiling: string[];
  status: AgentStatus;
}

export interface ImportParams {
  did: string;
  privateKeyHex: string;
  scopeCeiling?: string[];
  status?: AgentStatus;
}

export interface VerifyReceiptOptions {
  /** Expected agent DID (sub claim in receipt payload) */
  expectedDid: string;
  /** Cred's public key in hex format (defaults to CRED_PUBLIC_KEY_HEX) */
  credPublicKey?: string;
  /**
   * Max age (seconds) allowed for legacy receipts that predate the `exp`
   * claim (falls back to `iat` + this value). Defaults to 3600 (1 hour) to
   * match the server's default receipt TTL. Ignored for receipts that carry
   * an `exp` claim — those are checked against `exp` directly.
   */
  maxAgeSeconds?: number;
}

export interface DelegationReceiptPayload {
  /** Issuer — Cred's DID (did:web:cred.ninja) */
  iss: string;
  /** Subject — the requesting agent's DID */
  sub: string;
  /** Issued at (Unix timestamp) */
  iat: number;
  /** Service slug */
  service: string;
  /** Granted scopes */
  scopes: string[];
  /** Pseudonymous user ID (hashed) */
  userId: string;
  /** App client ID */
  appClientId: string;
  /** Delegation identifier */
  delegationId?: string;
  /** Parent delegation identifier for sub-delegation chains */
  parentDelegationId?: string;
  /** Root delegation starts at 0 and increments per hop */
  chainDepth?: number;
  /** SHA-256 of the parent receipt when this is a child delegation */
  parentReceiptHash?: string;
  /** Expiry (Unix timestamp). Absent on legacy receipts minted before this claim existed. */
  exp?: number;
  /** Intended audience for the receipt (e.g. the issuing server's base URI) */
  aud?: string;
  /** The acting agent DID (draft-02 layout; legacy receipts carry it in `sub`). */
  client_id?: string;
  /** Current actor, `{ sub: <agent DID> }`, with prior actors nested (draft-02 layout). */
  act?: { sub: string; act?: unknown };
}

// ── Base58btc alphabet (Bitcoin) ─────────────────────────────────────────────

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Count leading zeros
  let zeros = 0;
  for (const byte of bytes) {
    if (byte !== 0) break;
    zeros++;
  }

  // Convert to big integer and repeatedly divide by 58
  const size = Math.ceil(bytes.length * 138 / 100) + 1;
  const b58 = new Uint8Array(size);
  let length = 0;

  for (const byte of bytes) {
    let carry = byte;
    let i = 0;
    for (let j = size - 1; (carry !== 0 || i < length) && j >= 0; j--, i++) {
      carry += 256 * b58[j];
      b58[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    length = i;
  }

  // Skip leading zeros in base58 result
  let start = size - length;
  while (start < size && b58[start] === 0) {
    start++;
  }

  // Build result string
  let result = '1'.repeat(zeros);
  for (let i = start; i < size; i++) {
    result += BASE58_ALPHABET[b58[i]];
  }

  return result;
}

// ── Ed25519 multicodec prefix ────────────────────────────────────────────────

// did:key multicodec prefix for Ed25519 public keys: 0xed01
// Encoded as varint: [0xed, 0x01]
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

// ── Core Functions ───────────────────────────────────────────────────────────

/**
 * Generate a new agent identity with Ed25519 key pair.
 *
 * @returns AgentIdentity with DID, public key, private key, and export function
 */
export async function generateAgentIdentity(
  opts?: GenerateIdentityOptions,
): Promise<AgentIdentity> {
  const { publicKey, privateKey } = await generateKeyPairAsync('ed25519');

  // Extract raw key bytes from KeyObjects
  const publicKeyBytes = extractRawPublicKey(publicKey);
  const privateKeyBytes = extractRawPrivateKey(privateKey);

  // Build did:key from public key
  const did = publicKeyToDid(publicKeyBytes);

  const scopeCeiling = opts?.scopeCeiling ?? [];
  const status: AgentStatus = opts?.status ?? 'active';

  return createIdentity(did, publicKeyBytes, privateKeyBytes, scopeCeiling, status);
}

/**
 * Import a persisted agent identity.
 *
 * @param params - The exported identity (DID + private key hex)
 * @returns AgentIdentity with full key pair
 */
export function importAgentIdentity(params: ImportParams): AgentIdentity {
  const { did, privateKeyHex, scopeCeiling, status } = params;

  // Validate DID format
  if (!did.startsWith('did:key:z')) {
    throw new Error('Invalid DID format: must start with did:key:z');
  }

  // Decode private key from hex
  const privateKeyBytes = hexToBytes(privateKeyHex);
  if (privateKeyBytes.length !== 32) {
    throw new Error('Invalid private key: must be 32 bytes');
  }

  // Derive public key from private key using Node.js crypto
  const privateKeyObject = createPrivateKey({
    key: Buffer.concat([
      // Ed25519 PKCS#8 prefix
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.from(privateKeyBytes),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKeyObject = createPublicKey(privateKeyObject);
  const publicKeyBytes = extractRawPublicKey(publicKeyObject);

  // Verify DID matches derived public key
  const derivedDid = publicKeyToDid(publicKeyBytes);
  if (derivedDid !== did) {
    throw new Error('DID does not match derived public key');
  }

  return createIdentity(did, publicKeyBytes, privateKeyBytes, scopeCeiling ?? [], status ?? 'active');
}

/**
 * Verify a delegation receipt from the Cred API.
 *
 * Receipts are JWS compact serialization (header.payload.signature) signed
 * by Cred's Ed25519 key. Returns true if signature is valid and DID matches.
 *
 * @param receipt - JWS compact serialization string (or null/undefined)
 * @param opts - Verification options
 * @returns true if receipt is valid and matches expected DID
 */
export async function verifyDelegationReceipt(
  receipt: string | null | undefined,
  opts: VerifyReceiptOptions,
): Promise<boolean> {
  // Return false for missing receipts (don't throw)
  if (!receipt) {
    return false;
  }

  const credPublicKeyHex = opts.credPublicKey ?? CRED_PUBLIC_KEY_HEX;

  // Placeholder check — can't verify without real key
  if (credPublicKeyHex === 'PLACEHOLDER_REPLACE_BEFORE_LAUNCH') {
    throw new Error('CRED_PUBLIC_KEY_HEX is placeholder — cannot verify receipts');
  }

  try {
    // Parse JWS compact serialization: header.payload.signature
    const parts = receipt.split('.');
    if (parts.length !== 3) {
      return false;
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode and validate header
    const header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
    if (header.alg !== 'EdDSA' || header.typ !== 'JWT') {
      return false;
    }

    // Verify signature FIRST, before trusting anything in the payload —
    // defense-in-depth: an attacker-controlled/unsigned payload should
    // never influence a claims/expiry decision. Only decode and act on the
    // payload once the signature is confirmed to have come from
    // `credPublicKeyHex`.
    const signatureInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
    const signature = base64UrlDecode(signatureB64);

    // Build Ed25519 public key object from raw bytes
    const credPublicKeyBytes = hexToBytes(credPublicKeyHex);
    if (credPublicKeyBytes.length !== 32) {
      return false;
    }

    const publicKeyObject = createPublicKey({
      key: Buffer.concat([
        // Ed25519 SPKI prefix
        Buffer.from('302a300506032b6570032100', 'hex'),
        Buffer.from(credPublicKeyBytes),
      ]),
      format: 'der',
      type: 'spki',
    });

    const signatureValid = verify(null, signatureInput, publicKeyObject, signature);
    if (!signatureValid) {
      return false;
    }

    // Only now decode and trust claims from the payload.
    const payload: DelegationReceiptPayload = JSON.parse(
      base64UrlDecode(payloadB64).toString('utf8'),
    );
    // The acting agent: `act.sub` (which must equal `client_id`) on a
    // receipt in the draft-02 claim layout, where `sub` names the principal;
    // `sub` on a legacy receipt.
    const act = (payload as { act?: unknown }).act;
    let agentDid: unknown = payload.sub;
    if (act !== undefined) {
      if (typeof act !== 'object' || act === null || (act as { sub?: unknown }).sub !== payload.client_id) {
        return false;
      }
      agentDid = payload.client_id;
    }
    if (agentDid !== opts.expectedDid) {
      return false;
    }

    // Expiry check. Receipts with an `exp` claim are rejected once they age
    // past it (with a small allowance for clock skew). Legacy receipts
    // (minted before `exp` existed) fall back to `iat` + maxAgeSeconds, so
    // they age out rather than remaining valid forever.
    const nowSeconds = Math.floor(Date.now() / 1000);
    const maxAgeSeconds = opts.maxAgeSeconds ?? DEFAULT_RECEIPT_MAX_AGE_SECONDS;
    if (typeof payload.exp === 'number') {
      if (nowSeconds > payload.exp + RECEIPT_CLOCK_SKEW_SECONDS) {
        return false;
      }
    } else if (typeof payload.iat === 'number') {
      if (nowSeconds > payload.iat + maxAgeSeconds) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

// ── Internal Helpers ─────────────────────────────────────────────────────────

function createIdentity(
  did: string,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  scopeCeiling: string[],
  status: AgentStatus,
): AgentIdentity {
  // Store copies internally
  const pubKeyCopy = new Uint8Array(publicKey);
  const privKeyCopy = new Uint8Array(privateKey);
  const ceilCopy = [...scopeCeiling];

  return {
    did,
    scopeCeiling: ceilCopy,
    status,
    // Return fresh copies to prevent accidental mutation
    get publicKey(): Uint8Array {
      return new Uint8Array(pubKeyCopy);
    },
    get privateKey(): Uint8Array {
      return new Uint8Array(privKeyCopy);
    },
    export(): ExportedIdentity {
      return {
        did,
        privateKeyHex: bytesToHex(privKeyCopy),
        scopeCeiling: [...ceilCopy],
        status,
      };
    },
  };
}

/**
 * An RFC 7523 JWT assertion signed with the agent's own did:key: `iss` and
 * `sub` are the agent DID, `aud` the endpoint it is presented to. The Cred
 * server takes it as `actor_token` on `/api/v1/subdelegate` (proving the
 * caller is the agent its parent receipt names) and on `/api/v1/token`.
 * Valid for two minutes; the server rejects a replayed `jti`.
 */
export function createActorToken(identity: Pick<AgentIdentity, 'did' | 'privateKey'>, audience: string): string {
  const now = Math.floor(Date.now() / 1000);
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const signingInput = `${encode({ alg: 'EdDSA', typ: 'JWT' })}.${encode({
    iss: identity.did,
    sub: identity.did,
    aud: audience,
    iat: now,
    exp: now + 120,
    jti: randomUUID(),
  })}`;
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(identity.privateKey)]),
    format: 'der',
    type: 'pkcs8',
  });
  return `${signingInput}.${sign(null, Buffer.from(signingInput, 'utf8'), key).toString('base64url')}`;
}

/**
 * A DPoP proof (RFC 9449) signed with the agent's own did:key, for one
 * request to the Cred server. `htm` and `htu` name the method and URL
 * (without query or fragment). With `handle`, the proof also commits to that
 * delegation handle (`ath`, base64url SHA-256 of the handle id), so it cannot
 * be replayed against another handle. The server rejects a proof older than
 * two minutes or a replayed `jti`; make a new one per request.
 */
export function createDpopProof(
  identity: Pick<AgentIdentity, 'did' | 'privateKey'>,
  htm: string,
  htu: string,
  handle?: string,
): string {
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(identity.privateKey)]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicJwk = createPublicKey(key).export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const signingInput = `${encode({ alg: 'EdDSA', typ: 'dpop+jwt', jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x } })}.${encode({
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
    ...(handle !== undefined ? { ath: createHash('sha256').update(handle, 'ascii').digest('base64url') } : {}),
  })}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput, 'utf8'), key).toString('base64url')}`;
}

function publicKeyToDid(publicKey: Uint8Array): string {
  // Prepend multicodec prefix and encode as base58btc
  const prefixed = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + publicKey.length);
  prefixed.set(ED25519_MULTICODEC_PREFIX);
  prefixed.set(publicKey, ED25519_MULTICODEC_PREFIX.length);

  // 'z' is the multibase prefix for base58btc
  return `did:key:z${encodeBase58(prefixed)}`;
}

function extractRawPublicKey(keyObject: KeyObject): Uint8Array {
  // Export as SubjectPublicKeyInfo (SPKI) DER format
  const spki = keyObject.export({ type: 'spki', format: 'der' });
  // Ed25519 SPKI is 44 bytes: 12-byte header + 32-byte key
  // The raw key is the last 32 bytes
  return new Uint8Array(spki.slice(-32));
}

function extractRawPrivateKey(keyObject: KeyObject): Uint8Array {
  // Export as PKCS#8 DER format
  const pkcs8 = keyObject.export({ type: 'pkcs8', format: 'der' });
  // Ed25519 PKCS#8 is 48 bytes: 16-byte header + 32-byte key
  // The raw key is the last 32 bytes
  return new Uint8Array(pkcs8.slice(-32));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length');
  }
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function base64UrlDecode(str: string): Buffer {
  // Replace URL-safe characters and add padding
  const base64 = str
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(str.length + ((4 - (str.length % 4)) % 4), '=');
  return Buffer.from(base64, 'base64');
}

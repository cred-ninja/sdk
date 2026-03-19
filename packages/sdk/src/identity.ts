/**
 * Agent Identity — DID:key generation and management
 *
 * Uses Ed25519 key pairs with did:key encoding (RFC draft-multiformats-multibase).
 * Zero external dependencies — Node.js crypto module only.
 */

import { generateKeyPair, KeyObject, verify, createPublicKey } from 'node:crypto';
import { promisify } from 'node:util';

const generateKeyPairAsync = promisify(generateKeyPair);

// ── Cred Public Key (pinned at build time) ───────────────────────────────────

/**
 * Cred's Ed25519 public key for verifying delegation receipts.
 * PLACEHOLDER — will be replaced with real key before launch.
 */
export const CRED_PUBLIC_KEY_HEX = 'PLACEHOLDER_REPLACE_BEFORE_LAUNCH';

// ── Types ────────────────────────────────────────────────────────────────────

export interface AgentIdentity {
  /** DID in did:key format: did:key:z6Mk<base58-encoded-public-key> */
  did: string;
  /** Raw 32-byte Ed25519 public key */
  publicKey: Uint8Array;
  /** Raw 32-byte Ed25519 private key (caller must persist securely) */
  privateKey: Uint8Array;
  /** Export identity for persistence */
  export(): ExportedIdentity;
}

export interface ExportedIdentity {
  did: string;
  privateKeyHex: string;
}

export interface ImportParams {
  did: string;
  privateKeyHex: string;
}

export interface VerifyReceiptOptions {
  /** Expected agent DID (sub claim in receipt payload) */
  expectedDid: string;
  /** Cred's public key in hex format (defaults to CRED_PUBLIC_KEY_HEX) */
  credPublicKey?: string;
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

function decodeBase58(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Build alphabet lookup
  const lookup: Record<string, number> = {};
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    lookup[BASE58_ALPHABET[i]] = i;
  }

  // Count leading '1's (zeros)
  let zeros = 0;
  for (const char of str) {
    if (char !== '1') break;
    zeros++;
  }

  // Decode to bytes
  const size = Math.ceil(str.length * 733 / 1000) + 1;
  const bytes = new Uint8Array(size);
  let length = 0;

  for (const char of str) {
    const value = lookup[char];
    if (value === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    let carry = value;
    let i = 0;
    for (let j = size - 1; (carry !== 0 || i < length) && j >= 0; j--, i++) {
      carry += 58 * bytes[j];
      bytes[j] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    length = i;
  }

  // Skip leading zeros in byte array
  let start = size - length;
  while (start < size && bytes[start] === 0) {
    start++;
  }

  // Prepend zeros and return
  const result = new Uint8Array(zeros + (size - start));
  result.fill(0, 0, zeros);
  result.set(bytes.slice(start), zeros);

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
export async function generateAgentIdentity(): Promise<AgentIdentity> {
  const { publicKey, privateKey } = await generateKeyPairAsync('ed25519');

  // Extract raw key bytes from KeyObjects
  const publicKeyBytes = extractRawPublicKey(publicKey);
  const privateKeyBytes = extractRawPrivateKey(privateKey);

  // Build did:key from public key
  const did = publicKeyToDid(publicKeyBytes);

  return createIdentity(did, publicKeyBytes, privateKeyBytes);
}

/**
 * Import a persisted agent identity.
 *
 * @param params - The exported identity (DID + private key hex)
 * @returns AgentIdentity with full key pair
 */
export function importAgentIdentity(params: ImportParams): AgentIdentity {
  const { did, privateKeyHex } = params;

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
  const { createPrivateKey, createPublicKey } = require('node:crypto');
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

  return createIdentity(did, publicKeyBytes, privateKeyBytes);
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

    // Decode payload and verify DID matches
    const payload: DelegationReceiptPayload = JSON.parse(
      base64UrlDecode(payloadB64).toString('utf8'),
    );
    if (payload.sub !== opts.expectedDid) {
      return false;
    }

    // Verify signature
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

    return verify(null, signatureInput, publicKeyObject, signature);
  } catch {
    return false;
  }
}

// ── Internal Helpers ─────────────────────────────────────────────────────────

function createIdentity(
  did: string,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
): AgentIdentity {
  // Store copies internally
  const pubKeyCopy = new Uint8Array(publicKey);
  const privKeyCopy = new Uint8Array(privateKey);

  return {
    did,
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
      };
    },
  };
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

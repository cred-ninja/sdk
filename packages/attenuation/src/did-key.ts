/**
 * did:key resolution for the two key types Cred agents use: Ed25519
 * (multicodec 0xed) and P-256 (multicodec 0x1200, compressed point).
 * A did:key is self-certifying, so resolution is a decode with no lookup.
 */
import { createPublicKey, type KeyObject } from 'node:crypto';
import { jwkThumbprint } from './jws.js';

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function decodeBase58(text: string): Uint8Array | null {
  let value = 0n;
  for (const ch of text) {
    const digit = BASE58.indexOf(ch);
    if (digit < 0) return null;
    value = value * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value & 0xffn));
    value >>= 8n;
  }
  for (const ch of text) {
    if (ch !== '1') break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
// SubjectPublicKeyInfo for id-ecPublicKey / prime256v1 with a 33-byte compressed point.
const P256_COMPRESSED_SPKI_PREFIX = Buffer.from('3039301306072a8648ce3d020106082a8648ce3d030107032200', 'hex');

/** The public key a did:key names, or null when it is not an Ed25519 or P-256 did:key. */
export function publicKeyFromDidKey(did: string): KeyObject | null {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) return null;
  const bytes = decodeBase58(did.slice('did:key:z'.length));
  if (!bytes) return null;
  try {
    if (bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) {
      return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, bytes.subarray(2)]), format: 'der', type: 'spki' });
    }
    if (bytes.length === 35 && bytes[0] === 0x80 && bytes[1] === 0x24) {
      return createPublicKey({ key: Buffer.concat([P256_COMPRESSED_SPKI_PREFIX, bytes.subarray(2)]), format: 'der', type: 'spki' });
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * `cnf` for a token issued to a did:key agent: `{ jkt }`, the RFC 7638
 * thumbprint of the agent's own key. Null when the DID is not a did:key
 * this module decodes, in which case there is no key to bind to.
 */
export function didKeyConfirmation(did: string): { jkt: string } | null {
  const key = publicKeyFromDidKey(did);
  return key ? { jkt: jwkThumbprint(key) } : null;
}

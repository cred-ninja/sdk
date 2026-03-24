import { createHash, createPublicKey, generateKeyPair, KeyObject, verify } from 'node:crypto';
import { promisify } from 'node:util';
import type { GeneratedKeypair } from './types.js';

const generateKeyPairAsync = promisify(generateKeyPair);

const ED25519_PUBLIC_KEY_LENGTH = 32;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export async function generateKeypair(): Promise<GeneratedKeypair> {
  const { publicKey, privateKey } = await generateKeyPairAsync('ed25519');
  const publicKeyBytes = extractRawPublicKey(publicKey);
  const privateKeyBytes = extractRawPrivateKey(privateKey);

  return {
    publicKey: publicKeyBytes,
    privateKey: privateKeyBytes,
    fingerprint: fingerprintPublicKey(publicKeyBytes),
    keyId: publicKeyToJwkThumbprint(publicKeyBytes),
  };
}

export function fingerprintPublicKey(publicKey: Uint8Array): string {
  assertRawPublicKey(publicKey);
  return createHash('sha256')
    .update(Buffer.from(publicKey).toString('hex'))
    .digest('hex');
}

export function normalizePublicKey(publicKey: Uint8Array): string {
  assertRawPublicKey(publicKey);
  return Buffer.from(publicKey).toString('hex');
}

export interface Ed25519Jwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid?: string;
}

export type Ed25519JwkWithKid = Ed25519Jwk & { kid: string };

export function publicKeyToJwk(publicKey: Uint8Array): Ed25519Jwk {
  assertRawPublicKey(publicKey);
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(publicKey).toString('base64url'),
  };
}

export function jwkThumbprint(jwk: Pick<Ed25519Jwk, 'kty' | 'crv' | 'x'>): string {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
  });
  return createHash('sha256').update(canonical).digest('base64url');
}

export function publicKeyToJwkThumbprint(publicKey: Uint8Array): string {
  return jwkThumbprint(publicKeyToJwk(publicKey));
}

export function publicKeyToJwkWithKid(publicKey: Uint8Array): Ed25519JwkWithKid {
  const jwk = publicKeyToJwk(publicKey);
  return {
    ...jwk,
    kid: jwkThumbprint(jwk),
  };
}

export function verifySignature(
  publicKey: Uint8Array,
  payload: Uint8Array | Buffer,
  signature: Uint8Array | Buffer,
): boolean {
  assertRawPublicKey(publicKey);

  try {
    const keyObject = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey)]),
      format: 'der',
      type: 'spki',
    });

    return verify(null, Buffer.from(payload), keyObject, Buffer.from(signature));
  } catch {
    return false;
  }
}

export function publicKeyHexToBytes(publicKeyHex: string): Uint8Array {
  const bytes = new Uint8Array(Buffer.from(publicKeyHex, 'hex'));
  assertRawPublicKey(bytes);
  return bytes;
}

function assertRawPublicKey(publicKey: Uint8Array): void {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new Error('Invalid public key: must be 32 bytes (Ed25519)');
  }
}

function extractRawPublicKey(keyObject: KeyObject): Uint8Array {
  const spki = keyObject.export({ type: 'spki', format: 'der' });
  return new Uint8Array(spki.slice(-ED25519_PUBLIC_KEY_LENGTH));
}

function extractRawPrivateKey(keyObject: KeyObject): Uint8Array {
  const pkcs8 = keyObject.export({ type: 'pkcs8', format: 'der' });
  return new Uint8Array(pkcs8.slice(-ED25519_PUBLIC_KEY_LENGTH));
}

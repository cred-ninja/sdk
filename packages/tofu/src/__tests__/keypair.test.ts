import { createPrivateKey, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  fingerprintPublicKey,
  generateKeypair,
  jwkThumbprint,
  normalizePublicKey,
  publicKeyToJwk,
  publicKeyToJwkThumbprint,
  publicKeyToJwkWithKid,
  verifySignature,
} from '../index.js';

describe('keypair helpers', () => {
  it('generates Ed25519 keypairs with stable fingerprints', async () => {
    const keypair = await generateKeypair();

    expect(keypair.publicKey).toHaveLength(32);
    expect(keypair.privateKey).toHaveLength(32);
    expect(keypair.fingerprint).toBe(fingerprintPublicKey(keypair.publicKey));
    expect(normalizePublicKey(keypair.publicKey)).toHaveLength(64);
  });

  it('verifies signatures for generated raw keys', async () => {
    const keypair = await generateKeypair();
    const privateKey = createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        Buffer.from(keypair.privateKey),
      ]),
      format: 'der',
      type: 'pkcs8',
    });

    const payload = Buffer.from('tofu payload');
    const signature = sign(null, payload, privateKey);

    expect(verifySignature(keypair.publicKey, payload, signature)).toBe(true);
    expect(verifySignature(keypair.publicKey, Buffer.from('tampered'), signature)).toBe(false);
  });

  it('exports Ed25519 keys as Web Bot Auth compatible JWKs', () => {
    const publicKey = new Uint8Array(Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex'));

    const jwk = publicKeyToJwk(publicKey);
    expect(jwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    });

    const kid = publicKeyToJwkThumbprint(publicKey);
    expect(kid).toBe('P7IdLIpiTZiFaIoOSqbX3JrSyps3hvZ4Y2SieP96XIY');
    expect(jwkThumbprint(jwk)).toBe(kid);
    expect(publicKeyToJwkWithKid(publicKey)).toEqual({
      ...jwk,
      kid,
    });
  });
});

import { describe, it, expect } from 'vitest';
import {
  generateSalt,
  deriveKey,
  encryptWithKey,
  decryptWithKey,
  encrypt,
  decrypt,
} from '../crypto.js';

describe('crypto module', () => {
  const passphrase = 'test-passphrase-abc123';

  it('generates a 32-byte random salt', () => {
    const salt = generateSalt();
    expect(salt).toBeInstanceOf(Buffer);
    expect(salt.length).toBe(32);
  });

  it('generates unique salts each call', () => {
    const a = generateSalt();
    const b = generateSalt();
    expect(a.toString('hex')).not.toBe(b.toString('hex'));
  });

  it('derives a 32-byte key from passphrase + salt', () => {
    const salt = generateSalt();
    const key = deriveKey(passphrase, salt);
    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
  });

  it('derives the same key for the same passphrase + salt', () => {
    const salt = generateSalt();
    const key1 = deriveKey(passphrase, salt);
    const key2 = deriveKey(passphrase, salt);
    expect(key1.toString('hex')).toBe(key2.toString('hex'));
  });

  it('derives different keys for different salts', () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    const key1 = deriveKey(passphrase, salt1);
    const key2 = deriveKey(passphrase, salt2);
    expect(key1.toString('hex')).not.toBe(key2.toString('hex'));
  });

  it('encrypt/decrypt round-trip with encryptWithKey / decryptWithKey', () => {
    const salt = generateSalt();
    const key = deriveKey(passphrase, salt);
    const plaintext = 'my-secret-access-token-xyz';

    const payload = encryptWithKey(plaintext, key);
    const recovered = decryptWithKey(payload, key);

    expect(recovered).toBe(plaintext);
  });

  it('encrypt/decrypt round-trip with high-level encrypt / decrypt', () => {
    const salt = generateSalt();
    const plaintext = 'ya29.A0AfH6SMC-google-access-token';

    const payload = encrypt(plaintext, passphrase, salt);
    const recovered = decrypt(payload, passphrase, salt);

    expect(recovered).toBe(plaintext);
  });

  it('rejects decryption with wrong passphrase (throws)', () => {
    const salt = generateSalt();
    const plaintext = 'super-secret-token';

    const payload = encrypt(plaintext, passphrase, salt);

    expect(() => decrypt(payload, 'wrong-passphrase', salt)).toThrow();
  });

  it('rejects decryption with wrong salt (throws)', () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    const plaintext = 'another-token';

    const payload = encrypt(plaintext, passphrase, salt1);

    expect(() => decrypt(payload, passphrase, salt2)).toThrow();
  });

  it('encrypts empty string correctly', () => {
    const salt = generateSalt();
    const key = deriveKey(passphrase, salt);

    const payload = encryptWithKey('', key);
    const recovered = decryptWithKey(payload, key);

    expect(recovered).toBe('');
  });

  it('encrypts and decrypts unicode text correctly', () => {
    const salt = generateSalt();
    const key = deriveKey(passphrase, salt);
    const unicode = '日本語テスト 🚀 emoji and ñoño';

    const payload = encryptWithKey(unicode, key);
    const recovered = decryptWithKey(payload, key);

    expect(recovered).toBe(unicode);
  });

  it('produces unique IVs per encryption (no IV reuse)', () => {
    const salt = generateSalt();
    const key = deriveKey(passphrase, salt);

    const p1 = encryptWithKey('token-a', key);
    const p2 = encryptWithKey('token-a', key);

    // Same plaintext → different IV and different ciphertext
    expect(p1.iv).not.toBe(p2.iv);
    expect(p1.encrypted).not.toBe(p2.encrypted);
  });

  it('ciphertext is hex-encoded (not raw binary)', () => {
    const salt = generateSalt();
    const key = deriveKey(passphrase, salt);

    const payload = encryptWithKey('test', key);

    expect(payload.encrypted).toMatch(/^[0-9a-f]+$/);
    expect(payload.iv).toMatch(/^[0-9a-f]+$/);
    expect(payload.tag).toMatch(/^[0-9a-f]+$/);
  });

  it('auth tag is 16 bytes (32 hex chars) for GCM', () => {
    const salt = generateSalt();
    const key = deriveKey(passphrase, salt);

    const payload = encryptWithKey('test-tag-length', key);

    expect(payload.tag.length).toBe(32); // 16 bytes = 32 hex chars
  });
});

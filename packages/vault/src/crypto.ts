import crypto from 'crypto';
import type { EncryptedPayload } from './types.js';

const ALGORITHM = 'aes-256-gcm';
const PBKDF2_ITERATIONS = 100_000;
const KEY_LENGTH = 32; // 256 bits
const DIGEST = 'sha256';

/**
 * Derive a 256-bit AES key from a passphrase + salt using PBKDF2-SHA256.
 * The salt must be stored alongside encrypted data and is NOT secret.
 */
export function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, DIGEST);
}

/**
 * Generate a random salt suitable for PBKDF2 key derivation.
 * Store this alongside your encrypted vault data — one salt per vault.
 */
export function generateSalt(): Buffer {
  return crypto.randomBytes(32);
}

/**
 * Encrypt plaintext using AES-256-GCM with the provided key.
 * Returns encrypted ciphertext (hex), IV (hex), and auth tag (hex).
 *
 * The IV is random per encryption call — never reused.
 */
export function encryptWithKey(plaintext: string, key: Buffer): EncryptedPayload {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const tag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
}

/**
 * Decrypt ciphertext using AES-256-GCM with the provided key.
 * Throws if the auth tag fails (wrong key, tampered data, etc.).
 *
 * NEVER returns garbage silently — GCM authentication guarantees integrity.
 */
export function decryptWithKey(payload: EncryptedPayload, key: Buffer): string {
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(payload.iv, 'hex')
  );

  decipher.setAuthTag(Buffer.from(payload.tag, 'hex'));

  let decrypted = decipher.update(payload.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * High-level encrypt: derive key from passphrase + salt, then AES-256-GCM encrypt.
 */
export function encrypt(plaintext: string, passphrase: string, salt: Buffer): EncryptedPayload {
  const key = deriveKey(passphrase, salt);
  return encryptWithKey(plaintext, key);
}

/**
 * High-level decrypt: derive key from passphrase + salt, then AES-256-GCM decrypt.
 * Throws if passphrase is wrong or data is tampered.
 */
export function decrypt(payload: EncryptedPayload, passphrase: string, salt: Buffer): string {
  const key = deriveKey(passphrase, salt);
  return decryptWithKey(payload, key);
}

/**
 * Mask a token for display/logging purposes. Never logs real value.
 */
export function maskToken(token: string): string {
  if (!token || token.length <= 8) return '***';
  return `...${token.slice(-4)}`;
}

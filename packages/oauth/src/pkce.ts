/**
 * PKCE (Proof Key for Code Exchange) helpers — RFC 7636
 *
 * Zero dependencies. Uses Node.js built-in `crypto` module.
 */

import { createHash, randomBytes } from 'crypto';
import type { PKCEPair } from './types.js';

/**
 * Generate a cryptographically random code verifier.
 * RFC 7636 §4.1: 43-128 chars, URL-safe characters (A-Z, a-z, 0-9, -, _, ., ~)
 */
export function generateVerifier(length: number = 64): string {
  if (length < 43 || length > 128) {
    throw new RangeError(`PKCE verifier length must be between 43 and 128, got ${length}`);
  }

  // Generate enough random bytes then base64url encode
  // base64url is ~4/3 of the byte count, so generate enough
  const byteLength = Math.ceil(length * 3 / 4) + 4;
  const raw = randomBytes(byteLength)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
    .slice(0, length);

  return raw;
}

/**
 * Compute the PKCE code challenge from a verifier.
 * challenge = BASE64URL(SHA256(ASCII(verifier)))
 * Method: S256 (required by RFC 7636)
 */
export function computeChallenge(verifier: string): string {
  const hash = createHash('sha256').update(verifier, 'ascii').digest();
  return hash
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a complete PKCE pair: { verifier, challenge }
 */
export function generatePKCE(verifierLength: number = 64): PKCEPair {
  const verifier = generateVerifier(verifierLength);
  const challenge = computeChallenge(verifier);
  return { verifier, challenge };
}

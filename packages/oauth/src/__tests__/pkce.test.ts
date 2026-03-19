import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import { generateVerifier, computeChallenge, generatePKCE } from '../pkce.js';

describe('PKCE helpers', () => {
  it('generates a verifier of the default length (64)', () => {
    const verifier = generateVerifier();
    expect(verifier).toHaveLength(64);
  });

  it('generates a verifier of a custom length', () => {
    expect(generateVerifier(43)).toHaveLength(43);
    expect(generateVerifier(128)).toHaveLength(128);
  });

  it('throws for lengths outside RFC 7636 range', () => {
    expect(() => generateVerifier(42)).toThrow('43');
    expect(() => generateVerifier(129)).toThrow('128');
  });

  it('verifier contains only URL-safe characters', () => {
    const verifier = generateVerifier(128);
    expect(verifier).toMatch(/^[A-Za-z0-9\-_.~]+$/);
  });

  it('generates different verifiers each time', () => {
    const a = generateVerifier();
    const b = generateVerifier();
    expect(a).not.toBe(b);
  });

  it('computes correct SHA-256 base64url challenge', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const expected = createHash('sha256')
      .update(verifier, 'ascii')
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    expect(computeChallenge(verifier)).toBe(expected);
  });

  it('challenge has no base64 padding (=)', () => {
    const challenge = computeChallenge(generateVerifier());
    expect(challenge).not.toContain('=');
  });

  it('challenge contains only URL-safe characters', () => {
    const challenge = computeChallenge(generateVerifier());
    expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it('generatePKCE returns matching verifier and challenge', () => {
    const { verifier, challenge } = generatePKCE();
    const expected = computeChallenge(verifier);
    expect(challenge).toBe(expected);
  });

  it('generatePKCE with custom length', () => {
    const { verifier } = generatePKCE(100);
    expect(verifier).toHaveLength(100);
  });
});

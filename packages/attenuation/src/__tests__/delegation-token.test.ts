/**
 * Delegation Token (draft-sweeney-wimse-credential-delegation-02 Section 5):
 * a DPoP-bound JWT the Delegation Server issues to one agent.
 */
import { describe, it, expect } from 'vitest';
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  createKeySigner,
  createVerificationKey,
  staticKeyResolver,
  signCompactJws,
  base64urlEncode,
  canonicalJson,
  mintDelegationToken,
  verifyDelegationToken,
  delegationTokenAth,
  receiptContentId,
  DELEGATION_TOKEN_TYP,
  DELEGATION_TOKEN_MAX_LIFETIME_SECONDS,
} from '../index.js';
import type { DelegationTokenClaims } from '../index.js';

const ISSUER = 'https://ds.example';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const signer = createKeySigner(privateKey, 'ds-1');
const resolveKey = staticKeyResolver([createVerificationKey(publicKey, 'ds-1')]);
const NOW = 1_800_000_000;

function claims(overrides: Partial<DelegationTokenClaims> = {}): DelegationTokenClaims {
  return {
    iss: ISSUER,
    sub: 'user-1',
    client_id: 'did:key:z6MkAgent',
    act: { sub: 'did:key:z6MkAgent' },
    authorization_details: [{ type: 'cred_delegation', provider: 'google', operations: ['https://www.googleapis.com/auth/drive.readonly'] }],
    cnf: { jkt: 'thumbprint' },
    iat: NOW,
    exp: NOW + 900,
    jti: 'dt_1',
    consent_id: 'consent_1',
    credential_handle: 'ch_1',
    prf: ['receipt-hash-1'],
    ...overrides,
  };
}

const verifyOpts = { issuer: ISSUER, acceptedAlgs: ['EdDSA'], resolveKey, nowSeconds: NOW + 10 };

describe('Delegation Token', () => {
  it('mints a dt+jwt that verifies and round-trips every claim', () => {
    const token = mintDelegationToken(claims(), signer);
    const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString('utf8'));
    expect(header.typ).toBe(DELEGATION_TOKEN_TYP);
    const result = verifyDelegationToken(token, verifyOpts);
    expect(result).toEqual({ ok: true, claims: claims() });
  });

  it('carries delegation_constraints when given', () => {
    const constraints = [{ key: 'max_rows', max: 5000 }];
    const token = mintDelegationToken(claims({ delegation_constraints: constraints }), signer);
    const result = verifyDelegationToken(token, verifyOpts);
    expect(result.ok && result.claims.delegation_constraints).toEqual(constraints);
  });

  it('refuses to mint a token whose client_id and act.sub differ', () => {
    expect(() => mintDelegationToken(claims({ act: { sub: 'did:key:z6MkOther' } }), signer)).toThrow(/client_id/);
  });

  it('refuses to mint a token living longer than an hour', () => {
    expect(() => mintDelegationToken(claims({ exp: NOW + DELEGATION_TOKEN_MAX_LIFETIME_SECONDS + 1 }), signer)).toThrow(/lifetime/);
  });

  it('refuses to mint a token without a capability or a key binding', () => {
    expect(() => mintDelegationToken(claims({ authorization_details: [] }), signer)).toThrow(/authorization_details/);
    expect(() => mintDelegationToken(claims({ cnf: { jkt: '' } }), signer)).toThrow(/cnf/);
  });

  it('rejects an expired token, allowing clock skew', () => {
    const token = mintDelegationToken(claims(), signer);
    expect(verifyDelegationToken(token, { ...verifyOpts, nowSeconds: NOW + 900 + 59 }).ok).toBe(true);
    expect(verifyDelegationToken(token, { ...verifyOpts, nowSeconds: NOW + 900 + 61 })).toEqual({ ok: false, reason: 'expired' });
  });

  it('rejects a token from another issuer, under another key, or of another type', () => {
    const token = mintDelegationToken(claims(), signer);
    expect(verifyDelegationToken(token, { ...verifyOpts, issuer: 'https://other.example' })).toEqual({ ok: false, reason: 'wrong_issuer' });

    const other = generateKeyPairSync('ed25519');
    const forged = mintDelegationToken(claims(), createKeySigner(other.privateKey, 'ds-1'));
    expect(verifyDelegationToken(forged, verifyOpts)).toEqual({ ok: false, reason: 'bad_signature' });

    // A receipt (typ JWT) signed by the same key is not a Delegation Token.
    const receipt = signCompactJws({ ...claims() }, signer, { typ: 'JWT' });
    expect(verifyDelegationToken(receipt, verifyOpts)).toEqual({ ok: false, reason: 'wrong_type' });
  });

  it('rejects alg none and malformed tokens', () => {
    const header = base64urlEncode(Buffer.from(canonicalJson({ alg: 'none', typ: DELEGATION_TOKEN_TYP })));
    const payload = base64urlEncode(Buffer.from(canonicalJson({ ...claims() })));
    expect(verifyDelegationToken(`${header}.${payload}.`, verifyOpts)).toEqual({ ok: false, reason: 'bad_signature' });
    expect(verifyDelegationToken('not-a-jwt', verifyOpts)).toEqual({ ok: false, reason: 'malformed' });
  });

  it('rejects a signed token whose claims are malformed', () => {
    const bad = signCompactJws({ ...claims(), act: { sub: 'did:key:z6MkOther' } }, signer, { typ: DELEGATION_TOKEN_TYP });
    expect(verifyDelegationToken(bad, verifyOpts)).toEqual({ ok: false, reason: 'malformed_claims' });
    const noPrf = signCompactJws({ ...claims(), prf: 'x' }, signer, { typ: DELEGATION_TOKEN_TYP });
    expect(verifyDelegationToken(noPrf, verifyOpts)).toEqual({ ok: false, reason: 'malformed_claims' });
  });

  it('computes ath and receipt content identifiers as base64url SHA-256', () => {
    const token = mintDelegationToken(claims(), signer);
    expect(delegationTokenAth(token)).toBe(createHash('sha256').update(token, 'ascii').digest('base64url'));
    expect(receiptContentId('a.b.c')).toBe(createHash('sha256').update('a.b.c', 'ascii').digest('base64url'));
  });
});

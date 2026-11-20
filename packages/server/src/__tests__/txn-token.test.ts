import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { checkTxnTokenTrust, mappedProviderScopes, TxnTokenRefusal, verifyTxnToken } from '../identity/txn-token.js';
import { es256Jws, txnIssuer } from './wimse-fixture.js';

const AUD = 'domain-b.example';

function code(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    if (err instanceof TxnTokenRefusal) return err.code;
    throw err;
  }
  return 'accepted';
}

describe('Txn-Token verification (draft-ietf-oauth-transaction-tokens-11 §9, §12.2)', () => {
  it('verifies a token and reads txn, scope, req_wl and the user subject', () => {
    const tts = txnIssuer(AUD);
    const v = verifyTxnToken(tts.mint({ txn: 'txn-1', scope: 'calendar.read calendar.write' }), tts.trust());
    expect(v).toMatchObject({ txn: 'txn-1', scopes: ['calendar.read', 'calendar.write'], reqWl: `gateway.${AUD}`, userId: 'default' });
    expect(v.hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('verifies an Ed25519 token', () => {
    const key = crypto.generateKeyPairSync('ed25519');
    const tts = txnIssuer(AUD);
    const keys = { keyUse: 'sig', size: 1, get: (kid: string) => (kid === 'ed' ? { kid, key: key.publicKey } : undefined), kids: () => ['ed'] };
    const b = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const input = `${b({ alg: 'EdDSA', typ: 'txntoken+jwt', kid: 'ed' })}.${b({ iat: now, exp: now + 60, aud: AUD, txn: 't', sub: 'user:default', scope: 's', req_wl: 'w' })}`;
    const token = `${input}.${crypto.sign(null, Buffer.from(input), key.privateKey).toString('base64url')}`;
    expect(verifyTxnToken(token, tts.trust({ keys })).txn).toBe('t');
  });

  it.each(['iat', 'exp', 'txn', 'sub', 'scope', 'req_wl'])('refuses a token without %s', (claim) => {
    const tts = txnIssuer(AUD);
    expect(code(() => verifyTxnToken(tts.mint({ [claim]: undefined }), tts.trust()))).toBe(claim);
  });

  it('refuses a token for another trust domain (aud), even when signed by a trusted key', () => {
    const tts = txnIssuer(AUD);
    expect(code(() => verifyTxnToken(tts.mint({ aud: 'domain-a.example' }), tts.trust()))).toBe('aud');
  });

  it('chooses the key by configured kid only: iss naming this service does not help an unknown kid', () => {
    const tts = txnIssuer(AUD);
    expect(code(() => verifyTxnToken(tts.mint({ iss: `https://tts.${AUD}` }, { kid: 'other' }), tts.trust()))).toBe('kid');
    const stranger = txnIssuer(AUD);
    // Right kid name, wrong key: the signature does not verify.
    const forged = stranger.mint({}, { kid: `${AUD}-tts` });
    expect(code(() => verifyTxnToken(forged, tts.trust()))).toBe('signature');
  });

  it('refuses expired, future-issued, over-long and wrongly typed tokens', () => {
    const tts = txnIssuer(AUD);
    const now = Math.floor(Date.now() / 1000);
    expect(code(() => verifyTxnToken(tts.mint({ iat: now - 900, exp: now - 120 }), tts.trust()))).toBe('expired');
    expect(code(() => verifyTxnToken(tts.mint({ iat: now + 600, exp: now + 900 }), tts.trust()))).toBe('iat');
    expect(code(() => verifyTxnToken(tts.mint({ exp: now + 7200 }), tts.trust()))).toBe('lifetime');
    expect(code(() => verifyTxnToken(tts.mint({}, { typ: 'JWT' }), tts.trust()))).toBe('typ');
  });

  it('refuses alg none, HMAC and keys embedded in the header', () => {
    const tts = txnIssuer(AUD);
    const k = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    expect(code(() => verifyTxnToken(es256Jws({ alg: 'none', typ: 'txntoken+jwt', kid: `${AUD}-tts` }, {}, k.privateKey), tts.trust()))).toBe('alg');
    expect(code(() => verifyTxnToken(es256Jws({ alg: 'HS256', typ: 'txntoken+jwt', kid: `${AUD}-tts` }, {}, k.privateKey), tts.trust()))).toBe('alg');
    expect(code(() => verifyTxnToken(tts.mint({}, { jwk: k.publicKey.export({ format: 'jwk' }) }), tts.trust()))).toBe('embedded_key');
  });

  it('reads the user only through a full-string match; a token with no match is autonomous', () => {
    const tts = txnIssuer(AUD);
    expect(verifyTxnToken(tts.mint({ sub: 'workload:batch' }), tts.trust()).userId).toBeUndefined();
    // A prefix that would satisfy an unanchored pattern does not.
    expect(verifyTxnToken(tts.mint({ sub: 'xuser:default' }), tts.trust()).userId).toBeUndefined();
    expect(verifyTxnToken(tts.mint({ sub: 'user:default' }), tts.trust({ userSubject: undefined })).userId).toBeUndefined();
    expect(verifyTxnToken(tts.mint({ tctx: { user: 'alice' } }), tts.trust({ userSubject: { claim: 'tctx.user' } })).userId).toBe('alice');
  });

  it('refuses at load an unanchored pattern or one without exactly one capture group', () => {
    const tts = txnIssuer(AUD);
    expect(() => checkTxnTokenTrust(tts.trust({ userSubject: { claim: 'sub', pattern: 'user:(.+)' } }))).toThrow(/anchored/);
    expect(() => checkTxnTokenTrust(tts.trust({ userSubject: { claim: 'sub', pattern: '^(a)(b)$' } }))).toThrow(/one capture group/);
    expect(() => checkTxnTokenTrust(tts.trust())).not.toThrow();
  });

  it('maps scopes by service; any unmapped scope means no mapping at all', () => {
    const trust = txnIssuer(AUD).trust();
    expect(mappedProviderScopes(trust, 'google', ['calendar.read'])).toEqual(['calendar.readonly']);
    expect(mappedProviderScopes(trust, 'google', ['calendar.read', 'mail.send'])).toBeNull();
    expect(mappedProviderScopes(trust, 'github', ['calendar.read'])).toBeNull();
  });
});

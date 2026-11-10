import { describe, expect, it } from 'vitest';
import crypto from 'crypto';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { receiptHash, verifyReceiptChain } from '../receipt-chain.js';

// Same key derivation as the server and the subdelegate tests.
const PASSPHRASE = 'test-passphrase-for-receipt-chain';
function signingKey(passphrase = PASSPHRASE) {
  const seed = crypto.scryptSync(passphrase, 'cred:local-receipt:v1', 32);
  return createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
}
const publicKey = createPublicKey(signingKey());

function mint(payload: Record<string, unknown>, key = signingKey()): string {
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify({ iss: 'did:key:local-cred', ...payload })).toString('base64url');
  const signature = sign(null, Buffer.from(`${header}.${payloadB64}`, 'utf8'), key).toString('base64url');
  return `${header}.${payloadB64}.${signature}`;
}

const base = { service: 'google', userId: 'default', appClientId: 'local' };
const NOW = 1_800_000_000;

// Three hops the way the server would mint them: each child commits to the
// exact bytes of the receipt it was derived from.
function chain() {
  const root = mint({ ...base, sub: 'did:key:z6MkRoot', delegationId: 'del_r', chainDepth: 0, scopes: ['crm.*', 'mail.send'], iat: NOW, exp: NOW + 3600 });
  const mid = mint({ ...base, sub: 'did:key:z6MkMid', delegationId: 'del_m', chainDepth: 1, scopes: ['crm.read'], iat: NOW, exp: NOW + 900, parentDelegationId: 'del_r', parentReceiptHash: receiptHash(root), lineage: ['did:key:z6MkRoot'] });
  const leaf = mint({ ...base, sub: 'did:key:z6MkLeaf', delegationId: 'del_l', chainDepth: 2, scopes: ['crm.read'], iat: NOW, exp: NOW + 300, parentDelegationId: 'del_m', parentReceiptHash: receiptHash(mid), lineage: ['did:key:z6MkRoot', 'did:key:z6MkMid'] });
  return { root, mid, leaf };
}

describe('verifyReceiptChain', () => {
  it('accepts a chain the server would have minted', () => {
    const { root, mid, leaf } = chain();
    const result = verifyReceiptChain([root, mid, leaf], publicKey, { now: NOW });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.depth).toBe(2);
      expect(result.leaf.delegationId).toBe('del_l');
    }
  });

  it('rejects a spliced parent: a real child paired with a root it was never derived from', () => {
    const { mid, leaf } = chain();
    const otherRoot = mint({ ...base, sub: 'did:key:z6MkOther', delegationId: 'del_o', chainDepth: 0, scopes: ['crm.*', 'mail.send', 'pay.transfer'], iat: NOW, exp: NOW + 3600 });
    expect(verifyReceiptChain([otherRoot, mid, leaf], publicKey, { now: NOW })).toMatchObject({ ok: false, reason: 'parent_hash_mismatch', hop: 1 });
  });

  it('rejects a receipt signed by a different key', () => {
    const { root, mid } = chain();
    const forgedLeaf = mint({ ...base, sub: 'did:key:z6MkLeaf', delegationId: 'del_l', chainDepth: 2, scopes: ['crm.read'], iat: NOW, exp: NOW + 300, parentReceiptHash: receiptHash(mid) }, signingKey('other'));
    expect(verifyReceiptChain([root, mid, forgedLeaf], publicKey, { now: NOW })).toMatchObject({ ok: false, reason: 'signature_invalid', hop: 2 });
  });

  it('rejects a single flipped signature byte', () => {
    const { root, mid, leaf } = chain();
    const [h, p, sig] = leaf.split('.');
    const bytes = Buffer.from(sig, 'base64url');
    bytes[0] ^= 0x01;
    const tampered = `${h}.${p}.${bytes.toString('base64url')}`;
    expect(verifyReceiptChain([root, mid, tampered], publicKey, { now: NOW })).toMatchObject({ ok: false, reason: 'signature_invalid', hop: 2 });
  });

  it('rejects a widened scope even when linkage is intact', () => {
    const { root, mid } = chain();
    const wide = mint({ ...base, sub: 'did:key:z6MkLeaf', delegationId: 'del_l', chainDepth: 2, scopes: ['crm.read', 'pay.transfer'], iat: NOW, exp: NOW + 300, parentReceiptHash: receiptHash(mid) });
    expect(verifyReceiptChain([root, mid, wide], publicKey, { now: NOW })).toMatchObject({ ok: false, reason: 'not_narrower', hop: 2 });
  });

  it('rejects a child that expires after its parent', () => {
    const { root, mid } = chain();
    const late = mint({ ...base, sub: 'did:key:z6MkLeaf', delegationId: 'del_l', chainDepth: 2, scopes: ['crm.read'], iat: NOW, exp: NOW + 100_000, parentReceiptHash: receiptHash(mid) });
    expect(verifyReceiptChain([root, mid, late], publicKey, { now: NOW })).toMatchObject({ ok: false, reason: 'exp_not_monotonic', hop: 2 });
  });

  it('rejects a chain deeper than maxDepth', () => {
    const { root, mid, leaf } = chain();
    expect(verifyReceiptChain([root, mid, leaf], publicKey, { now: NOW, maxDepth: 1 })).toMatchObject({ ok: false, reason: 'depth_invalid' });
  });

  it('rejects an expired hop, honoring clock skew', () => {
    const { root, mid, leaf } = chain();
    expect(verifyReceiptChain([root, mid, leaf], publicKey, { now: NOW + 301 })).toMatchObject({ ok: false, reason: 'expired', hop: 2 });
    expect(verifyReceiptChain([root, mid, leaf], publicKey, { now: NOW + 301, clockSkewSeconds: 60 }).ok).toBe(true);
  });

  it('rejects hops for different services or users', () => {
    const { root, mid } = chain();
    const otherService = mint({ ...base, service: 'github', sub: 'did:key:z6MkLeaf', delegationId: 'del_l', chainDepth: 2, scopes: ['crm.read'], iat: NOW, exp: NOW + 300, parentReceiptHash: receiptHash(mid) });
    expect(verifyReceiptChain([root, mid, otherService], publicKey, { now: NOW })).toMatchObject({ ok: false, reason: 'context_mismatch', hop: 2 });
  });

  it('rejects garbage', () => {
    expect(verifyReceiptChain(['not.a.receipt'], publicKey, { now: NOW })).toMatchObject({ ok: false, reason: 'signature_invalid', hop: 0 });
    expect(verifyReceiptChain([], publicKey, { now: NOW })).toMatchObject({ ok: false, reason: 'empty_chain' });
  });
});

describe('verifyReceiptChain: derived read scopes', () => {
  const three = (a: string[], b: string[], c: string[]) => {
    const scoped = { ...base, service: 'github' };
    const r0 = mint({ ...scoped, sub: 'did:key:z6MkRoot', delegationId: 'del_r', chainDepth: 0, scopes: a, iat: NOW, exp: NOW + 3600 });
    const r1 = mint({ ...scoped, sub: 'did:key:z6MkMid', delegationId: 'del_m', chainDepth: 1, scopes: b, iat: NOW, exp: NOW + 900, parentDelegationId: 'del_r', parentReceiptHash: receiptHash(r0), lineage: ['did:key:z6MkRoot'] });
    const r2 = mint({ ...scoped, sub: 'did:key:z6MkLeaf', delegationId: 'del_l', chainDepth: 2, scopes: c, iat: NOW, exp: NOW + 300, parentDelegationId: 'del_m', parentReceiptHash: receiptHash(r1), lineage: ['did:key:z6MkRoot', 'did:key:z6MkMid'] });
    return [r0, r1, r2];
  };
  const verify = (chainOf: string[]) => verifyReceiptChain(chainOf, publicKey, { now: NOW });

  it('repo then github.read then github.read verifies', () => {
    expect(verify(three(['repo'], ['github.read'], ['github.read'])).ok).toBe(true);
  });

  it('a child with repo under a github.read parent fails, and so does another provider\'s name', () => {
    expect(verify(three(['repo'], ['github.read'], ['repo'])).ok).toBe(false);
    expect(verify(three(['read:user'], ['github.read'], ['github.read'])).ok).toBe(false);
    expect(verify(three(['repo'], ['salesforce.read'], ['salesforce.read'])).ok).toBe(false);
  });

  it('an empty hop stays empty: nothing below it can hold a scope', () => {
    expect(verify(three(['repo'], [], ['github.read'])).ok).toBe(false);
  });
});

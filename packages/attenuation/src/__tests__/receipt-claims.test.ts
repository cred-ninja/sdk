import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { didKeyConfirmation, publicKeyFromDidKey } from '../did-key.js';
import { jwkThumbprint } from '../jws.js';
import { readReceiptActor, receiptActorClaims } from '../receipt-claims.js';

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes: Uint8Array): string {
  let n = BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`);
  let out = '';
  while (n > 0n) { out = BASE58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = `1${out}`; }
  return out;
}

describe('did:key', () => {
  it('resolves an Ed25519 did:key and binds cnf to its thumbprint', () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const did = `did:key:z${base58(Buffer.concat([Buffer.from([0xed, 0x01]), raw]))}`;
    const resolved = publicKeyFromDidKey(did)!;
    expect(resolved.export({ format: 'jwk' })).toEqual(publicKey.export({ format: 'jwk' }));
    expect(didKeyConfirmation(did)).toEqual({ jkt: jwkThumbprint(publicKey) });
  });

  it('resolves a P-256 did:key with a compressed point', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
    const y = Buffer.from(jwk.y, 'base64url');
    const point = Buffer.concat([Buffer.from([y[y.length - 1]! & 1 ? 0x03 : 0x02]), Buffer.from(jwk.x, 'base64url')]);
    const did = `did:key:z${base58(Buffer.concat([Buffer.from([0x80, 0x24]), point]))}`;
    expect(publicKeyFromDidKey(did)!.export({ format: 'jwk' })).toEqual(publicKey.export({ format: 'jwk' }));
  });

  it('returns null for anything else', () => {
    expect(publicKeyFromDidKey('did:web:example.com')).toBeNull();
    expect(publicKeyFromDidKey('did:key:z0OIl')).toBeNull();
    expect(didKeyConfirmation('agent-1')).toBeNull();
  });
});

describe('receipt actor claims', () => {
  it('puts the principal in sub and the agent in client_id and act.sub, prior actors nested', () => {
    const claims = receiptActorClaims({ principal: 'user-1', agentDid: 'did:key:zC', priorActors: ['did:key:zA', 'did:key:zB'] });
    expect(claims).toEqual({
      sub: 'user-1',
      client_id: 'did:key:zC',
      act: { sub: 'did:key:zC', act: { sub: 'did:key:zB', act: { sub: 'did:key:zA' } } },
    });
    expect(readReceiptActor({ ...claims, userId: 'user-1' })).toEqual({ ok: true, agentDid: 'did:key:zC', principal: 'user-1', layout: 'draft-02' });
  });

  it('reads the legacy layout', () => {
    expect(readReceiptActor({ sub: 'did:key:zA', client_id: 'did:key:zA', userId: 'u' }))
      .toEqual({ ok: true, agentDid: 'did:key:zA', principal: 'u', layout: 'legacy' });
    expect(readReceiptActor({ sub: 'did:key:zA' })).toMatchObject({ ok: true, principal: 'default' });
  });

  it('rejects disagreeing actor claims', () => {
    expect(readReceiptActor({ sub: 'u', client_id: 'did:key:zA', act: { sub: 'did:key:zB' } }).ok).toBe(false);
    expect(readReceiptActor({ sub: 'u', client_id: 'did:key:zA', act: 'did:key:zA' }).ok).toBe(false);
    expect(readReceiptActor({ sub: 'u', client_id: 'did:key:zA', act: { sub: 'did:key:zA' }, userId: 'v' }).ok).toBe(false);
    expect(readReceiptActor({ sub: 'did:key:zA', client_id: 'did:key:zB' }).ok).toBe(false);
  });
});

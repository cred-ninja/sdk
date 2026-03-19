import { describe, it, expect } from 'vitest';
import { generateKeyPair, sign } from 'node:crypto';
import { promisify } from 'node:util';
import {
  generateAgentIdentity,
  importAgentIdentity,
  verifyDelegationReceipt,
  CRED_PUBLIC_KEY_HEX,
  AgentIdentity,
  AgentStatus,
  DelegateParams,
  DelegationResult,
} from '../index';

const generateKeyPairAsync = promisify(generateKeyPair);

// ── generateAgentIdentity() ──────────────────────────────────────────────────

describe('generateAgentIdentity()', () => {
  it('returns valid did:key string', async () => {
    const identity = await generateAgentIdentity();

    expect(identity.did).toMatch(/^did:key:z/);
    expect(typeof identity.did).toBe('string');
  });

  it('did:key prefix is correct (z6Mk for Ed25519)', async () => {
    const identity = await generateAgentIdentity();

    // z6Mk is the base58btc encoding of multicodec 0xed01 (Ed25519)
    // 'z' is multibase prefix, '6Mk' comes from base58 of [0xed, 0x01]
    expect(identity.did).toMatch(/^did:key:z6Mk/);
  });

  it('returns 32-byte public key', async () => {
    const identity = await generateAgentIdentity();

    expect(identity.publicKey).toBeInstanceOf(Uint8Array);
    expect(identity.publicKey.length).toBe(32);
  });

  it('returns 32-byte private key', async () => {
    const identity = await generateAgentIdentity();

    expect(identity.privateKey).toBeInstanceOf(Uint8Array);
    expect(identity.privateKey.length).toBe(32);
  });

  it('two calls produce different keys', async () => {
    const identity1 = await generateAgentIdentity();
    const identity2 = await generateAgentIdentity();

    expect(identity1.did).not.toBe(identity2.did);
    expect(Buffer.from(identity1.publicKey).toString('hex'))
      .not.toBe(Buffer.from(identity2.publicKey).toString('hex'));
    expect(Buffer.from(identity1.privateKey).toString('hex'))
      .not.toBe(Buffer.from(identity2.privateKey).toString('hex'));
  });

  it('export() returns did and privateKeyHex', async () => {
    const identity = await generateAgentIdentity();
    const exported = identity.export();

    expect(exported.did).toBe(identity.did);
    expect(typeof exported.privateKeyHex).toBe('string');
    expect(exported.privateKeyHex.length).toBe(64); // 32 bytes = 64 hex chars
    expect(exported.privateKeyHex).toMatch(/^[0-9a-f]+$/);
  });
});

// ── importAgentIdentity() ────────────────────────────────────────────────────

describe('importAgentIdentity()', () => {
  it('round-trip: generate → export → import → same DID', async () => {
    const original = await generateAgentIdentity();
    const exported = original.export();

    const imported = importAgentIdentity(exported);

    expect(imported.did).toBe(original.did);
    expect(Buffer.from(imported.publicKey).toString('hex'))
      .toBe(Buffer.from(original.publicKey).toString('hex'));
    expect(Buffer.from(imported.privateKey).toString('hex'))
      .toBe(Buffer.from(original.privateKey).toString('hex'));
  });

  it('imported identity can export again', async () => {
    const original = await generateAgentIdentity();
    const exported1 = original.export();

    const imported = importAgentIdentity(exported1);
    const exported2 = imported.export();

    expect(exported2.did).toBe(exported1.did);
    expect(exported2.privateKeyHex).toBe(exported1.privateKeyHex);
  });

  it('throws on invalid DID format', () => {
    expect(() => importAgentIdentity({
      did: 'not-a-did',
      privateKeyHex: '00'.repeat(32),
    })).toThrow('Invalid DID format');
  });

  it('throws on invalid private key length', () => {
    expect(() => importAgentIdentity({
      did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      privateKeyHex: '00'.repeat(16), // 16 bytes instead of 32
    })).toThrow('Invalid private key: must be 32 bytes');
  });

  it('throws on DID/key mismatch', async () => {
    const identity1 = await generateAgentIdentity();
    const identity2 = await generateAgentIdentity();

    // Use DID from identity1 but private key from identity2
    expect(() => importAgentIdentity({
      did: identity1.did,
      privateKeyHex: identity2.export().privateKeyHex,
    })).toThrow('DID does not match derived public key');
  });
});

// ── AgentIdentity interface ──────────────────────────────────────────────────

describe('AgentIdentity interface', () => {
  it('has all required properties', async () => {
    const identity = await generateAgentIdentity();

    expect(identity).toHaveProperty('did');
    expect(identity).toHaveProperty('publicKey');
    expect(identity).toHaveProperty('privateKey');
    expect(identity).toHaveProperty('export');
    expect(typeof identity.export).toBe('function');
  });

  it('keys are independent copies (not references)', async () => {
    const identity = await generateAgentIdentity();
    const publicKey1 = identity.publicKey;
    const publicKey2 = identity.publicKey;

    // Modifying one should not affect the other
    publicKey1[0] = 0xff;
    expect(publicKey2[0]).not.toBe(0xff);
  });
});

// ── verifyDelegationReceipt() ────────────────────────────────────────────────

describe('verifyDelegationReceipt()', () => {
  const agentDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

  it('returns false for null receipt', async () => {
    const result = await verifyDelegationReceipt(null, {
      expectedDid: agentDid,
      credPublicKey: '00'.repeat(32),
    });
    expect(result).toBe(false);
  });

  it('returns false for undefined receipt', async () => {
    const result = await verifyDelegationReceipt(undefined, {
      expectedDid: agentDid,
      credPublicKey: '00'.repeat(32),
    });
    expect(result).toBe(false);
  });

  it('returns false for empty string receipt', async () => {
    const result = await verifyDelegationReceipt('', {
      expectedDid: agentDid,
      credPublicKey: '00'.repeat(32),
    });
    expect(result).toBe(false);
  });

  it('returns false for malformed receipt (not 3 parts)', async () => {
    const result = await verifyDelegationReceipt('only.two', {
      expectedDid: agentDid,
      credPublicKey: '00'.repeat(32),
    });
    expect(result).toBe(false);
  });

  it('returns false for malformed receipt (invalid base64)', async () => {
    const result = await verifyDelegationReceipt('!!!.@@@.###', {
      expectedDid: agentDid,
      credPublicKey: '00'.repeat(32),
    });
    expect(result).toBe(false);
  });

  it('throws when using placeholder public key', async () => {
    // Create a minimal valid-looking JWS
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: agentDid })).toString('base64url');
    const receipt = `${header}.${payload}.fakesig`;

    await expect(
      verifyDelegationReceipt(receipt, {
        expectedDid: agentDid,
        // Uses default CRED_PUBLIC_KEY_HEX which is placeholder
      }),
    ).rejects.toThrow('CRED_PUBLIC_KEY_HEX is placeholder');
  });

  it('returns false for wrong algorithm in header', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: agentDid })).toString('base64url');
    const receipt = `${header}.${payload}.fakesig`;

    const result = await verifyDelegationReceipt(receipt, {
      expectedDid: agentDid,
      credPublicKey: '00'.repeat(32),
    });
    expect(result).toBe(false);
  });

  it('returns false for mismatched DID', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'did:key:z6MkWRONG' })).toString('base64url');
    const receipt = `${header}.${payload}.fakesig`;

    const result = await verifyDelegationReceipt(receipt, {
      expectedDid: agentDid,
      credPublicKey: '00'.repeat(32),
    });
    expect(result).toBe(false);
  });

  it('valid JWS with correct structure returns true when signature matches', async () => {
    // Generate a real key pair for this test
    const { publicKey, privateKey } = await generateKeyPairAsync('ed25519');

    // Extract raw public key bytes
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const rawPublicKey = spki.slice(-32);
    const credPublicKeyHex = Buffer.from(rawPublicKey).toString('hex');

    // Create a valid receipt
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'did:web:cred.ninja',
      sub: agentDid,
      iat: Math.floor(Date.now() / 1000),
      service: 'google',
      scopes: ['calendar.read'],
      userId: 'user_hash_123',
      appClientId: 'app_xxx',
    })).toString('base64url');

    // Sign the message
    const signatureInput = Buffer.from(`${header}.${payload}`, 'utf8');
    const signature = sign(null, signatureInput, privateKey);
    const signatureB64 = signature.toString('base64url');

    const receipt = `${header}.${payload}.${signatureB64}`;

    const result = await verifyDelegationReceipt(receipt, {
      expectedDid: agentDid,
      credPublicKey: credPublicKeyHex,
    });
    expect(result).toBe(true);
  });

  it('returns false when signature is invalid', async () => {
    // Generate a key pair
    const { publicKey } = await generateKeyPairAsync('ed25519');

    // Extract raw public key bytes
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const rawPublicKey = spki.slice(-32);
    const credPublicKeyHex = Buffer.from(rawPublicKey).toString('hex');

    // Create a receipt with a tampered signature
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'did:web:cred.ninja',
      sub: agentDid,
      iat: Math.floor(Date.now() / 1000),
      service: 'google',
      scopes: ['calendar.read'],
      userId: 'user_hash_123',
      appClientId: 'app_xxx',
    })).toString('base64url');

    // Use a fake signature
    const fakeSignature = Buffer.alloc(64, 0x42).toString('base64url');
    const receipt = `${header}.${payload}.${fakeSignature}`;

    const result = await verifyDelegationReceipt(receipt, {
      expectedDid: agentDid,
      credPublicKey: credPublicKeyHex,
    });
    expect(result).toBe(false);
  });
});

// ── scopeCeiling and status ──────────────────────────────────────────────────

describe('generateAgentIdentity() — scopeCeiling and status', () => {
  it('defaults to empty scopeCeiling and active status', async () => {
    const identity = await generateAgentIdentity();

    expect(identity.scopeCeiling).toEqual([]);
    expect(identity.status).toBe('active');
  });

  it('accepts custom scopeCeiling', async () => {
    const identity = await generateAgentIdentity({
      scopeCeiling: ['repo', 'read:org'],
    });

    expect(identity.scopeCeiling).toEqual(['repo', 'read:org']);
    expect(identity.status).toBe('active');
  });

  it('accepts custom status', async () => {
    const identity = await generateAgentIdentity({
      status: 'suspended',
    });

    expect(identity.scopeCeiling).toEqual([]);
    expect(identity.status).toBe('suspended');
  });

  it('accepts both scopeCeiling and status', async () => {
    const identity = await generateAgentIdentity({
      scopeCeiling: ['calendar.read'],
      status: 'revoked',
    });

    expect(identity.scopeCeiling).toEqual(['calendar.read']);
    expect(identity.status).toBe('revoked');
  });

  it('export() includes scopeCeiling and status', async () => {
    const identity = await generateAgentIdentity({
      scopeCeiling: ['repo', 'gist'],
      status: 'active',
    });
    const exported = identity.export();

    expect(exported.scopeCeiling).toEqual(['repo', 'gist']);
    expect(exported.status).toBe('active');
  });

  it('round-trip preserves scopeCeiling and status', async () => {
    const original = await generateAgentIdentity({
      scopeCeiling: ['calendar.read', 'calendar.write'],
      status: 'suspended',
    });
    const exported = original.export();
    const imported = importAgentIdentity(exported);

    expect(imported.scopeCeiling).toEqual(['calendar.read', 'calendar.write']);
    expect(imported.status).toBe('suspended');
    expect(imported.did).toBe(original.did);
  });

  it('import defaults to empty scopeCeiling and active status when not provided', async () => {
    const original = await generateAgentIdentity();
    const exported = original.export();
    const imported = importAgentIdentity({
      did: exported.did,
      privateKeyHex: exported.privateKeyHex,
    });

    expect(imported.scopeCeiling).toEqual([]);
    expect(imported.status).toBe('active');
  });
});

// ── CRED_PUBLIC_KEY_HEX constant ─────────────────────────────────────────────

describe('CRED_PUBLIC_KEY_HEX', () => {
  it('is exported as placeholder', () => {
    expect(CRED_PUBLIC_KEY_HEX).toBe('PLACEHOLDER_REPLACE_BEFORE_LAUNCH');
  });
});

// ── Type definitions ─────────────────────────────────────────────────────────

describe('Type definitions', () => {
  it('DelegateParams accepts optional agentDid', () => {
    // TypeScript compile-time check - if this compiles, the type is correct
    const params: DelegateParams = {
      service: 'google',
      userId: 'user_1',
      appClientId: 'app_1',
      agentDid: 'did:key:z6MkTest',
    };
    expect(params.agentDid).toBe('did:key:z6MkTest');
  });

  it('DelegateParams works without agentDid', () => {
    const params: DelegateParams = {
      service: 'google',
      userId: 'user_1',
      appClientId: 'app_1',
    };
    expect(params.agentDid).toBeUndefined();
  });

  it('DelegationResult includes optional receipt', () => {
    // TypeScript compile-time check
    const result: DelegationResult = {
      accessToken: 'token',
      tokenType: 'Bearer',
      service: 'google',
      scopes: [],
      delegationId: 'del_1',
      receipt: 'header.payload.signature',
    };
    expect(result.receipt).toBe('header.payload.signature');
  });

  it('DelegationResult works without receipt', () => {
    const result: DelegationResult = {
      accessToken: 'token',
      tokenType: 'Bearer',
      service: 'google',
      scopes: [],
      delegationId: 'del_1',
    };
    expect(result.receipt).toBeUndefined();
  });
});

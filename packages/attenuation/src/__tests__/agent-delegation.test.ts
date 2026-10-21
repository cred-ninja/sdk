import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  AgentDelegationMintError,
  agentDelegationCommitment,
  mintAgentDelegationToken,
  verifyAgentDelegationChain,
} from '../agent-delegation.js';
import {
  base64urlDecode,
  createKeySigner,
  createVerificationKey,
  jwkThumbprint,
  signCompactJws,
  staticKeyResolver,
} from '../jws.js';
import { canonicalJson } from '../jcs.js';

const ed = generateKeyPairSync('ed25519');
const p256 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const AUD = 'https://rs.example.com';

const ROOT_CONSTRAINTS = [
  { key: 'egress', rank: 'internal', order: ['none', 'internal', 'any'] },
  { key: 'max_calls', max_lifetime: 50 },
  { key: 'max_spend', max: 100 },
  { key: 'max_spend', max_subtree: 1000 },
];

function root(signer = createKeySigner(ed.privateKey), extra: Partial<Parameters<typeof mintAgentDelegationToken>[0]> = {}) {
  return mintAgentDelegationToken({
    signer,
    iss: 'https://ds.example.com',
    sub: 'user:alice',
    clientId: 'did:key:z6MkOrchestrator',
    aud: AUD,
    cnf: { jkt: jwkThumbprint(ed.publicKey) },
    jti: 'dt-0',
    iat: 1000,
    exp: 4600,
    scopes: ['crm.*', 'User.Read'],
    constraints: ROOT_CONSTRAINTS,
    delMaxDepth: 3,
    ...extra,
  });
}

function child(parent: string, signer = createKeySigner(ed.privateKey), extra: Partial<Parameters<typeof mintAgentDelegationToken>[0]> = {}) {
  return mintAgentDelegationToken({
    signer,
    iss: 'https://ds.example.com',
    sub: 'user:alice',
    clientId: 'did:key:z6MkSummarizer',
    aud: AUD,
    cnf: { jkt: 'stand-in' },
    jti: 'dt-1',
    iat: 1000,
    exp: 1900,
    scopes: ['crm.read'],
    parent,
    ...extra,
  });
}

function payload(token: string): Record<string, any> {
  return JSON.parse(base64urlDecode(token.split('.')[1]!)!.toString('utf8'));
}

describe('mintAgentDelegationToken / verifyAgentDelegationChain', () => {
  it('round-trips an EdDSA chain with kid in the header and the -02 claim layout', () => {
    const signer = createKeySigner(ed.privateKey);
    const t0 = root(signer);
    const t1 = child(t0, signer);
    const header = JSON.parse(base64urlDecode(t1.split('.')[0]!)!.toString('utf8'));
    expect(header).toEqual({ alg: 'EdDSA', c14n: 'JCS', kid: jwkThumbprint(ed.publicKey), typ: 'at+jwt' });
    const p1 = payload(t1);
    expect(p1.sub).toBe('user:alice');
    expect(p1.client_id).toBe('did:key:z6MkSummarizer');
    expect(p1.del_depth).toBe(1);
    expect(p1.par_hash).toBe(agentDelegationCommitment(t0));
    // Constraints omitted on the child are inherited unchanged.
    expect(p1.authorization_details[0].constraints).toEqual(ROOT_CONSTRAINTS);

    const result = verifyAgentDelegationChain([t0, t1], {
      acceptedAlgs: ['EdDSA'],
      resolveKey: staticKeyResolver([createVerificationKey(ed.publicKey)]),
      now: 1500,
      audience: AUD,
    });
    expect(result).toMatchObject({ ok: true, depth: 1, principal: 'user:alice', actingAgent: 'did:key:z6MkSummarizer' });
  });

  it('round-trips an ES256 chain', () => {
    const signer = createKeySigner(p256.privateKey);
    expect(signer.alg).toBe('ES256');
    const t0 = root(signer);
    const t1 = child(t0, signer);
    const result = verifyAgentDelegationChain([t0, t1], {
      acceptedAlgs: ['ES256', 'EdDSA'],
      resolveKey: staticKeyResolver([createVerificationKey(p256.publicKey)]),
      now: 1500,
    });
    expect(result.ok).toBe(true);
  });

  it('rejects an algorithm off the accepted list even when the signature verifies', () => {
    const t0 = root(createKeySigner(p256.privateKey));
    const result = verifyAgentDelegationChain([t0], {
      acceptedAlgs: ['EdDSA'],
      resolveKey: staticKeyResolver([createVerificationKey(p256.publicKey)]),
      now: 1500,
    });
    expect(result).toMatchObject({ ok: false, reason: 'signature_invalid', hop: 0 });
  });

  it('never lets the header alg choose the key algorithm', () => {
    // An ES256 key registered under the Ed25519 key's kid: the header says
    // EdDSA, both are accepted, but the resolved key is ES256.
    const kid = jwkThumbprint(ed.publicKey);
    const t0 = root(createKeySigner(ed.privateKey));
    const result = verifyAgentDelegationChain([t0], {
      acceptedAlgs: ['EdDSA', 'ES256'],
      resolveKey: staticKeyResolver([createVerificationKey(p256.publicKey, kid)]),
      now: 1500,
    });
    expect(result).toMatchObject({ ok: false, reason: 'signature_invalid' });
    expect(result.ok ? '' : result.message).toMatch(/alg_key_mismatch/);
  });

  it('rejects a payload whose bytes are not JCS', () => {
    const signer = createKeySigner(ed.privateKey);
    const claims = payload(root(signer));
    const header = { alg: 'EdDSA', kid: signer.kid };
    const h = Buffer.from(canonicalJson(header)).toString('base64url');
    const p = Buffer.from(JSON.stringify(claims, null, 1)).toString('base64url');
    const sig = Buffer.from(signer.sign(Buffer.from(`${h}.${p}`))).toString('base64url');
    const result = verifyAgentDelegationChain([`${h}.${p}.${sig}`], {
      acceptedAlgs: ['EdDSA'],
      resolveKey: staticKeyResolver([createVerificationKey(ed.publicKey)]),
      now: 1500,
    });
    expect(result).toMatchObject({ ok: false, reason: 'non_canonical' });
  });

  it('subsumes an unknown constraint type only by an identical one', () => {
    const signer = createKeySigner(ed.privateKey);
    const t0 = root(signer, { constraints: [{ key: 'units', units: ['metric'] }] });
    const same = child(t0, signer, { constraints: [{ key: 'units', units: ['metric'] }] });
    const resolveKey = staticKeyResolver([createVerificationKey(ed.publicKey)]);
    expect(verifyAgentDelegationChain([t0, same], { acceptedAlgs: ['EdDSA'], resolveKey, now: 1500 }).ok).toBe(true);
    expect(() => child(t0, signer, { constraints: [{ key: 'units', units: ['imperial'] }] })).toThrow(AgentDelegationMintError);
    // Hand-signed to get past the producer check: the verifier rejects it too.
    const p = payload(same);
    p.authorization_details[0].constraints = [{ key: 'units', units: ['imperial'] }];
    const forged = signCompactJws(p, signer, { typ: 'at+jwt', c14n: 'JCS' });
    expect(verifyAgentDelegationChain([t0, forged], { acceptedAlgs: ['EdDSA'], resolveKey, now: 1500 }))
      .toMatchObject({ ok: false, reason: 'not_narrower', hop: 1 });
  });

  it('enforces a tighter del_max_depth carried by a child', () => {
    const signer = createKeySigner(ed.privateKey);
    const resolveKey = staticKeyResolver([createVerificationKey(ed.publicKey)]);
    const t0 = root(signer, { delMaxDepth: 6 });
    const t1 = child(t0, signer, { delMaxDepth: 2 });
    const t2 = child(t1, signer, { jti: 'dt-2', clientId: 'did:key:z6MkFormatter' });
    expect(verifyAgentDelegationChain([t0, t1], { acceptedAlgs: ['EdDSA'], resolveKey, now: 1500 }).ok).toBe(true);
    expect(verifyAgentDelegationChain([t0, t1, t2], { acceptedAlgs: ['EdDSA'], resolveKey, now: 1500 }))
      .toMatchObject({ ok: false, reason: 'depth_invalid', hop: 2 });
  });

  it('refuses to mint a wider child', () => {
    const t0 = root();
    expect(() => child(t0, undefined, { scopes: ['mail.send'] })).toThrow(/not covered/);
    expect(() => child(t0, undefined, { exp: 9999 })).toThrow(/expire after/);
    expect(() => child(t0, undefined, { sub: 'user:mallory' })).toThrow(/Principal/);
    expect(() => child(t0, undefined, { constraints: [{ key: 'max_calls', max_lifetime: 50 }] })).toThrow(/omits/);
    expect(() => child(t0, undefined, { delMaxDepth: 9 })).toThrow(/del_max_depth/);
  });

  it('refuses to mint malformed claims', () => {
    expect(() => root(undefined, { cnf: {} })).toThrow(/cnf/);
    expect(() => root(undefined, { scopes: ['User.*'] })).toThrow(/invalid scope/);
    expect(() => root(undefined, { constraints: [{ key: 'egress', rank: 'none' }] })).toThrow(/order/);
    expect(() => root(undefined, { delMaxDepth: undefined })).toThrow(/del_max_depth/);
  });
});

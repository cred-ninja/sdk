import { describe, expect, it } from 'vitest';
import { verifyDelegationChain } from '../chain-verify.js';
import type { DelegationChainHop } from '../chain-verify.js';

// Shapes mirror attenu-guard tests/vectors/*.json: a 3-hop chain
// orchestrator -> summarizer -> formatter, scopes {crm.*, mail.send} -> {crm.read} -> {crm.read},
// exp 3600 -> 900 -> 300, evaluated at now = 0.
function chain(): DelegationChainHop[] {
  return [
    { agentDid: 'orchestrator', delegationId: 'chain:n0', chainDepth: 0, scopes: ['crm.*', 'mail.send'], iat: 0, exp: 3600, signatureValid: true, selfHash: 'h0' },
    { agentDid: 'summarizer', delegationId: 'chain:n1', chainDepth: 1, scopes: ['crm.read'], iat: 0, exp: 900, signatureValid: true, selfHash: 'h1', parentHash: 'h0' },
    { agentDid: 'formatter', delegationId: 'chain:n2', chainDepth: 2, scopes: ['crm.read'], iat: 0, exp: 300, signatureValid: true, selfHash: 'h2', parentHash: 'h1' },
  ];
}

describe('verifyDelegationChain', () => {
  it('accepts a valid strictly attenuating chain', () => {
    const result = verifyDelegationChain(chain(), { now: 0, maxDepth: 6 });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.depth).toBe(2);
      expect(result.leaf.agentDid).toBe('formatter');
    }
  });

  it('rejects an empty chain', () => {
    expect(verifyDelegationChain([], { now: 0 })).toMatchObject({ ok: false, reason: 'empty_chain' });
  });

  it('rejects a hop whose signature did not verify', () => {
    const hops = chain();
    hops[2].signatureValid = false;
    expect(verifyDelegationChain(hops, { now: 0 })).toMatchObject({ ok: false, reason: 'signature_invalid', hop: 2 });
  });

  it('rejects a widened scope', () => {
    const hops = chain();
    hops[2].scopes = ['crm.read', 'pay.transfer'];
    const result = verifyDelegationChain(hops, { now: 0 });
    expect(result).toMatchObject({ ok: false, reason: 'not_narrower', hop: 2 });
    if (!result.ok) expect(result.message).toContain('pay.transfer');
  });

  it('accepts wildcard narrowing at every level', () => {
    const hops = chain();
    hops[1].scopes = ['crm.contacts.*'];
    hops[2].scopes = ['crm.contacts.read'];
    expect(verifyDelegationChain(hops, { now: 0 }).ok).toBe(true);
  });

  it('rejects a parent commitment that points at a different hop (splice)', () => {
    const hops = chain();
    hops[1].parentHash = 'some-other-root';
    expect(verifyDelegationChain(hops, { now: 0 })).toMatchObject({ ok: false, reason: 'parent_hash_mismatch', hop: 1 });
  });

  it('rejects a missing parent commitment when required', () => {
    const hops = chain();
    delete hops[2].parentHash;
    expect(verifyDelegationChain(hops, { now: 0 })).toMatchObject({ ok: false, reason: 'parent_hash_mismatch', hop: 2 });
  });

  it('tolerates a missing commitment only when not required, and still checks one that is present', () => {
    const hops = chain();
    delete hops[2].parentHash;
    expect(verifyDelegationChain(hops, { now: 0, requireParentHash: false }).ok).toBe(true);
    hops[1].parentHash = 'wrong';
    expect(verifyDelegationChain(hops, { now: 0, requireParentHash: false })).toMatchObject({ ok: false, reason: 'parent_hash_mismatch', hop: 1 });
  });

  it('rejects a depth that does not step by one from the root', () => {
    const hops = chain();
    hops[2].chainDepth = 3;
    expect(verifyDelegationChain(hops, { now: 0 })).toMatchObject({ ok: false, reason: 'depth_invalid', hop: 2 });
  });

  it('rejects a chain longer than maxDepth allows', () => {
    // attenu-guard reject_depth_exceeded: root del_max_depth tampered to 2, so the
    // leaf at depth 2 is one past what the ceiling admits (Cred maxDepth = del_max_depth - 1).
    expect(verifyDelegationChain(chain(), { now: 0, maxDepth: 1 })).toMatchObject({ ok: false, reason: 'depth_invalid', hop: 2 });
  });

  it('rejects an expired hop', () => {
    expect(verifyDelegationChain(chain(), { now: 301 })).toMatchObject({ ok: false, reason: 'expired', hop: 2 });
    expect(verifyDelegationChain(chain(), { now: 301, clockSkewSeconds: 60 }).ok).toBe(true);
  });

  it('rejects a child that expires after its parent', () => {
    const hops = chain();
    hops[2].iat = 100000;
    hops[2].exp = 100300;
    expect(verifyDelegationChain(hops, { now: 0 })).toMatchObject({ ok: false, reason: 'exp_not_monotonic', hop: 2 });
  });

  it('rejects self delegation', () => {
    const hops = chain();
    hops[1].agentDid = 'orchestrator';
    expect(verifyDelegationChain(hops, { now: 0 })).toMatchObject({ ok: false, reason: 'self_delegation', hop: 1 });
  });

  it('rejects a malformed hop before anything else', () => {
    const hops = chain();
    (hops[0] as any).scopes = 'crm.*';
    expect(verifyDelegationChain(hops, { now: 0 })).toMatchObject({ ok: false, reason: 'malformed', hop: 0 });
  });
});

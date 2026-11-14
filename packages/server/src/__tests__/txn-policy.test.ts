/** Unit tests for the Txn-Token policy decisions (identity/txn-policy.ts). */
import { describe, it, expect } from 'vitest';
import { decideTxnToken, isCredentialRoute, txnTrustRequiredFor } from '../identity/txn-policy.js';
import type { VerifiedExternalIdentity } from '../identity/types.js';
import { txnIssuer } from './wimse-fixture.js';

const TD = 'domain-b.example';
const tts = txnIssuer(TD);

function wimse(proof: 'wpt' | 'http-sig', covered: string[] = ['txn-token'], trustDomain = TD): VerifiedExternalIdentity {
  return {
    kind: 'wimse', subject: `wimse://${trustDomain}/w`, trustDomain, proof, expiresAt: 9999999999,
    attributes: proof === 'http-sig' ? { covered } : {},
  };
}

const decide = (over: Partial<Parameters<typeof decideTxnToken>[0]>) => decideTxnToken({
  trustByDomain: { [TD]: tts.trust() }, identity: wimse('http-sig'), header: undefined,
  credentialRoute: true, requiredElsewhere: false, ...over,
});
const code = (d: ReturnType<typeof decideTxnToken>) => (d.ok ? 'ok' : d.code);

describe('isCredentialRoute', () => {
  it('names the credential routes, ignoring case, query and trailing slash', () => {
    for (const p of ['/api/v1/delegate', '/api/v1/use/', '/API/V1/SUBDELEGATE?x=1', '/api/v1/token', '/bc-authorize', '/api/token/google']) {
      expect(isCredentialRoute(p)).toBe(true);
    }
    for (const p of ['/api/v1/connections', '/api/v1/audit', '/api/v1/delegations/x/revoke']) expect(isCredentialRoute(p)).toBe(false);
  });
});

describe('txnTrustRequiredFor', () => {
  const mappings = [
    { kind: 'wimse' as const, subject: `wimse://${TD}/w`, agentDid: 'did:key:z6MkA' },
    { kind: 'wimse' as const, subject: 'not a workload id', agentDid: 'did:key:z6MkB' },
  ];
  it('returns the required trust of a mapped domain, and nothing otherwise', () => {
    expect(txnTrustRequiredFor({ [TD]: tts.trust() }, mappings, 'did:key:z6MkA')?.aud).toBe(TD);
    expect(txnTrustRequiredFor({ [TD]: tts.trust({ required: false }) }, mappings, 'did:key:z6MkA')).toBeUndefined();
    expect(txnTrustRequiredFor({ [TD]: tts.trust() }, mappings, 'did:key:z6MkB')).toBeUndefined();
    expect(txnTrustRequiredFor(undefined, mappings, 'did:key:z6MkA')).toBeUndefined();
  });
});

describe('decideTxnToken', () => {
  it('accepts a bound, valid token and returns it with its trust', () => {
    const d = decide({ header: tts.mint() });
    expect(d.ok && d.accepted?.token.userId).toBe('default');
    expect(d.ok && d.accepted?.trust.aud).toBe(TD);
    expect(code(decide({ identity: wimse('wpt'), header: tts.mint() }))).toBe('ok');
  });

  it('refuses a token without a WIMSE identity, and ignores its absence', () => {
    expect(code(decide({ identity: null, header: tts.mint() }))).toBe('txn_token_unbound');
    expect(decide({ identity: null })).toEqual({ ok: true });
  });

  it('refuses a token from a domain with no trust, and requires one only where configured', () => {
    expect(code(decide({ identity: wimse('http-sig', ['txn-token'], 'other.example'), header: tts.mint() }))).toBe('txn_token_untrusted');
    expect(code(decide({ identity: wimse('http-sig', [], 'other.example') }))).toBe('ok');
    expect(code(decide({ identity: wimse('http-sig', [], 'other.example'), requiredElsewhere: true }))).toBe('txn_token_required');
  });

  it('requires a token on credential routes only', () => {
    expect(code(decide({}))).toBe('txn_token_required');
    expect(code(decide({ credentialRoute: false }))).toBe('ok');
    expect(code(decide({ trustByDomain: { [TD]: tts.trust({ required: false }) } }))).toBe('ok');
    expect(code(decide({ trustByDomain: { [TD]: tts.trust({ required: false }) }, requiredElsewhere: true }))).toBe('txn_token_required');
  });

  it('refuses an unbound, duplicated or invalid token', () => {
    expect(code(decide({ identity: wimse('http-sig', ['authorization']), header: tts.mint() }))).toBe('txn_token_unbound');
    expect(code(decide({ identity: { ...wimse('wpt'), proof: 'channel' }, header: tts.mint() }))).toBe('txn_token_unbound');
    expect(code(decide({ header: [tts.mint(), tts.mint()] }))).toBe('txn_token_invalid');
    expect(code(decide({ header: `${tts.mint()},${tts.mint()}` }))).toBe('txn_token_invalid');
    expect(code(decide({ header: 'not.a.jwt' }))).toMatch(/^txn_token_/);
    expect(code(decide({ header: tts.mint({ exp: 1 }) }))).toMatch(/^txn_token_/);
  });
});

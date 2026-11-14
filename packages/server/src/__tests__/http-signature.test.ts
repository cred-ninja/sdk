import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import {
  signWimseRequest,
  signWimseResponse,
  verifyWimseRequestSignature,
  generateWorkloadKey,
  type HttpSigMessage,
  type HttpSigVerifyConfig,
} from '../identity/http-signature.js';
import { loadTrustBundle } from '../identity/trust-bundle.js';
import { createReplayCache, IdentityRefusal } from '../identity/types.js';

const TD = 'domain-b.example';
const AUD = 'https://cred.domain-b.example/api/v1/connections';
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');

function setup(alg: 'ES256' | 'EdDSA' = 'ES256') {
  const issuer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const workload = generateWorkloadKey(alg);
  const anchors = loadTrustBundle({ jwks: { keys: [{ ...issuer.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'wit-svid' } as any] } }, { keyUse: 'wit-svid' });
  const now = Math.floor(Date.now() / 1000);
  const mintWit = (claims: Record<string, unknown> = {}) => {
    const header = b64({ alg: 'ES256', kid: 'k1', typ: 'wit+jwt' });
    const payload = b64({
      sub: `spiffe://${TD}/agent/planner`, iat: now - 10, exp: now + 3600,
      cnf: { jwk: { ...workload.publicKey.export({ format: 'jwk' }), alg } }, ...claims,
    });
    const sig = crypto.sign('sha256', Buffer.from(`${header}.${payload}`), { key: issuer.privateKey, dsaEncoding: 'ieee-p1363' });
    return `${header}.${payload}.${sig.toString('base64url')}`;
  };
  const cfg = (over: Partial<HttpSigVerifyConfig> = {}): HttpSigVerifyConfig => ({
    trustDomains: { [TD]: anchors }, audiences: [AUD], replay: createReplayCache(), ...over,
  });
  const signed = (opts: { headers?: Record<string, string>; body?: string; wit?: string; method?: string; created?: number; lifetimeSec?: number; nonce?: string } = {}) => {
    const body = opts.body === undefined ? undefined : Buffer.from(opts.body);
    const headers = signWimseRequest({
      method: opts.method ?? 'POST', path: '/api/v1/connections', headers: opts.headers ?? {}, body,
      wit: opts.wit ?? mintWit(), privateKey: workload.privateKey, alg, audience: AUD,
      created: opts.created, lifetimeSec: opts.lifetimeSec, nonce: opts.nonce,
    });
    const msg: HttpSigMessage = { method: opts.method ?? 'POST', path: '/api/v1/connections', headers, body };
    return msg;
  };
  return { cfg, signed, mintWit, now };
}

function code(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    if (err instanceof IdentityRefusal) return err.code;
    throw err;
  }
  return 'accepted';
}

describe('http-signature-08 request verifier', () => {
  it.each(['ES256', 'EdDSA'] as const)('accepts a %s signed request with a JSON body and reports what it covered', (alg) => {
    const s = setup(alg);
    const msg = s.signed({ headers: { 'content-type': 'application/json' }, body: '{"a":1}' });
    const r = verifyWimseRequestSignature(msg, s.cfg());
    expect(r?.wit.subject).toBe(`spiffe://${TD}/agent/planner`);
    expect([...r!.covered]).toEqual(expect.arrayContaining(['@method', '@path', '@query', 'workload-identity-token', 'content-type', 'content-digest']));
  });

  it('refuses a Txn-Token added after signing (present but not covered)', () => {
    const s = setup();
    const msg = s.signed();
    (msg.headers as Record<string, string>)['txn-token'] = 'a.b.c';
    expect(code(() => verifyWimseRequestSignature(msg, s.cfg()))).toBe('coverage');
  });

  it('refuses an Authorization header added after signing', () => {
    const s = setup();
    const msg = s.signed();
    (msg.headers as Record<string, string>).authorization = 'DPoP swapped';
    expect(code(() => verifyWimseRequestSignature(msg, s.cfg()))).toBe('coverage');
  });

  it('covers a Txn-Token present at signing, and refuses one swapped afterwards', () => {
    const s = setup();
    const msg = s.signed({ headers: { 'txn-token': 'orig.txn.token' } });
    expect(verifyWimseRequestSignature(msg, s.cfg())?.covered.has('txn-token')).toBe(true);
    (msg.headers as Record<string, string>)['txn-token'] = 'other.txn.token';
    expect(code(() => verifyWimseRequestSignature(msg, s.cfg()))).toBe('bad_signature');
  });

  it('a forged signature does not consume the nonce; the genuine request then passes once', () => {
    const s = setup();
    const cfg = s.cfg();
    const msg = s.signed();
    const forged = { ...msg, headers: { ...msg.headers, signature: (msg.headers.signature as string).replace(/:[A-Za-z0-9+/]{4}/, ':AAAA') } };
    expect(code(() => verifyWimseRequestSignature(forged, cfg))).toBe('bad_signature');
    expect(code(() => verifyWimseRequestSignature(msg, cfg))).toBe('accepted');
    expect(code(() => verifyWimseRequestSignature(msg, cfg))).toBe('replay');
  });

  it('validates the WIT before the signature: an expired WIT is refused as such even with a broken signature', () => {
    const s = setup();
    const msg = s.signed({ wit: s.mintWit({ iat: s.now - 7200, exp: s.now - 3600 }) });
    const broken = { ...msg, headers: { ...msg.headers, signature: 'wimse=:AAAA:' } };
    expect(code(() => verifyWimseRequestSignature(broken, s.cfg()))).toBe('wit:wit_expired');
  });

  it('enforces the validity window: too long a lifetime, created in the future, already expired', () => {
    const s = setup();
    expect(code(() => verifyWimseRequestSignature(s.signed({ lifetimeSec: 301 }), s.cfg()))).toBe('bad_window');
    expect(code(() => verifyWimseRequestSignature(s.signed({ created: s.now + 120 }), s.cfg()))).toBe('bad_window');
    expect(code(() => verifyWimseRequestSignature(s.signed({ created: s.now - 100, lifetimeSec: 60 }), s.cfg()))).toBe('expired_signature');
  });

  it('applies the configured nonce floor', () => {
    const s = setup();
    expect(code(() => verifyWimseRequestSignature(s.signed({ nonce: 'abcd1111' }), s.cfg()))).toBe('bad_nonce');
    expect(code(() => verifyWimseRequestSignature(s.signed({ nonce: 'abcd1111' }), s.cfg({ minNonceLength: 8 })))).toBe('accepted');
  });

  it('returns null when no signature carries the WIMSE tag, so other sources may handle the request', () => {
    const s = setup();
    const msg = s.signed();
    const other = { ...msg, headers: { ...msg.headers, 'signature-input': (msg.headers['signature-input'] as string).replace('wimse-workload-to-workload', 'web-bot-auth') } };
    expect(verifyWimseRequestSignature(other, s.cfg())).toBeNull();
  });

  it('refuses content whose bytes differ from Content-Digest, and content without one', () => {
    const s = setup();
    const msg = s.signed({ headers: { 'content-type': 'text/plain' }, body: 'hello' });
    expect(code(() => verifyWimseRequestSignature({ ...msg, body: Buffer.from('hellO') }, s.cfg()))).toBe('content_digest_mismatch');
    const bare = s.signed();
    expect(code(() => verifyWimseRequestSignature({ ...bare, body: Buffer.from('x') }, s.cfg()))).toBe('content_digest_missing');
  });

  it('accepts sha-512 alongside sha-256 and refuses a Content-Digest with no supported algorithm', () => {
    const s = setup();
    const signed = s.signed({ body: 'payload' });
    // Digest is checked before the signature, so this isolates the algorithm rule.
    const unsupported = { ...signed, headers: { ...signed.headers, 'content-digest': 'md5=:AAAA:' } };
    expect(code(() => verifyWimseRequestSignature(unsupported, s.cfg()))).toBe('content_digest_unsupported');
    const sha512 = `sha-512=:${crypto.createHash('sha512').update('payload').digest('base64')}:`;
    const both = { ...signed, headers: { ...signed.headers, 'content-digest': `${signed.headers['content-digest']}, ${sha512}` } };
    // Changing a covered header breaks the signature, so the digest rule passed first.
    expect(code(() => verifyWimseRequestSignature(both, s.cfg()))).toBe('bad_signature');
  });

  it('refuses component parameters it does not implement and upper-case component names', () => {
    const s = setup();
    const msg = s.signed();
    const sf = { ...msg, headers: { ...msg.headers, 'signature-input': (msg.headers['signature-input'] as string).replace('"@query"', '"@query";sf') } };
    expect(code(() => verifyWimseRequestSignature(sf, s.cfg()))).toBe('bad_component');
    const upper = { ...msg, headers: { ...msg.headers, 'signature-input': (msg.headers['signature-input'] as string).replace('"workload-identity-token"', '"Workload-Identity-Token"') } };
    expect(code(() => verifyWimseRequestSignature(upper, s.cfg()))).toBe('bad_component');
  });

  it('refuses a request signed by a key other than the one the WIT confirms', () => {
    const s = setup('ES256');
    const msg = s.signed();
    const stranger = generateWorkloadKey('ES256');
    const witForStranger = s.mintWit({ cnf: { jwk: { ...stranger.publicKey.export({ format: 'jwk' }), alg: 'ES256' } } });
    const swapped = { ...msg, headers: { ...msg.headers, 'workload-identity-token': witForStranger } };
    // The WIT is valid, but its cnf key did not make the signature (§3.1). The
    // WIT header is covered too, so either way the signature cannot verify.
    expect(code(() => verifyWimseRequestSignature(swapped, s.cfg()))).toBe('bad_signature');
  });
});

describe('http-signature-08 response signer', () => {
  it('produces a §3.4 response signature that an independent RFC 9421 base check verifies', () => {
    const key = generateWorkloadKey('ES256');
    const body = Buffer.from('{"ok":true}');
    const h = signWimseResponse({
      status: 200, headers: { 'content-type': 'application/json' }, body,
      request: { method: 'POST', path: '/api/v1/use', query: 'a=1' },
      requestNonce: 'req-nonce-0123456789abcdef', wit: 'wit.of.cred', privateKey: key.privateKey, alg: 'ES256',
    });
    const params = h['signature-input'].slice(h['signature-input'].indexOf('=') + 1);
    expect(params).toContain('wimse-req-nonce="req-nonce-0123456789abcdef"');
    // Independent signature base: string operations only.
    const values: Record<string, string> = {
      '"@status"': '200', '"workload-identity-token"': 'wit.of.cred', '"content-type"': 'application/json',
      '"content-digest"': `sha-256=:${crypto.createHash('sha256').update(body).digest('base64')}:`,
      '"@method";req': 'POST', '"@path";req': '/api/v1/use', '"@query";req': '?a=1',
    };
    const items = params.slice(1, params.indexOf(')')).match(/"[^"]+"(?:;req)?/g)!;
    expect(items).toEqual(Object.keys(values));
    const base = `${items.map((i) => `${i}: ${values[i]}`).join('\n')}\n"@signature-params": ${params}`;
    const sig = Buffer.from(/=:([^:]+):/.exec(h.signature)![1], 'base64');
    expect(crypto.verify('sha256', Buffer.from(base), { key: key.publicKey, dsaEncoding: 'ieee-p1363' }, sig)).toBe(true);
    expect(h['content-digest']).toBe(values['"content-digest"']);
  });
});

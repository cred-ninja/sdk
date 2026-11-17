/**
 * WIMSE WIT + WPT verification (draft-ietf-wimse-workload-creds-03,
 * draft-ietf-wimse-wpt-02, draft-ietf-wimse-identifier-04).
 *
 * Every negative case mutates one thing in a request minted by `mint()` and is
 * paired with a control built the same way that passes, so a refusal proves
 * the mutated check, not a broken fixture.
 */
import { describe, it, expect } from 'vitest';
import crypto, { type KeyObject } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createReplayCache, IdentityRefusal, type IdentityRequest } from '../identity/types.js';
import { loadTrustBundle, type TrustAnchorKeys } from '../identity/trust-bundle.js';
import {
  createWimseIdentitySource,
  validateWorkloadIdentifier,
  verifyWit,
  type WimseSourceConfig,
} from '../identity/wimse.js';

const NOW = 1_800_000_000;
const TARGET = 'https://broker.example.net/v1/credentials';
const TD = 'prod.example.org';
const OTHER_TD = 'partner.example.com';
const SUB = `spiffe://${TD}/ns/agents/sa/runner`;
const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'wimse');

type Alg = 'ES256' | 'Ed25519' | 'EdDSA';

const b64u = (v: string | Buffer) => Buffer.from(v).toString('base64url');
const hash = (v: string) => crypto.createHash('sha256').update(v, 'ascii').digest('base64url');

function sign(alg: Alg, key: KeyObject, input: string): string {
  return alg === 'ES256'
    ? crypto.sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')
    : crypto.sign(null, Buffer.from(input), key).toString('base64url');
}

function jws(header: object, claims: object, alg: Alg, key: KeyObject): string {
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
  return `${input}.${sign(alg, key, input)}`;
}

function pair(kind: 'ec' | 'ed25519') {
  return kind === 'ec'
    ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    : crypto.generateKeyPairSync('ed25519');
}

function publicJwk(key: KeyObject, extra: object = {}) {
  return { ...(key.export({ format: 'jwk' }) as object), ...extra };
}

// One issuer per trust domain. Both use kid "k1", so a WIT signed by the other
// domain's key with a matching kid must still fail on the signature.
const issuers: Record<string, { publicKey: KeyObject; privateKey: KeyObject; alg: Alg }> = {
  [TD]: { ...pair('ec'), alg: 'ES256' as Alg },
  [OTHER_TD]: { ...pair('ed25519'), alg: 'Ed25519' as Alg },
};
const anchors: Record<string, TrustAnchorKeys> = Object.fromEntries(
  Object.entries(issuers).map(([td, k]) => [
    td,
    loadTrustBundle({ jwks: { keys: [publicJwk(k.publicKey, { kid: 'k1', use: 'wit-svid' })] } }, { keyUse: 'wit-svid' }),
  ]),
);
const workloadEc = pair('ec');
const workloadEd = pair('ed25519');

interface MintOpts {
  td?: string;
  workload?: 'ec' | 'ed25519';
  witHeader?: Record<string, unknown>;
  witClaims?: Record<string, unknown>;
  witSigner?: { alg: Alg; key: KeyObject };
  cnfJwk?: Record<string, unknown>;
  wptHeader?: Record<string, unknown>;
  wptClaims?: Record<string, unknown>;
  wptSigner?: { alg: Alg; key: KeyObject };
  wit?: string;
  headers?: Record<string, string | string[] | undefined>;
}

let jtiCounter = 0;
const freshJti = () => `jti-${crypto.randomBytes(12).toString('hex')}-${jtiCounter++}`;

function mint(o: MintOpts = {}): { req: IdentityRequest; wit: string; wpt: string } {
  const td = o.td ?? TD;
  const issuer = issuers[td] ?? issuers[TD];
  const wl = o.workload === 'ed25519' ? workloadEd : workloadEc;
  const wlAlg: Alg = o.workload === 'ed25519' ? 'Ed25519' : 'ES256';
  const cnfJwk = o.cnfJwk ?? publicJwk(wl.publicKey, { alg: wlAlg });
  const witSigner = o.witSigner ?? { alg: issuer.alg, key: issuer.privateKey };
  const wit =
    o.wit ??
    jws(
      { alg: witSigner.alg, kid: 'k1', typ: 'wit+jwt', ...o.witHeader },
      { sub: td === TD ? SUB : `spiffe://${td}/workload`, iat: NOW - 60, exp: NOW + 3600, cnf: { jwk: cnfJwk }, ...o.witClaims },
      witSigner.alg,
      witSigner.key,
    );
  const wptSigner = o.wptSigner ?? { alg: wlAlg, key: wl.privateKey };
  const wpt = jws(
    { alg: wptSigner.alg, typ: 'wpt+jwt', ...o.wptHeader },
    { aud: TARGET, exp: NOW + 120, jti: freshJti(), wth: hash(wit), ...o.wptClaims },
    wptSigner.alg,
    wptSigner.key,
  );
  return {
    wit,
    wpt,
    req: {
      method: 'POST',
      targetUri: TARGET,
      headers: { 'workload-identity-token': wit, authorization: `WPT ${wpt}`, host: 'broker.example.net', ...o.headers },
      socket: null,
    },
  };
}

function source(overrides: Partial<WimseSourceConfig> = {}) {
  return createWimseIdentitySource({ trustDomains: anchors, replay: createReplayCache(), now: () => NOW, ...overrides });
}

async function refusalCode(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    expect(err).toBeInstanceOf(IdentityRefusal);
    return (err as IdentityRefusal).code;
  }
  throw new Error('expected an IdentityRefusal');
}

/** Control passes, mutation is refused with `code`. */
async function expectPair(control: MintOpts, mutated: MintOpts, code: string, src = source()) {
  await expect(src.authenticate(mint(control).req)).resolves.toMatchObject({ kind: 'wimse', proof: 'wpt' });
  expect(await refusalCode(src.authenticate(mint(mutated).req))).toBe(code);
}

describe('WIMSE identity source: positive paths', () => {
  it('ES256 issuer + ES256 workload key: returns subject, trust domain, cnf thumbprint, min expiry', async () => {
    const id = await source().authenticate(mint().req);
    const jwk = workloadEc.publicKey.export({ format: 'jwk' });
    const jkt = crypto
      .createHash('sha256')
      .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
      .digest('base64url');
    expect(id).toEqual({
      kind: 'wimse',
      subject: SUB,
      trustDomain: TD,
      attributes: { cnfJkt: jkt },
      proof: 'wpt',
      expiresAt: NOW + 120,
    });
  });

  it('Ed25519 issuer + Ed25519 workload key passes; WPT alg "EdDSA" matches cnf alg "Ed25519"', async () => {
    const src = source();
    const id = await src.authenticate(mint({ td: OTHER_TD, workload: 'ed25519' }).req);
    expect(id).toMatchObject({ subject: `spiffe://${OTHER_TD}/workload`, trustDomain: OTHER_TD });
    await expect(
      src.authenticate(mint({ workload: 'ed25519', wptSigner: { alg: 'EdDSA', key: workloadEd.privateKey } }).req),
    ).resolves.not.toBeNull();
  });

  it('returns null without a Workload-Identity-Token header; same source authenticates when present', async () => {
    const src = source();
    const { req } = mint();
    const { ['workload-identity-token']: _wit, ...rest } = req.headers;
    await expect(src.authenticate({ ...req, headers: rest })).resolves.toBeNull();
    await expect(src.authenticate(req)).resolves.not.toBeNull();
  });
});

describe('proof of possession is mandatory', () => {
  it('WIT with no Authorization header is refused (proof_required)', async () => {
    await expectPair({}, { headers: { authorization: undefined } }, 'proof_required');
  });

  it('WIT with Authorization: Bearer <WIT> is refused; lower-case "wpt" scheme passes', async () => {
    const src = source();
    const m = mint();
    expect(await refusalCode(src.authenticate({ ...m.req, headers: { ...m.req.headers, authorization: `Bearer ${m.wit}` } }))).toBe(
      'proof_required',
    );
    const ok = mint();
    await expect(src.authenticate({ ...ok.req, headers: { ...ok.req.headers, authorization: `wpt ${ok.wpt}` } })).resolves.not.toBeNull();
  });

  it('a second Authorization field (seen only in rawHeaders) is refused; one field passes', async () => {
    const src = source();
    const one = mint();
    const auth = one.req.headers['authorization'] as string;
    await expect(src.authenticate({ ...one.req, rawHeaders: ['Authorization', auth] })).resolves.not.toBeNull();
    const two = mint();
    const auth2 = two.req.headers['authorization'] as string;
    expect(await refusalCode(src.authenticate({ ...two.req, rawHeaders: ['Authorization', auth2, 'authorization', `Bearer x`] }))).toBe('proof_required');
  });

  it('two Workload-Identity-Token values are refused', async () => {
    const m = mint();
    await expectPair({}, { headers: { 'workload-identity-token': [m.wit, m.wit] } }, 'multiple_wit');
  });
});

describe('replay', () => {
  it('the same WPT twice: second is refused; a fresh jti passes', async () => {
    const src = source();
    const { req } = mint();
    await expect(src.authenticate(req)).resolves.not.toBeNull();
    expect(await refusalCode(src.authenticate(req))).toBe('replay');
    await expect(src.authenticate(mint().req)).resolves.not.toBeNull();
    // Past exp but inside the skew window: still accepted once, so the replay
    // entry must outlive exp until exp + skew.
    const late = mint({ wptClaims: { exp: NOW - 30 } }).req;
    await expect(src.authenticate(late)).resolves.not.toBeNull();
    expect(await refusalCode(src.authenticate(late))).toBe('replay');
  });

  it('a bad-signature WPT does not burn its jti: the valid WPT with that jti still passes', async () => {
    const src = source();
    const jti = freshJti();
    const forged = mint({ wptClaims: { jti }, wptSigner: { alg: 'ES256', key: pair('ec').privateKey } });
    expect(await refusalCode(src.authenticate(forged.req))).toBe('wpt_signature');
    await expect(src.authenticate(mint({ wptClaims: { jti } }).req)).resolves.not.toBeNull();
  });

  it('jti shorter than 16 characters is refused', async () => {
    await expectPair({ wptClaims: { jti: 'a'.repeat(16) } }, { wptClaims: { jti: 'a'.repeat(15) } }, 'wpt_jti');
  });
});

describe('WIT trust', () => {
  it('trust domain outside the allowlist is refused', async () => {
    const stranger = pair('ec');
    await expectPair(
      {},
      {
        witClaims: { sub: 'spiffe://evil.example/ns/agents/sa/runner' },
        witSigner: { alg: 'ES256', key: stranger.privateKey },
      },
      'untrusted_trust_domain',
    );
  });

  it('WIT for one trust domain signed by another configured domain key (same kid) is refused', async () => {
    await expectPair(
      {},
      { witSigner: { alg: 'Ed25519', key: issuers[OTHER_TD].privateKey }, witHeader: { alg: 'EdDSA' } },
      'wit_alg',
    );
    // Same algorithm family, so only the signature can catch it: the other
    // domain's ES256 issuer is configured, but not for this sub's domain.
    const otherIssuer = pair('ec');
    const sameAlgOther = loadTrustBundle(
      { jwks: { keys: [publicJwk(otherIssuer.publicKey, { kid: 'k1', use: 'wit-svid' })] } },
      { keyUse: 'wit-svid' },
    );
    const cfg = { [TD]: anchors[TD], [OTHER_TD]: sameAlgOther };
    await expectPair({}, { witSigner: { alg: 'ES256', key: otherIssuer.privateKey } }, 'wit_signature', source({ trustDomains: cfg }));
  });

  it('header jwk / jku / x5u / x5c injection is refused even when the signature verifies with the injected key', async () => {
    const attacker = pair('ec');
    for (const h of ['jwk', 'jku', 'x5u', 'x5c']) {
      const value = h === 'jwk' ? publicJwk(attacker.publicKey) : h === 'x5c' ? ['MIIB'] : 'https://attacker.example/keys';
      await expectPair({}, { witHeader: { [h]: value }, witSigner: { alg: 'ES256', key: attacker.privateKey } }, 'wit_embedded_key');
    }
  });

  it('WIT without kid is refused; unknown kid is refused', async () => {
    await expectPair({}, { witHeader: { kid: undefined } }, 'wit_kid');
    await expectPair({}, { witHeader: { kid: 'k2' } }, 'unknown_kid');
  });

  it('alg none and HS256 are refused', async () => {
    const m = mint();
    const [, p] = m.wit.split('.');
    for (const alg of ['none', 'HS256']) {
      const h = b64u(JSON.stringify({ alg, kid: 'k1', typ: 'wit+jwt' }));
      await expectPair({}, { wit: `${h}.${p}.${b64u('sig')}` }, 'wit_alg');
    }
  });

  it('typ other than wit+jwt is refused; "application/WIT+JWT" passes', async () => {
    await expectPair({ witHeader: { typ: 'application/WIT+JWT' } }, { witHeader: { typ: 'JWT' } }, 'wit_type');
  });

  it('a WIT whose payload was altered after signing is refused', async () => {
    const m = mint();
    const [h, , s] = m.wit.split('.');
    const p = b64u(JSON.stringify({ sub: SUB.replace('runner', 'admin'), iat: NOW - 60, exp: NOW + 3600, cnf: { jwk: publicJwk(workloadEc.publicKey, { alg: 'ES256' }) } }));
    await expectPair({}, { wit: `${h}.${p}.${s}` }, 'wit_signature');
  });
});

describe('WIT lifetime', () => {
  it('expired WIT is refused; one expired inside the skew window passes', async () => {
    await expectPair({ witClaims: { exp: NOW - 30 } }, { witClaims: { exp: NOW - 61 } }, 'wit_expired');
  });

  it('WIT lifetime over maxWitLifetimeSec is refused', async () => {
    await expectPair({ witClaims: { iat: NOW, exp: NOW + 86_400 } }, { witClaims: { iat: NOW, exp: NOW + 86_401 } }, 'wit_lifetime');
  });

  it('WIT nbf in the future is refused', async () => {
    await expectPair({ witClaims: { nbf: NOW + 60 } }, { witClaims: { nbf: NOW + 61 } }, 'wit_not_yet_valid');
  });
});

describe('WIT confirmation key', () => {
  it('cnf.jwk without alg is refused', async () => {
    const jwk = publicJwk(workloadEc.publicKey);
    await expectPair({ cnfJwk: { ...jwk, alg: 'ES256' } }, { cnfJwk: jwk }, 'wit_cnf_alg');
  });

  it('cnf.jwk carrying a private member is refused', async () => {
    const priv = workloadEc.privateKey.export({ format: 'jwk' });
    await expectPair({}, { cnfJwk: { ...priv, alg: 'ES256' } }, 'wit_cnf');
  });

  it('cnf.jwk alg inconsistent with the key (ES256 on an Ed25519 key) is refused', async () => {
    await expectPair(
      { workload: 'ed25519' },
      { workload: 'ed25519', cnfJwk: publicJwk(workloadEd.publicKey, { alg: 'ES256' }), wptSigner: { alg: 'Ed25519', key: workloadEd.privateKey } },
      'wit_cnf_alg',
    );
  });
});

describe('WPT', () => {
  it('wrong audience is refused; single-element aud array passes; Host is never used', async () => {
    await expectPair({ wptClaims: { aud: [TARGET] } }, { wptClaims: { aud: 'https://broker.example.net/v1/other' } }, 'wpt_audience');
    // aud matches the Host header but not the configured target URI.
    await expectPair({}, { wptClaims: { aud: 'https://broker.example.net' } }, 'wpt_audience');
  });

  it('expired WPT is refused', async () => {
    await expectPair({ wptClaims: { exp: NOW - 30 } }, { wptClaims: { exp: NOW - 61 } }, 'wpt_expired');
  });

  it('WPT exp too far in the future is refused', async () => {
    await expectPair({ wptClaims: { exp: NOW + 360 } }, { wptClaims: { exp: NOW + 361 } }, 'wpt_lifetime');
  });

  it('WPT signed by a key other than the cnf key is refused', async () => {
    await expectPair({}, { wptSigner: { alg: 'ES256', key: pair('ec').privateKey } }, 'wpt_signature');
  });

  it('WPT minted for another WIT (wth mismatch) is refused', async () => {
    const other = mint({ witClaims: { iat: NOW - 10 } });
    await expectPair({}, { wptClaims: { wth: hash(other.wit) } }, 'wpt_wth');
  });

  it('WPT alg different from cnf.jwk.alg is refused', async () => {
    // cnf says ES256; the WPT is a valid Ed25519 signature by a different key type.
    await expectPair({}, { wptSigner: { alg: 'Ed25519', key: workloadEd.privateKey } }, 'wpt_alg_mismatch');
  });

  it('WPT typ other than wpt+jwt is refused', async () => {
    await expectPair({}, { wptHeader: { typ: 'wit+jwt' } }, 'wpt_type');
  });
});

describe('WPT context-token binding', () => {
  const txn = 'eyJhbGciOiJFUzI1NiJ9.eyJ0eG4iOiIxIn0.c2ln';

  it('Txn-Token present without tth is refused; with matching tth passes', async () => {
    await expectPair({ headers: { 'txn-token': txn }, wptClaims: { tth: hash(txn) } }, { headers: { 'txn-token': txn } }, 'wpt_tth_missing');
  });

  it('swapped Txn-Token value (tth mismatch) is refused', async () => {
    await expectPair(
      { headers: { 'txn-token': txn }, wptClaims: { tth: hash(txn) } },
      { headers: { 'txn-token': `${txn}x` }, wptClaims: { tth: hash(txn) } },
      'wpt_tth',
    );
  });

  it('oth entry for an absent header is refused; present header with matching hash passes; mismatch refused', async () => {
    const ctx = 'ctx-token-value';
    await expectPair(
      { headers: { 'x-user-context': ` ${ctx} ` }, wptClaims: { oth: { 'x-user-context': hash(ctx) } } },
      { wptClaims: { oth: { 'x-user-context': hash(ctx) } } },
      'wpt_oth',
    );
    await expectPair(
      { headers: { 'x-user-context': ctx }, wptClaims: { oth: { 'x-user-context': hash(ctx) } } },
      { headers: { 'x-user-context': `${ctx}2` }, wptClaims: { oth: { 'x-user-context': hash(ctx) } } },
      'wpt_oth',
    );
  });
});

describe('Workload Identifier syntax (identifier-04 §4.1)', () => {
  it('refuses dot segments, query, fragment, empty path, userinfo, port; accepts valid forms', () => {
    const ok = validateWorkloadIdentifier('SPIFFE://Prod.Example.ORG/ns/%7Euser/a%2fb');
    expect(ok).toEqual({ identifier: 'spiffe://prod.example.org/ns/~user/a%2Fb', trustDomain: 'prod.example.org' });
    expect(validateWorkloadIdentifier('wimse://example.com/specific-workload').trustDomain).toBe('example.com');
    for (const bad of [
      'spiffe://td.example/ns/../admin',
      'spiffe://td.example/./x',
      'spiffe://td.example/ns/%2e%2E/admin',
      'spiffe://td.example/ns/x?y=1',
      'spiffe://td.example/ns/x#frag',
      'spiffe://td.example',
      'spiffe://td.example/',
      'spiffe:///path',
      'spiffe://user@td.example/x',
      'spiffe://td.example:8443/x',
      'td.example/x',
      `spiffe://td.example/${'a'.repeat(2048)}`,
    ]) {
      expect(() => validateWorkloadIdentifier(bad), bad).toThrow(IdentityRefusal);
    }
  });

  it('a WIT whose sub has a ".." segment is refused through authenticate', async () => {
    await expectPair({}, { witClaims: { sub: `spiffe://${TD}/ns/../admin` } }, 'invalid_subject');
  });
});

describe('draft example vectors (fixed clock)', () => {
  const read = (f: string) => fs.readFileSync(path.join(FIXTURES, f), 'utf8').trim();
  const bundle = () => loadTrustBundle({ path: path.join(FIXTURES, 'issuer-bundle.json') }, { keyUse: 'wit-svid' });
  const req = (wit: string, wpt: string): IdentityRequest => ({
    method: 'POST',
    targetUri: 'https://workload.example.com/path',
    headers: { 'workload-identity-token': wit, authorization: `WPT ${wpt}`, 'content-type': 'application/json' },
    socket: null,
  });

  it.each([
    ['s2s-protocol 499f060 includes (Ed25519)', 's2s-wit.txt', 's2s-wpt.txt'],
    ['wpt-02 Figure 5 (EdDSA)', 'wpt02-fig5-wit.txt', 'wpt02-fig5-wpt.txt'],
  ])('%s verifies; one clock tick past WIT exp + skew does not', async (_name, witFile, wptFile) => {
    const wit = read(witFile);
    const wpt = read(wptFile);
    const src = createWimseIdentitySource({ trustDomains: { 'example.com': bundle() }, replay: createReplayCache(), now: () => 1_745_509_800 });
    await expect(src.authenticate(req(wit, wpt))).resolves.toMatchObject({
      subject: 'wimse://example.com/specific-workload',
      trustDomain: 'example.com',
      proof: 'wpt',
      expiresAt: 1_745_510_016,
    });
    expect(() => verifyWit(wit, { trustDomains: { 'example.com': bundle() }, now: () => 1_745_512_510 + 60 })).toThrow(IdentityRefusal);
  });
});

describe('trust bundle loading', () => {
  const ec = () => publicJwk(pair('ec').publicKey);

  it('keeps only keys with the requested use, from a SPIFFE bundle file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wimse-bundle-'));
    const file = path.join(dir, 'bundle.json');
    fs.writeFileSync(
      file,
      JSON.stringify({
        spiffe_sequence: 7,
        spiffe_refresh_hint: 300,
        keys: [
          { ...ec(), use: 'x509-svid', x5c: ['MIIB'] },
          { ...ec(), use: 'jwt-svid', kid: 'jwt-1' },
          { ...ec(), use: 'wit-svid', kid: 'wit-1' },
        ],
      }),
    );
    try {
      const keys = loadTrustBundle({ path: file }, { keyUse: 'wit-svid' });
      expect(keys.kids()).toEqual(['wit-1']);
      expect(keys.get('jwt-1')).toBeUndefined();
      expect(() => loadTrustBundle({ path: file }, { keyUse: 'jwt' })).toThrow(/no keys with use/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses private keys, symmetric keys, missing kid, duplicate kid, and a missing keyUse', () => {
    const good = { ...ec(), use: 'wit-svid', kid: 'a' };
    expect(loadTrustBundle({ jwks: { keys: [good] } }, { keyUse: 'wit-svid' }).size).toBe(1);
    const priv = { ...(pair('ec').privateKey.export({ format: 'jwk' }) as object), use: 'wit-svid', kid: 'p' };
    const cases: object[][] = [
      [good, priv],
      [good, { kty: 'oct', k: 'c2VjcmV0', use: 'wit-svid', kid: 's' }],
      [good, { ...ec(), use: 'wit-svid' }],
      [good, { ...ec(), use: 'wit-svid', kid: 'a' }],
      // A private key is refused even under another use.
      [good, { ...priv, use: 'jwt-svid' }],
    ];
    for (const keys of cases) {
      expect(() => loadTrustBundle({ jwks: { keys } as never }, { keyUse: 'wit-svid' })).toThrow();
    }
    expect(() => loadTrustBundle({ jwks: { keys: [good] } }, { keyUse: '' })).toThrow(/keyUse is required/);
  });
});

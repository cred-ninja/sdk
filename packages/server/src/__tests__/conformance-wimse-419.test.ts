/**
 * Conformance: the draft-ietf-wimse-http-signature-08 test vectors from
 * ietf-wg-wimse/draft-ietf-wimse-s2s-protocol issue #419 (6 positive, 22
 * negative), with the corrections posted in that issue's comments. Data:
 * conformance/wimse-419/vectors.json. Set WIMSE419_RESULTS to a file path to
 * write per-vector results.
 *
 * Re-signed negative variations use the independent signature-base builder
 * below (string operations on the published Signature-Input text), not
 * Cred's parser or signer, so a component-derivation bug shared by Cred's
 * signer and verifier cannot pass unnoticed.
 *
 * This suite is outside the branch's test-case budget.
 */
import { describe, it, expect, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  verifyWimseRequestSignature,
  verifyWimseResponseSignature,
  signWimseRequest,
  type HttpSigMessage,
  type HttpSigVerifyConfig,
} from '../identity/http-signature.js';
import { loadTrustBundle } from '../identity/trust-bundle.js';
import { createReplayCache, IdentityRefusal } from '../identity/types.js';
import { serverBehaviour } from './conformance-wimse-419-server.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = path.resolve(here, '../../../../conformance/wimse-419/vectors.json');
const V = JSON.parse(fs.readFileSync(VECTORS, 'utf8'));

type RawMsg = { method: string; path?: string; query?: string; authority?: string; scheme?: 'https'; status?: number; headers: Record<string, string>; body?: string };

const results: Array<{ id: string; expected: string; outcome: string; pass: boolean; detail?: string }> = [];
afterAll(() => {
  const out = process.env.WIMSE419_RESULTS;
  if (!out) return;
  const passed = results.filter((r) => r.pass).length;
  fs.writeFileSync(out, `${JSON.stringify({
    source: V.source,
    draft: V.draft,
    corrections: V.corrections,
    verifier: 'packages/server/src/identity/http-signature.ts',
    summary: `${passed}/${results.length} passed`,
    vectors: [...results].sort((a, b) => a.id.localeCompare(b.id)),
  }, null, 2)}\n`);
});

// The deployment's configuration for the vectors: the Issuer key is the trust
// anchor for example.com. A JWK `use` is added because Cred loads only keys
// whose use is configured (keyUse "wit-svid"); the key itself is unchanged.
const issuer = { ...V.keys['issuer-key'] };
delete issuer.d;
const anchors = loadTrustBundle({ jwks: { keys: [{ ...issuer, use: 'wit-svid' }] } }, { keyUse: 'wit-svid' });

function cfg(at: number = V.verifyAt): HttpSigVerifyConfig {
  return {
    trustDomains: { [V.trust.trustDomain]: anchors },
    audiences: V.trust.audiences,
    now: () => at,
    replay: createReplayCache(),
  };
}

function toMsg(m: RawMsg): HttpSigMessage {
  return { ...m, headers: { ...m.headers }, body: m.body === undefined ? undefined : Buffer.from(m.body, 'utf8') };
}

function privateKey(kid: string): crypto.KeyObject {
  return crypto.createPrivateKey({ key: V.keys[kid], format: 'jwk' });
}

// ── Independent signature base (RFC 9421 §2.5), string operations only ──────
function member(si: string, label: string): string {
  // Members are separated by ", " outside parentheses and quotes in these vectors.
  const parts: string[] = [];
  let depth = 0;
  let inStr = false;
  let cur = '';
  for (let i = 0; i < si.length; i++) {
    const c = si[i];
    if (c === '"' && si[i - 1] !== '\\') inStr = !inStr;
    if (!inStr && c === '(') depth++;
    if (!inStr && c === ')') depth--;
    if (!inStr && depth === 0 && c === ',') { parts.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  parts.push(cur.trim());
  const found = parts.find((p) => p.startsWith(`${label}=`));
  if (!found) throw new Error(`no member ${label}`);
  return found.slice(label.length + 1);
}

function independentBase(m: RawMsg, params: string, req?: RawMsg): string {
  const inner = params.slice(1, params.indexOf(')'));
  const items = inner.match(/"[^"]+"(?:;req)?/g) ?? [];
  const lines = items.map((it) => {
    const name = it.slice(1, it.indexOf('"', 1));
    const src = it.endsWith(';req') ? req! : m;
    let value: string;
    if (name === '@method') value = src.method;
    else if (name === '@path') value = src.path || '/';
    else if (name === '@query') value = `?${src.query ?? ''}`;
    else if (name === '@authority') value = src.authority!.toLowerCase().replace(/:443$/, '');
    else if (name === '@status') value = String(src.status);
    else value = src.headers[name];
    return `${it}: ${value}`;
  });
  return `${lines.join('\n')}\n"@signature-params": ${params}`;
}

function rawSign(base: string, kid: string): string {
  const key = privateKey(kid);
  const sig = V.keys[kid].kty === 'EC'
    ? crypto.sign('sha256', Buffer.from(base), { key, dsaEncoding: 'ieee-p1363' })
    : crypto.sign(null, Buffer.from(base), key);
  return sig.toString('base64');
}

function clone(m: RawMsg): RawMsg {
  return JSON.parse(JSON.stringify(m));
}

function find(id: string) {
  return V.positive.find((p: { id: string }) => p.id === id);
}

/** Apply a declared mutation to a baseline, re-signing where the vector says so. */
function mutate(n: any): { msg: RawMsg; request?: RawMsg; base: any } {
  const base = find(n.baseline);
  let msg = clone(base.message);
  let request: RawMsg | undefined = base.request ? clone(base.request) : undefined;
  const mu = n.mutation ?? {};
  const wimseLabel = n.baseline === 'P-06' ? 'sig2' : 'sig1';
  let params = member(msg.headers['signature-input'], wimseLabel);
  const edit = (fn: (p: string) => string, label = wimseLabel) => {
    const old = member(msg.headers['signature-input'], label);
    const next = fn(old);
    msg.headers['signature-input'] = msg.headers['signature-input'].replace(`${label}=${old}`, `${label}=${next}`);
    if (label === wimseLabel) params = next;
  };
  if (mu.connect) {
    // N-21: the P-02 response moved to a CONNECT exchange (request P-04), covering @authority;req.
    request = clone(find('P-04').message);
    edit((p) => p.replace('"@path";req "@query";req', '"@authority";req'));
  }
  if (mu.removeComponent) edit((p) => p.replace(` "${mu.removeComponent}"`, '').replace(`"${mu.removeComponent}" `, ''));
  if (mu.addComponent) {
    const [name, req] = mu.addComponent.split(';');
    edit((p) => p.replace(')', ` "${name}"${req ? `;${req}` : ''})`));
    if (name === '@path' && !req) msg.path = '/';
  }
  if (mu.removeParam) edit((p) => p.replace(new RegExp(`;${mu.removeParam}(=("[^"]*"|\\d+))?`), ''));
  if (mu.addParam) edit((p) => `${p};${mu.addParam[0]}="${mu.addParam[1]}"`);
  if (mu.setParam) edit((p) => p.replace(new RegExp(`;${mu.setParam[0]}="[^"]*"`), `;${mu.setParam[0]}="${mu.setParam[1]}"`));
  if (mu.body !== undefined) msg.body = mu.body;
  for (const h of [mu.removeHeader ?? []].flat()) delete msg.headers[h];
  if (mu.decoyTag) {
    // N-08: the decoy sig1 also carries the WIMSE tag, with full coverage, signed by `other`.
    edit((p) => p.replace('("@method" "@path");created=1795000000;keyid="other-key";tag="example-other"',
      `("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="0123456789abcdef0123456789abcdef";tag="${mu.decoyTag}";wimse-aud="https://svcb.example.com/gimme-ice-cream"`), 'sig1');
    const p1 = member(msg.headers['signature-input'], 'sig1');
    const s1 = rawSign(independentBase(msg, p1), n.resign);
    msg.headers.signature = msg.headers.signature.replace(/sig1=:[^:]+:/, `sig1=:${s1}:`);
    return { msg, request, base };
  }
  if (n.resign && msg.headers['signature-input']) {
    const sig = rawSign(independentBase(msg, params, request), n.resign);
    msg.headers.signature = msg.headers.signature.replace(new RegExp(`${wimseLabel}=:[^:]+:`), `${wimseLabel}=:${sig}:`);
  }
  return { msg, request, base };
}

function outcome(fn: () => unknown): { outcome: 'accept' | 'reject'; detail?: string } {
  try {
    const r = fn();
    return r === null ? { outcome: 'reject', detail: 'no WIMSE signature found' } : { outcome: 'accept' };
  } catch (err) {
    if (err instanceof IdentityRefusal) return { outcome: 'reject', detail: err.code };
    throw err;
  }
}

function record(id: string, expected: string, got: { outcome: string; detail?: string }) {
  results.push({ id, expected, outcome: got.outcome, pass: got.outcome === expected, ...(got.detail ? { detail: got.detail } : {}) });
  expect(got.outcome, `${id}: ${got.detail ?? ''}`).toBe(expected);
}

describe('#419 positive vectors', () => {
  for (const p of V.positive) {
    it(`${p.id} verifies`, () => {
      if (p.kind === 'response') {
        record(p.id, 'accept', outcome(() => verifyWimseResponseSignature(toMsg(p.message), toMsg(p.request), p.requestNonce, p.signResponseRequested, cfg())));
        return;
      }
      let label: string | undefined;
      const got = outcome(() => {
        const r = verifyWimseRequestSignature(toMsg(p.message), cfg());
        label = r?.label;
        if (r && p.signResponse !== undefined) expect(r.signResponse).toBe(p.signResponse);
        return r;
      });
      record(p.id, 'accept', got);
      if (p.expectLabel) expect(label).toBe(p.expectLabel);
    });
  }

  it('the independent base builder reproduces each published positive signature (cross-check of the test harness)', () => {
    for (const p of V.positive) {
      const label = p.expectLabel ?? 'sig1';
      const params = member(p.message.headers['signature-input'], label);
      const base = independentBase(p.message, params, p.request);
      const kid = p.kind === 'response' ? 'vec-b-key' : ({ 'P-03': 'vec-c-key' } as Record<string, string>)[p.id] ?? 'vec-a-key';
      const pub = crypto.createPublicKey({ key: { ...V.keys[kid], d: undefined }, format: 'jwk' });
      const sig = Buffer.from(/=:([^:]+):/.exec(p.message.headers.signature.split(', ').find((s: string) => s.startsWith(`${label}=`))!)![1], 'base64');
      const ok = V.keys[kid].kty === 'EC'
        ? crypto.verify('sha256', Buffer.from(base), { key: pub, dsaEncoding: 'ieee-p1363' }, sig)
        : crypto.verify(null, Buffer.from(base), pub, sig);
      expect(ok, p.id).toBe(true);
    }
  });
});

describe('#419 negative vectors (message variations)', () => {
  for (const n of V.negative.filter((x: any) => !x.behaviour)) {
    it(`${n.id} is rejected`, () => {
      if (n.id === 'N-15') {
        record(n.id, 'reject', outcome(() => verifyWimseRequestSignature(toMsg(n.message), cfg())));
        return;
      }
      const { msg, request, base } = mutate(n);
      const at = n.verifyAt ?? V.verifyAt;
      if (base.kind === 'response') {
        record(n.id, 'reject', outcome(() => verifyWimseResponseSignature(
          toMsg(msg), toMsg(request!), base.requestNonce, base.signResponseRequested, cfg(at),
        )));
        return;
      }
      record(n.id, 'reject', outcome(() => verifyWimseRequestSignature(toMsg(msg), cfg(at))));
    });
  }
});

describe('#419 negative vectors (behaviour cases)', () => {
  it('N-16 Cred as sender: nonces come from a CSPRNG with at least 64 bits (128 here) and do not repeat', () => {
    const { privateKey: pk } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const seen = new Set<string>();
    let minBits = Infinity;
    for (let i = 0; i < 2000; i++) {
      const h = signWimseRequest({ method: 'GET', path: '/x', headers: {}, wit: 'a.b.c', privateKey: pk, alg: 'ES256', audience: 'https://x' });
      const nonce = /nonce="([^"]+)"/.exec(h['signature-input'])![1];
      seen.add(nonce);
      minBits = Math.min(minBits, Buffer.from(nonce, 'base64url').length * 8);
    }
    const pass = seen.size === 2000 && minBits >= 64;
    record('N-16', 'conformant', { outcome: pass ? 'conformant' : 'not conformant', detail: `sender conformant: ${seen.size} unique nonces, ${minBits} bits each` });
  });

  it('N-22 the WIMSE signature is chosen by tag, never by label or position', () => {
    const p6 = find('P-06').message as RawMsg;
    // Swap the labels: the WIMSE signature is now first and named sig1.
    const swapped = clone(p6);
    swapped.headers['signature-input'] = p6.headers['signature-input'].replace('sig1=', 'tmp=').replace('sig2=', 'sig1=').replace('tmp=', 'sig2=');
    swapped.headers.signature = p6.headers.signature.replace('sig1=', 'tmp=').replace('sig2=', 'sig1=').replace('tmp=', 'sig2=');
    const a = verifyWimseRequestSignature(toMsg(p6), cfg());
    const b = verifyWimseRequestSignature(toMsg(swapped), cfg());
    const pass = a?.label === 'sig2' && b?.label === 'sig1';
    // A verifier that chose by label would fail one of the two.
    record('N-22', 'conformant', { outcome: pass ? 'conformant' : 'not conformant', detail: 'label-based selection is not used' });
  });

  for (const b of ['N-17', 'N-18', 'N-19', 'N-20']) {
    it(`${b} Cred as server`, async () => {
      const r = await serverBehaviour(b, V);
      record(b, 'conformant', r);
    });
  }
});

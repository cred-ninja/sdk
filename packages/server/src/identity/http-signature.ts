/**
 * WIMSE workload-to-workload authentication with HTTP Message Signatures:
 * draft-ietf-wimse-http-signature-08, a profile of RFC 9421.
 *
 * The signing key is the WIT's confirmation key (`cnf.jwk`); the algorithm is
 * `cnf.jwk.alg` (§3.1), never a signature parameter. Accepted: ES256 on P-256
 * (RFC 9421 ecdsa-p256-sha256, raw r||s) and EdDSA/Ed25519 (RFC 9421 ed25519).
 *
 * Verification order (§3): the WIMSE signature is selected by its `tag`
 * (never by label); its parameters and covered components are checked; the
 * WIT is validated BEFORE the message signature; then the validity window,
 * Content-Digest (RFC 9530), the signature, `wimse-aud` against configured
 * audiences (never Host, §3.2) and, last, the nonce replay cache, so a forged
 * message cannot burn a nonce.
 *
 * Every failure throws IdentityRefusal with proof 'http-sig'. The code and
 * detail are for logs only: callers answer every failure the same way
 * (§3.6: "MUST NOT distinguish in the response which check failed").
 *
 * Only node:crypto is used.
 */
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign, timingSafeEqual, type KeyObject } from 'node:crypto';
import { IdentityRefusal, type ReplayCache } from './types.js';
import {
  keyFitsAlg,
  sigAlg,
  verifySignature,
  verifyWit,
  type VerifiedWit,
  type WimseVerifyConfig,
} from './wimse.js';
import {
  parseDictionary,
  serializeInnerList,
  serializeItem,
  StructuredFieldError,
  type BareItem,
  type InnerList,
  type Item,
  type Parameters,
} from './structured-fields.js';

/** §3 and §7.2.7 of RFC 9421: the tag that marks the WIMSE signature. */
export const WIMSE_SIGNATURE_TAG = 'wimse-workload-to-workload';

/** §7.2 problem types. */
export const WIMSE_PROBLEM_TYPES = {
  signatureInvalid: 'https://iana.org/assignments/http-problem-types#wimse-signature-invalid',
  signedResponseUnsupported: 'https://iana.org/assignments/http-problem-types#wimse-signed-response-unsupported',
  signedResponseUnavailable: 'https://iana.org/assignments/http-problem-types#wimse-signed-response-unavailable',
} as const;

/** The parts of an HTTP message the profile signs. Header names are lower case. */
export interface HttpSigMessage {
  /** Request method, or for a response the method of its request (`;req`). */
  method: string;
  /** `@path`: the absolute path as received; empty means "/". */
  path?: string;
  /** The query without "?", or undefined when the target has none (`@query` is then "?"). */
  query?: string;
  /** `@authority` source: host[:port]. Used for CONNECT only. */
  authority?: string;
  /** Scheme, to drop the default port from `@authority` (RFC 9421 §2.2.3). */
  scheme?: 'https' | 'http';
  /** Response status (responses only). */
  status?: number;
  headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  /** The exact message content; undefined when the message has none. */
  body?: Buffer;
}

export interface HttpSigVerifyConfig extends WimseVerifyConfig {
  /** Trusted `wimse-aud` values, compared by RFC 3986 §6.2.1 simple string comparison (§3.2). */
  audiences: readonly string[];
  /** Nonce replay cache (§3 "SHOULD reject a message whose nonce they have already seen"). */
  replay?: ReplayCache;
  /** Cap on `expires - created`. Default 300 ("on the order of minutes", §3). */
  maxSignatureLifetimeSec?: number;
  /**
   * Shortest nonce accepted. Entropy cannot be measured from one value, so
   * this is a floor, not proof of 64 bits (§3). Default 16 characters.
   */
  minNonceLength?: number;
}

export interface VerifiedHttpSignature {
  wit: VerifiedWit;
  label: string;
  nonce: string;
  created: number;
  expires: number;
  /** Covered component identifiers, serialized (e.g. `"authorization"`, `"@query";req`), without quotes for plain names. */
  covered: ReadonlySet<string>;
  /** `wimse-sign-response` is present and true (§3.3). */
  signResponse: boolean;
}

const DEFAULT_MAX_SIG_LIFETIME = 300;
const DEFAULT_SKEW = 60;
const DEFAULT_MIN_NONCE = 16;
const MAX_NONCE = 256;

/** §3: request headers that MUST be signed when they exist. */
const REQUEST_HEADERS_IF_PRESENT = ['content-type', 'content-digest', 'authorization', 'txn-token', 'workload-identity-token'] as const;
/** §3: response headers that MUST be signed when they exist. */
const RESPONSE_HEADERS_IF_PRESENT = ['content-type', 'content-digest', 'workload-identity-token'] as const;
/** Derived components this verifier can compute. */
const DERIVED = new Set(['@method', '@path', '@query', '@authority', '@status']);

function refuse(code: string, detail: string): never {
  throw new IdentityRefusal('wimse', code, detail, 'http-sig');
}

function headerValue(headers: HttpSigMessage['headers'], name: string): string | undefined {
  const v = headers[name];
  if (v === undefined) return undefined;
  // RFC 9421 §2.1: field lines are trimmed and combined with ", ".
  return (Array.isArray(v) ? v : [v as string]).map((x) => x.trim()).join(', ');
}

function hasHeader(headers: HttpSigMessage['headers'], name: string): boolean {
  return headers[name] !== undefined;
}

/** RFC 9421 §2.2.3: lower-case host; the scheme's default port is omitted. */
export function normalizeAuthority(authority: string, scheme: 'https' | 'http' = 'https'): string {
  const a = authority.trim().toLowerCase();
  const def = scheme === 'https' ? ':443' : ':80';
  return a.endsWith(def) ? a.slice(0, -def.length) : a;
}

interface Selected {
  label: string;
  input: InnerList;
  signature: Buffer;
}

/**
 * Find the one WIMSE signature (§3). Null when no Signature-Input member
 * carries the tag; throws if more than one does or the fields are malformed.
 */
export function selectWimseSignature(headers: HttpSigMessage['headers']): Selected | null {
  const rawInput = headerValue(headers, 'signature-input');
  const rawSig = headerValue(headers, 'signature');
  if (rawInput === undefined) return null;
  let inputs;
  let sigs;
  try {
    inputs = parseDictionary(rawInput);
  } catch (err) {
    refuse('malformed_signature_input', err instanceof StructuredFieldError ? err.message : 'unparseable');
  }
  const tagged: string[] = [];
  for (const [label, member] of inputs) {
    const tag = member.params.get('tag');
    if (tag?.type === 'string' && tag.value === WIMSE_SIGNATURE_TAG) tagged.push(label);
  }
  if (tagged.length === 0) return null;
  // §3: "If more than one signature has that tag value, the recipient MUST reject the message."
  if (tagged.length > 1) refuse('duplicate_wimse_tag', `${tagged.length} signatures carry the WIMSE tag`);
  const label = tagged[0];
  const input = inputs.get(label)!;
  if (input.kind !== 'inner-list') refuse('malformed_signature_input', 'signature input is not an inner list');
  if (rawSig === undefined) refuse('missing_signature', 'Signature-Input without Signature');
  try {
    sigs = parseDictionary(rawSig!);
  } catch (err) {
    refuse('malformed_signature', err instanceof StructuredFieldError ? err.message : 'unparseable');
  }
  const sig = sigs!.get(label);
  if (!sig || sig.kind !== 'item' || sig.value.type !== 'bytes') refuse('missing_signature', `no byte-sequence Signature member "${label}"`);
  const bytes = (sig as Item).value as { type: 'bytes'; value: Buffer };
  return { label, input: input as InnerList, signature: bytes.value };
}

function intParam(params: Parameters, name: string): number | undefined {
  const v = params.get(name);
  if (v === undefined) return undefined;
  if (v.type !== 'integer') refuse('bad_parameter', `${name} is not an integer`);
  return (v as { value: number }).value;
}

function strParam(params: Parameters, name: string): string | undefined {
  const v = params.get(name);
  if (v === undefined) return undefined;
  if (v.type !== 'string') refuse('bad_parameter', `${name} is not a string`);
  return (v as { value: string }).value;
}

interface Component {
  name: string;
  req: boolean;
  /** Serialized identifier, e.g. `"@path";req`. */
  id: string;
}

function components(input: InnerList, allowReq: boolean): Component[] {
  const out: Component[] = [];
  const seen = new Set<string>();
  for (const item of input.items) {
    if (item.value.type !== 'string') refuse('bad_component', 'component identifier is not a string');
    const name = (item.value as { value: string }).value;
    // RFC 9421 §2.1: identifiers are lower case.
    if (name.length === 0 || name !== name.toLowerCase()) refuse('bad_component', 'component name is not lower case');
    let req = false;
    for (const [k, v] of item.params) {
      // Only `req` is supported; sf, key, bs, tr and name are refused, not ignored.
      if (k !== 'req' || !allowReq || v.type !== 'boolean' || v.value !== true) refuse('bad_component', `unsupported component parameter "${k}"`);
      req = true;
    }
    if (name.startsWith('@') && !DERIVED.has(name)) refuse('bad_component', `unsupported derived component ${name}`);
    const id = serializeItem(item);
    if (seen.has(id)) refuse('bad_component', 'a component is covered twice');
    seen.add(id);
    out.push({ name, req, id });
  }
  return out;
}

/** The plain name of each covered component, plus `;req` where present. */
function coveredSet(cs: Component[]): Set<string> {
  return new Set(cs.map((c) => (c.req ? `${c.name};req` : c.name)));
}

function componentValue(c: Component, msg: HttpSigMessage, req: HttpSigMessage | undefined): string {
  const source = c.req ? req : msg;
  if (!source) refuse('bad_component', `${c.id} needs the request`);
  const m = source as HttpSigMessage;
  switch (c.name) {
    case '@method':
      return m.method;
    case '@path':
      return m.path && m.path.length > 0 ? m.path : '/';
    case '@query':
      // RFC 9421 §2.2.7: includes the leading "?"; "?" alone when there is no query.
      return `?${m.query ?? ''}`;
    case '@authority':
      if (!m.authority) refuse('bad_component', '@authority unavailable');
      return normalizeAuthority(m.authority!, m.scheme);
    case '@status':
      if (c.req || typeof m.status !== 'number') refuse('bad_component', '@status only on a response');
      return String(m.status);
    default: {
      const v = headerValue(m.headers, c.name);
      if (v === undefined) refuse('missing_covered_header', `covered header ${c.name} absent`);
      return v as string;
    }
  }
}

/** RFC 9421 §2.5 signature base. */
export function signatureBase(input: InnerList, msg: HttpSigMessage, req?: HttpSigMessage): string {
  const cs = components(input, req !== undefined);
  let base = '';
  for (const c of cs) {
    const value = componentValue(c, msg, req);
    if (/[\r\n]/.test(value)) refuse('bad_component', 'component value contains a line break');
    base += `${c.id}: ${value}\n`;
  }
  return `${base}"@signature-params": ${serializeInnerList(input)}`;
}

const DIGEST_ALGS: Record<string, string> = { 'sha-256': 'sha256', 'sha-512': 'sha512' };

/**
 * RFC 9530 / §3: when the message has content, Content-Digest is required and
 * recomputed. At least one supported algorithm must be present and every
 * supported one must match.
 */
function checkContentDigest(msg: HttpSigMessage): void {
  const header = headerValue(msg.headers, 'content-digest');
  const hasContent = msg.body !== undefined && msg.body.length > 0;
  if (header === undefined) {
    if (hasContent) refuse('content_digest_missing', 'message has content but no Content-Digest');
    return;
  }
  let dict;
  try {
    dict = parseDictionary(header);
  } catch {
    refuse('content_digest_malformed', 'Content-Digest is not a dictionary');
  }
  let checked = 0;
  for (const [alg, member] of dict!) {
    const node = DIGEST_ALGS[alg];
    if (!node) continue;
    if (member.kind !== 'item' || member.value.type !== 'bytes') refuse('content_digest_malformed', `${alg} is not a byte sequence`);
    const want = createHash(node).update(msg.body ?? Buffer.alloc(0)).digest();
    const got = (member.value as { value: Buffer }).value;
    if (got.length !== want.length || !timingSafeEqual(got, want)) refuse('content_digest_mismatch', `${alg} does not match the content`);
    checked++;
  }
  if (checked === 0) refuse('content_digest_unsupported', 'no supported Content-Digest algorithm');
}

interface CommonParams {
  created: number;
  expires: number;
  nonce: string;
}

function commonParams(params: Parameters, cfg: HttpSigVerifyConfig): CommonParams {
  // §3: "The following signature parameters ... MUST NOT be used: keyid, alg".
  if (params.has('keyid')) refuse('forbidden_parameter', 'keyid present');
  if (params.has('alg')) refuse('forbidden_parameter', 'alg present');
  const created = intParam(params, 'created');
  const expires = intParam(params, 'expires');
  const nonce = strParam(params, 'nonce');
  if (created === undefined) refuse('missing_parameter', 'created missing');
  if (expires === undefined) refuse('missing_parameter', 'expires missing');
  if (nonce === undefined) refuse('missing_parameter', 'nonce missing');
  const min = cfg.minNonceLength ?? DEFAULT_MIN_NONCE;
  if (nonce!.length < min || nonce!.length > MAX_NONCE) refuse('bad_nonce', `nonce length outside ${min}..${MAX_NONCE}`);
  return { created: created!, expires: expires!, nonce: nonce! };
}

function checkWindow(p: CommonParams, cfg: HttpSigVerifyConfig, now: number): void {
  const skew = cfg.clockSkewSec ?? DEFAULT_SKEW;
  const max = cfg.maxSignatureLifetimeSec ?? DEFAULT_MAX_SIG_LIFETIME;
  if (p.expires <= p.created) refuse('bad_window', 'expires is not after created');
  if (p.expires - p.created > max) refuse('bad_window', 'signature lifetime exceeds the configured maximum');
  if (p.created > now + skew) refuse('bad_window', 'created is in the future');
  // §3: "Recipients MUST reject signatures that fall outside their validity time window."
  if (now > p.expires) refuse('expired_signature', 'signature expired');
}

function checkCryptoSignature(base: string, signature: Buffer, wit: VerifiedWit): void {
  // §3.1: the algorithm is cnf.jwk.alg; the key is cnf.jwk.
  const alg = sigAlg(wit.cnfAlg);
  if (alg !== 'ES256' && alg !== 'EdDSA') refuse('bad_alg', 'cnf.jwk.alg is not acceptable for HTTP signatures');
  if (!keyFitsAlg(wit.cnfKey, alg)) refuse('bad_alg', 'cnf key does not fit cnf.jwk.alg');
  if (!verifySignature(alg, wit.cnfKey, Buffer.from(base, 'utf8'), signature)) refuse('bad_signature', 'signature invalid');
}

function witFrom(msg: HttpSigMessage, cfg: HttpSigVerifyConfig): VerifiedWit {
  const raw = msg.headers['workload-identity-token'];
  if (raw === undefined) refuse('wit_missing', 'no Workload-Identity-Token');
  if (Array.isArray(raw) && raw.length !== 1) refuse('wit_multiple', 'more than one Workload-Identity-Token');
  const token = (Array.isArray(raw) ? raw[0] : raw) as string;
  try {
    return verifyWit(token.trim(), cfg);
  } catch (err) {
    if (err instanceof IdentityRefusal) refuse(`wit:${err.code}`, err.detail);
    throw err;
  }
}

/**
 * Verify a signed request (§3, §3.1, §3.2). Returns null when the message
 * carries no WIMSE signature at all; throws IdentityRefusal on any failure.
 */
export function verifyWimseRequestSignature(msg: HttpSigMessage, cfg: HttpSigVerifyConfig): VerifiedHttpSignature | null {
  const selected = selectWimseSignature(msg.headers);
  if (!selected) return null;
  const { label, input, signature } = selected;
  const params = input.params;
  const common = commonParams(params, cfg);
  const aud = strParam(params, 'wimse-aud');
  // §3: "For requests only ... MUST also be included: wimse-aud".
  if (aud === undefined) refuse('missing_parameter', 'wimse-aud missing');
  if (params.has('wimse-req-nonce')) refuse('bad_parameter', 'wimse-req-nonce on a request');
  const signResponseParam = params.get('wimse-sign-response');
  if (signResponseParam !== undefined && signResponseParam.type !== 'boolean') refuse('bad_parameter', 'wimse-sign-response is not a boolean');

  const cs = components(input, false);
  const covered = coveredSet(cs);
  const isConnect = msg.method.toUpperCase() === 'CONNECT';
  if (isConnect) {
    // §3 CONNECT exception.
    for (const n of ['@method', '@authority']) if (!covered.has(n)) refuse('coverage', `${n} not covered`);
    for (const n of ['@path', '@query']) if (covered.has(n)) refuse('coverage', `${n} covered on CONNECT`);
  } else {
    for (const n of ['@method', '@path', '@query']) if (!covered.has(n)) refuse('coverage', `${n} not covered`);
  }
  for (const h of REQUEST_HEADERS_IF_PRESENT) {
    if (hasHeader(msg.headers, h) && !covered.has(h)) refuse('coverage', `${h} present but not covered`);
  }
  if (!hasHeader(msg.headers, 'workload-identity-token')) refuse('wit_missing', 'no Workload-Identity-Token');

  // §3: the WIT is validated before the HTTP message signature.
  const wit = witFrom(msg, cfg);
  const now = (cfg.now ?? (() => Math.floor(Date.now() / 1000)))();
  checkWindow(common, cfg, now);
  checkContentDigest(msg);
  checkCryptoSignature(signatureBase(input, msg), signature, wit);
  // §3.2: simple string comparison against configured values, never Host.
  if (!cfg.audiences.includes(aud!)) refuse('audience', 'wimse-aud is not a configured audience');
  if (cfg.replay) {
    const until = common.expires + (cfg.clockSkewSec ?? DEFAULT_SKEW);
    if (!cfg.replay.checkAndRecord(`httpsig:${common.nonce}`, until, now)) refuse('replay', 'nonce already used');
  }
  return {
    wit,
    label,
    nonce: common.nonce,
    created: common.created,
    expires: common.expires,
    covered,
    signResponse: signResponseParam?.type === 'boolean' && signResponseParam.value === true,
  };
}

/**
 * Verify a response to a signed request (§3.4, §3.5). `request` is the
 * request as sent; `requestNonce` its nonce; `signResponseRequested` whether
 * it carried `wimse-sign-response` true. Returns null for an unsigned
 * response the client must accept; throws on any failure.
 */
export function verifyWimseResponseSignature(
  response: HttpSigMessage,
  request: HttpSigMessage,
  requestNonce: string,
  signResponseRequested: boolean,
  cfg: Omit<HttpSigVerifyConfig, 'audiences'>,
): VerifiedHttpSignature | null {
  const selected = selectWimseSignature(response.headers);
  if (!selected) {
    // §3.5: "The client MUST reject an unsigned response when ... wimse-sign-response ... true."
    if (signResponseRequested) refuse('unsigned_response', 'signed response required but absent');
    return null;
  }
  const { label, input, signature } = selected;
  const params = input.params;
  const common = commonParams(params, { ...cfg, audiences: [] });
  const reqNonce = strParam(params, 'wimse-req-nonce');
  // §3.4: "Every signed response MUST include wimse-req-nonce."
  if (reqNonce === undefined) refuse('missing_parameter', 'wimse-req-nonce missing');
  // §3.5: "MUST verify that wimse-req-nonce is present and equals the nonce from the corresponding request."
  const a = Buffer.from(reqNonce!, 'utf8');
  const b = Buffer.from(requestNonce, 'utf8');
  if (a.length !== b.length || !timingSafeEqual(a, b)) refuse('req_nonce_mismatch', 'wimse-req-nonce differs from the request nonce');

  const cs = components(input, true);
  const covered = coveredSet(cs);
  const isConnect = request.method.toUpperCase() === 'CONNECT';
  if (!covered.has('@status')) refuse('coverage', '@status not covered');
  if (isConnect) {
    for (const n of ['@method;req', '@authority;req']) if (!covered.has(n)) refuse('coverage', `${n} not covered`);
    for (const n of ['@path;req', '@query;req']) if (covered.has(n)) refuse('coverage', `${n} covered on CONNECT`);
  } else {
    for (const n of ['@method;req', '@path;req', '@query;req']) if (!covered.has(n)) refuse('coverage', `${n} not covered`);
  }
  for (const h of RESPONSE_HEADERS_IF_PRESENT) {
    if (hasHeader(response.headers, h) && !covered.has(h)) refuse('coverage', `${h} present but not covered`);
  }
  if (!covered.has('workload-identity-token')) refuse('coverage', 'workload-identity-token not covered');

  const wit = witFrom(response, { ...cfg, audiences: [] });
  const now = (cfg.now ?? (() => Math.floor(Date.now() / 1000)))();
  checkWindow(common, { ...cfg, audiences: [] }, now);
  checkContentDigest(response);
  checkCryptoSignature(signatureBase(input, response, request), signature, wit);
  if (cfg.replay) {
    const until = common.expires + (cfg.clockSkewSec ?? DEFAULT_SKEW);
    if (!cfg.replay.checkAndRecord(`httpsig-resp:${common.nonce}`, until, now)) refuse('replay', 'response nonce already used');
  }
  return { wit, label, nonce: common.nonce, created: common.created, expires: common.expires, covered, signResponse: false };
}

// ── Signing (client side: demo, interop, tests) ─────────────────────────────

export interface SignRequestInput {
  method: string;
  path: string;
  /** Without "?"; undefined for no query. */
  query?: string;
  authority?: string;
  headers: Record<string, string>;
  body?: Buffer;
  /** The WIT, sent in Workload-Identity-Token. */
  wit: string;
  /** The private key matching the WIT's cnf.jwk. */
  privateKey: KeyObject;
  /** `cnf.jwk.alg`: 'ES256' or 'EdDSA'/'Ed25519'. */
  alg: string;
  audience: string;
  created?: number;
  lifetimeSec?: number;
  nonce?: string;
  signResponse?: boolean;
  label?: string;
}

/**
 * Sign a request per §3. Returns the headers to send (the input headers plus
 * Workload-Identity-Token, Content-Digest when there is a body, Signature-Input
 * and Signature). Covers every header §3 requires when present.
 */
export function signWimseRequest(input: SignRequestInput): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers)) headers[k.toLowerCase()] = v;
  headers['workload-identity-token'] = input.wit;
  if (input.body !== undefined && input.body.length > 0) {
    headers['content-digest'] = `sha-256=:${createHash('sha256').update(input.body).digest('base64')}:`;
  }
  const isConnect = input.method.toUpperCase() === 'CONNECT';
  const names = isConnect ? ['@method', '@authority'] : ['@method', '@path', '@query'];
  for (const h of REQUEST_HEADERS_IF_PRESENT) if (headers[h] !== undefined) names.push(h);
  const created = input.created ?? Math.floor(Date.now() / 1000);
  const params: Parameters = new Map<string, BareItem>([
    ['created', { type: 'integer', value: created }],
    ['expires', { type: 'integer', value: created + (input.lifetimeSec ?? 60) }],
    // §3: at least 64 bits from a CSPRNG; 128 here.
    ['nonce', { type: 'string', value: input.nonce ?? randomBytes(16).toString('base64url') }],
    ['tag', { type: 'string', value: WIMSE_SIGNATURE_TAG }],
    ['wimse-aud', { type: 'string', value: input.audience }],
  ]);
  if (input.signResponse) params.set('wimse-sign-response', { type: 'boolean', value: true });
  const inner: InnerList = {
    kind: 'inner-list',
    items: names.map((n) => ({ kind: 'item', value: { type: 'string', value: n }, params: new Map() })),
    params,
  };
  const msg: HttpSigMessage = {
    method: input.method,
    path: input.path,
    query: input.query,
    authority: input.authority,
    headers,
    body: input.body,
  };
  const base = signatureBase(inner, msg);
  const alg = sigAlg(input.alg);
  let sig: Buffer;
  if (alg === 'ES256') sig = cryptoSign('sha256', Buffer.from(base, 'utf8'), { key: input.privateKey, dsaEncoding: 'ieee-p1363' });
  else if (alg === 'EdDSA') sig = cryptoSign(null, Buffer.from(base, 'utf8'), input.privateKey);
  else throw new Error(`signWimseRequest: unsupported alg ${input.alg}`);
  const label = input.label ?? 'wimse';
  headers['signature-input'] = `${label}=${serializeInnerList(inner)}`;
  headers['signature'] = `${label}=:${sig.toString('base64')}:`;
  return headers;
}

/** A fresh workload key pair, for tests and the demo. */
export function generateWorkloadKey(alg: 'ES256' | 'EdDSA' = 'ES256'): { privateKey: KeyObject; publicKey: KeyObject } {
  return alg === 'ES256' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('ed25519');
}

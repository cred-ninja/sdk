/**
 * A WIMSE HTTP-signature request signer for the SDK's `signRequest` hook
 * (draft-ietf-wimse-http-signature-08, an RFC 9421 profile). No
 * dependencies: node:crypto only.
 *
 * It signs the exact request the SDK sends: the final headers (including the
 * SDK's own `Authorization: DPoP <Delegation Token>` on `/api/v1/use`) and the
 * body bytes, so `authorization`, `content-type`, `content-digest`,
 * `txn-token` and `workload-identity-token` are covered whenever present.
 */
import { createHash, randomBytes, sign, type KeyObject } from 'node:crypto';

export interface WimseHttpSignerOptions {
  /** The workload's WIT, or a function returning the current one (rotation). */
  wit: string | (() => string);
  /** The private key the WIT's cnf.jwk names. */
  privateKey: KeyObject;
  /** `cnf.jwk.alg`: 'ES256' (P-256) or 'EdDSA' / 'Ed25519'. */
  alg: 'ES256' | 'EdDSA' | 'Ed25519';
  /**
   * The `wimse-aud` for a request URL. Default: the URL without its query,
   * which is what Cred accepts for its own routes.
   */
  audience?: (url: URL) => string;
  /** A Txn-Token to carry (and cover) on each request, if any. */
  txnToken?: () => string | undefined;
  /** Signature lifetime in seconds. Default 60; Cred accepts at most 300. */
  lifetimeSec?: number;
}

/** The request the SDK is about to send. */
export interface SdkSignableRequest {
  method: string;
  /** Absolute URL including any query. */
  url: string;
  /** Final headers, as they will be sent. */
  headers: Record<string, string>;
  /** The exact body bytes, when there is a body. */
  body?: string;
}

const TAG = 'wimse-workload-to-workload';
/** §3: request headers that MUST be signed when they exist. */
const COVER_IF_PRESENT = ['content-type', 'content-digest', 'authorization', 'txn-token', 'workload-identity-token'];

function sfString(value: string): string {
  for (const c of value) {
    const code = c.charCodeAt(0);
    if (code < 0x20 || code > 0x7e) throw new Error('wimse signer: header or parameter value outside VCHAR/SP');
  }
  return `"${value.replace(/[\\"]/g, (m) => `\\${m}`)}"`;
}

/**
 * Returns a function for `signRequest`: given the final request, the headers
 * to add (`Workload-Identity-Token`, `Txn-Token` when configured,
 * `Content-Digest` when there is a body, `Signature-Input`, `Signature`).
 */
export function createWimseHttpSigner(options: WimseHttpSignerOptions): (request: SdkSignableRequest) => Record<string, string> {
  const alg = options.alg === 'Ed25519' ? 'EdDSA' : options.alg;
  if (alg !== 'ES256' && alg !== 'EdDSA') throw new Error(`wimse signer: unsupported alg ${String(options.alg)}`);
  return (request) => {
    const url = new URL(request.url);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(request.headers)) headers[k.toLowerCase()] = v;
    const added: Record<string, string> = {};
    added['workload-identity-token'] = typeof options.wit === 'function' ? options.wit() : options.wit;
    const txn = options.txnToken?.();
    if (txn) added['txn-token'] = txn;
    if (request.body !== undefined && request.body.length > 0) {
      added['content-digest'] = `sha-256=:${createHash('sha256').update(request.body, 'utf8').digest('base64')}:`;
    }
    Object.assign(headers, added);

    const components: Array<[string, string]> = [
      ['@method', request.method.toUpperCase()],
      ['@path', url.pathname || '/'],
      // RFC 9421 §2.2.7: the leading "?" included; "?" alone for no query.
      ['@query', `?${url.search.startsWith('?') ? url.search.slice(1) : ''}`],
    ];
    for (const name of COVER_IF_PRESENT) if (headers[name] !== undefined) components.push([name, headers[name].trim()]);

    const created = Math.floor(Date.now() / 1000);
    const audience = options.audience ? options.audience(url) : `${url.origin}${url.pathname}`;
    const params = `(${components.map(([n]) => sfString(n)).join(' ')})`
      + `;created=${created};expires=${created + (options.lifetimeSec ?? 60)}`
      + `;nonce=${sfString(randomBytes(16).toString('base64url'))};tag=${sfString(TAG)};wimse-aud=${sfString(audience)}`;
    const base = `${components.map(([n, v]) => `${sfString(n)}: ${v}`).join('\n')}\n"@signature-params": ${params}`;
    const signature = alg === 'ES256'
      ? sign('sha256', Buffer.from(base, 'utf8'), { key: options.privateKey, dsaEncoding: 'ieee-p1363' })
      : sign(null, Buffer.from(base, 'utf8'), options.privateKey);
    added['signature-input'] = `wimse=${params}`;
    added['signature'] = `wimse=:${signature.toString('base64')}:`;
    return added;
  };
}

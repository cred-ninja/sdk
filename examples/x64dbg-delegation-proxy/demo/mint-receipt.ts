/**
 * Mint Cred-style delegation receipts for the demo.
 *
 * A receipt is an Ed25519 JWS (header.payload.signature) whose payload matches
 * what @credninja/sdk verifyDelegationReceipt expects. In production these are
 * minted by the Cred server from its signing key; here we mint them with a
 * throwaway demo issuer key so the example runs end to end with no server.
 *
 * The proxy is configured with the issuer's *public* key, so it verifies these
 * exactly as it would verify real Cred receipts.
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, createHash, randomUUID, type KeyObject } from 'node:crypto';

// Ed25519 PKCS#8 DER prefix (same as @credninja/sdk identity.ts), used to wrap a
// raw 32-byte private key into a KeyObject for signing.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export interface IssuerKeypairHex {
  privateKeyHex: string;
  publicKeyHex: string;
}

/** Generate a throwaway Ed25519 issuer keypair, returned as raw 32-byte hex. */
export function generateIssuerKeypairHex(): IssuerKeypairHex {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privRaw = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  return { privateKeyHex: Buffer.from(privRaw).toString('hex'), publicKeyHex: Buffer.from(pubRaw).toString('hex') };
}

function privateKeyFromHex(hex: string): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(hex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
}

export function publicKeyHexFromPrivateHex(privateKeyHex: string): string {
  const pub = createPublicKey(privateKeyFromHex(privateKeyHex));
  return Buffer.from(pub.export({ type: 'spki', format: 'der' }).subarray(-32)).toString('hex');
}

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

export interface MintParams {
  privateKeyHex: string;
  /** Agent DID (did:key:...). */
  subject: string;
  scopes: string[];
  service?: string;
  /** Seconds until expiry. Use a small or negative value to test expiry. */
  ttlSeconds?: number;
  issuer?: string;
  userId?: string;
  appClientId?: string;
  delegationId?: string;
  audience?: string;
}

/** Mint a signed delegation receipt (compact JWS). */
export function mintReceipt(params: MintParams): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'EdDSA', typ: 'JWT' };
  const payload = {
    iss: params.issuer ?? 'did:web:demo.cred.ninja',
    sub: params.subject,
    iat: now,
    exp: now + (params.ttlSeconds ?? 300),
    service: params.service ?? 'x64dbg',
    scopes: params.scopes,
    userId: params.userId ?? 'demo-user',
    appClientId: params.appClientId ?? 'demo-app',
    ...(params.delegationId ? { delegationId: params.delegationId } : {}),
    ...(params.audience ? { aud: params.audience } : {}),
  };
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const signature = sign(null, Buffer.from(signingInput, 'utf8'), privateKeyFromHex(params.privateKeyHex));
  return `${signingInput}.${signature.toString('base64url')}`;
}

/**
 * Sign a proof-of-possession for one request, with the agent's did:key private
 * key. Binds the request (method, path, body) to a specific receipt (ath).
 */
export function signPop(params: {
  privateKeyHex: string;
  method: string;
  path: string;
  receipt: string;
  body?: Buffer | string;
}): string {
  const header = { alg: 'EdDSA', typ: 'x64dbg-pop+jwt' };
  const payload: Record<string, unknown> = {
    htm: params.method,
    htu: params.path,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
    ath: createHash('sha256').update(params.receipt).digest('base64url'),
  };
  if (params.body !== undefined) {
    payload.bh = createHash('sha256').update(params.body).digest('base64url');
  }
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const signature = sign(null, Buffer.from(signingInput, 'utf8'), privateKeyFromHex(params.privateKeyHex));
  return `${signingInput}.${signature.toString('base64url')}`;
}

// CLI: print a fresh issuer public key and a sample read-only receipt.
const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const { privateKeyHex, publicKeyHex } = generateIssuerKeypairHex();
  const scopes = (process.env.SCOPES ?? 'x64dbg:read').split(',').map((s) => s.trim());
  const subject = process.env.SUBJECT ?? 'did:key:zDemoAnalystAgent';
  const receipt = mintReceipt({ privateKeyHex, subject, scopes, ttlSeconds: Number(process.env.TTL ?? '300') });
  process.stdout.write(
    JSON.stringify({ issuerPublicKeyHex: publicKeyHex, subject, scopes, receipt }, null, 2) + '\n',
  );
}

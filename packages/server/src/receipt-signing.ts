/**
 * Delegation receipt signing and verification behind the JwsSigner
 * interface from @credninja/attenuation.
 *
 * Signing: the configured signer, else a PKCS#8 Ed25519 or P-256 key from
 * config, else the Ed25519 key derived from the vault passphrase that every
 * earlier release used (so EdDSA stays the default and existing receipts
 * keep verifying). The JWS header carries `kid`.
 *
 * Verification (draft-sweeney-wimse-credential-delegation-02 "Agent
 * Identity"): the server holds its own accepted-algorithm list, and a
 * receipt verifies only when its header `alg` is on that list and equals
 * the algorithm of the key its `kid` names. A receipt minted before `kid`
 * existed (no `kid` in the header) resolves to the passphrase-derived
 * Ed25519 key, the only key such a receipt can have been signed with.
 */
import { createPrivateKey, type KeyObject } from 'node:crypto';
import {
  checkJwsSignature,
  createKeySigner,
  createVerificationKey,
  type JwsKeyResolver,
  type JwsSigner,
  type JwsVerificationKey,
  type JwsSignatureFailure,
} from '@credninja/attenuation';

export const DEFAULT_RECEIPT_ACCEPTED_ALGS: readonly string[] = ['EdDSA', 'ES256'];

export interface ReceiptKeys {
  signer: JwsSigner;
  acceptedAlgs: readonly string[];
  resolveKey: JwsKeyResolver;
  /** Verification keys by kid, the signer's first. */
  verificationKeys: readonly JwsVerificationKey[];
}

export interface ReceiptKeyOptions {
  /** The Ed25519 key derived from the vault passphrase (legacy default). */
  derivedKey: KeyObject;
  signer?: JwsSigner;
  signingKeyPem?: string;
  verificationKeys?: readonly JwsVerificationKey[];
  acceptedAlgs?: readonly string[];
}

export function createReceiptKeys(options: ReceiptKeyOptions): ReceiptKeys {
  const derivedVerification = createVerificationKey(options.derivedKey);
  let signer: JwsSigner;
  let signerVerification: JwsVerificationKey | undefined;
  if (options.signer) {
    signer = options.signer;
  } else if (options.signingKeyPem) {
    const key = createPrivateKey(options.signingKeyPem);
    signer = createKeySigner(key);
    signerVerification = createVerificationKey(key);
  } else {
    signer = createKeySigner(options.derivedKey);
    signerVerification = derivedVerification;
  }
  const keys: JwsVerificationKey[] = [];
  for (const k of [signerVerification, ...(options.verificationKeys ?? []), derivedVerification]) {
    if (k && !keys.some((existing) => existing.kid === k.kid)) keys.push(k);
  }
  // A signer exposes no key, so a custom one needs its public key among
  // verificationKeys under the same kid, or the server could not verify the
  // receipts it mints. Refuse that configuration up front.
  if (!keys.some((k) => k.kid === signer.kid && k.alg === signer.alg)) {
    throw new Error(`Receipt signer kid ${signer.kid} has no ${signer.alg} verification key; add its public key to receiptVerificationKeys`);
  }
  const acceptedAlgs = options.acceptedAlgs ?? DEFAULT_RECEIPT_ACCEPTED_ALGS;
  if (!acceptedAlgs.includes(signer.alg)) {
    throw new Error(`Receipt signer algorithm ${signer.alg} is not on the accepted list (${acceptedAlgs.join(', ')})`);
  }
  const resolveKey: JwsKeyResolver = (header) => {
    if (header.kid === undefined) return derivedVerification;
    return typeof header.kid === 'string' ? keys.find((k) => k.kid === header.kid) : undefined;
  };
  return { signer, acceptedAlgs, resolveKey, verificationKeys: keys };
}

/** Step 1 for one compact receipt. Null when the signature verifies under the accepted list. */
export function checkReceiptSignature(receipt: string, keys: Pick<ReceiptKeys, 'acceptedAlgs' | 'resolveKey'>): JwsSignatureFailure | 'malformed' | null {
  const parts = receipt.split('.');
  if (parts.length !== 3) return 'malformed';
  let header: unknown;
  try {
    header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8'));
  } catch {
    return 'malformed';
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) return 'malformed';
  return checkJwsSignature(
    header as Record<string, unknown>,
    Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'),
    Buffer.from(parts[2]!, 'base64url'),
    keys.acceptedAlgs,
    keys.resolveKey,
  );
}

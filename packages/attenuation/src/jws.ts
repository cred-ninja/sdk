/**
 * Compact JWS signing and verification behind a signer interface.
 *
 * draft-sweeney-wimse-credential-delegation-02 "Agent Identity" requires
 * every verifier to hold a local list of accepted signature algorithms and
 * to reject an object signed with an algorithm not on it; the `alg` header
 * of the object under verification never selects the algorithm by itself
 * (as in step 1 of Section 6 of draft-asor-wimse-agent-delegation-chain-02).
 * So verification here takes two inputs the token cannot supply: the
 * accepted list, and a key resolver that returns a key bound to exactly one
 * algorithm. A token verifies only when its header `alg` is on the list AND
 * equals the resolved key's algorithm AND the signature checks.
 *
 * Header and payload are encoded as RFC 8785 JCS bytes, which is what both
 * drafts sign over. The signing primitives come from node:crypto; this
 * package has no npm runtime dependencies.
 */
import {
  createHash,
  createHmac,
  createPublicKey,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { canonicalJson } from './jcs.js';

/** JWS algorithms this package can sign and verify. HS256 exists for the interop vectors only. */
export type JwsAlgorithm = 'EdDSA' | 'ES256' | 'HS256';

export const JWS_ALGORITHMS: readonly JwsAlgorithm[] = ['EdDSA', 'ES256', 'HS256'];

/** Produces signatures for one key under one algorithm. */
export interface JwsSigner {
  readonly alg: JwsAlgorithm;
  /** Written to the JWS header as `kid`. */
  readonly kid: string;
  sign(signingInput: Uint8Array): Uint8Array;
}

/** Checks signatures for one key under one algorithm. */
export interface JwsVerificationKey {
  readonly alg: JwsAlgorithm;
  readonly kid?: string;
  verify(signingInput: Uint8Array, signature: Uint8Array): boolean;
}

export interface JwsHeaderRef {
  alg: unknown;
  kid: unknown;
}

/**
 * Returns the verification key for a header, or undefined when the verifier
 * knows no such key. The resolver may consult `kid`; it must not derive the
 * key's algorithm from `alg`.
 */
export type JwsKeyResolver = (header: JwsHeaderRef, index: number) => JwsVerificationKey | undefined;

export function base64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

const B64URL = /^[A-Za-z0-9_-]*$/;

/**
 * Strict base64url decode: unpadded alphabet only. Node's decoder skips
 * characters outside the alphabet, which would let two different strings
 * name the same bytes.
 */
export function base64urlDecode(text: string): Buffer | null {
  if (typeof text !== 'string' || !B64URL.test(text) || text.length % 4 === 1) return null;
  const out = Buffer.from(text, 'base64url');
  return out.toString('base64url') === text ? out : null;
}

/** RFC 7638 JWK SHA-256 thumbprint of a public key (OKP Ed25519 or EC P-256). */
export function jwkThumbprint(key: KeyObject): string {
  const publicKey = key.type === 'private' ? createPublicKey(key) : key;
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
  let members: Record<string, string>;
  if (jwk.kty === 'OKP') members = { crv: jwk.crv!, kty: 'OKP', x: jwk.x! };
  else if (jwk.kty === 'EC') members = { crv: jwk.crv!, kty: 'EC', x: jwk.x!, y: jwk.y! };
  else throw new Error(`Unsupported key type for a thumbprint: ${jwk.kty}`);
  return createHash('sha256').update(canonicalJson(members), 'utf8').digest('base64url');
}

function algorithmOfKey(key: KeyObject): 'EdDSA' | 'ES256' {
  if (key.asymmetricKeyType === 'ed25519') return 'EdDSA';
  if (key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1') return 'ES256';
  throw new Error(`Unsupported signing key: ${key.asymmetricKeyType ?? 'unknown'}`);
}

/**
 * A signer for an Ed25519 (EdDSA) or P-256 (ES256) private key. The
 * algorithm follows from the key; `kid` defaults to the key's RFC 7638
 * thumbprint.
 */
export function createKeySigner(privateKey: KeyObject, kid?: string): JwsSigner {
  if (privateKey.type !== 'private') throw new Error('createKeySigner needs a private key');
  const alg = algorithmOfKey(privateKey);
  const resolvedKid = kid ?? jwkThumbprint(privateKey);
  return {
    alg,
    kid: resolvedKid,
    sign(signingInput) {
      return alg === 'EdDSA'
        ? cryptoSign(null, signingInput, privateKey)
        : cryptoSign('sha256', signingInput, { key: privateKey, dsaEncoding: 'ieee-p1363' });
    },
  };
}

/** A verification key for an Ed25519 or P-256 public (or private) key. */
export function createVerificationKey(key: KeyObject, kid?: string): JwsVerificationKey {
  const publicKey = key.type === 'private' ? createPublicKey(key) : key;
  const alg = algorithmOfKey(publicKey);
  return {
    alg,
    kid: kid ?? jwkThumbprint(publicKey),
    verify(signingInput, signature) {
      try {
        return alg === 'EdDSA'
          ? cryptoVerify(null, signingInput, publicKey, signature)
          : cryptoVerify('sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
      } catch {
        return false;
      }
    },
  };
}

/** HS256 with a shared secret. For the published interop vectors; not for Cred receipts. */
export function createHs256Key(secret: Uint8Array, kid: string): JwsSigner & JwsVerificationKey {
  return {
    alg: 'HS256',
    kid,
    sign(signingInput) {
      return createHmac('sha256', secret).update(signingInput).digest();
    },
    verify(signingInput, signature) {
      const mac = createHmac('sha256', secret).update(signingInput).digest();
      return signature.length === mac.length && timingSafeEqual(mac, Buffer.from(signature));
    },
  };
}

/** A resolver over a fixed set of keys, matched by `kid` (or the only key when there is one and no kid). */
export function staticKeyResolver(keys: readonly JwsVerificationKey[]): JwsKeyResolver {
  return (header) => {
    if (typeof header.kid === 'string') return keys.find((k) => k.kid === header.kid);
    return keys.length === 1 && keys[0]!.kid === undefined ? keys[0] : undefined;
  };
}

/**
 * Sign `payload` as a compact JWS. The header carries `alg` and `kid` from
 * the signer, plus `extraHeader` (for example `typ`); both parts are JCS.
 */
export function signCompactJws(
  payload: Record<string, unknown>,
  signer: JwsSigner,
  extraHeader: Record<string, unknown> = {},
): string {
  const header = { ...extraHeader, alg: signer.alg, kid: signer.kid };
  const signingInput = `${base64urlEncode(Buffer.from(canonicalJson(header), 'utf8'))}.${base64urlEncode(Buffer.from(canonicalJson(payload), 'utf8'))}`;
  const signature = signer.sign(Buffer.from(signingInput, 'ascii'));
  return `${signingInput}.${base64urlEncode(signature)}`;
}

export type JwsSignatureFailure = 'alg_not_accepted' | 'alg_key_mismatch' | 'unknown_key' | 'bad_signature';

/**
 * Step 1 for one already-decoded token: `alg` on the accepted list, a key
 * known for the header, the key's algorithm equal to `alg`, and the
 * signature valid. Returns null on success, else why it failed.
 */
export function checkJwsSignature(
  header: Record<string, unknown>,
  signingInput: Uint8Array,
  signature: Uint8Array,
  acceptedAlgs: readonly string[],
  resolveKey: JwsKeyResolver,
  index = 0,
): JwsSignatureFailure | null {
  const alg = header.alg;
  if (typeof alg !== 'string' || !acceptedAlgs.includes(alg)) return 'alg_not_accepted';
  const key = resolveKey({ alg, kid: header.kid }, index);
  if (!key) return 'unknown_key';
  if (key.alg !== alg) return 'alg_key_mismatch';
  return key.verify(signingInput, signature) ? null : 'bad_signature';
}

/**
 * Trust anchor loading for WIMSE Workload Identity Tokens.
 *
 * draft-ietf-wimse-workload-creds-03 §3: trust anchors are bound to one trust
 * domain, are distributed out of band, and "MAY include more than one public
 * key so that operators can rotate signing keys". This module reads such a
 * key set from a JWKS document or a SPIFFE trust bundle (a JWKS that may also
 * carry `spiffe_sequence` / `spiffe_refresh_hint`, whose keys are tagged by
 * `use`, e.g. "x509-svid", "jwt-svid", "wit-svid") and keeps only the public
 * signing keys whose `use` equals the caller's `keyUse`.
 *
 * Everything that would make the key set ambiguous or unsafe is refused at
 * load time rather than at verification time: private key material, symmetric
 * keys, a kept key without `kid`, and two kept keys sharing one `kid`.
 */
import { createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';

/** One public verification key from a trust bundle. */
export interface TrustAnchorKey {
  readonly kid: string;
  readonly key: KeyObject;
  /** The JWK `alg` member, when the bundle pins one; verification then requires it. */
  readonly alg?: string;
}

/** Public keys for one trust domain, selected by `kid` only. */
export interface TrustAnchorKeys {
  /** The `use` value the keys were filtered on. */
  readonly keyUse: string;
  readonly size: number;
  get(kid: string): TrustAnchorKey | undefined;
  kids(): string[];
}

export type TrustBundleInput = { jwks: { keys: JsonWebKey[] } } | { path: string };

export interface TrustBundleOptions {
  /** Required: the JWK `use` value to keep (no default; see module comment). */
  keyUse: string;
}

/** JWK members that only private or symmetric keys carry (RFC 7518 §6.2.2, §6.3.2, §6.4.1). */
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as const;

/** Smallest RSA modulus accepted for a signing anchor (RFC 7518 §3.3). */
const MIN_RSA_BITS = 2048;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Thrown for any trust bundle that cannot be loaded as given. */
export class TrustBundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TrustBundleError';
  }
}

export function loadTrustBundle(input: TrustBundleInput, opts: TrustBundleOptions): TrustAnchorKeys {
  if (!opts || typeof opts.keyUse !== 'string' || opts.keyUse.length === 0) {
    throw new TrustBundleError('keyUse is required');
  }
  const keyUse = opts.keyUse;

  let doc: unknown;
  if ('path' in input) {
    let text: string;
    try {
      text = readFileSync(input.path, 'utf8');
    } catch (err) {
      throw new TrustBundleError(`cannot read trust bundle at ${input.path}: ${(err as Error).message}`);
    }
    try {
      doc = JSON.parse(text);
    } catch {
      throw new TrustBundleError(`trust bundle at ${input.path} is not valid JSON`);
    }
  } else {
    doc = input.jwks;
  }

  if (!isPlainObject(doc) || !Array.isArray(doc.keys)) {
    throw new TrustBundleError('trust bundle must be a JWKS object with a "keys" array');
  }

  const byKid = new Map<string, TrustAnchorKey>();
  doc.keys.forEach((raw: unknown, i: number) => {
    if (!isPlainObject(raw) || typeof raw.kty !== 'string') {
      throw new TrustBundleError(`key ${i} is not a JWK object with a "kty"`);
    }
    // Checked for every entry, kept or not: a bundle that carries private or
    // symmetric material is mis-provisioned as a whole.
    for (const m of PRIVATE_MEMBERS) {
      if (m in raw) throw new TrustBundleError(`key ${i} carries private or symmetric member "${m}"`);
    }
    if (raw.kty === 'oct') throw new TrustBundleError(`key ${i} is a symmetric (oct) key`);

    if (raw.use !== keyUse) return;

    if (typeof raw.kid !== 'string' || raw.kid.length === 0) {
      throw new TrustBundleError(`key ${i} (use "${keyUse}") has no kid`);
    }
    if (byKid.has(raw.kid)) {
      throw new TrustBundleError(`duplicate kid "${raw.kid}" among keys with use "${keyUse}"`);
    }
    if (raw.alg !== undefined && typeof raw.alg !== 'string') {
      throw new TrustBundleError(`key ${i} has a non-string alg`);
    }

    let key: KeyObject;
    try {
      key = createPublicKey({ key: publicJwkMembers(raw), format: 'jwk' });
    } catch (err) {
      throw new TrustBundleError(`key ${i} (kid "${raw.kid}") is not a usable public key: ${(err as Error).message}`);
    }
    if (key.asymmetricKeyType === 'rsa' || key.asymmetricKeyType === 'rsa-pss') {
      const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
      if (bits < MIN_RSA_BITS) throw new TrustBundleError(`key ${i} (kid "${raw.kid}") RSA modulus below ${MIN_RSA_BITS} bits`);
    }
    byKid.set(raw.kid, { kid: raw.kid, key, ...(typeof raw.alg === 'string' ? { alg: raw.alg } : {}) });
  });

  if (byKid.size === 0) {
    throw new TrustBundleError(`trust bundle has no keys with use "${keyUse}"`);
  }

  return {
    keyUse,
    size: byKid.size,
    get: (kid) => byKid.get(kid),
    kids: () => [...byKid.keys()],
  };
}

/** Only the members createPublicKey needs, so stray members cannot change parsing. */
function publicJwkMembers(jwk: Record<string, unknown>): JsonWebKey {
  switch (jwk.kty) {
    case 'EC':
      return { kty: 'EC', crv: jwk.crv as string, x: jwk.x as string, y: jwk.y as string };
    case 'OKP':
      return { kty: 'OKP', crv: jwk.crv as string, x: jwk.x as string };
    case 'RSA':
      return { kty: 'RSA', n: jwk.n as string, e: jwk.e as string };
    default:
      throw new Error(`unsupported kty "${String(jwk.kty)}"`);
  }
}

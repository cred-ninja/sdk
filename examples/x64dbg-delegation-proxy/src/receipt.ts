/**
 * Delegated-token (Cred delegation receipt) verification.
 *
 * A "delegated token" here is a Cred delegation receipt: an Ed25519 JWS
 * (header.payload.signature) minted by the delegation issuer, carrying the
 * granted `scopes`, the agent `sub`, the `service`, and an `exp`.
 *
 * All cryptographic verification (signature, subject binding, expiry) is done
 * by the SDK's verifyDelegationReceipt - we do not re-implement it. We only
 * decode the payload *after* the SDK confirms it, to read scopes/exp/service.
 */

import { createHash } from 'node:crypto';
import { verifyDelegationReceipt, type DelegationReceiptPayload } from '@credninja/sdk';
import type { ProxyConfig } from './config.js';

const CLOCK_SKEW_SECONDS = 60;

export interface VerifiedToken {
  ok: true;
  /** Delegated subject (agent DID) from the verified receipt. */
  subject: string;
  /** Scopes the receipt grants. */
  scopes: string[];
  /** Expiry (unix seconds), if present. */
  exp?: number;
  /** SHA-256 of the raw receipt, for the audit trail (never the raw token). */
  tokenHash: string;
  payload: DelegationReceiptPayload;
}

export interface RejectedToken {
  ok: false;
  reason: string;
  /** Best-effort subject from the (unverified) payload, for the audit trail. */
  subject?: string;
  tokenHash?: string;
}

export type TokenResult = VerifiedToken | RejectedToken;

function decodeUnverifiedPayload(jws: string): Partial<DelegationReceiptPayload> | null {
  const parts = jws.split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Partial<DelegationReceiptPayload>;
  } catch {
    return null;
  }
}

export async function verifyReceipt(jws: string | undefined, cfg: ProxyConfig): Promise<TokenResult> {
  if (!jws) return { ok: false, reason: 'missing_credential' };

  const tokenHash = createHash('sha256').update(jws).digest('hex');
  const untrusted = decodeUnverifiedPayload(jws);
  if (!untrusted) return { ok: false, reason: 'malformed_receipt', tokenHash };

  // Pin to the configured agent DID if set; otherwise accept any validly signed
  // receipt and read its own `sub`. This is NOT bearer trust: the proxy layer
  // then requires a proof-of-possession bound to this `sub`, so a stolen receipt
  // without the subject's key is useless (see src/pop.ts, README threat model).
  const expectedDid = cfg.expectedAgentDid ?? untrusted.sub;
  if (!expectedDid) return { ok: false, reason: 'missing_subject', tokenHash };

  const valid = await verifyDelegationReceipt(jws, {
    expectedDid,
    credPublicKey: cfg.issuerPublicKeyHex,
    ...(cfg.receiptMaxAgeSeconds !== undefined ? { maxAgeSeconds: cfg.receiptMaxAgeSeconds } : {}),
  });

  if (!valid) {
    // The boolean above is authoritative. Derive a legible reason for audit only.
    const now = Math.floor(Date.now() / 1000);
    const expired = typeof untrusted.exp === 'number' && now > untrusted.exp + CLOCK_SKEW_SECONDS;
    return {
      ok: false,
      reason: expired ? 'expired' : 'invalid_signature_or_binding',
      subject: untrusted.sub,
      tokenHash,
    };
  }

  // Verified: the payload is now trustworthy.
  const payload = untrusted as DelegationReceiptPayload;
  if (payload.service !== cfg.service) {
    return { ok: false, reason: `wrong_service:${payload.service ?? 'none'}`, subject: payload.sub, tokenHash };
  }
  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    return { ok: false, reason: 'missing_subject', tokenHash };
  }

  const scopes = Array.isArray(payload.scopes)
    ? payload.scopes.filter((s): s is string => typeof s === 'string' && s.length > 0)
    : [];

  return {
    ok: true,
    subject: payload.sub,
    scopes,
    exp: typeof payload.exp === 'number' ? payload.exp : undefined,
    tokenHash,
    payload,
  };
}

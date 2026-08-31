/**
 * Offline verification of a chain of Cred delegation receipts.
 *
 * A receipt is a compact Ed25519 JWS minted by the Delegation Server at each
 * hop (see createReceipt() in server.ts). Every non-root receipt carries
 * `parentReceiptHash`, the SHA-256 hex digest of the full compact parent
 * receipt. Until now that claim was written and never read; this module reads
 * it. Given a root-first list of receipts it checks each signature and then
 * hands plain hop records to @credninja/vault's verifyDelegationChain(), which
 * enforces linkage, depth, scope subsumption, and expiry ordering.
 *
 * Hash convention: Cred commits to the whole compact receipt, signature
 * included. draft-asor-wimse-agent-delegation-chain commits to the JWS
 * Signing Input only. Both bind the child to one specific parent; changing
 * Cred's convention is a wire change and belongs in an ADR, not here.
 */
import { createHash, verify, type KeyObject } from 'node:crypto';
import { verifyDelegationChain } from '@credninja/vault';
import type { ChainVerifyReason, ChainVerifyResult, DelegationChainHop } from '@credninja/vault';

export type ReceiptChainReason = ChainVerifyReason | 'context_mismatch';

export type ReceiptChainResult =
  | { ok: true; depth: number; leaf: ParsedReceipt }
  | { ok: false; reason: ReceiptChainReason; hop: number; message: string };

export interface ParsedReceipt {
  sub: string;
  service: string;
  userId: string;
  appClientId: string;
  scopes: string[];
  delegationId: string;
  chainDepth: number;
  iat?: number;
  exp?: number;
  parentReceiptHash?: string;
  lineage: string[];
}

export interface VerifyReceiptChainOptions {
  now?: number;
  clockSkewSeconds?: number;
  maxDepth?: number;
  /** Defaults to true. See verifyDelegationChain(). */
  requireParentHash?: boolean;
}

/** SHA-256 hex over the full compact receipt: the value createReceipt() writes as parentReceiptHash. */
export function receiptHash(receipt: string): string {
  return createHash('sha256').update(receipt).digest('hex');
}

function decodeReceipt(receipt: string, publicKey: KeyObject): { valid: boolean; payload: Record<string, unknown> | null } {
  const parts = receipt.split('.');
  if (parts.length !== 3) return { valid: false, payload: null };
  const [headerB64, payloadB64, signatureB64] = parts;
  let valid = false;
  try {
    valid = verify(null, Buffer.from(`${headerB64}.${payloadB64}`, 'utf8'), publicKey, Buffer.from(signatureB64, 'base64url'));
  } catch {
    valid = false;
  }
  let payload: Record<string, unknown> | null = null;
  try {
    const parsedJson: unknown = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (typeof parsedJson === 'object' && parsedJson !== null && !Array.isArray(parsedJson)) {
      payload = parsedJson as Record<string, unknown>;
    }
  } catch {
    payload = null;
  }
  return { valid, payload };
}

/**
 * Narrow an untyped receipt payload into a ParsedReceipt. Returns null when a
 * required identity field (sub, service, delegationId) is missing or not a
 * string, or when a present optional field has the wrong type, so a malformed
 * payload can never masquerade as a parsed receipt.
 */
export function parseReceiptPayload(payload: Record<string, unknown>): ParsedReceipt | null {
  const { sub, service, delegationId } = payload;
  if (typeof sub !== 'string' || typeof service !== 'string' || typeof delegationId !== 'string') return null;
  const userId = payload.userId ?? 'default';
  const appClientId = payload.appClientId ?? 'local';
  if (typeof userId !== 'string' || typeof appClientId !== 'string') return null;
  const chainDepth = payload.chainDepth ?? 0;
  if (typeof chainDepth !== 'number') return null;
  return {
    sub,
    service,
    userId,
    appClientId,
    scopes: Array.isArray(payload.scopes) ? payload.scopes.filter((v): v is string => typeof v === 'string') : [],
    delegationId,
    chainDepth,
    ...(typeof payload.iat === 'number' ? { iat: payload.iat } : {}),
    ...(typeof payload.exp === 'number' ? { exp: payload.exp } : {}),
    ...(typeof payload.parentReceiptHash === 'string' ? { parentReceiptHash: payload.parentReceiptHash } : {}),
    lineage: Array.isArray(payload.lineage) ? payload.lineage.filter((d: unknown): d is string => typeof d === 'string') : [],
  };
}

/**
 * Verify a root-first chain of receipts against the server's receipt public
 * key. Returns the leaf on success or the first failing hop and reason.
 */
export function verifyReceiptChain(
  receipts: readonly string[],
  publicKey: KeyObject,
  options: VerifyReceiptChainOptions = {},
): ReceiptChainResult {
  const hops: DelegationChainHop[] = [];
  const parsed: ParsedReceipt[] = [];

  for (let i = 0; i < receipts.length; i++) {
    const receipt = receipts[i];
    if (typeof receipt !== 'string' || receipt.trim() === '') {
      return { ok: false, reason: 'malformed', hop: i, message: `Receipt ${i} is not a string` };
    }
    const { valid, payload } = decodeReceipt(receipt, publicKey);
    const p = payload ? parseReceiptPayload(payload) : null;
    if (!p) {
      return { ok: false, reason: valid ? 'malformed' : 'signature_invalid', hop: i, message: `Receipt ${i} could not be parsed` };
    }
    parsed.push(p);
    hops.push({
      agentDid: p.sub,
      delegationId: p.delegationId,
      chainDepth: p.chainDepth,
      scopes: p.scopes,
      ...(p.iat !== undefined ? { iat: p.iat } : {}),
      ...(p.exp !== undefined ? { exp: p.exp } : {}),
      signatureValid: valid,
      selfHash: receiptHash(receipt),
      ...(p.parentReceiptHash !== undefined ? { parentHash: p.parentReceiptHash } : {}),
    });
  }

  // Cred-specific: every hop in a chain is for one service, one user, one app.
  for (let i = 1; i < parsed.length; i++) {
    const a = parsed[i - 1];
    const b = parsed[i];
    if (a.service !== b.service || a.userId !== b.userId || a.appClientId !== b.appClientId) {
      return { ok: false, reason: 'context_mismatch', hop: i, message: `Receipt ${i} is for a different service, user, or app than receipt ${i - 1}` };
    }
  }

  const result: ChainVerifyResult = verifyDelegationChain(hops, {
    now: options.now,
    clockSkewSeconds: options.clockSkewSeconds ?? 0,
    maxDepth: options.maxDepth,
    requireParentHash: options.requireParentHash,
  });

  if (!result.ok) return result;
  return { ok: true, depth: result.depth, leaf: parsed[result.depth] };
}

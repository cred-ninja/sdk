/**
 * @credninja/guard — Proposals and signed approvals
 *
 * A proposal binds a patch to the exact snapshot it was written against
 * (its hash), the result it produces, its classification, its magnitude and
 * its dry-run report, and hashes all of that. An approval is an Ed25519
 * signature over the proposal hash by a key the editor was configured to
 * trust. The agent that proposes cannot approve, and a proposal whose base
 * no longer matches the live chain cannot be applied: it must be re-proposed
 * against the current state.
 *
 * Signing uses node:crypto only. Keys are PEM: PKCS#8 for private keys,
 * SPKI for public keys.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { canonicalJson, sha256Hex } from './snapshot.js';
import type { PatchClassification, PolicyPatch, ReplayReport } from './types.js';

export const PROPOSAL_SIGNING_PREFIX = 'cred-policy-proposal-v1:';

export interface PatchProposal {
  version: 1;
  /** `pp_` plus the first 24 hex characters of `hash`. */
  id: string;
  /** Hash of the snapshot the patch applies to. */
  baseHash: string;
  /** Hash of the snapshot the patch produces. */
  resultHash: string;
  patch: PolicyPatch;
  rationale: string;
  /** Who proposed: an agent DID, an admin id, a service name. Free-form. */
  proposer: string;
  createdAt: string;
  /** ISO timestamp after which the proposal cannot be applied. */
  expiresAt: string;
  classification: PatchClassification;
  dryRun: ReplayReport | null;
  /** SHA-256 over the canonical JSON of every field above. */
  hash: string;
}

export interface ProposalApproval {
  /** The approver id, matching an `Approver.id` the editor trusts. */
  approver: string;
  /** Base64url Ed25519 signature over `PROPOSAL_SIGNING_PREFIX + proposal.hash`. */
  signature: string;
  signedAt: string;
}

export interface Approver {
  id: string;
  /** SPKI PEM or a KeyObject holding an Ed25519 public key. */
  publicKey: string | KeyObject;
}

export function proposalHash(proposal: Omit<PatchProposal, 'hash' | 'id'>): string {
  const { version, baseHash, resultHash, patch, rationale, proposer, createdAt, expiresAt, classification, dryRun } = proposal;
  return sha256Hex(canonicalJson({ version, baseHash, resultHash, patch, rationale, proposer, createdAt, expiresAt, classification, dryRun }));
}

export function finalizeProposal(content: Omit<PatchProposal, 'hash' | 'id'>): PatchProposal {
  const hash = proposalHash(content);
  return { ...content, hash, id: `pp_${hash.slice(0, 24)}` };
}

/** True when the proposal's stored hash matches its content. */
export function proposalIntact(proposal: PatchProposal): boolean {
  const { hash, id, ...content } = proposal;
  return proposalHash(content) === hash && id === `pp_${hash.slice(0, 24)}`;
}

function signingPayload(hash: string): Buffer {
  return Buffer.from(PROPOSAL_SIGNING_PREFIX + hash, 'utf8');
}

function toPrivateKey(key: string | KeyObject): KeyObject {
  const object = typeof key === 'string' ? createPrivateKey(key) : key;
  if (object.asymmetricKeyType !== 'ed25519') throw new Error('approval keys must be Ed25519');
  return object;
}

function toPublicKey(key: string | KeyObject): KeyObject {
  const object = typeof key === 'string' ? createPublicKey(key) : key.type === 'private' ? createPublicKey(key) : key;
  if (object.asymmetricKeyType !== 'ed25519') throw new Error('approval keys must be Ed25519');
  return object;
}

/** Generate an approver key pair (PEM). Keep the private key off the agent's host. */
export function generateApproverKeyPair(): { publicKey: string; privateKey: string } {
  const pair = generateKeyPairSync('ed25519');
  return {
    publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/** Sign a proposal's hash. Signs what the approver reviewed, nothing else. */
export function signProposal(
  proposal: Pick<PatchProposal, 'hash'>,
  approver: string,
  privateKey: string | KeyObject,
  now: Date = new Date(),
): ProposalApproval {
  if (!/^[0-9a-f]{64}$/.test(proposal.hash)) throw new Error('proposal hash must be 64 hex characters');
  const signature = sign(null, signingPayload(proposal.hash), toPrivateKey(privateKey));
  return { approver, signature: signature.toString('base64url'), signedAt: now.toISOString() };
}

/** Verify one approval against one public key. Never throws. */
export function verifyApproval(proposal: Pick<PatchProposal, 'hash'>, approval: ProposalApproval, publicKey: string | KeyObject): boolean {
  try {
    if (!/^[0-9a-f]{64}$/.test(proposal.hash)) return false;
    const signature = Buffer.from(approval.signature, 'base64url');
    if (signature.length !== 64) return false;
    return verify(null, signingPayload(proposal.hash), toPublicKey(publicKey), signature);
  } catch {
    return false;
  }
}

/**
 * @credninja/guard — Weight-space tooling
 *
 * Read a guard's policy chain as data, interpret it, diagnose it against
 * observed decisions, patch it surgically, and apply patches under signed
 * approval. See packages/guard/README.md, "Weight-space editing".
 */

export { snapshotGuard, buildSnapshot, materializePolicies, canonicalJson, snapshotHash, builtinPolicyKinds, OPAQUE_KIND } from './snapshot.js';
export type { MaterializeOptions } from './snapshot.js';
export { applyPatch, diffSnapshots, classifyPatch, PatchError } from './patch.js';
export { interpretSnapshot } from './interpret.js';
export { diagnosePolicies } from './diagnose.js';
export { replayDecisions, contextFromObservation } from './replay.js';
export type { ReplayOptions } from './replay.js';
export {
  generateApproverKeyPair,
  signProposal,
  verifyApproval,
  proposalHash,
  proposalIntact,
  finalizeProposal,
  PROPOSAL_SIGNING_PREFIX,
} from './proposal.js';
export type { PatchProposal, ProposalApproval, Approver } from './proposal.js';
export { PolicyWeightSpaceEditor } from './editor.js';
export type {
  PolicyWeightSpaceEditorOptions,
  PolicyEditEvent,
  ProposeInput,
  ApplyResult,
  ApplyRejectionCode,
  InspectResult,
  AppliedEdit,
} from './editor.js';
export { encodeRegExp, decodeRegExp, isEncodedRegExp, countLeaves, parsePointer, joinPointer, getAtPointer } from './params.js';
export type { EncodedRegExp, OpaqueMarker } from './params.js';
export type {
  PolicyEntry,
  PolicySnapshot,
  PatchOp,
  NewPolicyValue,
  PolicyPatch,
  OpEffect,
  ClassifiedOp,
  PatchClassification,
  ProviderProfile,
  SnapshotInterpretation,
  Finding,
  DiagnosisOptions,
  Diagnosis,
  ReplayFlip,
  ReplayReport,
  Observation,
} from './types.js';

/**
 * @credninja/guard — Policy diagnostics
 *
 * Read a guard's policy chain as data, interpret it, diagnose it against
 * recorded decisions, and dry-run minimal least-privilege patches. Pure
 * functions: nothing here changes a running guard. See
 * packages/guard/README.md, "Policy diagnostics".
 */

export { snapshotGuard, buildSnapshot, materializePolicies, canonicalJson, snapshotHash, builtinPolicyKinds, OPAQUE_KIND } from './snapshot.js';
export type { MaterializeOptions } from './snapshot.js';
export { applyPatch, diffSnapshots, classifyPatch, PatchError } from './patch.js';
export { interpretSnapshot } from './interpret.js';
export { diagnosePolicies } from './diagnose.js';
export { replayDecisions, contextFromObservation } from './replay.js';
export type { ReplayOptions } from './replay.js';
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

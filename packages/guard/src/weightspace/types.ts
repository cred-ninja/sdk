/**
 * @credninja/guard — Weight-space types
 *
 * The policy chain of a CredGuard, read as data. A snapshot is the chain's
 * "weights": one parameter tree per policy, in evaluation order, plus the
 * guard's error disposition. Patches are minimal JSON Pointer edits against
 * that tree, so an edit that changes one scope touches one leaf, not the
 * whole configuration.
 */

import type { GuardAuditEvent, ParameterValue, PolicyDescriptor } from '../types.js';

/** One policy in a snapshot. */
export interface PolicyEntry {
  /** The policy's unique name (its address in patch paths). */
  name: string;
  /** Its serialized configuration. Opaque policies report `kind: "opaque"`. */
  descriptor: PolicyDescriptor;
}

/** The guard's whole policy chain, serialized. */
export interface PolicySnapshot {
  version: 1;
  /** ISO timestamp the snapshot was taken. Not part of the hash. */
  takenAt: string;
  /** The guard's error disposition. */
  onError: 'deny' | 'allow' | 'log-and-deny';
  /** Policies in evaluation order. */
  policies: PolicyEntry[];
  /** Number of leaves across all parameter trees (plus one per policy). */
  parameterCount: number;
  /** SHA-256 over the canonical JSON of `{ version, onError, policies }`. */
  hash: string;
}

/** One minimal edit. Paths are JSON Pointers into the patch root (see below). */
export interface PatchOp {
  op: 'add' | 'remove' | 'replace';
  /**
   * `/onError`, `/<policyName>` (a whole policy: `{ kind, parameters }`), or
   * `/<policyName>/<pointer into parameters>`. Array indexes address array
   * elements; `-` appends on `add`.
   */
  path: string;
  /** Required for `add` and `replace`. */
  value?: ParameterValue | NewPolicyValue;
}

/** The value of an `add` on `/<policyName>`: a new policy, by kind. */
export interface NewPolicyValue {
  kind: string;
  parameters: Record<string, ParameterValue>;
}

/** A sequence of ops applied in order, all or nothing. */
export type PolicyPatch = PatchOp[];

/**
 * What an op does to the guard's permissiveness. `widening` lets requests
 * through that were denied before; `narrowing` the reverse; `neutral`
 * changes neither; `unknown` could not be determined and is treated as
 * widening everywhere a decision depends on it (fail-closed).
 */
export type OpEffect = 'widening' | 'narrowing' | 'neutral' | 'unknown';

export interface ClassifiedOp {
  op: PatchOp;
  effect: OpEffect;
  /** One sentence on why, for the reviewer. */
  rationale: string;
  /** Leaves this op touches. */
  touched: number;
}

export interface PatchClassification {
  /** The whole patch's effect: `mixed` when ops disagree. */
  effect: OpEffect | 'mixed';
  ops: ClassifiedOp[];
  /** Leaves touched, leaves in the base snapshot and their ratio. */
  magnitude: { touched: number; total: number; fraction: number };
}

/** An interpretation of what a snapshot lets an agent do, per provider. */
export interface ProviderProfile {
  provider: string;
  allowedScopes?: string[];
  scopeNarrowingInsteadOfDeny?: boolean;
  allowedUrls?: string[];
  wildcardSubdomains?: string[];
  rateLimit?: { maxRequests: number; windowMs: number };
  maxTtlSeconds?: number;
  requiredReceiptClaims?: string[];
  /** Experimental weight-artifact policy, when it names this provider. */
  artifactStore?: { hosts: string[]; allowWrite: boolean; pinnedDigests: number; maxBytes?: number };
}

export interface SnapshotInterpretation {
  /** Sentences a reviewer or an LLM can read as the chain's behaviour. */
  summary: string[];
  /** Whether unlisted providers are constrained by anything at all. */
  unlistedProviders: 'unconstrained' | 'rate-limited-only' | 'constrained';
  providers: ProviderProfile[];
  global: {
    onError: PolicySnapshot['onError'];
    timeWindow?: { start: number; end: number; timezone: string; days?: number[] };
    identity?: { requireKeyId?: boolean; allowedIdentitySources?: string[]; allowedSignatureAgentPrefixes?: string[] };
    defaultRateLimit?: { maxRequests: number; windowMs: number };
    defaultMaxTtlSeconds?: number;
    opaquePolicies: string[];
  };
}

/** A diagnostic finding with the minimal patch that addresses it. */
export interface Finding {
  /** Stable code, for example `unused-allowed-scope`. */
  code: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  /** Which policy and parameter path the finding is about. */
  policy?: string;
  path?: string;
  provider?: string;
  /** One or two sentences a reviewer can act on. */
  message: string;
  /** Observation counts that support the finding. */
  evidence: Record<string, number | string>;
  /** The surgical fix, when one exists. Absent for purely informational findings. */
  suggestedPatch?: PolicyPatch;
  /** The suggested patch's effect, so a reviewer sees whether it widens. */
  suggestedEffect?: OpEffect;
}

export interface DiagnosisOptions {
  /** Events below this count for a provider give no unused-parameter findings. Default 25. */
  minObservations?: number;
  /** A rate limit whose observed peak is under this share of the limit is slack. Default 0.25. */
  rateLimitSlackThreshold?: number;
  /** The same denial repeated this many times is a finding. Default 5. */
  repeatedDenialThreshold?: number;
}

export interface Diagnosis {
  observed: { events: number; providers: string[]; from?: string; to?: string };
  findings: Finding[];
}

/** One event replayed against the base and the patched chain. */
export interface ReplayFlip {
  index: number;
  provider: string;
  targetUrl?: string;
  requestedScopes: string[];
  before: { allowed: boolean; deniedBy?: string };
  after: { allowed: boolean; deniedBy?: string };
}

export interface ReplayReport {
  events: number;
  /** Policies left out of both chains because they hold runtime state. */
  excludedPolicies: string[];
  unchanged: number;
  /** Denied before, allowed after. */
  newlyAllowed: ReplayFlip[];
  /** Allowed before, denied after. */
  newlyDenied: ReplayFlip[];
}

/** Events the diagnostics and replay consume. */
export type Observation = GuardAuditEvent;

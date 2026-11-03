/**
 * @credninja/guard — PolicyWeightSpaceEditor
 *
 * The edit loop over a live CredGuard: read the chain as a snapshot,
 * interpret and diagnose it, propose a minimal patch (classified, measured
 * and dry-run against recorded decisions), collect signed approval, and
 * apply it by swapping only the policies the patch touched.
 *
 * Defaults are closed: every patch needs approval from a configured
 * approver, a proposer cannot approve its own proposal, a proposal applies
 * only to the exact snapshot it was written against, and an editor with no
 * approvers can propose but never apply. `requireApprovalFor: 'widening'`
 * lets narrowing patches apply without a signature, for operators who want
 * an agent to tighten its own guard but never loosen it.
 */

import type { CredGuard } from '../guard.js';
import type { CredPolicy, ParameterValue } from '../types.js';
import { diagnosePolicies } from './diagnose.js';
import { interpretSnapshot } from './interpret.js';
import { applyPatch, classifyPatch, diffSnapshots } from './patch.js';
import { finalizeProposal, proposalIntact, verifyApproval, type Approver, type PatchProposal, type ProposalApproval } from './proposal.js';
import { replayDecisions } from './replay.js';
import { materializePolicies, snapshotGuard } from './snapshot.js';
import type { Diagnosis, DiagnosisOptions, Observation, PolicyPatch, PolicySnapshot, SnapshotInterpretation } from './types.js';

export interface PolicyEditEvent {
  type: 'policy.proposed' | 'policy.applied' | 'policy.rejected';
  timestamp: string;
  proposalId: string;
  proposer: string;
  baseHash: string;
  resultHash: string;
  effect: string;
  magnitude: { touched: number; total: number; fraction: number };
  /** On applied: the approvers whose signatures verified. On rejected: the reason code. */
  approvers?: string[];
  reason?: string;
  /** The patch itself, so the audit trail can reproduce the edit. */
  patch: PolicyPatch;
}

export interface PolicyWeightSpaceEditorOptions {
  /** Keys whose signatures count as approval. None: nothing can be applied. */
  approvers?: Approver[];
  /** Which patches need a signature. Default `all`. */
  requireApprovalFor?: 'all' | 'widening';
  /** Distinct valid approvals an applied patch needs. Default 1. */
  minApprovals?: number;
  /** Let a proposer approve its own proposal. Default false. */
  allowSelfApproval?: boolean;
  /** Where the editor reads decisions for diagnosis and replay. Default: the guard's own history buffer. */
  observations?: () => Observation[];
  /** Factories for custom policy kinds a patch may add. */
  factories?: Record<string, (parameters: Record<string, ParameterValue>) => CredPolicy>;
  /** Proposal lifetime in milliseconds. Default one hour. */
  proposalTtlMs?: number;
  /** Pending proposals kept in memory. Default 64; the oldest is dropped. */
  maxPendingProposals?: number;
  /** Called on every proposal, application and rejection; wire it to the audit log. */
  onEvent?: (event: PolicyEditEvent) => void;
  diagnosis?: DiagnosisOptions;
  clock?: () => Date;
}

export interface ProposeInput {
  patch: PolicyPatch;
  rationale: string;
  proposer: string;
  /** Skip the dry-run replay (it is on by default). */
  dryRun?: boolean;
}

export type ApplyResult =
  | { applied: true; proposal: PatchProposal; snapshot: PolicySnapshot; approvers: string[]; rebuilt: string[]; kept: string[] }
  | { applied: false; code: ApplyRejectionCode; message: string; proposal?: PatchProposal };

export type ApplyRejectionCode =
  | 'proposal_not_found'
  | 'proposal_tampered'
  | 'proposal_expired'
  | 'base_mismatch'
  | 'approval_required'
  | 'approval_unavailable'
  | 'approval_invalid'
  | 'self_approval'
  | 'materialize_failed';

export interface InspectResult {
  snapshot: PolicySnapshot;
  interpretation: SnapshotInterpretation;
  diagnosis: Diagnosis;
}

export interface AppliedEdit {
  proposal: PatchProposal;
  appliedAt: string;
  approvers: string[];
  /** The snapshot before, so `proposeRollback` can diff back to it. */
  before: PolicySnapshot;
  after: PolicySnapshot;
}

export class PolicyWeightSpaceEditor {
  private readonly guard: CredGuard;
  private readonly approvers: Approver[];
  private readonly requireApprovalFor: 'all' | 'widening';
  private readonly minApprovals: number;
  private readonly allowSelfApproval: boolean;
  private readonly observations: () => Observation[];
  private readonly factories?: PolicyWeightSpaceEditorOptions['factories'];
  private readonly proposalTtlMs: number;
  private readonly maxPendingProposals: number;
  private readonly onEvent?: (event: PolicyEditEvent) => void;
  private readonly diagnosisOptions: DiagnosisOptions;
  private readonly clock: () => Date;
  private readonly pending = new Map<string, PatchProposal>();
  private readonly applied: AppliedEdit[] = [];

  constructor(guard: CredGuard, options: PolicyWeightSpaceEditorOptions = {}) {
    this.guard = guard;
    this.approvers = [...(options.approvers ?? [])];
    const ids = new Set<string>();
    for (const approver of this.approvers) {
      if (!approver.id || ids.has(approver.id)) throw new Error('approver ids must be unique and non-empty');
      ids.add(approver.id);
    }
    this.requireApprovalFor = options.requireApprovalFor ?? 'all';
    this.minApprovals = Math.max(1, options.minApprovals ?? 1);
    this.allowSelfApproval = options.allowSelfApproval ?? false;
    this.observations = options.observations ?? (() => guard.recentDecisions());
    this.factories = options.factories;
    this.proposalTtlMs = options.proposalTtlMs ?? 60 * 60 * 1000;
    this.maxPendingProposals = Math.max(1, options.maxPendingProposals ?? 64);
    this.onEvent = options.onEvent;
    this.diagnosisOptions = options.diagnosis ?? {};
    this.clock = options.clock ?? (() => new Date());
  }

  /** The live chain, read as data. */
  snapshot(): PolicySnapshot {
    return snapshotGuard(this.guard, this.clock());
  }

  /** Snapshot plus what it means plus where it disagrees with observed traffic. */
  inspect(): InspectResult {
    const snapshot = this.snapshot();
    return {
      snapshot,
      interpretation: interpretSnapshot(snapshot),
      diagnosis: diagnosePolicies(snapshot, this.observations(), this.diagnosisOptions),
    };
  }

  /**
   * Validate, classify, measure and dry-run a patch against the live chain.
   * Throws PatchError on an invalid patch. Never changes the guard.
   */
  async propose(input: ProposeInput): Promise<PatchProposal> {
    if (typeof input.rationale !== 'string' || input.rationale.trim().length === 0) throw new Error('a proposal needs a rationale');
    if (typeof input.proposer !== 'string' || input.proposer.trim().length === 0) throw new Error('a proposal needs a proposer');
    const now = this.clock();
    const base = this.snapshot();
    const result = applyPatch(base, input.patch, now);
    // Prove the result can be built before anyone signs it.
    materializePolicies(result, { previous: this.guard.getPolicies(), factories: this.factories });
    const classification = classifyPatch(base, input.patch);
    const dryRun = input.dryRun === false
      ? null
      : await replayDecisions(base, result, this.observations(), { previous: this.guard.getPolicies(), factories: this.factories });
    const proposal = finalizeProposal({
      version: 1,
      baseHash: base.hash,
      resultHash: result.hash,
      patch: structuredClone(input.patch),
      rationale: input.rationale,
      proposer: input.proposer,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.proposalTtlMs).toISOString(),
      classification,
      dryRun,
    });
    this.remember(proposal);
    this.emit('policy.proposed', proposal);
    return proposal;
  }

  getProposal(id: string): PatchProposal | undefined {
    const proposal = this.pending.get(id);
    return proposal ? structuredClone(proposal) : undefined;
  }

  pendingProposals(): PatchProposal[] {
    return [...this.pending.values()].map((proposal) => structuredClone(proposal));
  }

  /** Does this proposal need a signature under the editor's rules? */
  approvalRequired(proposal: PatchProposal): boolean {
    if (this.requireApprovalFor === 'all') return true;
    return proposal.classification.effect !== 'narrowing' && proposal.classification.effect !== 'neutral';
  }

  /**
   * Apply a proposal. Accepts an id (looked up among pending proposals) or a
   * full proposal object (checked for integrity). Verifies expiry, base
   * hash, approvals, then rebuilds only the policies the patch changed.
   */
  async apply(proposalOrId: string | PatchProposal, approvals: ProposalApproval[] = []): Promise<ApplyResult> {
    const proposal = typeof proposalOrId === 'string' ? this.pending.get(proposalOrId) : proposalOrId;
    if (!proposal) return this.reject(undefined, 'proposal_not_found', 'No pending proposal with that id. Propose again against the current chain.');
    if (!proposalIntact(proposal)) return this.reject(proposal, 'proposal_tampered', 'The proposal content does not match its hash.');

    const now = this.clock();
    if (now.getTime() > Date.parse(proposal.expiresAt)) return this.reject(proposal, 'proposal_expired', 'The proposal expired. Propose again.');

    const base = this.snapshot();
    if (base.hash !== proposal.baseHash) {
      return this.reject(proposal, 'base_mismatch', 'The chain changed since the proposal was made. Propose again against the current chain.');
    }

    let approverIds: string[] = [];
    if (this.approvalRequired(proposal)) {
      if (this.approvers.length === 0) {
        return this.reject(proposal, 'approval_unavailable', 'This editor has no approvers configured, so nothing can be applied.');
      }
      const verified = new Set<string>();
      for (const approval of approvals) {
        const approver = this.approvers.find((candidate) => candidate.id === approval.approver);
        if (!approver) continue;
        if (!this.allowSelfApproval && approver.id === proposal.proposer) {
          return this.reject(proposal, 'self_approval', `"${approver.id}" proposed this patch and cannot approve it.`);
        }
        if (verifyApproval(proposal, approval, approver.publicKey)) verified.add(approver.id);
      }
      if (approvals.length > 0 && verified.size === 0) {
        return this.reject(proposal, 'approval_invalid', 'No approval carried a valid signature from a configured approver.');
      }
      if (verified.size < this.minApprovals) {
        return this.reject(proposal, 'approval_required', `${this.minApprovals} valid approval(s) needed, ${verified.size} given.`);
      }
      approverIds = [...verified].sort();
    }

    let result: PolicySnapshot;
    let policies: CredPolicy[];
    try {
      result = applyPatch(base, proposal.patch, now);
      policies = materializePolicies(result, { previous: this.guard.getPolicies(), factories: this.factories });
    } catch (error) {
      return this.reject(proposal, 'materialize_failed', error instanceof Error ? error.message : String(error));
    }
    if (result.hash !== proposal.resultHash) {
      return this.reject(proposal, 'proposal_tampered', 'The patch no longer produces the result the proposal was signed for.');
    }

    const previous = new Set(this.guard.getPolicies());
    this.guard.replacePolicies(policies);
    this.pending.delete(proposal.id);
    const applied: AppliedEdit = { proposal: structuredClone(proposal), appliedAt: now.toISOString(), approvers: approverIds, before: base, after: result };
    this.applied.push(applied);
    this.emit('policy.applied', proposal, { approvers: approverIds });
    const rebuilt = policies.filter((policy) => !previous.has(policy)).map((policy) => policy.name);
    const kept = policies.filter((policy) => previous.has(policy)).map((policy) => policy.name);
    return { applied: true, proposal: applied.proposal, snapshot: result, approvers: approverIds, rebuilt, kept };
  }

  /** Applied edits, oldest first. */
  history(): AppliedEdit[] {
    return this.applied.map((edit) => structuredClone(edit));
  }

  /**
   * Propose the inverse of an applied edit. Goes through the same approval
   * rules as any other patch: undoing a narrowing edit widens the guard.
   */
  async proposeRollback(proposalId: string, proposer: string, rationale = `Roll back ${proposalId}`): Promise<PatchProposal> {
    const edit = this.applied.find((candidate) => candidate.proposal.id === proposalId);
    if (!edit) throw new Error(`no applied edit with id ${proposalId}`);
    const current = this.snapshot();
    if (current.hash !== edit.after.hash) {
      throw new Error('the chain changed after this edit; diff the current snapshot against the one you want instead');
    }
    return this.propose({ patch: diffSnapshots(current, edit.before), rationale, proposer });
  }

  private remember(proposal: PatchProposal): void {
    this.pending.set(proposal.id, proposal);
    while (this.pending.size > this.maxPendingProposals) {
      const oldest = this.pending.keys().next().value;
      if (oldest === undefined) break;
      this.pending.delete(oldest);
    }
  }

  private reject(proposal: PatchProposal | undefined, code: ApplyRejectionCode, message: string): ApplyResult {
    if (proposal) this.emit('policy.rejected', proposal, { reason: code });
    return { applied: false, code, message, ...(proposal ? { proposal: structuredClone(proposal) } : {}) };
  }

  private emit(type: PolicyEditEvent['type'], proposal: PatchProposal, extra: Partial<Pick<PolicyEditEvent, 'approvers' | 'reason'>> = {}): void {
    if (!this.onEvent) return;
    this.onEvent({
      type,
      timestamp: this.clock().toISOString(),
      proposalId: proposal.id,
      proposer: proposal.proposer,
      baseHash: proposal.baseHash,
      resultHash: proposal.resultHash,
      effect: proposal.classification.effect,
      magnitude: proposal.classification.magnitude,
      patch: structuredClone(proposal.patch),
      ...extra,
    });
  }
}

/**
 * @credninja/guard — Type Definitions
 */

/** Context provided to every policy evaluation */
export interface GuardContext {
  /** Which provider is being accessed */
  provider: string;
  /** The agent token hash (SHA-256, never plaintext) */
  agentTokenHash: string;
  /** Scopes being requested */
  requestedScopes: string[];
  /** Scopes the user originally consented to */
  consentedScopes: string[];
  /** For cred_use: the target URL being called */
  targetUrl?: string;
  /** For cred_use: the HTTP method */
  targetMethod?: string;
  /** ISO timestamp of the request */
  timestamp: string;
  /** Delegation ID if this is a token usage (not initial delegation) */
  delegationId?: string;
  /** Arbitrary metadata from the agent request */
  metadata?: Record<string, unknown>;
  /** Identity source used for this request */
  identitySource?: 'agent-token' | 'did' | 'tofu' | 'web-bot-auth';
  /** Optional agent DID */
  agentDid?: string;
  /** Optional TOFU fingerprint */
  tofuFingerprint?: string;
  /** Optional Web Bot Auth key identifier */
  webBotAuthKeyId?: string;
  /** Optional Signature-Agent directory URL */
  signatureAgent?: string;
  /** Optional claims carried by a delegation receipt chain */
  receiptClaims?: string[];
  /**
   * Set only when the call names a Cred Link connection. Absent for every
   * other call, and Link policies (clientGrantPolicy) SKIP when it is absent.
   * Must be built by the server from verified request state: `agentId` is
   * the authenticated principal's id, never a request body field.
   */
  link?: GuardLinkContext;
  /**
   * A human approval presented with this request (see approvalRequiredPolicy).
   * Untrusted until a policy verifies it: the agent supplies it, so a policy
   * must check its binding, expiry and signature before relying on it.
   */
  approval?: GuardApproval;
}

/**
 * A human approval for one specific request, as presented by the caller.
 * Issued by an approval service (for example after a CIBA-style backchannel
 * prompt to the approver) and checked by approvalRequiredPolicy.
 */
export interface GuardApproval {
  /** Principal id of the human who approved. */
  approverId: string;
  /** The `requestDigest` from the ApprovalRequirement this approval answers. */
  requestDigest: string;
  /** ISO timestamp after which the approval is no longer accepted. */
  expiresAt: string;
  /** ISO timestamp of the approval, when the issuer records one. */
  approvedAt?: string;
  /** Issuer's id for this approval (for example to enforce single use in the verifier). */
  id?: string;
  /** Issuer signature or token over the approval, checked by the policy's verifyApproval. */
  signature?: string;
}

/** Typed code carried by every REQUIRE_APPROVAL result and response. */
export type ApprovalRequiredCode = 'approval_required';

/** Who should approve. A hint for routing the approval prompt, not an authorization rule. */
export interface ApproverHint {
  /** Role expected to approve (for example 'finance-approver'). */
  role?: string;
  /** Specific principal expected to approve. */
  principal?: string;
}

/** What a REQUIRE_APPROVAL result asks for. */
export interface ApprovalRequirement {
  code: ApprovalRequiredCode;
  /** Policy that asked for the approval. */
  policy: string;
  /** Human-readable reason, suitable for showing the approver. */
  reason: string;
  /** Digest the approval must carry; binds it to this exact request. */
  requestDigest: string;
  /** Who should approve, when the policy knows. */
  approver?: ApproverHint;
  /** Latest `expiresAt` an approval for this request may carry, when the policy caps it. */
  expiresAt?: string;
}

/**
 * Cred Link call context (spec 4 call-time check, spec 6). Mirrors the
 * fields of @credninja/protocol's LinkAccessCheckInput that the request
 * itself carries; provider and requested scopes come from GuardContext.
 */
export interface GuardLinkContext {
  /**
   * The Link connection the call names (`conn_...`). This names a resource,
   * not an identity, so it may come from the call; an unknown or malformed
   * id is denied with `permission_required`.
   */
  connectionId: string;
  /**
   * The calling agent's verified principal id, in the same id space as
   * Permission.agentId. null when the request carries no verified agent
   * identity (always denied for Link calls). Never taken from body fields.
   */
  agentId: string | null;
  /**
   * Which route is being checked. Required, with no default: a 'use' path
   * that omitted it would otherwise skip the grant id check. Anything other
   * than 'delegate' or 'use' is denied.
   */
  operation: 'delegate' | 'use';
  /** use only: the grant id carried by the brokered handle minted at delegate time. */
  grantId?: string;
  /** use only: informational, see LinkHooks.checkLinkAccess. */
  grantVersion?: number;
}

/**
 * A single policy's decision. REQUIRE_APPROVAL means the request may proceed
 * only after a human approves it; until then the guard refuses it.
 */
export type PolicyDecision = 'ALLOW' | 'DENY' | 'SKIP' | 'REQUIRE_APPROVAL';

/** Result of a single policy evaluation */
export interface PolicyResult {
  decision: PolicyDecision;
  /** Human-readable reason (required for DENY and REQUIRE_APPROVAL, optional for ALLOW/SKIP) */
  reason?: string;
  /** Policy name for audit trail */
  policy: string;
  /** Optional: modified context to pass to next policy (e.g., scope narrowing) */
  narrowedScopes?: string[];
  /** Duration of this policy evaluation in ms */
  durationMs?: number;
  /**
   * Optional typed machine code (for example a Cred Link code such as
   * `permission_required` or `grant_revoked`). Set on DENY by policies that
   * have one, so callers never need to parse `reason`.
   */
  code?: string;
  /**
   * On REQUIRE_APPROVAL: the approval needed. The guard fills in anything
   * missing (code, policy, reason, a default request digest).
   */
  approval?: ApprovalRequirement;
  /** On ALLOW by an approval policy: the approver id of the verified approval. */
  approvedBy?: string;
}

/** A single policy — the core extension point */
export interface CredPolicy {
  /** Unique name for this policy (used in audit events) */
  name: string;
  /** Evaluate the request against this policy */
  evaluate(ctx: GuardContext): PolicyResult | Promise<PolicyResult>;
}

/** Guard configuration */
export interface GuardConfig {
  /** Ordered list of policies to evaluate */
  policies: CredPolicy[];
  /** What to do if a policy throws an error. Default: 'deny' */
  onError?: 'deny' | 'allow' | 'log-and-deny';
  /**
   * Callback for every policy decision (for audit/logging). `decision` is the
   * final GuardDecision (for example to pass to buildAuditEvent, or to see
   * `approvalRequired`).
   */
  onDecision?: (ctx: GuardContext, results: PolicyResult[], decision: GuardDecision) => void;
}

/** Final decision from the guard */
export interface GuardDecision {
  allowed: boolean;
  /** All policy results in evaluation order */
  results: PolicyResult[];
  /**
   * The result that blocked, if any: the first DENY, or when no policy
   * denied, the first REQUIRE_APPROVAL (its `code` is 'approval_required').
   */
  deniedBy?: PolicyResult;
  /**
   * Set when the request is refused only because it needs human approval.
   * Never set together with a DENY: any DENY wins.
   */
  approvalRequired?: ApprovalRequirement;
  /** Final scopes after any narrowing */
  effectiveScopes: string[];
  /** Duration of policy evaluation in ms */
  evaluationMs: number;
}

/** Structured audit event for the guard decision */
export interface GuardAuditEvent {
  type: 'guard.decision';
  timestamp: string;
  agentTokenHash: string;
  provider: string;
  allowed: boolean;
  policies: Array<{
    name: string;
    decision: PolicyDecision;
    reason?: string;
    /** The policy's typed code, when it set one. */
    code?: string;
    durationMs: number;
  }>;
  /** The denying policy's typed code, when it set one ('approval_required' for approval). */
  code?: string;
  /** Present when the request was refused pending human approval. */
  approvalRequired?: ApprovalRequirement;
  /** Approver ids of approvals a policy verified and accepted for this request. */
  approvedBy?: string[];
  /** Present when the call named a Cred Link connection. */
  link?: GuardLinkContext;
  requestedScopes: string[];
  effectiveScopes: string[];
  targetUrl?: string;
  targetMethod?: string;
  identitySource?: 'agent-token' | 'did' | 'tofu' | 'web-bot-auth';
  agentDid?: string;
  tofuFingerprint?: string;
  webBotAuthKeyId?: string;
  signatureAgent?: string;
}

// ============================================================================
// Policy Configuration Types
// ============================================================================

/** Sliding-window rate limit per agent per provider */
export interface RateLimitPolicyConfig {
  /** Max requests per window */
  maxRequests: number;
  /** Window size in milliseconds */
  windowMs: number;
  /** Optional: separate limits per provider (overrides global) */
  perProvider?: Record<string, { maxRequests: number; windowMs: number }>;
}

/** Restrict which scopes an agent can request */
export interface ScopeFilterPolicyConfig {
  /** Allowlist of scopes per provider. Agent can only request scopes in this list. */
  allowedScopes: Record<string, string[]>;
  /** If true, silently narrow to allowed scopes instead of denying. Default: false (deny). */
  narrowInsteadOfDeny?: boolean;
}

/** Restrict when delegations can occur */
export interface TimeWindowPolicyConfig {
  /** Allowed hours (24h format). Agent can only delegate during these hours. */
  allowedHours: { start: number; end: number };
  /** Timezone for hour evaluation (IANA, e.g. 'America/New_York'). Default: 'UTC'. */
  timezone?: string;
  /** Allowed days of week (0=Sunday, 6=Saturday). Default: all days. */
  allowedDays?: number[];
}

/** For cred_use: restrict which API endpoints the agent can call */
export interface UrlAllowlistPolicyConfig {
  /** Per-provider list of allowed URL patterns (string prefix or RegExp) */
  allowedUrls: Record<string, (string | RegExp)[]>;
  /**
   * Per-provider list of allowed hostname suffixes for providers whose API
   * origin varies per tenant (e.g. Salesforce's `mycompany.salesforce.com`).
   * A hostname matches when it ends with the suffix (`.salesforce.com`
   * matches `mycompany.salesforce.com`, not `salesforce.com` itself unless
   * the suffix omits the leading dot). Guards against DNS-rebinding via a
   * numeric-looking leading label (e.g. `192.168.1.1.salesforce.com`) the
   * same way the fixed-origin `allowedUrls` prefix match does implicitly.
   */
  wildcardSubdomains?: Record<string, string[]>;
  /**
   * Optional per-provider predicate gating an otherwise-allowed URL by the
   * request's scopes — e.g. a provider whose API surface is broader than
   * what any single OAuth scope grants. Runs only after a URL already
   * matches an `allowedUrls` pattern; providers with no entry here are
   * ungated beyond the base URL match.
   */
  scopeGate?: Record<string, (requestedScopes: string[], targetUrl: string) => boolean>;
}

/** Cap how long a delegated token can live */
export interface MaxTtlPolicyConfig {
  /** Maximum TTL in seconds. Delegation expires after this regardless of token expiry. */
  maxTtlSeconds: number;
  /** Per-provider overrides */
  perProvider?: Record<string, number>;
}

/** Require or constrain Web Bot Auth identities */
export interface WebBotAuthPolicyConfig {
  /** Deny when no Web Bot Auth key id is present */
  requireKeyId?: boolean;
  /** Restrict allowed identity sources */
  allowedIdentitySources?: Array<'agent-token' | 'did' | 'tofu' | 'web-bot-auth'>;
  /** Optional allowed Signature-Agent URL prefixes */
  allowedSignatureAgentPrefixes?: string[];
}

/** Require claims present on a delegation receipt chain */
export interface ReceiptClaimsPolicyConfig {
  /** Claims required for every provider unless overridden */
  requiredClaims?: string[];
  /** Optional per-provider claim requirements */
  perProvider?: Record<string, string[]>;
}

/** One matching rule for approvalRequiredPolicy. Every field set must match. */
export interface ApprovalMatchRule {
  /** Providers the rule covers. Default: any. */
  providers?: string[];
  /** HTTP methods the rule covers (case-insensitive). Default: any. */
  methods?: string[];
  /**
   * Metadata the request must carry. Each key must be present with an equal
   * value, or one of the listed values when an array is given (for example
   * `{ classification: ['secret', 'restricted'] }` or `{ newPayee: true }`).
   */
  metadata?: Record<string, unknown>;
}

/** Input to ApprovalRequiredPolicyConfig.verifyApproval. */
export interface ApprovalVerificationInput {
  approval: GuardApproval;
  /** The digest computed for this request (already compared with approval.requestDigest). */
  requestDigest: string;
  ctx: GuardContext;
}

/** Require a human approval before a matching request proceeds */
export interface ApprovalRequiredPolicyConfig {
  /** Policy name for results and audit events. Default: 'approval-required'. */
  name?: string;
  /** Requests for which this returns true need approval. */
  when?: (ctx: GuardContext) => boolean;
  /** Requests matching any rule need approval. Combined with `when` by OR. */
  match?: ApprovalMatchRule[];
  /** Reason shown to the caller and approver. */
  reason?: string;
  /** Who should approve. */
  approver?: ApproverHint;
  /**
   * Metadata keys bound into the request digest, in addition to provider,
   * agent, method, URL and scopes. Default: the keys named by `match` rules.
   */
  digestMetadataKeys?: string[];
  /**
   * Check that an approval is genuine (for example its signature). Return
   * true only for a valid approval. Without it every approval is treated as
   * unverified and refused (fail closed). A throw is a refusal.
   */
  verifyApproval?: (input: ApprovalVerificationInput) => boolean | Promise<boolean>;
  /** Refuse approvals whose expiry is further than this from now. */
  maxApprovalTtlSeconds?: number;
  /** Refuse approvals by the agent's own sponsor. Requires resolveSponsor. */
  forbidSelfApproval?: boolean;
  /** The agent's sponsor principal id, in the same id space as GuardApproval.approverId. */
  resolveSponsor?: (ctx: GuardContext) => string | undefined | Promise<string | undefined>;
  /** Clock. Default: ctx.timestamp, else the current time. */
  now?: () => Date;
}

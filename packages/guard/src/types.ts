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

/** Result of a single policy evaluation */
export interface PolicyResult {
  decision: 'ALLOW' | 'DENY' | 'SKIP';
  /** Human-readable reason (required for DENY, optional for ALLOW/SKIP) */
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
  /** Callback for every policy decision (for audit/logging) */
  onDecision?: (ctx: GuardContext, results: PolicyResult[]) => void;
}

/** Final decision from the guard */
export interface GuardDecision {
  allowed: boolean;
  /** All policy results in evaluation order */
  results: PolicyResult[];
  /** The DENY result that blocked, if any */
  deniedBy?: PolicyResult;
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
    decision: 'ALLOW' | 'DENY' | 'SKIP';
    reason?: string;
    /** The policy's typed code, when it set one. */
    code?: string;
    durationMs: number;
  }>;
  /** The denying policy's typed code, when it set one. */
  code?: string;
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

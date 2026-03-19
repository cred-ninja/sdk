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
    durationMs: number;
  }>;
  requestedScopes: string[];
  effectiveScopes: string[];
  targetUrl?: string;
  targetMethod?: string;
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
}

/** Cap how long a delegated token can live */
export interface MaxTtlPolicyConfig {
  /** Maximum TTL in seconds. Delegation expires after this regardless of token expiry. */
  maxTtlSeconds: number;
  /** Per-provider overrides */
  perProvider?: Record<string, number>;
}

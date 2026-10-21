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

/** Typed DENY codes set by classificationCeilingPolicy */
export type ClassificationCeilingDenyCode =
  /** A requested level is above the agent's ceiling */
  | 'classification_exceeded'
  /** noWriteDown is on and data would move from a higher level to a lower one */
  | 'write_down_blocked'
  /** A level is present but not in `levels`, or could not be read */
  | 'classification_unknown'
  /** No level is present and `onMissing` is 'deny', or a flow names only one side */
  | 'classification_missing'
  /** The agent has no ceiling, or its ceiling is not in `levels` */
  | 'ceiling_unknown';

/**
 * Deny access to resources classified above the agent's ceiling.
 * Fails closed: unknown levels, unknown agents and resolver errors are DENY.
 */
export interface ClassificationCeilingPolicyConfig {
  /**
   * Ordered classification levels, lowest first (for example
   * `['public', 'internal', 'confidential', 'restricted']` or
   * `['U', 'CUI', 'S', 'TS']`). Matching is exact and case-sensitive.
   */
  levels: string[];
  /**
   * Agent ceilings keyed by `agentTokenHash`, or also by `agentDid` when
   * `trustAgentDid` is set. When both identifiers have an entry, the lower
   * ceiling applies.
   */
  agentCeilings?: Record<string, string>;
  /**
   * Look up `agentCeilings` by `ctx.agentDid` as well as `agentTokenHash`.
   * Default: false, so DID-keyed entries are ignored. Enable only when
   * `agentDid` comes from verified authentication state: the bundled Express
   * middleware and MCP wrapper currently copy it from request input, so an
   * agent could claim any DID.
   */
  trustAgentDid?: boolean;
  /**
   * Resolve the agent's ceiling. Takes precedence over `agentCeilings`.
   * Return undefined for an unknown agent (DENY).
   */
  resolveAgentCeiling?: (ctx: GuardContext) => string | undefined;
  /** Read the requested resource's level. Default: `ctx.metadata.classification`. */
  resolveResourceLevel?: (ctx: GuardContext) => unknown;
  /** What to do when no classification is present. Default: 'deny'. */
  onMissing?: 'deny' | 'skip';
  /**
   * Deny moving data from a higher level to a lower one. When set, the
   * source and destination levels are also checked against the ceiling,
   * and a flow that names only one side is denied. Default: false.
   */
  noWriteDown?: boolean;
  /**
   * Read the data flow levels (used only with `noWriteDown`). Default:
   * `ctx.metadata.sourceClassification` and `ctx.metadata.destinationClassification`.
   */
  resolveFlow?: (ctx: GuardContext) => { source?: unknown; destination?: unknown } | undefined;
}

/** Typed DENY codes set by amountLimitPolicy */
export type AmountLimitDenyCode =
  /** The amount is above the per-request maximum */
  | 'amount_exceeds_per_request'
  /** The amount would take the agent's rolling period total above the maximum */
  | 'amount_exceeds_period'
  /** No amount is present and `onMissing` is 'deny' */
  | 'amount_missing'
  /** The amount is not a non-negative safe integer */
  | 'amount_invalid'
  /** The currency is missing or differs from the configured currency */
  | 'currency_mismatch'
  /** The aggregate store failed, so the request is denied (fail closed) */
  | 'amount_store_error';

/** Amount limits in integer minor units. Unset per-agent fields fall back to the policy defaults. */
export interface AmountLimits {
  /** Max amount per request */
  maxPerRequest?: number;
  /** Max total of allowed amounts per rolling period */
  maxPerPeriod?: number;
}

/**
 * Limit the monetary amounts an agent may act on.
 *
 * Amounts are integer minor units of `currency` (1050 is USD 10.50, and
 * 1050 is JPY 1050). Decimal, negative and non-numeric amounts are denied.
 * At least one of `maxPerRequest` and `maxPerPeriod` is required.
 */
export interface AmountLimitPolicyConfig extends AmountLimits {
  /** ISO 4217 currency code the limits are expressed in (compared case-insensitively) */
  currency: string;
  /** Rolling period for `maxPerPeriod` in milliseconds. Default: 86_400_000 (24 hours). */
  periodMs?: number;
  /**
   * Per-agent overrides keyed by `agentTokenHash`, or also by `agentDid`
   * when `trustAgentDid` is set. When both identifiers have an entry, the
   * lower value of each limit applies.
   */
  perAgent?: Record<string, AmountLimits>;
  /**
   * Look up `perAgent` by `ctx.agentDid` as well as `agentTokenHash`.
   * Default: false, so DID-keyed entries are ignored. Enable only when
   * `agentDid` comes from verified authentication state: the bundled Express
   * middleware and MCP wrapper currently copy it from request input, so an
   * agent could claim any DID.
   */
  trustAgentDid?: boolean;
  /** Read the amount and currency. Default: `ctx.metadata.amount` and `ctx.metadata.currency`. */
  resolveAmount?: (ctx: GuardContext) => { amount?: unknown; currency?: unknown } | undefined;
  /** What to do when no amount is present. Default: 'deny'. */
  onMissing?: 'deny' | 'skip';
  /** Rolling period totals. Default: an in-memory store that resets on restart. */
  store?: AmountLimitStore;
}

/**
 * Storage for rolling period totals. Implement this to back amountLimitPolicy
 * with a persistent or shared store (for example Redis).
 */
export interface AmountLimitStore {
  /**
   * Record `amount` at time `at` for `key` only when the total of entries
   * recorded after `since`, plus `amount`, is at most `max`. Must be atomic
   * per key so concurrent requests cannot both pass the check.
   */
  consume(
    key: string,
    amount: number,
    at: number,
    since: number,
    max: number,
  ): AmountLimitConsumeResult | Promise<AmountLimitConsumeResult>;
  /** Total of entries recorded for `key` after `since` */
  total(key: string, since: number): number | Promise<number>;
}

/** Result of AmountLimitStore.consume */
export interface AmountLimitConsumeResult {
  /** True when the amount was recorded */
  recorded: boolean;
  /** Period total after the call (includes the amount only when recorded) */
  total: number;
}

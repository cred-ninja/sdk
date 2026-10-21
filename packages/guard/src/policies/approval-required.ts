/**
 * @credninja/guard: Approval Required Policy
 *
 * Holds matching requests (for example writes at a sensitive classification,
 * or a payment to a new payee) until a named human approves them. Returns
 * REQUIRE_APPROVAL unless the context carries an approval that is bound to
 * this exact request, unexpired, verified by the configured verifyApproval,
 * and (optionally) not given by the agent's own sponsor.
 *
 * The approval itself comes from outside Guard: an approval service prompts
 * the approver (CIBA-style backchannel, a chat button, a ticket) using the
 * ApprovalRequirement from the refusal, and issues a signed GuardApproval
 * that the caller presents on retry. This policy never throws: any failure
 * while checking an approval is a REQUIRE_APPROVAL, so GuardConfig.onError:
 * 'allow' cannot turn an error into access.
 */

import { createHash } from 'node:crypto';
import type {
  ApprovalMatchRule,
  ApprovalRequiredPolicyConfig,
  ApprovalRequirement,
  CredPolicy,
  GuardApproval,
  GuardContext,
  PolicyResult,
} from '../types.js';

/** Policy name used in results and audit events unless configured. */
export const APPROVAL_REQUIRED_POLICY_NAME = 'approval-required';

/** Typed code on every REQUIRE_APPROVAL result and response. */
export const APPROVAL_REQUIRED_CODE = 'approval_required' as const;

const DEFAULT_REASON = 'Human approval required';

/** Options for computeApprovalDigest. */
export interface ApprovalDigestOptions {
  /** Metadata keys bound into the digest. Default: none. */
  metadataKeys?: string[];
}

/**
 * Digest that binds an approval to one request: SHA-256 (hex) over a
 * canonical JSON of the provider, agent token hash, HTTP method, target URL,
 * requested scopes and the chosen metadata keys. An approval for one request
 * therefore cannot be replayed for another (different URL, method, payee,
 * agent and so on).
 */
export function computeApprovalDigest(ctx: GuardContext, options: ApprovalDigestOptions = {}): string {
  const keys = [...new Set(options.metadataKeys ?? [])].sort();
  const metadata: Record<string, unknown> = {};
  for (const key of keys) {
    // Absent keys are bound as null so adding the key later changes the digest.
    metadata[key] = ctx.metadata && key in ctx.metadata ? ctx.metadata[key] : null;
  }
  const payload = {
    v: 1,
    provider: ctx.provider,
    agentTokenHash: ctx.agentTokenHash,
    method: typeof ctx.targetMethod === 'string' ? ctx.targetMethod.toUpperCase() : null,
    url: typeof ctx.targetUrl === 'string' ? ctx.targetUrl : null,
    scopes: [...(ctx.requestedScopes ?? [])].sort(),
    metadata,
  };
  return createHash('sha256').update(canonicalJson(payload)).digest('hex');
}

/**
 * Read an untrusted value (a request body field, a tool input) as a
 * GuardApproval. Returns undefined unless the required fields are strings;
 * unknown fields are dropped.
 */
export function toGuardApproval(value: unknown): GuardApproval | undefined {
  if (!isRecord(value)) return undefined;
  const { approverId, requestDigest, expiresAt, approvedAt, id, signature } = value;
  if (!isNonEmptyString(approverId) || !isNonEmptyString(requestDigest) || !isNonEmptyString(expiresAt)) {
    return undefined;
  }
  return {
    approverId,
    requestDigest,
    expiresAt,
    ...(typeof approvedAt === 'string' ? { approvedAt } : {}),
    ...(typeof id === 'string' ? { id } : {}),
    ...(typeof signature === 'string' ? { signature } : {}),
  };
}

/**
 * Create the approval required policy. Configure `when`, `match` or both;
 * a policy with neither would never apply, so it is rejected.
 */
export function approvalRequiredPolicy(config: ApprovalRequiredPolicyConfig): CredPolicy {
  if (!config || (typeof config.when !== 'function' && !(Array.isArray(config.match) && config.match.length > 0))) {
    throw new TypeError('approvalRequiredPolicy requires `when` or a non-empty `match`');
  }
  if (config.forbidSelfApproval && typeof config.resolveSponsor !== 'function') {
    throw new TypeError('approvalRequiredPolicy: forbidSelfApproval requires resolveSponsor');
  }

  const name = config.name ?? APPROVAL_REQUIRED_POLICY_NAME;
  const baseReason = config.reason ?? DEFAULT_REASON;
  const metadataKeys = config.digestMetadataKeys ?? metadataKeysFromRules(config.match ?? []);

  return {
    name,
    async evaluate(ctx: GuardContext): Promise<PolicyResult> {
      let requestDigest: string | undefined;
      let now: Date | undefined;
      try {
        if (!requiresApproval(config, ctx)) {
          return { decision: 'SKIP', policy: name };
        }

        requestDigest = computeApprovalDigest(ctx, { metadataKeys });
        now = resolveNow(config.now, ctx.timestamp);

        if (ctx.approval === undefined || ctx.approval === null) {
          return requireApproval(baseReason);
        }
        const approval = toGuardApproval(ctx.approval);
        if (!approval) {
          return requireApproval(`${baseReason}: approval is malformed`);
        }
        if (approval.requestDigest !== requestDigest) {
          return requireApproval(`${baseReason}: approval is for a different request`);
        }

        const expiresAtMs = Date.parse(approval.expiresAt);
        if (Number.isNaN(expiresAtMs) || expiresAtMs <= now.getTime()) {
          return requireApproval(`${baseReason}: approval has expired`);
        }
        if (
          typeof config.maxApprovalTtlSeconds === 'number'
          && expiresAtMs - now.getTime() > config.maxApprovalTtlSeconds * 1000
        ) {
          return requireApproval(`${baseReason}: approval expiry exceeds the allowed lifetime`);
        }

        // No verifier means nothing vouches for the approval: fail closed.
        if (typeof config.verifyApproval !== 'function') {
          return requireApproval(`${baseReason}: no approval verifier is configured`);
        }
        const verified = await config.verifyApproval({ approval, requestDigest, ctx });
        if (verified !== true) {
          return requireApproval(`${baseReason}: approval could not be verified`);
        }

        // Separation of duties, checked after verification so approverId is trusted.
        if (config.forbidSelfApproval && config.resolveSponsor) {
          const sponsor = await config.resolveSponsor(ctx);
          if (!isNonEmptyString(sponsor)) {
            return requireApproval(`${baseReason}: agent sponsor could not be resolved`);
          }
          if (sponsor === approval.approverId) {
            return requireApproval(`${baseReason}: approver may not be the agent's sponsor`);
          }
        }

        return {
          decision: 'ALLOW',
          policy: name,
          reason: `Approved by ${approval.approverId}`,
          approvedBy: approval.approverId,
        };
      } catch {
        return requireApproval(`${baseReason}: approval check failed`);
      }

      function requireApproval(reason: string): PolicyResult {
        const digest = requestDigest ?? safeDigest(ctx, metadataKeys);
        const at = now ?? new Date();
        const approvalRequirement: ApprovalRequirement = {
          code: APPROVAL_REQUIRED_CODE,
          policy: name,
          reason,
          requestDigest: digest,
          ...(config.approver ? { approver: { ...config.approver } } : {}),
          ...(typeof config.maxApprovalTtlSeconds === 'number'
            ? { expiresAt: new Date(at.getTime() + config.maxApprovalTtlSeconds * 1000).toISOString() }
            : {}),
        };
        return {
          decision: 'REQUIRE_APPROVAL',
          policy: name,
          reason,
          code: APPROVAL_REQUIRED_CODE,
          approval: approvalRequirement,
        };
      }
    },
  };
}

function requiresApproval(config: ApprovalRequiredPolicyConfig, ctx: GuardContext): boolean {
  if (typeof config.when === 'function' && config.when(ctx) === true) return true;
  return (config.match ?? []).some((rule) => ruleMatches(rule, ctx));
}

function ruleMatches(rule: ApprovalMatchRule, ctx: GuardContext): boolean {
  if (rule.providers && !rule.providers.includes(ctx.provider)) return false;
  if (rule.methods) {
    const method = typeof ctx.targetMethod === 'string' ? ctx.targetMethod.toUpperCase() : undefined;
    if (!method || !rule.methods.some((m) => m.toUpperCase() === method)) return false;
  }
  if (rule.metadata) {
    for (const [key, expected] of Object.entries(rule.metadata)) {
      if (!ctx.metadata || !(key in ctx.metadata)) return false;
      const actual = ctx.metadata[key];
      const candidates = Array.isArray(expected) ? expected : [expected];
      if (!candidates.some((candidate) => Object.is(candidate, actual))) return false;
    }
  }
  return true;
}

function metadataKeysFromRules(rules: ApprovalMatchRule[]): string[] {
  const keys = new Set<string>();
  for (const rule of rules) {
    for (const key of Object.keys(rule.metadata ?? {})) keys.add(key);
  }
  return [...keys];
}

/** Digest for the refusal path; a metadata value that cannot be serialized must not throw here. */
function safeDigest(ctx: GuardContext, metadataKeys: string[]): string {
  try {
    return computeApprovalDigest(ctx, { metadataKeys });
  } catch {
    return computeApprovalDigest(ctx);
  }
}

function resolveNow(now: (() => Date) | undefined, timestamp: string | undefined): Date {
  if (now) return now();
  if (typeof timestamp === 'string' && !Number.isNaN(Date.parse(timestamp))) {
    return new Date(timestamp);
  }
  return new Date();
}

/** JSON with object keys sorted at every level, so equal values give equal digests. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    const encoded = JSON.stringify(value);
    // undefined, functions and symbols have no JSON form; bind them as null.
    return encoded === undefined ? 'null' : encoded;
  }
  const withJson = value as { toJSON?: unknown }; // probing for an optional toJSON (Date and friends)
  if (typeof withJson.toJSON === 'function') {
    return canonicalJson(JSON.parse(JSON.stringify(value)));
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  const record = value as Record<string, unknown>; // narrowed above: non-null, non-array object
  const entries = Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
  return `{${entries.join(',')}}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

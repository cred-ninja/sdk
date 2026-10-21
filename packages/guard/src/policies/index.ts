/**
 * @credninja/guard — Built-in Policies
 */

export { RateLimitPolicy, rateLimitPolicy } from './rate-limit.js';
export type { RateLimitPolicyResult } from './rate-limit.js';
export { ScopeFilterPolicy, scopeFilterPolicy } from './scope-filter.js';
export { TimeWindowPolicy, timeWindowPolicy } from './time-window.js';
export { UrlAllowlistPolicy, urlAllowlistPolicy } from './url-allowlist.js';
export { MaxTtlPolicy, maxTtlPolicy } from './max-ttl.js';
export { webBotAuthPolicy } from './web-bot-auth.js';
export { receiptClaimsPolicy } from './receipt-claims.js';
export {
  approvalRequiredPolicy,
  computeApprovalDigest,
  toGuardApproval,
  APPROVAL_REQUIRED_CODE,
  APPROVAL_REQUIRED_POLICY_NAME,
} from './approval-required.js';
export type { ApprovalDigestOptions } from './approval-required.js';
export type { MaxTtlPolicyResult } from './max-ttl.js';

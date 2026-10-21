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
export type { MaxTtlPolicyResult } from './max-ttl.js';
export { ClassificationCeilingPolicy, classificationCeilingPolicy } from './classification-ceiling.js';
export type { ClassificationCeilingPolicyResult } from './classification-ceiling.js';
export { AmountLimitPolicy, amountLimitPolicy, InMemoryAmountLimitStore } from './amount-limit.js';
export type { AmountLimitPolicyResult } from './amount-limit.js';

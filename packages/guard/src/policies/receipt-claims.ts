/**
 * @credninja/guard — Delegation Receipt Claims Policy
 *
 * Requires specific claims to be present on the current delegation chain.
 */

import type { CredPolicy, PolicyResult, GuardContext, ReceiptClaimsPolicyConfig } from '../types.js';

export function receiptClaimsPolicy(config: ReceiptClaimsPolicyConfig): CredPolicy {
  return {
    name: 'receipt-claims',
    evaluate(ctx: GuardContext): PolicyResult {
      const requiredClaims = config.perProvider?.[ctx.provider] ?? config.requiredClaims ?? [];
      if (requiredClaims.length === 0) {
        return {
          decision: 'SKIP',
          policy: 'receipt-claims',
        };
      }

      const presentClaims = new Set(ctx.receiptClaims ?? []);
      const missingClaims = requiredClaims.filter((claim) => !presentClaims.has(claim));
      if (missingClaims.length > 0) {
        return {
          decision: 'DENY',
          policy: 'receipt-claims',
          reason: `Missing required receipt claims: ${missingClaims.join(', ')}`,
        };
      }

      return {
        decision: 'ALLOW',
        policy: 'receipt-claims',
      };
    },
  };
}

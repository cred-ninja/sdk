/**
 * @credninja/guard — Delegation Receipt Claims Policy
 *
 * Requires specific claims to be present on the current delegation chain.
 */

import type {
  CredPolicy,
  GuardContext,
  ParameterValue,
  PolicyDescriptor,
  PolicyResult,
  ReceiptClaimsPolicyConfig,
} from '../types.js';
import {
  cloneParameters,
  isPlainObject,
  requireOptionalStringArray,
  requireStringArrayRecord,
} from '../policy-diagnostics/params.js';

export function parseReceiptClaimsParameters(parameters: Record<string, ParameterValue>): ReceiptClaimsPolicyConfig {
  if (!isPlainObject(parameters)) throw new Error('receipt-claims parameters must be an object');
  const config: ReceiptClaimsPolicyConfig = {};
  const required = requireOptionalStringArray(parameters.requiredClaims, 'receipt-claims.requiredClaims');
  if (required !== undefined) config.requiredClaims = required;
  if (parameters.perProvider !== undefined && parameters.perProvider !== null) {
    config.perProvider = requireStringArrayRecord(parameters.perProvider, 'receipt-claims.perProvider');
  }
  return config;
}

export function receiptClaimsPolicy(config: ReceiptClaimsPolicyConfig): CredPolicy {
  return {
    name: 'receipt-claims',
    describe(): PolicyDescriptor {
      return { kind: 'receipt-claims', parameters: cloneParameters(config) as Record<string, ParameterValue> };
    },
    withParameters(parameters: Record<string, ParameterValue>): CredPolicy {
      return receiptClaimsPolicy(parseReceiptClaimsParameters(parameters));
    },
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

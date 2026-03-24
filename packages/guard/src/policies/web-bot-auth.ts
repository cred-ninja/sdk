/**
 * @credninja/guard — Web Bot Auth Policy
 *
 * Enforces presence and basic shape of Web Bot Auth identity metadata.
 */

import type { CredPolicy, PolicyResult, GuardContext, WebBotAuthPolicyConfig } from '../types.js';

export function webBotAuthPolicy(config: WebBotAuthPolicyConfig = {}): CredPolicy {
  return {
    name: 'web-bot-auth',
    evaluate(ctx: GuardContext): PolicyResult {
      if (config.allowedIdentitySources && config.allowedIdentitySources.length > 0) {
        const identitySource = ctx.identitySource ?? 'agent-token';
        if (!config.allowedIdentitySources.includes(identitySource)) {
          return {
            decision: 'DENY',
            policy: 'web-bot-auth',
            reason: `Identity source ${identitySource} is not allowed`,
          };
        }
      }

      if (config.requireKeyId && !ctx.webBotAuthKeyId) {
        return {
          decision: 'DENY',
          policy: 'web-bot-auth',
          reason: 'Missing Web Bot Auth key id',
        };
      }

      if (config.allowedSignatureAgentPrefixes && config.allowedSignatureAgentPrefixes.length > 0) {
        if (!ctx.signatureAgent) {
          return {
            decision: 'DENY',
            policy: 'web-bot-auth',
            reason: 'Missing Signature-Agent URL',
          };
        }
        const allowed = config.allowedSignatureAgentPrefixes.some((prefix) => ctx.signatureAgent!.startsWith(prefix));
        if (!allowed) {
          return {
            decision: 'DENY',
            policy: 'web-bot-auth',
            reason: 'Signature-Agent URL is not allowed',
          };
        }
      }

      return {
        decision: 'ALLOW',
        policy: 'web-bot-auth',
      };
    },
  };
}

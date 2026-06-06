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
        const allowed = config.allowedSignatureAgentPrefixes.some(
          (prefix) => signatureAgentMatchesPrefix(ctx.signatureAgent!, prefix),
        );
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

/**
 * Match a Signature-Agent URL against an allowed prefix.
 *
 * A raw `signatureAgent.startsWith(prefix)` is unsafe: an allowed prefix of
 * `https://agents.example.com` would also match `https://agents.example.com.evil.com`
 * (attacker-controlled subdomain) or `https://agents.example.com@evil.com`
 * (userinfo trick). We require an exact origin (scheme + host + port) match and
 * reject embedded credentials before applying the prefix on the path.
 */
function signatureAgentMatchesPrefix(signatureAgent: string, prefix: string): boolean {
  let agent: URL;
  let allowed: URL;
  try {
    agent = new URL(signatureAgent);
    allowed = new URL(prefix);
  } catch {
    // Unparseable Signature-Agent or prefix — fail closed.
    return false;
  }

  // Reject embedded credentials (e.g. https://host@evil.com); a common bypass.
  if (agent.username || agent.password) {
    return false;
  }

  if (agent.origin !== allowed.origin || agent.protocol !== allowed.protocol) {
    return false;
  }

  // Within the same origin, keep prefix semantics on path + query.
  const agentPath = agent.pathname + agent.search;
  const allowedPath = allowed.pathname + allowed.search;
  return agentPath.startsWith(allowedPath);
}

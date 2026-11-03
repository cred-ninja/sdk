/**
 * @credninja/guard — Interpret: say what a policy chain does
 *
 * Reads a snapshot and reports, per provider, what an agent can request and
 * reach, and what applies to every provider. The configuration is the ground
 * truth; the sentences are derived from it, so a reviewer gets a description
 * they did not have to infer from code.
 */

import { isEncodedRegExp, isPlainObject } from './params.js';
import { OPAQUE_KIND } from './snapshot.js';
import type { PolicySnapshot, ProviderProfile, SnapshotInterpretation } from './types.js';

function patternToString(pattern: unknown): string {
  if (typeof pattern === 'string') return pattern;
  if (isEncodedRegExp(pattern)) return `/${pattern.$regex}/${pattern.flags}`;
  return JSON.stringify(pattern);
}

export function interpretSnapshot(snapshot: PolicySnapshot): SnapshotInterpretation {
  const profiles = new Map<string, ProviderProfile>();
  const profile = (provider: string): ProviderProfile => {
    let entry = profiles.get(provider);
    if (!entry) {
      entry = { provider };
      profiles.set(provider, entry);
    }
    return entry;
  };

  const global: SnapshotInterpretation['global'] = { onError: snapshot.onError, opaquePolicies: [] };
  let hasScopeFilter = false;
  let hasUrlAllowlist = false;
  let hasGlobalRateLimit = false;

  for (const entry of snapshot.policies) {
    const { kind, parameters } = entry.descriptor;
    switch (kind) {
      case OPAQUE_KIND:
        global.opaquePolicies.push(entry.name);
        break;
      case 'scope-filter': {
        hasScopeFilter = true;
        const narrow = parameters.narrowInsteadOfDeny === true;
        if (isPlainObject(parameters.allowedScopes)) {
          for (const [provider, scopes] of Object.entries(parameters.allowedScopes)) {
            const p = profile(provider);
            p.allowedScopes = Array.isArray(scopes) ? scopes.map(String) : [];
            if (narrow) p.scopeNarrowingInsteadOfDeny = true;
          }
        }
        break;
      }
      case 'url-allowlist': {
        hasUrlAllowlist = true;
        if (isPlainObject(parameters.allowedUrls)) {
          for (const [provider, patterns] of Object.entries(parameters.allowedUrls)) {
            profile(provider).allowedUrls = Array.isArray(patterns) ? patterns.map(patternToString) : [];
          }
        }
        if (isPlainObject(parameters.wildcardSubdomains)) {
          for (const [provider, suffixes] of Object.entries(parameters.wildcardSubdomains)) {
            profile(provider).wildcardSubdomains = Array.isArray(suffixes) ? suffixes.map(String) : [];
          }
        }
        break;
      }
      case 'rate-limit': {
        if (typeof parameters.maxRequests === 'number' && typeof parameters.windowMs === 'number') {
          hasGlobalRateLimit = true;
          global.defaultRateLimit = { maxRequests: parameters.maxRequests, windowMs: parameters.windowMs };
        }
        if (isPlainObject(parameters.perProvider)) {
          for (const [provider, limits] of Object.entries(parameters.perProvider)) {
            if (isPlainObject(limits) && typeof limits.maxRequests === 'number' && typeof limits.windowMs === 'number') {
              profile(provider).rateLimit = { maxRequests: limits.maxRequests, windowMs: limits.windowMs };
            }
          }
        }
        break;
      }
      case 'max-ttl': {
        if (typeof parameters.maxTtlSeconds === 'number') global.defaultMaxTtlSeconds = parameters.maxTtlSeconds;
        if (isPlainObject(parameters.perProvider)) {
          for (const [provider, ttl] of Object.entries(parameters.perProvider)) {
            if (typeof ttl === 'number') profile(provider).maxTtlSeconds = ttl;
          }
        }
        break;
      }
      case 'time-window': {
        const hours = parameters.allowedHours;
        if (isPlainObject(hours) && typeof hours.start === 'number' && typeof hours.end === 'number') {
          global.timeWindow = {
            start: hours.start,
            end: hours.end,
            timezone: typeof parameters.timezone === 'string' ? parameters.timezone : 'UTC',
            ...(Array.isArray(parameters.allowedDays) ? { days: parameters.allowedDays.map(Number) } : {}),
          };
        }
        break;
      }
      case 'web-bot-auth': {
        global.identity = {
          ...(typeof parameters.requireKeyId === 'boolean' ? { requireKeyId: parameters.requireKeyId } : {}),
          ...(Array.isArray(parameters.allowedIdentitySources) ? { allowedIdentitySources: parameters.allowedIdentitySources.map(String) } : {}),
          ...(Array.isArray(parameters.allowedSignatureAgentPrefixes) ? { allowedSignatureAgentPrefixes: parameters.allowedSignatureAgentPrefixes.map(String) } : {}),
        };
        break;
      }
      case 'receipt-claims': {
        if (isPlainObject(parameters.perProvider)) {
          for (const [provider, claims] of Object.entries(parameters.perProvider)) {
            profile(provider).requiredReceiptClaims = Array.isArray(claims) ? claims.map(String) : [];
          }
        }
        break;
      }
      default:
        break;
    }
  }

  // Fill inherited defaults so every profile is self-contained.
  for (const p of profiles.values()) {
    if (!p.rateLimit && global.defaultRateLimit) p.rateLimit = global.defaultRateLimit;
    if (p.maxTtlSeconds === undefined && global.defaultMaxTtlSeconds !== undefined) p.maxTtlSeconds = global.defaultMaxTtlSeconds;
  }

  const unlistedProviders: SnapshotInterpretation['unlistedProviders'] =
    global.opaquePolicies.length > 0 || global.timeWindow || global.identity
      ? 'constrained'
      : hasGlobalRateLimit
        ? 'rate-limited-only'
        : 'unconstrained';

  const summary: string[] = [];
  if (snapshot.policies.length === 0) {
    summary.push('No policies are configured: every request is allowed.');
  } else {
    summary.push(`${snapshot.policies.length} policies in order: ${snapshot.policies.map((entry) => entry.name).join(', ')}.`);
  }
  summary.push(
    snapshot.onError === 'allow'
      ? 'A policy that throws lets the request through (onError: allow).'
      : 'A policy that throws denies the request (fail-closed).',
  );
  if (!hasScopeFilter) summary.push('No scope filter: an agent may request any scope the user consented to.');
  if (!hasUrlAllowlist) summary.push('No URL allowlist: brokered calls may reach any URL the operation tables map.');
  if (unlistedProviders === 'unconstrained') {
    summary.push('Providers not named in any policy are unconstrained: scope-filter and url-allowlist skip them.');
  } else if (unlistedProviders === 'rate-limited-only') {
    summary.push('Providers not named in any policy are only rate-limited: scope-filter and url-allowlist skip them.');
  }
  if (global.timeWindow) {
    const { start, end, timezone, days } = global.timeWindow;
    summary.push(`Requests are allowed ${start}:00 to ${end}:00 ${timezone}${days ? ` on weekdays ${days.join(',')}` : ''}.`);
  }
  if (global.identity?.requireKeyId) summary.push('Every request must carry a Web Bot Auth key id.');
  if (global.identity?.allowedIdentitySources) summary.push(`Accepted identity sources: ${global.identity.allowedIdentitySources.join(', ')}.`);
  for (const p of [...profiles.values()].sort((a, b) => a.provider.localeCompare(b.provider))) {
    const parts: string[] = [];
    if (p.allowedScopes) parts.push(`scopes ${p.allowedScopes.length === 0 ? '(none)' : p.allowedScopes.join(', ')}${p.scopeNarrowingInsteadOfDeny ? ' (others dropped silently)' : ''}`);
    if (p.allowedUrls) parts.push(`${p.allowedUrls.length} URL pattern${p.allowedUrls.length === 1 ? '' : 's'}`);
    if (p.wildcardSubdomains) parts.push(`hosts under ${p.wildcardSubdomains.join(', ')}`);
    if (p.rateLimit) parts.push(`${p.rateLimit.maxRequests} requests per ${p.rateLimit.windowMs}ms`);
    if (p.maxTtlSeconds !== undefined) parts.push(`TTL at most ${p.maxTtlSeconds}s`);
    if (p.requiredReceiptClaims) parts.push(`receipt claims ${p.requiredReceiptClaims.join(', ')}`);
    summary.push(`${p.provider}: ${parts.join('; ')}.`);
  }
  if (global.opaquePolicies.length > 0) {
    summary.push(`Opaque policies (custom code, not readable here): ${global.opaquePolicies.join(', ')}.`);
  }

  return {
    summary,
    unlistedProviders,
    providers: [...profiles.values()].sort((a, b) => a.provider.localeCompare(b.provider)),
    global,
  };
}

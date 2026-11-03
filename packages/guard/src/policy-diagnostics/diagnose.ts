/**
 * @credninja/guard — Diagnose: least-privilege findings from recorded decisions
 *
 * Takes a snapshot and the guard's recent decisions and reports where the
 * configuration and the observed traffic disagree: allowed scopes nobody
 * requests, URL patterns nobody hits, providers the chain never looks at,
 * rate limits with far more headroom than traffic, the same denial over and
 * over. Each finding carries the smallest patch that addresses it and says
 * whether that patch widens or narrows the guard. The heuristics are
 * deterministic with observation thresholds, in the spirit of IAM Access
 * Analyzer's unused-permission findings: evidence for a reviewer, not a
 * verdict.
 */

import { classifyPatch } from './patch.js';
import { escapePointerSegment, isEncodedRegExp, isPlainObject } from './params.js';
import type { Diagnosis, DiagnosisOptions, Finding, Observation, PolicyPatch, PolicySnapshot } from './types.js';

interface ProviderStats {
  events: number;
  uses: number;
  requestedScopes: Map<string, number>;
  urls: string[];
  /** Highest `used` seen in a rate-limit ALLOW reason "n/limit requests in window". */
  rateLimitPeak: number;
  rateLimitLimit: number;
  denials: Map<string, { policy: string; reason: string; count: number; code?: string }>;
  policiesThatApplied: Set<string>;
}

function stats(events: Observation[]): Map<string, ProviderStats> {
  const byProvider = new Map<string, ProviderStats>();
  for (const event of events) {
    let s = byProvider.get(event.provider);
    if (!s) {
      s = { events: 0, uses: 0, requestedScopes: new Map(), urls: [], rateLimitPeak: 0, rateLimitLimit: 0, denials: new Map(), policiesThatApplied: new Set() };
      byProvider.set(event.provider, s);
    }
    s.events += 1;
    if (event.targetUrl) {
      s.uses += 1;
      s.urls.push(event.targetUrl);
    }
    for (const scope of event.requestedScopes ?? []) s.requestedScopes.set(scope, (s.requestedScopes.get(scope) ?? 0) + 1);
    for (const result of event.policies ?? []) {
      if (result.decision !== 'SKIP') s.policiesThatApplied.add(result.name);
      if (result.name === 'rate-limit' && result.decision === 'ALLOW' && result.reason) {
        const match = /^(\d+)\/(\d+) requests in window/.exec(result.reason);
        if (match) {
          s.rateLimitPeak = Math.max(s.rateLimitPeak, Number(match[1]));
          s.rateLimitLimit = Number(match[2]);
        }
      }
      if (result.decision === 'DENY') {
        const key = `${result.name}|${result.reason ?? ''}`;
        const existing = s.denials.get(key);
        if (existing) existing.count += 1;
        else s.denials.set(key, { policy: result.name, reason: result.reason ?? '', count: 1, ...(result.code ? { code: result.code } : {}) });
      }
    }
  }
  return byProvider;
}

function matchesPattern(url: string, pattern: unknown): boolean {
  if (isEncodedRegExp(pattern)) {
    try {
      return new RegExp(pattern.$regex, pattern.flags).test(url);
    } catch {
      return false;
    }
  }
  if (typeof pattern !== 'string') return false;
  try {
    const target = new URL(url);
    const allowed = new URL(pattern);
    if (target.origin !== allowed.origin) return false;
    return (target.pathname + target.search).startsWith(allowed.pathname + allowed.search);
  } catch {
    return false;
  }
}

export function diagnosePolicies(snapshot: PolicySnapshot, events: Observation[], options: DiagnosisOptions = {}): Diagnosis {
  const minObservations = options.minObservations ?? 25;
  const slack = options.rateLimitSlackThreshold ?? 0.25;
  const repeated = options.repeatedDenialThreshold ?? 5;
  const byProvider = stats(events);
  const findings: Finding[] = [];
  const timestamps = events.map((event) => event.timestamp).filter((value) => typeof value === 'string').sort();

  const withPatch = (finding: Omit<Finding, 'suggestedEffect'>): Finding => {
    if (!finding.suggestedPatch) return finding;
    try {
      const effect = classifyPatch(snapshot, finding.suggestedPatch).effect;
      return { ...finding, suggestedEffect: effect === 'mixed' ? 'unknown' : effect };
    } catch {
      return { ...finding, suggestedEffect: 'unknown' };
    }
  };

  // Configuration-only findings.
  if (snapshot.onError === 'allow') {
    findings.push(withPatch({
      code: 'error-fails-open',
      severity: 'high',
      path: '/onError',
      message: 'A policy that throws lets the request through. Set onError to "deny" so an outage in one policy cannot widen access.',
      evidence: {},
      suggestedPatch: [{ op: 'replace', path: '/onError', value: 'deny' }],
    }));
  }

  const scopeFilter = snapshot.policies.find((entry) => entry.descriptor.kind === 'scope-filter');
  const urlAllowlist = snapshot.policies.find((entry) => entry.descriptor.kind === 'url-allowlist');
  const rateLimit = snapshot.policies.find((entry) => entry.descriptor.kind === 'rate-limit');

  if (scopeFilter && scopeFilter.descriptor.parameters.narrowInsteadOfDeny === true) {
    findings.push(withPatch({
      code: 'scope-narrowing-silent',
      severity: 'low',
      policy: scopeFilter.name,
      path: `/${escapePointerSegment(scopeFilter.name)}/narrowInsteadOfDeny`,
      message: 'Disallowed scopes are dropped silently instead of denying the request, so an agent asking for too much never learns it. Prefer deny unless callers expect narrowing.',
      evidence: {},
      suggestedPatch: [{ op: 'replace', path: `/${escapePointerSegment(scopeFilter.name)}/narrowInsteadOfDeny`, value: false }],
    }));
  }

  // Observation-backed findings, per provider.
  const allowedScopes = scopeFilter && isPlainObject(scopeFilter.descriptor.parameters.allowedScopes)
    ? (scopeFilter.descriptor.parameters.allowedScopes as Record<string, unknown>)
    : undefined;
  const allowedUrls = urlAllowlist && isPlainObject(urlAllowlist.descriptor.parameters.allowedUrls)
    ? (urlAllowlist.descriptor.parameters.allowedUrls as Record<string, unknown>)
    : undefined;

  for (const [provider, s] of [...byProvider.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const synthetic = provider.startsWith('_');

    // Unconstrained provider: traffic seen, but neither scope filter nor URL allowlist names it.
    if (!synthetic && s.events >= minObservations) {
      const scopesListed = allowedScopes ? Object.prototype.hasOwnProperty.call(allowedScopes, provider) : false;
      const urlsListed = allowedUrls ? Object.prototype.hasOwnProperty.call(allowedUrls, provider) : false;
      if (scopeFilter && !scopesListed && s.requestedScopes.size > 0) {
        const observed = [...s.requestedScopes.keys()].sort();
        findings.push(withPatch({
          code: 'unconstrained-provider-scopes',
          severity: 'medium',
          policy: scopeFilter.name,
          provider,
          path: `/${escapePointerSegment(scopeFilter.name)}/allowedScopes/${escapePointerSegment(provider)}`,
          message: `${s.events} requests reached "${provider}" but scope-filter has no entry for it, so it skips them. The patch pins the scopes actually observed.`,
          evidence: { events: s.events, distinctScopes: s.requestedScopes.size },
          suggestedPatch: [{ op: 'add', path: `/${escapePointerSegment(scopeFilter.name)}/allowedScopes/${escapePointerSegment(provider)}`, value: observed }],
        }));
      }
      if (urlAllowlist && !urlsListed && s.uses >= minObservations) {
        const origins = new Set<string>();
        for (const url of s.urls) {
          try {
            origins.add(new URL(url).origin + '/');
          } catch {
            // ignore unparseable
          }
        }
        findings.push(withPatch({
          code: 'unconstrained-provider-urls',
          severity: 'medium',
          policy: urlAllowlist.name,
          provider,
          path: `/${escapePointerSegment(urlAllowlist.name)}/allowedUrls/${escapePointerSegment(provider)}`,
          message: `${s.uses} brokered calls reached "${provider}" but url-allowlist has no entry for it. The patch pins the origins actually called; tighten to paths before applying.`,
          evidence: { uses: s.uses, distinctOrigins: origins.size },
          suggestedPatch: [{ op: 'add', path: `/${escapePointerSegment(urlAllowlist.name)}/allowedUrls/${escapePointerSegment(provider)}`, value: [...origins].sort() }],
        }));
      }
    }

    // Unused allowed scopes.
    if (scopeFilter && allowedScopes && Array.isArray(allowedScopes[provider]) && s.events >= minObservations) {
      const list = allowedScopes[provider] as unknown[];
      list.forEach((scope, index) => {
        if (typeof scope !== 'string' || s.requestedScopes.has(scope)) return;
        findings.push(withPatch({
          code: 'unused-allowed-scope',
          severity: 'low',
          policy: scopeFilter.name,
          provider,
          path: `/${escapePointerSegment(scopeFilter.name)}/allowedScopes/${escapePointerSegment(provider)}/${index}`,
          message: `Scope "${scope}" is allowed for "${provider}" but none of ${s.events} observed requests asked for it. Removing it narrows the guard without affecting observed traffic.`,
          evidence: { events: s.events, requests: 0 },
          suggestedPatch: [{ op: 'remove', path: `/${escapePointerSegment(scopeFilter.name)}/allowedScopes/${escapePointerSegment(provider)}/${index}` }],
        }));
      });
    }

    // Unused URL patterns.
    if (urlAllowlist && allowedUrls && Array.isArray(allowedUrls[provider]) && s.uses >= minObservations) {
      const list = allowedUrls[provider] as unknown[];
      list.forEach((pattern, index) => {
        const hits = s.urls.filter((url) => matchesPattern(url, pattern)).length;
        if (hits > 0) return;
        const shown = isEncodedRegExp(pattern) ? `/${pattern.$regex}/${pattern.flags}` : String(pattern);
        findings.push(withPatch({
          code: 'unused-url-pattern',
          severity: 'low',
          policy: urlAllowlist.name,
          provider,
          path: `/${escapePointerSegment(urlAllowlist.name)}/allowedUrls/${escapePointerSegment(provider)}/${index}`,
          message: `URL pattern ${shown} for "${provider}" matched none of ${s.uses} observed calls. Removing it narrows the guard without affecting observed traffic.`,
          evidence: { uses: s.uses, hits: 0 },
          suggestedPatch: [{ op: 'remove', path: `/${escapePointerSegment(urlAllowlist.name)}/allowedUrls/${escapePointerSegment(provider)}/${index}` }],
        }));
      });
    }

    // Rate-limit slack.
    if (rateLimit && s.rateLimitLimit > 0 && s.events >= minObservations && s.rateLimitPeak < s.rateLimitLimit * slack) {
      const perProvider = isPlainObject(rateLimit.descriptor.parameters.perProvider)
        ? (rateLimit.descriptor.parameters.perProvider as Record<string, unknown>)
        : undefined;
      const hasOverride = perProvider ? Object.prototype.hasOwnProperty.call(perProvider, provider) : false;
      const proposed = Math.max(1, Math.ceil(s.rateLimitPeak * 2));
      // Three shapes: tighten an existing override, add an override to an
      // existing table, or create the table with this one override.
      const path = hasOverride
        ? `/${escapePointerSegment(rateLimit.name)}/perProvider/${escapePointerSegment(provider)}/maxRequests`
        : perProvider
          ? `/${escapePointerSegment(rateLimit.name)}/perProvider/${escapePointerSegment(provider)}`
          : `/${escapePointerSegment(rateLimit.name)}/perProvider`;
      const windowMs = hasOverride && isPlainObject(perProvider![provider]) && typeof (perProvider![provider] as Record<string, unknown>).windowMs === 'number'
        ? ((perProvider![provider] as Record<string, unknown>).windowMs as number)
        : typeof rateLimit.descriptor.parameters.windowMs === 'number'
          ? rateLimit.descriptor.parameters.windowMs
          : undefined;
      const patch: PolicyPatch | undefined = hasOverride
        ? [{ op: 'replace', path, value: proposed }]
        : windowMs === undefined
          ? undefined
          : perProvider
            ? [{ op: 'add', path, value: { maxRequests: proposed, windowMs } }]
            : [{ op: 'add', path, value: { [provider]: { maxRequests: proposed, windowMs } } }];
      findings.push(withPatch({
        code: 'rate-limit-slack',
        severity: 'info',
        policy: rateLimit.name,
        provider,
        path,
        message: `"${provider}" peaked at ${s.rateLimitPeak} of ${s.rateLimitLimit} requests per window over ${s.events} requests. A limit of ${proposed} keeps twice the observed peak and cuts the blast radius of a runaway agent.`,
        evidence: { events: s.events, peak: s.rateLimitPeak, limit: s.rateLimitLimit },
        ...(patch ? { suggestedPatch: patch } : {}),
      }));
    }

    // Repeated identical denials.
    for (const denial of s.denials.values()) {
      if (denial.count < repeated) continue;
      let suggestedPatch: PolicyPatch | undefined;
      if (denial.policy === scopeFilter?.name && allowedScopes && Array.isArray(allowedScopes[provider])) {
        const match = /^Disallowed scopes requested: (.+)$/.exec(denial.reason);
        if (match) {
          suggestedPatch = match[1].split(',').map((scope) => scope.trim()).filter(Boolean).map((scope) => ({
            op: 'add' as const,
            path: `/${escapePointerSegment(scopeFilter.name)}/allowedScopes/${escapePointerSegment(provider)}/-`,
            value: scope,
          }));
        }
      }
      findings.push(withPatch({
        code: 'repeated-denial',
        severity: denial.count >= repeated * 4 ? 'medium' : 'low',
        policy: denial.policy,
        provider,
        message: `"${denial.policy}" denied "${provider}" ${denial.count} times for the same reason: ${denial.reason}. Either the rule is too tight for a legitimate workflow or an agent keeps probing; ${suggestedPatch ? 'the patch widens the rule and needs a human decision' : 'no automatic patch is offered'}.`,
        evidence: { count: denial.count, reason: denial.reason, ...(denial.code ? { code: denial.code } : {}) },
        ...(suggestedPatch ? { suggestedPatch } : {}),
      }));
    }
  }

  // Dead policies: configured, but skipped for every observed request.
  if (events.length >= minObservations) {
    const applied = new Set<string>();
    for (const s of byProvider.values()) for (const name of s.policiesThatApplied) applied.add(name);
    for (const entry of snapshot.policies) {
      if (applied.has(entry.name)) continue;
      const evaluated = events.some((event) => (event.policies ?? []).some((result) => result.name === entry.name));
      if (!evaluated) continue; // never reached (an earlier policy denied first); say nothing
      findings.push({
        code: 'dead-policy',
        severity: 'info',
        policy: entry.name,
        message: `"${entry.name}" skipped every one of ${events.length} observed requests. It constrains nothing the chain currently sees; check that its provider keys match real provider slugs.`,
        evidence: { events: events.length, applied: 0 },
      });
    }
  }

  const order: Record<Finding['severity'], number> = { high: 0, medium: 1, low: 2, info: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.code.localeCompare(b.code));

  return {
    observed: {
      events: events.length,
      providers: [...byProvider.keys()].sort(),
      ...(timestamps.length > 0 ? { from: timestamps[0], to: timestamps[timestamps.length - 1] } : {}),
    },
    findings,
  };
}

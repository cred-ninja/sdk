import { describe, it, expect } from 'vitest';
import { CredGuard } from '../guard.js';
import type { CredPolicy, GuardContext, GuardAuditEvent } from '../types.js';
import {
  rateLimitPolicy,
  scopeFilterPolicy,
  urlAllowlistPolicy,
  maxTtlPolicy,
  timeWindowPolicy,
  webBotAuthPolicy,
  receiptClaimsPolicy,
} from '../policies/index.js';
import {
  snapshotGuard,
  applyPatch,
  diffSnapshots,
  classifyPatch,
  materializePolicies,
  interpretSnapshot,
  diagnosePolicies,
  replayDecisions,
  PatchError,
  canonicalJson,
} from '../policy-diagnostics/index.js';

function ctx(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'github',
    agentTokenHash: 'hash-a',
    requestedScopes: ['repo'],
    consentedScopes: ['repo'],
    timestamp: '2026-11-03T12:00:00.000Z',
    ...overrides,
  };
}

function buildGuard(extra: CredPolicy[] = []): CredGuard {
  return new CredGuard({
    policies: [
      rateLimitPolicy({ maxRequests: 100, windowMs: 60_000 }),
      scopeFilterPolicy({ allowedScopes: { github: ['repo', 'read:user', 'gist'], google: ['gmail.readonly'] } }),
      urlAllowlistPolicy({
        allowedUrls: {
          github: ['https://api.github.com/repos/', 'https://api.github.com/user', /^https:\/\/api\.github\.com\/gists/],
        },
        scopeGate: { github: () => true },
      }),
      maxTtlPolicy({ maxTtlSeconds: 900, perProvider: { google: 300 } }),
      ...extra,
    ],
    decisionHistorySize: 500,
  });
}

describe('snapshotGuard', () => {
  it('reads every built-in policy as a parameter tree with a stable hash', () => {
    const a = snapshotGuard(buildGuard());
    const b = snapshotGuard(buildGuard());
    expect(a.hash).toBe(b.hash);
    expect(a.policies.map((entry) => entry.name)).toEqual(['rate-limit', 'scope-filter', 'url-allowlist', 'max-ttl']);
    expect(a.policies[0].descriptor.stateful).toBe(true);
    const urls = a.policies[2].descriptor;
    expect(urls.parameters.allowedUrls).toEqual({
      github: ['https://api.github.com/repos/', 'https://api.github.com/user', { $regex: '^https:\\/\\/api\\.github\\.com\\/gists', flags: '' }],
    });
    expect(urls.parameters.scopeGate).toEqual({ github: { $opaque: true } });
    expect(urls.opaquePaths).toEqual(['/scopeGate/github']);
    expect(a.parameterCount).toBeGreaterThan(10);
    expect(JSON.parse(JSON.stringify(a))).toEqual(a);
  });

  it('records custom policies as opaque and the remaining built-ins by kind', () => {
    const custom: CredPolicy = { name: 'no-delete', evaluate: () => ({ decision: 'ALLOW', policy: 'no-delete' }) };
    const guard = new CredGuard({
      policies: [
        custom,
        timeWindowPolicy({ allowedHours: { start: 9, end: 17 }, timezone: 'America/New_York', allowedDays: [1, 2, 3, 4, 5] }),
        webBotAuthPolicy({ requireKeyId: true, allowedIdentitySources: ['web-bot-auth'] }),
        receiptClaimsPolicy({ requiredClaims: ['purpose'], perProvider: { github: ['purpose', 'ticket'] } }),
      ],
    });
    const snapshot = snapshotGuard(guard);
    expect(snapshot.policies[0].descriptor).toEqual({ kind: 'opaque', parameters: {} });
    expect(snapshot.policies.map((entry) => entry.descriptor.kind)).toEqual(['opaque', 'time-window', 'web-bot-auth', 'receipt-claims']);
    const rebuilt = materializePolicies(snapshot, { previous: guard.getPolicies() });
    expect(rebuilt[0]).toBe(custom);
    expect(rebuilt.map((policy) => policy.name)).toEqual(['no-delete', 'time-window', 'web-bot-auth', 'receipt-claims']);
  });

  it('canonical JSON sorts keys and keeps array order', () => {
    expect(canonicalJson({ b: [2, 1], a: { d: 1, c: null } })).toBe('{"a":{"c":null,"d":1},"b":[2,1]}');
  });
});

describe('applyPatch', () => {
  it('adds one scope and touches nothing else', () => {
    const base = snapshotGuard(buildGuard());
    const next = applyPatch(base, [{ op: 'add', path: '/scope-filter/allowedScopes/github/-', value: 'workflow' }]);
    expect(next.hash).not.toBe(base.hash);
    expect(next.policies[1].descriptor.parameters.allowedScopes).toEqual({
      github: ['repo', 'read:user', 'gist', 'workflow'],
      google: ['gmail.readonly'],
    });
    expect(base.policies[1].descriptor.parameters.allowedScopes).toEqual({
      github: ['repo', 'read:user', 'gist'],
      google: ['gmail.readonly'],
    });
    expect(diffSnapshots(base, next)).toEqual([{ op: 'add', path: '/scope-filter/allowedScopes/github/-', value: 'workflow' }]);
  });

  it('is all-or-nothing and names the failing op', () => {
    const base = snapshotGuard(buildGuard());
    expect(() => applyPatch(base, [
      { op: 'remove', path: '/scope-filter/allowedScopes/github/0' },
      { op: 'remove', path: '/scope-filter/allowedScopes/github/9' },
    ])).toThrow(PatchError);
    try {
      applyPatch(base, [{ op: 'replace', path: '/onError', value: 'maybe' }]);
    } catch (error) {
      expect((error as PatchError).opIndex).toBe(0);
      expect((error as Error).message).toContain('/onError');
    }
  });

  it('surfaces parameters the policy rejects when the patched chain is built', () => {
    const base = snapshotGuard(buildGuard());
    const bad = applyPatch(base, [{ op: 'replace', path: '/rate-limit/maxRequests', value: -1 }]);
    expect(() => materializePolicies(bad, { previous: buildGuard().getPolicies() })).toThrow(/positive integer/);
    const http = applyPatch(base, [{ op: 'add', path: '/url-allowlist/allowedUrls/github/-', value: 'http://api.github.com/' }]);
    expect(() => materializePolicies(http, { previous: buildGuard().getPolicies() })).toThrow(/https/);
    const unknown = applyPatch(base, [{ op: 'add', path: '/mystery', value: { kind: 'mystery', parameters: {} } }]);
    expect(() => materializePolicies(unknown, { previous: buildGuard().getPolicies() })).toThrow(/no factory/);
  });

  it('refuses to touch opaque values, their ancestors, and opaque policies', () => {
    const base = snapshotGuard(buildGuard([{ name: 'custom', evaluate: () => ({ decision: 'ALLOW', policy: 'custom' }) }]));
    expect(() => applyPatch(base, [{ op: 'remove', path: '/url-allowlist/scopeGate/github' }])).toThrow(/opaque/);
    expect(() => applyPatch(base, [{ op: 'remove', path: '/url-allowlist/scopeGate' }])).toThrow(/opaque/);
    expect(() => applyPatch(base, [{ op: 'replace', path: '/url-allowlist/scopeGate', value: {} }])).toThrow(/opaque/);
    expect(() => applyPatch(base, [{ op: 'replace', path: '/url-allowlist', value: { kind: 'url-allowlist', parameters: { allowedUrls: {} } } }])).toThrow(/opaque/);
    expect(() => applyPatch(base, [{ op: 'add', path: '/custom/anything', value: 1 }])).toThrow(/opaque/);
    // Adding a sibling under the same parent is fine.
    expect(() => applyPatch(base, [{ op: 'add', path: '/url-allowlist/allowedUrls/slack', value: ['https://slack.com/api/'] }])).not.toThrow();
  });

  it('diffs a reordered scalar array as a whole-array replace so the result hashes equal', () => {
    const base = snapshotGuard(buildGuard());
    const removedMiddle = applyPatch(base, [{ op: 'remove', path: '/scope-filter/allowedScopes/github/1' }]);
    const rollback = diffSnapshots(removedMiddle, base);
    expect(rollback).toEqual([{ op: 'replace', path: '/scope-filter/allowedScopes/github', value: ['repo', 'read:user', 'gist'] }]);
    expect(applyPatch(removedMiddle, rollback).hash).toBe(base.hash);
    const removedLast = applyPatch(base, [{ op: 'remove', path: '/scope-filter/allowedScopes/github/2' }]);
    expect(diffSnapshots(removedLast, base)).toEqual([{ op: 'add', path: '/scope-filter/allowedScopes/github/-', value: 'gist' }]);
  });

  it('adds and removes whole policies', () => {
    const base = snapshotGuard(buildGuard());
    const next = applyPatch(base, [
      { op: 'remove', path: '/max-ttl' },
      { op: 'add', path: '/time-window', value: { kind: 'time-window', parameters: { allowedHours: { start: 8, end: 18 } } } },
    ]);
    expect(next.policies.map((entry) => entry.name)).toEqual(['rate-limit', 'scope-filter', 'url-allowlist', 'time-window']);
    const policies = materializePolicies(next, { previous: buildGuard().getPolicies() });
    expect(policies.map((policy) => policy.name)).toEqual(['rate-limit', 'scope-filter', 'url-allowlist', 'time-window']);
    expect(diffSnapshots(base, next)).toEqual([
      { op: 'remove', path: '/max-ttl' },
      { op: 'add', path: '/time-window', value: { kind: 'time-window', parameters: { allowedHours: { start: 8, end: 18 } } } },
    ]);
  });

  it('round-trips an arbitrary diff', () => {
    const base = snapshotGuard(buildGuard());
    const target = snapshotGuard(new CredGuard({
      policies: [
        rateLimitPolicy({ maxRequests: 50, windowMs: 60_000, perProvider: { google: { maxRequests: 5, windowMs: 1000 } } }),
        scopeFilterPolicy({ allowedScopes: { github: ['repo', 'gist'], slack: ['chat:write'] }, narrowInsteadOfDeny: true }),
        maxTtlPolicy({ maxTtlSeconds: 600 }),
      ],
      onError: 'log-and-deny',
    }));
    const patch = diffSnapshots(base, target);
    const applied = applyPatch(base, patch);
    expect(applied.hash).toBe(target.hash);
  });
});

describe('classifyPatch', () => {
  it('classifies widening and narrowing edits by policy semantics', () => {
    const base = snapshotGuard(buildGuard());
    const widening = classifyPatch(base, [{ op: 'add', path: '/scope-filter/allowedScopes/github/-', value: 'workflow' }]);
    expect(widening.effect).toBe('widening');
    expect(widening.magnitude.touched).toBe(1);
    expect(widening.magnitude.fraction).toBeLessThan(0.1);

    const narrowing = classifyPatch(base, [
      { op: 'remove', path: '/scope-filter/allowedScopes/github/2' },
      { op: 'replace', path: '/rate-limit/maxRequests', value: 20 },
      { op: 'replace', path: '/max-ttl/maxTtlSeconds', value: 300 },
    ]);
    expect(narrowing.effect).toBe('narrowing');
    expect(narrowing.ops.map((op) => op.effect)).toEqual(['narrowing', 'narrowing', 'narrowing']);

    const mixed = classifyPatch(base, [
      { op: 'remove', path: '/scope-filter/allowedScopes/github/2' },
      { op: 'replace', path: '/rate-limit/windowMs', value: 1000 },
    ]);
    expect(mixed.effect).toBe('mixed');
  });

  it('treats dropping a provider key, removing a policy and failing open as widening', () => {
    const base = snapshotGuard(buildGuard());
    expect(classifyPatch(base, [{ op: 'remove', path: '/scope-filter/allowedScopes/google' }]).effect).toBe('widening');
    expect(classifyPatch(base, [{ op: 'remove', path: '/url-allowlist' }]).effect).toBe('widening');
    expect(classifyPatch(base, [{ op: 'replace', path: '/onError', value: 'allow' }]).effect).toBe('widening');
    expect(classifyPatch(base, [{ op: 'add', path: '/scope-filter/allowedScopes/slack', value: ['chat:write'] }]).effect).toBe('narrowing');
    expect(classifyPatch(base, [{ op: 'add', path: '/time-window', value: { kind: 'time-window', parameters: { allowedHours: { start: 1, end: 2 } } } }]).effect).toBe('narrowing');
  });

  it('compares a per-provider rate limit with the limit it replaces', () => {
    const base = snapshotGuard(buildGuard());
    // No override table yet: the patch creates it with one override.
    const table = (value: unknown) => classifyPatch(base, [{ op: 'add', path: '/rate-limit/perProvider', value: { github: value } as never }]).effect;
    expect(table({ maxRequests: 20, windowMs: 60_000 })).toBe('narrowing');
    expect(table({ maxRequests: 500, windowMs: 60_000 })).toBe('widening');
    expect(table({ maxRequests: 20, windowMs: 1000 })).toBe('unknown');
    const withTable = applyPatch(base, [{ op: 'add', path: '/rate-limit/perProvider', value: { github: { maxRequests: 20, windowMs: 60_000 } } }]);
    const add = (value: unknown) => classifyPatch(withTable, [{ op: 'add', path: '/rate-limit/perProvider/google', value: value as never }]).effect;
    expect(add({ maxRequests: 10, windowMs: 60_000 })).toBe('narrowing');
    expect(add({ maxRequests: 500, windowMs: 60_000 })).toBe('widening');
    expect(classifyPatch(withTable, [{ op: 'remove', path: '/rate-limit/perProvider/github' }]).effect).toBe('widening');
    expect(classifyPatch(withTable, [{ op: 'remove', path: '/rate-limit/perProvider' }]).effect).toBe('widening');
  });

  it('treats removing the last entry of an allowlist as widening when the policy then skips', () => {
    const guard = new CredGuard({
      policies: [
        urlAllowlistPolicy({ allowedUrls: { github: ['https://api.github.com/repos/'], slack: ['https://slack.com/api/'] }, wildcardSubdomains: { slack: ['.slack.com'] } }),
        timeWindowPolicy({ allowedHours: { start: 9, end: 17 }, allowedDays: [1] }),
        webBotAuthPolicy({ allowedIdentitySources: ['web-bot-auth'], allowedSignatureAgentPrefixes: ['https://a.example/', 'https://b.example/'] }),
      ],
    });
    const base = snapshotGuard(guard);
    expect(classifyPatch(base, [{ op: 'remove', path: '/url-allowlist/allowedUrls/github/0' }]).effect).toBe('widening');
    expect(classifyPatch(base, [{ op: 'remove', path: '/url-allowlist/allowedUrls/slack/0' }]).effect).toBe('narrowing');
    expect(classifyPatch(base, [{ op: 'remove', path: '/time-window/allowedDays/0' }]).effect).toBe('widening');
    expect(classifyPatch(base, [{ op: 'remove', path: '/web-bot-auth/allowedIdentitySources/0' }]).effect).toBe('widening');
    expect(classifyPatch(base, [{ op: 'remove', path: '/web-bot-auth/allowedSignatureAgentPrefixes/0' }]).effect).toBe('narrowing');
  });

  it('refuses to compare the edges of an overnight time window', () => {
    const base = snapshotGuard(new CredGuard({ policies: [timeWindowPolicy({ allowedHours: { start: 2, end: 6 } })] }));
    expect(classifyPatch(base, [{ op: 'replace', path: '/time-window/allowedHours/start', value: 22 }]).effect).toBe('unknown');
    expect(classifyPatch(base, [{ op: 'replace', path: '/time-window/allowedHours/start', value: 3 }]).effect).toBe('narrowing');
    const overnight = snapshotGuard(new CredGuard({ policies: [timeWindowPolicy({ allowedHours: { start: 22, end: 6 } })] }));
    expect(classifyPatch(overnight, [{ op: 'replace', path: '/time-window/allowedHours/end', value: 5 }]).effect).toBe('unknown');
  });

  it('compares a per-provider receipt-claims list with the global list it replaces', () => {
    const base = snapshotGuard(new CredGuard({ policies: [receiptClaimsPolicy({ requiredClaims: ['purpose', 'ticket'], perProvider: { slack: ['purpose'] } })] }));
    expect(classifyPatch(base, [{ op: 'add', path: '/receipt-claims/perProvider/github', value: [] }]).effect).toBe('widening');
    expect(classifyPatch(base, [{ op: 'add', path: '/receipt-claims/perProvider/github', value: ['purpose'] }]).effect).toBe('widening');
    expect(classifyPatch(base, [{ op: 'add', path: '/receipt-claims/perProvider/github', value: ['purpose', 'ticket', 'owner'] }]).effect).toBe('narrowing');
    expect(classifyPatch(base, [{ op: 'remove', path: '/receipt-claims/perProvider/slack' }]).effect).toBe('narrowing');
  });

  it('falls back to unknown, which callers treat as widening', () => {
    const base = snapshotGuard(buildGuard());
    const result = classifyPatch(base, [{ op: 'replace', path: '/scope-filter/allowedScopes', value: { github: ['repo'] } }]);
    expect(result.effect).toBe('unknown');
  });
});

describe('interpretSnapshot', () => {
  it('describes per-provider access and the treatment of unlisted providers', () => {
    const interpretation = interpretSnapshot(snapshotGuard(buildGuard()));
    expect(interpretation.unlistedProviders).toBe('rate-limited-only');
    const github = interpretation.providers.find((profile) => profile.provider === 'github');
    expect(github).toMatchObject({
      allowedScopes: ['repo', 'read:user', 'gist'],
      rateLimit: { maxRequests: 100, windowMs: 60_000 },
      maxTtlSeconds: 900,
    });
    expect(github?.allowedUrls).toHaveLength(3);
    const google = interpretation.providers.find((profile) => profile.provider === 'google');
    expect(google?.maxTtlSeconds).toBe(300);
    expect(interpretation.summary.join('\n')).toContain('only rate-limited');
    expect(interpretation.summary.join('\n')).toContain('fail-closed');
  });

  it('does not count an empty web-bot-auth policy as a constraint', () => {
    const empty = interpretSnapshot(snapshotGuard(new CredGuard({ policies: [webBotAuthPolicy({})] })));
    expect(empty.global.identity).toBeUndefined();
    expect(empty.unlistedProviders).toBe('unconstrained');
    const strict = interpretSnapshot(snapshotGuard(new CredGuard({ policies: [webBotAuthPolicy({ requireKeyId: true })] })));
    expect(strict.global.identity).toEqual({ requireKeyId: true });
    expect(strict.unlistedProviders).toBe('constrained');
  });

  it('says so when nothing is configured', () => {
    const interpretation = interpretSnapshot(snapshotGuard(new CredGuard({ policies: [] })));
    expect(interpretation.unlistedProviders).toBe('unconstrained');
    expect(interpretation.summary[0]).toContain('every request is allowed');
  });
});

async function observe(guard: CredGuard, contexts: GuardContext[]): Promise<GuardAuditEvent[]> {
  for (const c of contexts) await guard.evaluate(c);
  return guard.recentDecisions();
}

describe('diagnosePolicies', () => {
  it('finds unused scopes and URL patterns, pins unconstrained providers, and measures rate-limit slack', async () => {
    const guard = buildGuard();
    const contexts: GuardContext[] = [];
    for (let i = 0; i < 30; i += 1) {
      contexts.push(ctx({ requestedScopes: ['repo'], targetUrl: 'https://api.github.com/repos/o/r', targetMethod: 'GET' }));
      contexts.push(ctx({ provider: 'slack', requestedScopes: ['chat:write'], agentTokenHash: 'hash-b' }));
    }
    const events = await observe(guard, contexts);
    const diagnosis = diagnosePolicies(snapshotGuard(guard), events, { minObservations: 25, rateLimitSlackThreshold: 0.5 });
    const codes = diagnosis.findings.map((finding) => `${finding.code}:${finding.path ?? finding.provider ?? ''}`);
    expect(codes).toContain('unused-allowed-scope:/scope-filter/allowedScopes/github/1');
    expect(codes).toContain('unused-allowed-scope:/scope-filter/allowedScopes/github/2');
    expect(codes).toContain('unused-url-pattern:/url-allowlist/allowedUrls/github/1');
    expect(codes).toContain('unused-url-pattern:/url-allowlist/allowedUrls/github/2');
    expect(codes).toContain('unconstrained-provider-scopes:/scope-filter/allowedScopes/slack');
    expect(codes).toContain('rate-limit-slack:/rate-limit/perProvider');

    const unconstrained = diagnosis.findings.find((finding) => finding.code === 'unconstrained-provider-scopes');
    expect(unconstrained?.suggestedPatch).toEqual([{ op: 'add', path: '/scope-filter/allowedScopes/slack', value: ['chat:write'] }]);
    expect(unconstrained?.suggestedEffect).toBe('narrowing');
    for (const finding of diagnosis.findings) {
      if (finding.code.startsWith('unused-')) expect(finding.suggestedEffect).toBe('narrowing');
    }
    expect(diagnosis.observed.events).toBe(60);
    expect(diagnosis.observed.providers).toEqual(['github', 'slack']);
  });

  it('flags repeated denials with a widening patch that needs approval, and fail-open config', async () => {
    const guard = new CredGuard({
      policies: [scopeFilterPolicy({ allowedScopes: { github: ['repo'] } })],
      onError: 'allow',
      decisionHistorySize: 100,
    });
    const events = await observe(guard, Array.from({ length: 6 }, () => ctx({ requestedScopes: ['repo', 'delete_repo'] })));
    const diagnosis = diagnosePolicies(snapshotGuard(guard), events, { minObservations: 100 });
    const denial = diagnosis.findings.find((finding) => finding.code === 'repeated-denial');
    expect(denial?.evidence.count).toBe(6);
    expect(denial?.suggestedPatch).toEqual([{ op: 'add', path: '/scope-filter/allowedScopes/github/-', value: 'delete_repo' }]);
    expect(denial?.suggestedEffect).toBe('widening');
    expect(diagnosis.findings[0].code).toBe('error-fails-open');
    expect(diagnosis.findings[0].severity).toBe('high');
  });

  it('stays quiet below the observation threshold', async () => {
    const guard = buildGuard();
    const events = await observe(guard, [ctx()]);
    const diagnosis = diagnosePolicies(snapshotGuard(guard), events);
    expect(diagnosis.findings.filter((finding) => finding.code.startsWith('unused-'))).toEqual([]);
  });
});

describe('replayDecisions', () => {
  it('leaves opaque policies out and replays receipt claims as recorded', async () => {
    let evaluations = 0;
    const counting: CredPolicy = { name: 'counting', evaluate: () => { evaluations += 1; return { decision: 'ALLOW', policy: 'counting' }; } };
    const guard = new CredGuard({
      policies: [counting, receiptClaimsPolicy({ requiredClaims: ['purpose'] })],
      decisionHistorySize: 10,
    });
    const events = await observe(guard, [ctx({ receiptClaims: ['purpose'] }), ctx({ receiptClaims: [] })]);
    expect(events.map((event) => event.receiptClaims)).toEqual([['purpose'], []]);
    evaluations = 0;
    const base = snapshotGuard(guard);
    const patched = applyPatch(base, [{ op: 'add', path: '/receipt-claims/requiredClaims/-', value: 'ticket' }]);
    const report = await replayDecisions(base, patched, events, { previous: guard.getPolicies() });
    expect(evaluations).toBe(0);
    expect(report.excludedPolicies).toEqual(['counting']);
    // First request carried only "purpose": allowed before, denied once "ticket" is also required.
    expect(report.newlyDenied.map((flip) => flip.index)).toEqual([0]);
    expect(report.unchanged).toBe(1);
  });

  it('reports which recorded decisions a patch flips, leaving stateful policies out', async () => {
    const guard = buildGuard();
    const events = await observe(guard, [
      ctx({ requestedScopes: ['repo'] }),
      ctx({ requestedScopes: ['gist'] }),
      ctx({ requestedScopes: ['workflow'] }),
      ctx({ targetUrl: 'https://api.github.com/user', targetMethod: 'GET' }),
    ]);
    const base = snapshotGuard(guard);
    const patched = applyPatch(base, [
      { op: 'remove', path: '/scope-filter/allowedScopes/github/2' },
      { op: 'add', path: '/scope-filter/allowedScopes/github/-', value: 'workflow' },
    ]);
    const report = await replayDecisions(base, patched, events, { previous: guard.getPolicies() });
    // The running guard is untouched: gist is still allowed on it.
    expect((await guard.evaluate(ctx({ requestedScopes: ['gist'] }))).allowed).toBe(true);
    expect(report.excludedPolicies).toEqual(['rate-limit']);
    expect(report.events).toBe(4);
    expect(report.unchanged).toBe(2);
    expect(report.newlyDenied.map((flip) => flip.requestedScopes)).toEqual([['gist']]);
    expect(report.newlyAllowed.map((flip) => flip.requestedScopes)).toEqual([['workflow']]);
    expect(report.newlyDenied[0].after.deniedBy).toBe('scope-filter');
  });
});

describe('CredGuard.recentDecisions', () => {
  it('does not alias the caller\'s scopes array', async () => {
    const guard = new CredGuard({ policies: [], decisionHistorySize: 5 });
    const scopes = ['repo'];
    await guard.evaluate(ctx({ requestedScopes: scopes }));
    scopes.push('delete_repo');
    expect(guard.recentDecisions()[0].requestedScopes).toEqual(['repo']);
  });

  it('is off by default and bounded when on', async () => {
    const off = new CredGuard({ policies: [] });
    await off.evaluate(ctx());
    expect(off.recentDecisions()).toEqual([]);
    const on = new CredGuard({ policies: [maxTtlPolicy({ maxTtlSeconds: 1 })], decisionHistorySize: 2 });
    for (let i = 0; i < 5; i += 1) await on.evaluate(ctx({ requestedScopes: [`s${i}`] }));
    expect(on.recentDecisions().map((event) => event.requestedScopes)).toEqual([['s3'], ['s4']]);
  });
});

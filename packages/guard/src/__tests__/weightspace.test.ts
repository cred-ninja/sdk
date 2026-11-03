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
  generateApproverKeyPair,
  signProposal,
  verifyApproval,
  PolicyWeightSpaceEditor,
  PatchError,
  canonicalJson,
} from '../weightspace/index.js';
import type { PolicyEditEvent } from '../weightspace/index.js';

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

  it('refuses to touch opaque values and opaque policies', () => {
    const base = snapshotGuard(buildGuard([{ name: 'custom', evaluate: () => ({ decision: 'ALLOW', policy: 'custom' }) }]));
    expect(() => applyPatch(base, [{ op: 'remove', path: '/url-allowlist/scopeGate/github' }])).toThrow(/opaque/);
    expect(() => applyPatch(base, [{ op: 'add', path: '/custom/anything', value: 1 }])).toThrow(/opaque/);
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

  it('falls back to unknown, which approval rules treat as widening', () => {
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
    expect(codes).toContain('rate-limit-slack:/rate-limit/perProvider/github');

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
    expect(report.excludedPolicies).toEqual(['rate-limit']);
    expect(report.events).toBe(4);
    expect(report.unchanged).toBe(2);
    expect(report.newlyDenied.map((flip) => flip.requestedScopes)).toEqual([['gist']]);
    expect(report.newlyAllowed.map((flip) => flip.requestedScopes)).toEqual([['workflow']]);
    expect(report.newlyDenied[0].after.deniedBy).toBe('scope-filter');
  });
});

describe('approvals', () => {
  it('signs and verifies a proposal hash with Ed25519, and rejects the wrong key', () => {
    const alice = generateApproverKeyPair();
    const mallory = generateApproverKeyPair();
    const proposal = { hash: 'a'.repeat(64) };
    const approval = signProposal(proposal, 'alice', alice.privateKey);
    expect(verifyApproval(proposal, approval, alice.publicKey)).toBe(true);
    expect(verifyApproval(proposal, approval, mallory.publicKey)).toBe(false);
    expect(verifyApproval({ hash: 'b'.repeat(64) }, approval, alice.publicKey)).toBe(false);
    expect(verifyApproval(proposal, { ...approval, signature: 'AAAA' }, alice.publicKey)).toBe(false);
  });
});

describe('PolicyWeightSpaceEditor', () => {
  const alice = generateApproverKeyPair();
  const bob = generateApproverKeyPair();

  function editor(guard: CredGuard, options: ConstructorParameters<typeof PolicyWeightSpaceEditor>[1] = {}) {
    const events: PolicyEditEvent[] = [];
    const instance = new PolicyWeightSpaceEditor(guard, {
      approvers: [{ id: 'alice', publicKey: alice.publicKey }, { id: 'bob', publicKey: bob.publicKey }],
      onEvent: (event) => events.push(event),
      ...options,
    });
    return { editor: instance, events };
  }

  it('proposes with classification, magnitude and a dry run, without changing the guard', async () => {
    const guard = buildGuard();
    await observe(guard, [ctx({ requestedScopes: ['gist'] })]);
    const { editor: e, events } = editor(guard);
    const before = e.snapshot().hash;
    const proposal = await e.propose({
      patch: [{ op: 'remove', path: '/scope-filter/allowedScopes/github/2' }],
      rationale: 'gist is never used',
      proposer: 'did:key:agent',
    });
    expect(proposal.id).toMatch(/^pp_[0-9a-f]{24}$/);
    expect(proposal.baseHash).toBe(before);
    expect(proposal.classification.effect).toBe('narrowing');
    expect(proposal.classification.magnitude.touched).toBe(1);
    expect(proposal.dryRun?.newlyDenied).toHaveLength(1);
    expect(e.snapshot().hash).toBe(before);
    expect(events.map((event) => event.type)).toEqual(['policy.proposed']);
    expect(e.getProposal(proposal.id)?.hash).toBe(proposal.hash);
  });

  it('refuses to apply without a valid approval, and applies with one', async () => {
    const guard = buildGuard();
    const { editor: e, events } = editor(guard);
    const proposal = await e.propose({
      patch: [{ op: 'add', path: '/scope-filter/allowedScopes/github/-', value: 'workflow' }],
      rationale: 'CI needs workflow scope',
      proposer: 'did:key:agent',
    });

    const none = await e.apply(proposal.id);
    expect(none).toMatchObject({ applied: false, code: 'approval_required' });

    const forged = await e.apply(proposal.id, [signProposal(proposal, 'alice', generateApproverKeyPair().privateKey)]);
    expect(forged).toMatchObject({ applied: false, code: 'approval_invalid' });

    const unknownApprover = await e.apply(proposal.id, [signProposal(proposal, 'carol', alice.privateKey)]);
    expect(unknownApprover).toMatchObject({ applied: false, code: 'approval_invalid' });

    const result = await e.apply(proposal.id, [signProposal(proposal, 'alice', alice.privateKey)]);
    expect(result).toMatchObject({ applied: true, approvers: ['alice'], rebuilt: ['scope-filter'], kept: ['rate-limit', 'url-allowlist', 'max-ttl'] });
    const decision = await guard.evaluate(ctx({ requestedScopes: ['workflow'] }));
    expect(decision.allowed).toBe(true);
    expect(e.getProposal(proposal.id)).toBeUndefined();
    expect(e.history()).toHaveLength(1);
    expect(events.map((event) => event.type)).toEqual([
      'policy.proposed', 'policy.rejected', 'policy.rejected', 'policy.rejected', 'policy.applied',
    ]);
    expect(events.at(-1)?.approvers).toEqual(['alice']);
  });

  it('keeps the rate-limit instance and its counters when a patch does not touch it', async () => {
    const guard = buildGuard();
    const { editor: e } = editor(guard);
    await guard.evaluate(ctx());
    await guard.evaluate(ctx());
    const rateLimit = guard.getPolicies()[0] as ReturnType<typeof rateLimitPolicy>;
    expect(rateLimit.getCount('hash-a', 'github')).toBe(2);
    const proposal = await e.propose({ patch: [{ op: 'replace', path: '/max-ttl/maxTtlSeconds', value: 600 }], rationale: 'shorter', proposer: 'ops' });
    const result = await e.apply(proposal.id, [signProposal(proposal, 'bob', bob.privateKey)]);
    expect(result.applied).toBe(true);
    expect(guard.getPolicies()[0]).toBe(rateLimit);
    expect(rateLimit.getCount('hash-a', 'github')).toBe(2);
  });

  it('rejects self-approval, stale bases, expired and tampered proposals', async () => {
    let now = new Date('2026-11-03T12:00:00Z');
    const guard = buildGuard();
    const { editor: e } = editor(guard, { clock: () => now, proposalTtlMs: 1000 });
    const proposal = await e.propose({ patch: [{ op: 'replace', path: '/max-ttl/maxTtlSeconds', value: 600 }], rationale: 'x', proposer: 'alice' });

    expect(await e.apply(proposal.id, [signProposal(proposal, 'alice', alice.privateKey)])).toMatchObject({ applied: false, code: 'self_approval' });

    const tampered = { ...proposal, patch: [{ op: 'replace' as const, path: '/max-ttl/maxTtlSeconds', value: 60_000 }] };
    expect(await e.apply(tampered, [signProposal(proposal, 'bob', bob.privateKey)])).toMatchObject({ applied: false, code: 'proposal_tampered' });

    guard.addPolicy({ name: 'extra', evaluate: () => ({ decision: 'ALLOW', policy: 'extra' }) });
    expect(await e.apply(proposal.id, [signProposal(proposal, 'bob', bob.privateKey)])).toMatchObject({ applied: false, code: 'base_mismatch' });
    guard.removePolicy('extra');

    now = new Date('2026-11-03T12:00:02Z');
    expect(await e.apply(proposal.id, [signProposal(proposal, 'bob', bob.privateKey)])).toMatchObject({ applied: false, code: 'proposal_expired' });
    expect(await e.apply('pp_missing')).toMatchObject({ applied: false, code: 'proposal_not_found' });
  });

  it('cannot apply anything without approvers, and lets narrowing through when configured', async () => {
    const guard = buildGuard();
    const locked = new PolicyWeightSpaceEditor(guard);
    const p1 = await locked.propose({ patch: [{ op: 'replace', path: '/max-ttl/maxTtlSeconds', value: 600 }], rationale: 'x', proposer: 'agent' });
    expect(await locked.apply(p1.id)).toMatchObject({ applied: false, code: 'approval_unavailable' });

    const tightenOnly = new PolicyWeightSpaceEditor(guard, { requireApprovalFor: 'widening' });
    const narrowing = await tightenOnly.propose({ patch: [{ op: 'replace', path: '/max-ttl/maxTtlSeconds', value: 600 }], rationale: 'x', proposer: 'agent' });
    expect(await tightenOnly.apply(narrowing.id)).toMatchObject({ applied: true, approvers: [] });
    const widening = await tightenOnly.propose({ patch: [{ op: 'replace', path: '/max-ttl/maxTtlSeconds', value: 6000 }], rationale: 'x', proposer: 'agent' });
    expect(await tightenOnly.apply(widening.id)).toMatchObject({ applied: false, code: 'approval_unavailable' });
    const unknown = await tightenOnly.propose({ patch: [{ op: 'replace', path: '/scope-filter/allowedScopes', value: { github: ['repo'] } }], rationale: 'x', proposer: 'agent' });
    expect(unknown.classification.effect).toBe('unknown');
    expect(await tightenOnly.apply(unknown.id)).toMatchObject({ applied: false, code: 'approval_unavailable' });
  });

  it('requires minApprovals distinct approvers and rolls back through the same flow', async () => {
    const guard = buildGuard();
    const { editor: e } = editor(guard, { minApprovals: 2 });
    const proposal = await e.propose({ patch: [{ op: 'remove', path: '/scope-filter/allowedScopes/github/2' }], rationale: 'x', proposer: 'agent' });
    const a = signProposal(proposal, 'alice', alice.privateKey);
    const b = signProposal(proposal, 'bob', bob.privateKey);
    expect(await e.apply(proposal.id, [a, a])).toMatchObject({ applied: false, code: 'approval_required' });
    expect(await e.apply(proposal.id, [a, b])).toMatchObject({ applied: true, approvers: ['alice', 'bob'] });
    expect((await guard.evaluate(ctx({ requestedScopes: ['gist'] }))).allowed).toBe(false);

    const rollback = await e.proposeRollback(proposal.id, 'ops');
    expect(rollback.patch).toEqual([{ op: 'add', path: '/scope-filter/allowedScopes/github/-', value: 'gist' }]);
    expect(rollback.classification.effect).toBe('widening');
    const restored = await e.apply(rollback.id, [signProposal(rollback, 'alice', alice.privateKey), signProposal(rollback, 'bob', bob.privateKey)]);
    expect(restored.applied).toBe(true);
    expect((await guard.evaluate(ctx({ requestedScopes: ['gist'] }))).allowed).toBe(true);
  });

  it('refuses a patch whose parameters the policy rejects, before anyone signs', async () => {
    const { editor: e } = editor(buildGuard());
    await expect(e.propose({ patch: [{ op: 'replace', path: '/rate-limit/maxRequests', value: -1 }], rationale: 'x', proposer: 'agent' }))
      .rejects.toThrow(/positive integer/);
    await expect(e.propose({ patch: [{ op: 'add', path: '/url-allowlist/allowedUrls/github/-', value: 'http://api.github.com/' }], rationale: 'x', proposer: 'agent' }))
      .rejects.toThrow(/https/);
    await expect(e.propose({ patch: [{ op: 'add', path: '/mystery', value: { kind: 'mystery', parameters: {} } }], rationale: 'x', proposer: 'agent' }))
      .rejects.toThrow(/no factory/);
  });
});

describe('CredGuard.recentDecisions', () => {
  it('is off by default and bounded when on', async () => {
    const off = new CredGuard({ policies: [] });
    await off.evaluate(ctx());
    expect(off.recentDecisions()).toEqual([]);
    const on = new CredGuard({ policies: [maxTtlPolicy({ maxTtlSeconds: 1 })], decisionHistorySize: 2 });
    for (let i = 0; i < 5; i += 1) await on.evaluate(ctx({ requestedScopes: [`s${i}`] }));
    expect(on.recentDecisions().map((event) => event.requestedScopes)).toEqual([['s3'], ['s4']]);
  });
});

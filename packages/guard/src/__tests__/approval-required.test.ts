import { describe, it, expect, vi } from 'vitest';
import { CredGuard } from '../guard.js';
import { buildAuditEvent } from '../audit.js';
import {
  approvalRequiredPolicy,
  computeApprovalDigest,
  toGuardApproval,
  APPROVAL_REQUIRED_CODE,
} from '../policies/approval-required.js';
import type {
  ApprovalRequiredPolicyConfig,
  CredPolicy,
  GuardApproval,
  GuardContext,
  PolicyResult,
} from '../types.js';

const NOW = '2026-10-21T12:00:00.000Z';
const IN_FIVE_MINUTES = '2026-10-21T12:05:00.000Z';

function makeContext(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'stripe',
    agentTokenHash: 'agent-hash-123',
    requestedScopes: ['payments.write'],
    consentedScopes: ['payments.write'],
    targetUrl: 'https://api.stripe.com/v1/transfers',
    targetMethod: 'POST',
    timestamp: NOW,
    metadata: { newPayee: true, payeeId: 'acct_EXAMPLE_1' },
    ...overrides,
  };
}

const paymentRule: ApprovalRequiredPolicyConfig = {
  match: [{ providers: ['stripe'], methods: ['POST'], metadata: { newPayee: true } }],
  digestMetadataKeys: ['newPayee', 'payeeId'],
  approver: { role: 'finance-approver' },
  reason: 'Payment to a new payee',
};

function makeApproval(ctx: GuardContext, overrides: Partial<GuardApproval> = {}): GuardApproval {
  return {
    approverId: 'user_alice',
    requestDigest: computeApprovalDigest(ctx, { metadataKeys: ['newPayee', 'payeeId'] }),
    expiresAt: IN_FIVE_MINUTES,
    signature: 'EXAMPLE_SIGNATURE',
    ...overrides,
  };
}

const acceptAll = () => true;

function makePolicy(name: string, decision: PolicyResult['decision'], options: Partial<PolicyResult> = {}): CredPolicy {
  return {
    name,
    evaluate: () => ({ decision, policy: name, ...options }),
  };
}

describe('approvalRequiredPolicy', () => {
  describe('configuration', () => {
    it('requires `when` or a non-empty `match`', () => {
      expect(() => approvalRequiredPolicy({})).toThrow(TypeError);
      expect(() => approvalRequiredPolicy({ match: [] })).toThrow(TypeError);
    });

    it('requires resolveSponsor when forbidSelfApproval is set', () => {
      expect(() => approvalRequiredPolicy({ ...paymentRule, forbidSelfApproval: true })).toThrow(/resolveSponsor/);
    });
  });

  describe('matching', () => {
    it('SKIPs requests that match no rule', async () => {
      const policy = approvalRequiredPolicy(paymentRule);

      const result = await policy.evaluate(makeContext({ metadata: { newPayee: false } }));

      expect(result.decision).toBe('SKIP');
    });

    it('SKIPs a matching provider with a non-matching method', async () => {
      const policy = approvalRequiredPolicy(paymentRule);

      const result = await policy.evaluate(makeContext({ targetMethod: 'GET' }));

      expect(result.decision).toBe('SKIP');
    });

    it('matches methods case-insensitively', async () => {
      const policy = approvalRequiredPolicy(paymentRule);

      const result = await policy.evaluate(makeContext({ targetMethod: 'post' }));

      expect(result.decision).toBe('REQUIRE_APPROVAL');
    });

    it('matches any of a list of metadata values', async () => {
      const policy = approvalRequiredPolicy({
        match: [{ methods: ['PUT', 'POST', 'PATCH', 'DELETE'], metadata: { classification: ['secret', 'restricted'] } }],
      });

      const secret = await policy.evaluate(makeContext({ provider: 'google', metadata: { classification: 'secret' } }));
      const internal = await policy.evaluate(makeContext({ provider: 'google', metadata: { classification: 'internal' } }));

      expect(secret.decision).toBe('REQUIRE_APPROVAL');
      expect(internal.decision).toBe('SKIP');
    });

    it('supports a predicate', async () => {
      const policy = approvalRequiredPolicy({ when: (ctx) => ctx.targetUrl?.includes('/admin/') === true });

      const admin = await policy.evaluate(makeContext({ targetUrl: 'https://api.example.com/admin/users' }));
      const other = await policy.evaluate(makeContext({ targetUrl: 'https://api.example.com/users' }));

      expect(admin.decision).toBe('REQUIRE_APPROVAL');
      expect(other.decision).toBe('SKIP');
    });
  });

  describe('without an approval', () => {
    it('returns REQUIRE_APPROVAL with the approval details', async () => {
      const policy = approvalRequiredPolicy({ ...paymentRule, maxApprovalTtlSeconds: 600 });
      const ctx = makeContext();

      const result = await policy.evaluate(ctx);

      expect(result.decision).toBe('REQUIRE_APPROVAL');
      expect(result.code).toBe(APPROVAL_REQUIRED_CODE);
      expect(result.reason).toBe('Payment to a new payee');
      expect(result.approval).toEqual({
        code: 'approval_required',
        policy: 'approval-required',
        reason: 'Payment to a new payee',
        requestDigest: computeApprovalDigest(ctx, { metadataKeys: ['newPayee', 'payeeId'] }),
        approver: { role: 'finance-approver' },
        expiresAt: '2026-10-21T12:10:00.000Z',
      });
    });

    it('uses the configured policy name', async () => {
      const policy = approvalRequiredPolicy({ ...paymentRule, name: 'payments-approval' });

      const result = await policy.evaluate(makeContext());

      expect(policy.name).toBe('payments-approval');
      expect(result.policy).toBe('payments-approval');
      expect(result.approval?.policy).toBe('payments-approval');
    });
  });

  describe('with an approval', () => {
    it('ALLOWs a valid, verified approval for this request', async () => {
      const verifyApproval = vi.fn().mockResolvedValue(true);
      const policy = approvalRequiredPolicy({ ...paymentRule, verifyApproval });
      const ctx = makeContext();
      const approval = makeApproval(ctx);

      const result = await policy.evaluate({ ...ctx, approval });

      expect(result.decision).toBe('ALLOW');
      expect(result.approvedBy).toBe('user_alice');
      expect(verifyApproval).toHaveBeenCalledWith(expect.objectContaining({
        approval,
        requestDigest: approval.requestDigest,
      }));
    });

    it('fails closed when no verifier is configured', async () => {
      const policy = approvalRequiredPolicy(paymentRule);
      const ctx = makeContext();

      const result = await policy.evaluate({ ...ctx, approval: makeApproval(ctx) });

      expect(result.decision).toBe('REQUIRE_APPROVAL');
      expect(result.reason).toMatch(/no approval verifier/);
    });

    it('refuses an approval the verifier rejects', async () => {
      const policy = approvalRequiredPolicy({ ...paymentRule, verifyApproval: () => false });
      const ctx = makeContext();

      const result = await policy.evaluate({ ...ctx, approval: makeApproval(ctx) });

      expect(result.decision).toBe('REQUIRE_APPROVAL');
      expect(result.reason).toMatch(/could not be verified/);
    });

    it('refuses a truthy non-true verifier result', async () => {
      const verifyApproval = (() => 'yes') as unknown as ApprovalRequiredPolicyConfig['verifyApproval'];
      const policy = approvalRequiredPolicy({ ...paymentRule, verifyApproval });
      const ctx = makeContext();

      const result = await policy.evaluate({ ...ctx, approval: makeApproval(ctx) });

      expect(result.decision).toBe('REQUIRE_APPROVAL');
    });

    it('treats a throwing verifier as a refusal, never an error', async () => {
      const policy = approvalRequiredPolicy({
        ...paymentRule,
        verifyApproval: () => {
          throw new Error('kms down');
        },
      });
      const ctx = makeContext();
      const guard = new CredGuard({ policies: [policy], onError: 'allow' });

      const decision = await guard.evaluate({ ...ctx, approval: makeApproval(ctx) });

      expect(decision.allowed).toBe(false);
      expect(decision.approvalRequired?.reason).toMatch(/approval check failed/);
    });

    it('binds the approval to the request digest', async () => {
      const policy = approvalRequiredPolicy({ ...paymentRule, verifyApproval: acceptAll });
      const approved = makeContext();
      const approval = makeApproval(approved);

      const otherPayee = makeContext({ metadata: { newPayee: true, payeeId: 'acct_EXAMPLE_2' } });
      const otherUrl = makeContext({ targetUrl: 'https://api.stripe.com/v1/payouts' });
      const otherAgent = makeContext({ agentTokenHash: 'agent-hash-456' });

      for (const ctx of [otherPayee, otherUrl, otherAgent]) {
        const result = await policy.evaluate({ ...ctx, approval });
        expect(result.decision).toBe('REQUIRE_APPROVAL');
        expect(result.reason).toMatch(/different request/);
      }
    });

    it('refuses an expired approval', async () => {
      const policy = approvalRequiredPolicy({ ...paymentRule, verifyApproval: acceptAll });
      const ctx = makeContext();

      const atExpiry = await policy.evaluate({ ...ctx, approval: makeApproval(ctx, { expiresAt: NOW }) });
      const unparseable = await policy.evaluate({ ...ctx, approval: makeApproval(ctx, { expiresAt: 'tomorrow' }) });

      expect(atExpiry.decision).toBe('REQUIRE_APPROVAL');
      expect(atExpiry.reason).toMatch(/expired/);
      expect(unparseable.decision).toBe('REQUIRE_APPROVAL');
    });

    it('uses the configured clock for expiry', async () => {
      const policy = approvalRequiredPolicy({
        ...paymentRule,
        verifyApproval: acceptAll,
        now: () => new Date('2026-10-21T12:06:00.000Z'),
      });
      const ctx = makeContext();

      const result = await policy.evaluate({ ...ctx, approval: makeApproval(ctx) });

      expect(result.decision).toBe('REQUIRE_APPROVAL');
      expect(result.reason).toMatch(/expired/);
    });

    it('refuses an approval that lives longer than maxApprovalTtlSeconds', async () => {
      const policy = approvalRequiredPolicy({ ...paymentRule, verifyApproval: acceptAll, maxApprovalTtlSeconds: 60 });
      const ctx = makeContext();

      const result = await policy.evaluate({ ...ctx, approval: makeApproval(ctx) });

      expect(result.decision).toBe('REQUIRE_APPROVAL');
      expect(result.reason).toMatch(/allowed lifetime/);
    });

    it('refuses a malformed approval', async () => {
      const policy = approvalRequiredPolicy({ ...paymentRule, verifyApproval: acceptAll });
      const approval = { approverId: 'user_alice' } as unknown as GuardApproval;

      const result = await policy.evaluate({ ...makeContext(), approval });

      expect(result.decision).toBe('REQUIRE_APPROVAL');
      expect(result.reason).toMatch(/malformed/);
    });
  });

  describe('separation of duties', () => {
    const sodConfig: ApprovalRequiredPolicyConfig = {
      ...paymentRule,
      verifyApproval: acceptAll,
      forbidSelfApproval: true,
      resolveSponsor: () => 'user_alice',
    };

    it('refuses an approval by the agent sponsor', async () => {
      const policy = approvalRequiredPolicy(sodConfig);
      const ctx = makeContext();

      const result = await policy.evaluate({ ...ctx, approval: makeApproval(ctx) });

      expect(result.decision).toBe('REQUIRE_APPROVAL');
      expect(result.reason).toMatch(/sponsor/);
    });

    it('accepts an approval by someone other than the sponsor', async () => {
      const policy = approvalRequiredPolicy(sodConfig);
      const ctx = makeContext();

      const result = await policy.evaluate({ ...ctx, approval: makeApproval(ctx, { approverId: 'user_bob' }) });

      expect(result.decision).toBe('ALLOW');
      expect(result.approvedBy).toBe('user_bob');
    });

    it('fails closed when the sponsor cannot be resolved', async () => {
      const policy = approvalRequiredPolicy({ ...sodConfig, resolveSponsor: async () => undefined });
      const ctx = makeContext();

      const result = await policy.evaluate({ ...ctx, approval: makeApproval(ctx, { approverId: 'user_bob' }) });

      expect(result.decision).toBe('REQUIRE_APPROVAL');
      expect(result.reason).toMatch(/sponsor could not be resolved/);
    });
  });
});

describe('computeApprovalDigest', () => {
  it('is stable across metadata key order', () => {
    const a = computeApprovalDigest(makeContext({ metadata: { payeeId: 'p', newPayee: true } }), { metadataKeys: ['newPayee', 'payeeId'] });
    const b = computeApprovalDigest(makeContext({ metadata: { newPayee: true, payeeId: 'p' } }), { metadataKeys: ['payeeId', 'newPayee'] });

    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it('ignores metadata keys that are not bound', () => {
    const a = computeApprovalDigest(makeContext({ metadata: { newPayee: true, note: 'a' } }), { metadataKeys: ['newPayee'] });
    const b = computeApprovalDigest(makeContext({ metadata: { newPayee: true, note: 'b' } }), { metadataKeys: ['newPayee'] });

    expect(a).toBe(b);
  });

  it('changes with method and scopes', () => {
    const base = computeApprovalDigest(makeContext());

    expect(computeApprovalDigest(makeContext({ targetMethod: 'DELETE' }))).not.toBe(base);
    expect(computeApprovalDigest(makeContext({ requestedScopes: ['payments.admin'] }))).not.toBe(base);
  });
});

describe('toGuardApproval', () => {
  it('keeps known fields and drops the rest', () => {
    expect(toGuardApproval({
      approverId: 'user_alice',
      requestDigest: 'abc',
      expiresAt: IN_FIVE_MINUTES,
      signature: 'EXAMPLE_SIGNATURE',
      extra: 'dropped',
    })).toEqual({
      approverId: 'user_alice',
      requestDigest: 'abc',
      expiresAt: IN_FIVE_MINUTES,
      signature: 'EXAMPLE_SIGNATURE',
    });
  });

  it('returns undefined for malformed values', () => {
    expect(toGuardApproval(undefined)).toBeUndefined();
    expect(toGuardApproval('approved')).toBeUndefined();
    expect(toGuardApproval({ approverId: 'user_alice', requestDigest: 'abc' })).toBeUndefined();
    expect(toGuardApproval({ approverId: '', requestDigest: 'abc', expiresAt: IN_FIVE_MINUTES })).toBeUndefined();
  });
});

describe('CredGuard with REQUIRE_APPROVAL', () => {
  it('refuses (fail closed) and surfaces approvalRequired', async () => {
    const guard = new CredGuard({ policies: [approvalRequiredPolicy(paymentRule)] });

    const decision = await guard.evaluate(makeContext());

    expect(decision.allowed).toBe(false);
    expect(decision.approvalRequired?.code).toBe('approval_required');
    expect(decision.approvalRequired?.approver).toEqual({ role: 'finance-approver' });
    expect(decision.deniedBy?.decision).toBe('REQUIRE_APPROVAL');
    expect(decision.deniedBy?.code).toBe('approval_required');
  });

  it('lets DENY win over an earlier REQUIRE_APPROVAL', async () => {
    const guard = new CredGuard({
      policies: [approvalRequiredPolicy(paymentRule), makePolicy('deny-all', 'DENY', { reason: 'blocked' })],
    });

    const decision = await guard.evaluate(makeContext());

    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy?.policy).toBe('deny-all');
    expect(decision.approvalRequired).toBeUndefined();
    expect(decision.results.map((r) => r.decision)).toEqual(['REQUIRE_APPROVAL', 'DENY']);
  });

  it('lets DENY win over a later REQUIRE_APPROVAL', async () => {
    const guard = new CredGuard({
      policies: [makePolicy('deny-all', 'DENY', { reason: 'blocked' }), approvalRequiredPolicy(paymentRule)],
    });

    const decision = await guard.evaluate(makeContext());

    expect(decision.deniedBy?.policy).toBe('deny-all');
    expect(decision.approvalRequired).toBeUndefined();
    expect(decision.results).toHaveLength(1);
  });

  it('allows once a valid approval is presented', async () => {
    const guard = new CredGuard({
      policies: [approvalRequiredPolicy({ ...paymentRule, verifyApproval: acceptAll })],
    });
    const ctx = makeContext();

    const decision = await guard.evaluate({ ...ctx, approval: makeApproval(ctx) });

    expect(decision.allowed).toBe(true);
    expect(decision.approvalRequired).toBeUndefined();
    expect(decision.deniedBy).toBeUndefined();
  });

  it('keeps the first approval requirement when several policies ask', async () => {
    const guard = new CredGuard({
      policies: [
        makePolicy('first', 'REQUIRE_APPROVAL', { reason: 'first reason' }),
        makePolicy('second', 'REQUIRE_APPROVAL', { reason: 'second reason' }),
      ],
    });

    const decision = await guard.evaluate(makeContext());

    expect(decision.approvalRequired?.policy).toBe('first');
    expect(decision.results).toHaveLength(2);
  });

  it('fills in the code, reason and digest for a custom REQUIRE_APPROVAL policy', async () => {
    const guard = new CredGuard({ policies: [makePolicy('custom', 'REQUIRE_APPROVAL')] });
    const ctx = makeContext();

    const decision = await guard.evaluate(ctx);

    expect(decision.approvalRequired).toEqual({
      code: 'approval_required',
      policy: 'custom',
      reason: 'Human approval required',
      requestDigest: computeApprovalDigest(ctx),
    });
    expect(decision.deniedBy?.code).toBe('approval_required');
  });

  it('passes the final decision to onDecision', async () => {
    const onDecision = vi.fn();
    const guard = new CredGuard({ policies: [approvalRequiredPolicy(paymentRule)], onDecision });
    const ctx = makeContext();

    await guard.evaluate(ctx);

    expect(onDecision).toHaveBeenCalledWith(
      ctx,
      [expect.objectContaining({ decision: 'REQUIRE_APPROVAL' })],
      expect.objectContaining({ allowed: false, approvalRequired: expect.any(Object) }),
    );
  });
});

describe('audit events for approval', () => {
  it('records a pending approval', async () => {
    const guard = new CredGuard({ policies: [approvalRequiredPolicy(paymentRule)] });
    const ctx = makeContext();

    const event = buildAuditEvent(ctx, await guard.evaluate(ctx));

    expect(event.allowed).toBe(false);
    expect(event.code).toBe('approval_required');
    expect(event.policies[0]).toMatchObject({ decision: 'REQUIRE_APPROVAL', code: 'approval_required' });
    expect(event.approvalRequired?.requestDigest).toBe(computeApprovalDigest(ctx, { metadataKeys: ['newPayee', 'payeeId'] }));
    expect(event.approvedBy).toBeUndefined();
  });

  it('records the approver of an accepted approval', async () => {
    const guard = new CredGuard({ policies: [approvalRequiredPolicy({ ...paymentRule, verifyApproval: acceptAll })] });
    const ctx = { ...makeContext(), approval: makeApproval(makeContext()) };

    const event = buildAuditEvent(ctx, await guard.evaluate(ctx));

    expect(event.allowed).toBe(true);
    expect(event.approvedBy).toEqual(['user_alice']);
    expect(event.approvalRequired).toBeUndefined();
  });

  it('keeps the previous event shape when no approval is involved', async () => {
    const guard = new CredGuard({ policies: [makePolicy('allow-all', 'ALLOW')] });
    const ctx = makeContext();

    const event = buildAuditEvent(ctx, await guard.evaluate(ctx));

    expect('approvalRequired' in event).toBe(false);
    expect('approvedBy' in event).toBe(false);
  });
});

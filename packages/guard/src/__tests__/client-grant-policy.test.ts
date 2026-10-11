import { describe, it, expect, vi } from 'vitest';
import type { Request, Response } from 'express';
import type { LinkAccessCheckInput, LinkAccessResult, LinkHooks } from '@credninja/protocol';
import { CredGuard } from '../guard.js';
import { buildAuditEvent } from '../audit.js';
import { createExpressMiddleware } from '../middleware/express.js';
import { wrapMcpToolHandler } from '../middleware/mcp.js';
import { clientGrantPolicy, CLIENT_GRANT_POLICY_NAME } from '../link/client-grant-policy.js';
import type { CredPolicy, GuardContext, GuardLinkContext } from '../types.js';
import * as root from '../index.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function baseCtx(overrides: Partial<GuardContext> = {}): GuardContext {
  return {
    provider: 'google',
    agentTokenHash: 'hash',
    requestedScopes: ['calendar.readonly'],
    consentedScopes: ['calendar.readonly'],
    timestamp: '2026-10-11T12:00:00.000Z',
    ...overrides,
  };
}

const LINK: GuardLinkContext = { connectionId: 'conn_abc123', agentId: 'agt_1', operation: 'delegate' };

function okResult(effective: string[]): LinkAccessResult {
  return {
    ok: true,
    effective_scopes: effective,
    connection: { id: 'conn_abc123' } as never,
    grant: { id: 'grt_abc123', version: 7 } as never,
    permission: { id: 'perm_1' } as never,
  };
}

function stubHooks(result: LinkAccessResult | (() => Promise<LinkAccessResult>)) {
  const checkLinkAccess = vi.fn(async (_input: LinkAccessCheckInput) =>
    typeof result === 'function' ? result() : result,
  );
  return { checkLinkAccess } as Pick<LinkHooks, 'checkLinkAccess'> & { checkLinkAccess: typeof checkLinkAccess };
}

const denyPermission: LinkAccessResult = {
  ok: false,
  code: 'permission_required',
  status: 403,
  missing_scopes: ['gmail.send'],
};

function mockRequest(overrides: Record<string, unknown> = {}): Request {
  return {
    params: { provider: 'google' },
    headers: { authorization: 'Bearer test-agent-token' },
    query: {},
    body: { scopes: ['calendar.readonly'] },
    method: 'POST',
    ...overrides,
  } as unknown as Request;
}

function mockResponse(): Response & { _status: number; _json: any } {
  const res = {
    _status: 200,
    _json: null,
    status(code: number) {
      this._status = code;
      return this;
    },
    json(data: any) {
      this._json = data;
      return this;
    },
  };
  return res as unknown as Response & { _status: number; _json: any };
}

function codedDenyPolicy(code = 'grant_revoked'): CredPolicy {
  return {
    name: 'coded-deny',
    evaluate: () => ({ decision: 'DENY', policy: 'coded-deny', reason: 'nope', code }),
  };
}

// ── clientGrantPolicy ────────────────────────────────────────────────────────

describe('clientGrantPolicy', () => {
  it('SKIPs when the context is not a Link call, without calling checkLinkAccess', async () => {
    const hooks = stubHooks(okResult(['calendar.readonly']));
    const policy = clientGrantPolicy({ hooks });
    const result = await policy.evaluate(baseCtx());
    expect(result.decision).toBe('SKIP');
    expect(result.policy).toBe(CLIENT_GRANT_POLICY_NAME);
    expect(hooks.checkLinkAccess).not.toHaveBeenCalled();
  });

  it('ignores Link-looking body metadata: only ctx.link makes a Link call', async () => {
    const hooks = stubHooks(okResult(['calendar.readonly']));
    const policy = clientGrantPolicy({ hooks });
    const result = await policy.evaluate(baseCtx({ metadata: { connection_id: 'conn_abc123', agent_id: 'agt_1' } }));
    expect(result.decision).toBe('SKIP');
  });

  it('maps the context to checkLinkAccess input', async () => {
    const hooks = stubHooks(okResult(['calendar.readonly']));
    const policy = clientGrantPolicy({ hooks });
    await policy.evaluate(baseCtx({
      link: { connectionId: 'conn_abc123', agentId: 'agt_1', operation: 'use', grantId: 'grt_abc123', grantVersion: 7 },
      requestedScopes: ['calendar.readonly', 'gmail.send'],
    }));
    expect(hooks.checkLinkAccess).toHaveBeenCalledWith({
      operation: 'use',
      connection_id: 'conn_abc123',
      agent_id: 'agt_1',
      provider: 'google',
      requested_scopes: ['calendar.readonly', 'gmail.send'],
      grant_id: 'grt_abc123',
      grant_version: 7,
      now: '2026-10-11T12:00:00.000Z',
    });
  });

  it('uses the injected clock', async () => {
    const hooks = stubHooks(okResult(['calendar.readonly']));
    const policy = clientGrantPolicy({ hooks, now: () => new Date('2030-01-01T00:00:00.000Z') });
    await policy.evaluate(baseCtx({ link: LINK }));
    expect(hooks.checkLinkAccess.mock.calls[0][0]).toMatchObject({ operation: 'delegate', now: '2030-01-01T00:00:00.000Z' });
  });

  it.each([
    ['missing', undefined],
    ['unknown', 'refresh'],
    ['wrong case', 'USE'],
  ])('DENYs when operation is %s, without calling checkLinkAccess (no default to delegate)', async (_label, operation) => {
    const hooks = stubHooks(okResult(['calendar.readonly']));
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks })], onError: 'allow' });
    const link = { connectionId: 'conn_abc123', agentId: 'agt_1', operation } as unknown as GuardLinkContext;
    const decision = await guard.evaluate(baseCtx({ link }));
    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy).toMatchObject({ policy: CLIENT_GRANT_POLICY_NAME, code: 'permission_required' });
    expect(hooks.checkLinkAccess).not.toHaveBeenCalled();
  });

  it('DENYs a link context that is not an object', async () => {
    const hooks = stubHooks(okResult(['calendar.readonly']));
    const policy = clientGrantPolicy({ hooks });
    const result = await policy.evaluate(baseCtx({ link: 'conn_abc123' as unknown as GuardLinkContext }));
    expect(result).toMatchObject({ decision: 'DENY', code: 'permission_required' });
  });

  it('ALLOWs and narrows to the effective scopes', async () => {
    const hooks = stubHooks(okResult(['calendar.readonly', 'gmail.send']));
    const policy = clientGrantPolicy({ hooks });
    const result = await policy.evaluate(baseCtx({ link: LINK, requestedScopes: [] }));
    expect(result).toMatchObject({
      decision: 'ALLOW',
      narrowedScopes: ['calendar.readonly', 'gmail.send'],
      grantId: 'grt_abc123',
      grantVersion: 7,
      permissionId: 'perm_1',
    });
    expect(result.code).toBeUndefined();
  });

  it('DENYs with the machine code, status and missing scopes', async () => {
    const policy = clientGrantPolicy({ hooks: stubHooks(denyPermission) });
    const result = await policy.evaluate(baseCtx({ link: LINK }));
    expect(result).toMatchObject({
      decision: 'DENY',
      policy: CLIENT_GRANT_POLICY_NAME,
      code: 'permission_required',
      httpStatus: 403,
      missingScopes: ['gmail.send'],
    });
    expect(typeof result.reason).toBe('string');
  });

  it('DENYs (never throws) when checkLinkAccess throws, even with onError: allow', async () => {
    const hooks = stubHooks(() => Promise.reject(new Error('store down')));
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks })], onError: 'allow' });
    const decision = await guard.evaluate(baseCtx({ link: LINK }));
    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy?.code).toBe('permission_required');
  });

  // Regression (review): an ok:true result missing its fields used to throw
  // out of evaluate, and a Guard with onError 'allow' turned that into ALLOW
  // with the request's own scopes.
  it('DENYs (not ALLOW) an ok:true result with missing fields, even with onError: allow', async () => {
    const hooks = { checkLinkAccess: async () => ({ ok: true }) } as unknown as Pick<LinkHooks, 'checkLinkAccess'>;
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks })], onError: 'allow' });
    const decision = await guard.evaluate(baseCtx({ link: LINK, requestedScopes: ['gmail.send'] }));
    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy).toMatchObject({ policy: CLIENT_GRANT_POLICY_NAME, decision: 'DENY', code: 'permission_required' });
    expect(decision.results[0].reason).not.toMatch(/Policy error/);
  });

  const good = okResult(['calendar.readonly']) as unknown as Record<string, unknown>;
  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a string', 'ok'],
    ['ok missing', { effective_scopes: ['x'] }],
    ['ok: "true" as a string', { ...good, ok: 'true' }],
    ['effective_scopes not an array', { ...good, effective_scopes: 'calendar.readonly' }],
    ['effective_scopes with a non-string', { ...good, effective_scopes: ['calendar.readonly', 3] }],
    ['effective_scopes empty', { ...good, effective_scopes: [] }],
    ['connection missing', { ...good, connection: undefined }],
    ['grant missing', { ...good, grant: null }],
    ['grant version missing', { ...good, grant: { id: 'grt_abc123' } }],
    ['permission missing', { ...good, permission: undefined }],
    ['permission id not a string', { ...good, permission: { id: 9 } }],
    ['deny with an unknown code', { ok: false, code: 'nope', status: 200 }],
    ['deny without a code', { ok: false }],
    ['a getter that throws', Object.defineProperty({ ...good }, 'effective_scopes', { get() { throw new Error('x'); } })],
  ])('DENYs a malformed result (%s), even with onError: allow', async (_label, value) => {
    const hooks = { checkLinkAccess: async () => value } as unknown as Pick<LinkHooks, 'checkLinkAccess'>;
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks })], onError: 'allow' });
    const decision = await guard.evaluate(baseCtx({ link: LINK }));
    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy?.code).toBe('permission_required');
  });

  it('a deny result keeps its own code, with httpStatus from the protocol table', async () => {
    const hooks = stubHooks({ ok: false, code: 'grant_revoked', status: 999 });
    const result = await clientGrantPolicy({ hooks }).evaluate(baseCtx({ link: LINK }));
    expect(result).toMatchObject({ decision: 'DENY', code: 'grant_revoked', httpStatus: 403 });
  });

  it('rejects a config without hooks', () => {
    expect(() => clientGrantPolicy({} as never)).toThrow(TypeError);
  });

  it('is exported from the package root', () => {
    expect(root.clientGrantPolicy).toBe(clientGrantPolicy);
    expect(typeof root.createLinkHooks).toBe('function');
  });
});

// ── PolicyResult.code through CredGuard and the audit event ──────────────────

describe('PolicyResult.code propagation', () => {
  it('CredGuard.deniedBy carries the code', async () => {
    const guard = new CredGuard({ policies: [codedDenyPolicy('grant_revoked')] });
    const decision = await guard.evaluate(baseCtx());
    expect(decision.deniedBy?.code).toBe('grant_revoked');
  });

  it('clientGrantPolicy runs first and its narrowing reaches later policies', async () => {
    const seen: string[][] = [];
    const later: CredPolicy = {
      name: 'later',
      evaluate: (ctx) => {
        seen.push(ctx.requestedScopes);
        return { decision: 'ALLOW', policy: 'later' };
      },
    };
    const guard = new CredGuard({
      policies: [clientGrantPolicy({ hooks: stubHooks(okResult(['calendar.readonly'])) }), later],
    });
    const decision = await guard.evaluate(baseCtx({ link: LINK, requestedScopes: [] }));
    expect(decision.allowed).toBe(true);
    expect(decision.effectiveScopes).toEqual(['calendar.readonly']);
    expect(seen).toEqual([['calendar.readonly']]);
  });

  it('a Link deny short-circuits the rest of the chain', async () => {
    const later = { name: 'later', evaluate: vi.fn(() => ({ decision: 'ALLOW' as const, policy: 'later' })) };
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks: stubHooks(denyPermission) }), later] });
    const decision = await guard.evaluate(baseCtx({ link: LINK }));
    expect(decision.allowed).toBe(false);
    expect(decision.deniedBy?.code).toBe('permission_required');
    expect(later.evaluate).not.toHaveBeenCalled();
  });

  it('the audit event carries per-policy code, the top-level code and the link context', async () => {
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks: stubHooks(denyPermission) })] });
    const ctx = baseCtx({ link: LINK });
    const event = buildAuditEvent(ctx, await guard.evaluate(ctx));
    expect(event.code).toBe('permission_required');
    expect(event.policies[0].code).toBe('permission_required');
    expect(event.link).toEqual(LINK);
  });

  it('audit events without codes keep their previous shape', async () => {
    const guard = new CredGuard({ policies: [{ name: 'a', evaluate: () => ({ decision: 'ALLOW', policy: 'a' }) }] });
    const ctx = baseCtx();
    const event = buildAuditEvent(ctx, await guard.evaluate(ctx));
    expect('code' in event).toBe(false);
    expect('link' in event).toBe(false);
    expect('code' in event.policies[0]).toBe(false);
  });
});

// ── Express middleware ───────────────────────────────────────────────────────

describe('Express middleware with Link context and codes', () => {
  it('default deny response includes the code; existing fields keep their names', async () => {
    const guard = new CredGuard({ policies: [codedDenyPolicy('grant_expired')] });
    const res = mockResponse();
    await createExpressMiddleware(guard)(mockRequest(), res, vi.fn());
    expect(res._status).toBe(403);
    expect(res._json).toMatchObject({
      error: 'Request denied by policy',
      policy: 'coded-deny',
      reason: 'nope',
      code: 'grant_expired',
    });
  });

  it('default deny response has no code key when the policy set none', async () => {
    const guard = new CredGuard({
      policies: [{ name: 'plain', evaluate: () => ({ decision: 'DENY', policy: 'plain', reason: 'x' }) }],
    });
    const res = mockResponse();
    await createExpressMiddleware(guard)(mockRequest(), res, vi.fn());
    expect(res._status).toBe(403);
    expect('code' in res._json).toBe(false);
  });

  it('takes the Link context from resolveLinkContext (verified state), never from the body', async () => {
    const hooks = stubHooks(denyPermission);
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks })] });
    const req = mockRequest({
      body: { scopes: ['calendar.readonly'], connection_id: 'conn_abc123', agent_id: 'agt_spoofed', link: { agentId: 'agt_spoofed' } },
      agentPrincipal: { type: 'custom-verifier', principalId: 'agt_verified' },
    });
    const middleware = createExpressMiddleware(guard, {
      resolveLinkContext: (r) => ({
        operation: 'delegate',
        connectionId: (r.body as { connection_id: string }).connection_id,
        agentId: ((r as unknown as { agentPrincipal: { principalId: string } }).agentPrincipal).principalId,
      }),
    });
    const res = mockResponse();
    await middleware(req, res, vi.fn());
    expect(hooks.checkLinkAccess.mock.calls[0][0]).toMatchObject({ connection_id: 'conn_abc123', agent_id: 'agt_verified' });
    expect(res._json.code).toBe('permission_required');
    expect((req as unknown as { guardContext: GuardContext }).guardContext.link).toEqual({
      operation: 'delegate',
      connectionId: 'conn_abc123',
      agentId: 'agt_verified',
    });
  });

  it('without resolveLinkContext, body fields never make a Link call', async () => {
    const hooks = stubHooks(denyPermission);
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks })] });
    const req = mockRequest({ body: { scopes: ['calendar.readonly'], connection_id: 'conn_abc123', agent_id: 'agt_1', link: LINK } });
    const next = vi.fn();
    await createExpressMiddleware(guard)(req, mockResponse(), next);
    expect(hooks.checkLinkAccess).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
    expect((req as unknown as { guardContext: GuardContext }).guardContext.link).toBeUndefined();
  });

  it('on allow, req.body.scopes becomes the effective scopes', async () => {
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks: stubHooks(okResult(['calendar.readonly', 'gmail.send'])) })] });
    const req = mockRequest({ body: { scopes: [] } });
    const next = vi.fn();
    await createExpressMiddleware(guard, { resolveLinkContext: () => LINK })(req, mockResponse(), next);
    expect(next).toHaveBeenCalled();
    expect(req.body.scopes).toEqual(['calendar.readonly', 'gmail.send']);
  });

  it('a throwing resolveLinkContext fails closed', async () => {
    const guard = new CredGuard({ policies: [] });
    const res = mockResponse();
    const next = vi.fn();
    await createExpressMiddleware(guard, {
      resolveLinkContext: () => {
        throw new Error('no principal');
      },
    })(mockRequest(), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res._status).toBe(500);
  });
});

// ── MCP wrapper ──────────────────────────────────────────────────────────────

describe('MCP wrapper with Link context and codes', () => {
  const handler = vi.fn(async () => ({ content: [{ type: 'text', text: 'ok' }] }));

  it('default deny carries the code in text and structuredContent', async () => {
    const guard = new CredGuard({ policies: [codedDenyPolicy('reauth_required')] });
    const result = await wrapMcpToolHandler(guard, handler)({ provider: 'google' }, { agentToken: 't' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Code: reauth_required');
    expect(result.structuredContent).toEqual({
      error: 'policy_denied',
      code: 'reauth_required',
      policy: 'coded-deny',
      reason: 'nope',
    });
  });

  it('default deny without a code is unchanged', async () => {
    const guard = new CredGuard({
      policies: [{ name: 'plain', evaluate: () => ({ decision: 'DENY', policy: 'plain', reason: 'x' }) }],
    });
    const result = await wrapMcpToolHandler(guard, handler)({ provider: 'google' }, { agentToken: 't' });
    expect(result.content[0].text).toBe('Request denied by policy: plain. Reason: x');
    expect(result.structuredContent).toBeUndefined();
  });

  it('takes the Link context from resolveLinkContext only', async () => {
    const hooks = stubHooks(denyPermission);
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks })] });
    const wrapped = wrapMcpToolHandler(guard, handler, {
      resolveLinkContext: (_input, ctx) => ({ operation: 'delegate', connectionId: 'conn_abc123', agentId: ctx.verifiedAgentId as string }),
    });
    const result = await wrapped(
      { provider: 'google', scopes: ['calendar.readonly'], metadata: { agentId: 'agt_spoofed' } },
      { agentToken: 't', verifiedAgentId: 'agt_verified' },
    );
    expect(hooks.checkLinkAccess.mock.calls[0][0]).toMatchObject({ agent_id: 'agt_verified' });
    expect(result.structuredContent).toMatchObject({ code: 'permission_required' });
  });

  it('without resolveLinkContext the Link policy SKIPs', async () => {
    const hooks = stubHooks(denyPermission);
    const guard = new CredGuard({ policies: [clientGrantPolicy({ hooks })] });
    const result = await wrapMcpToolHandler(guard, handler)({ provider: 'google', scopes: ['x'] }, { agentToken: 't' });
    expect(result.isError).toBeUndefined();
    expect(hooks.checkLinkAccess).not.toHaveBeenCalled();
  });
});

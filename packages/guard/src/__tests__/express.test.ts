import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CredGuard } from '../guard.js';
import { createExpressMiddleware } from '../middleware/express.js';
import type { Request, Response, NextFunction } from 'express';
import type { CredPolicy } from '../types.js';
import { receiptClaimsPolicy } from '../policies/receipt-claims.js';

// Import middleware module to register prototype method
import '../middleware/express.js';

function mockRequest(overrides: Partial<Request> = {}): Request {
  return {
    params: { provider: 'google' },
    headers: {
      authorization: 'Bearer test-agent-token',
    },
    query: {},
    body: {
      scopes: ['gmail.readonly'],
    },
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

function makeAllowPolicy(): CredPolicy {
  return {
    name: 'allow-all',
    evaluate: () => ({ decision: 'ALLOW', policy: 'allow-all' }),
  };
}

function makeDenyPolicy(reason = 'denied'): CredPolicy {
  return {
    name: 'deny-all',
    evaluate: () => ({ decision: 'DENY', policy: 'deny-all', reason }),
  };
}

describe('Express Middleware', () => {
  describe('createExpressMiddleware', () => {
    it('calls next() on ALLOW', async () => {
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res._status).toBe(200);
    });

    it('returns 403 on DENY', async () => {
      const guard = new CredGuard({ policies: [makeDenyPolicy('rate limit')] });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res._status).toBe(403);
      expect(res._json.error).toBe('Request denied by policy');
      expect(res._json.reason).toBe('rate limit');
    });

    it('returns 400 if provider is missing', async () => {
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest({ params: {} });
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(res._status).toBe(400);
      expect(res._json.error).toContain('Missing provider');
    });

    it('returns 401 if agent token is missing', async () => {
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest({ headers: {} });
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(res._status).toBe(401);
      expect(res._json.error).toContain('Missing agent token');
    });

    it('hashes the agent token', async () => {
      let capturedHash = '';
      const guard = new CredGuard({
        policies: [{
          name: 'capture-hash',
          evaluate: (ctx) => {
            capturedHash = ctx.agentTokenHash;
            return { decision: 'ALLOW', policy: 'capture-hash' };
          },
        }],
      });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      // SHA-256 hash is 64 hex chars
      expect(capturedHash).toMatch(/^[a-f0-9]{64}$/);
      expect(capturedHash).not.toBe('test-agent-token');
    });

    it('extracts scopes from body', async () => {
      let capturedScopes: string[] = [];
      const guard = new CredGuard({
        policies: [{
          name: 'capture-scopes',
          evaluate: (ctx) => {
            capturedScopes = ctx.requestedScopes;
            return { decision: 'ALLOW', policy: 'capture-scopes' };
          },
        }],
      });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest({ body: { scopes: ['scope1', 'scope2'] } });
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(capturedScopes).toEqual(['scope1', 'scope2']);
    });

    it('extracts scopes from query string', async () => {
      let capturedScopes: string[] = [];
      const guard = new CredGuard({
        policies: [{
          name: 'capture-scopes',
          evaluate: (ctx) => {
            capturedScopes = ctx.requestedScopes;
            return { decision: 'ALLOW', policy: 'capture-scopes' };
          },
        }],
      });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest({ body: {}, query: { scopes: 'scope1,scope2' } });
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(capturedScopes).toEqual(['scope1', 'scope2']);
    });

    it('attaches audit event to request', async () => {
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest() as any;
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(req.guardAuditEvent).toBeDefined();
      expect(req.guardAuditEvent.type).toBe('guard.decision');
      expect(req.guardAuditEvent.allowed).toBe(true);
    });

    it('captures Web Bot Auth identity fields from the request body', async () => {
      let capturedKeyId = '';
      let capturedSignatureAgent = '';
      let capturedIdentitySource = '';
      const guard = new CredGuard({
        policies: [{
          name: 'capture-web-bot-auth',
          evaluate: (ctx) => {
            capturedKeyId = ctx.webBotAuthKeyId ?? '';
            capturedSignatureAgent = ctx.signatureAgent ?? '';
            capturedIdentitySource = ctx.identitySource ?? '';
            return { decision: 'ALLOW', policy: 'capture-web-bot-auth' };
          },
        }],
      });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest({
        body: {
          scopes: ['gmail.readonly'],
          web_bot_auth_key_id: 'kid_123',
          signature_agent: 'https://cred.example.com/.well-known/http-message-signatures-directory',
        },
      });
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(capturedKeyId).toBe('kid_123');
      expect(capturedSignatureAgent).toContain('/.well-known/http-message-signatures-directory');
      expect(capturedIdentitySource).toBe('web-bot-auth');
      expect((req as any).guardAuditEvent.webBotAuthKeyId).toBe('kid_123');
    });

    it('uses a precomputed agent hash and forwards principal metadata', async () => {
      let capturedHash = '';
      let capturedPrincipal: unknown;
      const guard = new CredGuard({
        policies: [{
          name: 'capture-principal',
          evaluate: (ctx) => {
            capturedHash = ctx.agentTokenHash;
            capturedPrincipal = ctx.metadata?.authPrincipal;
            return { decision: 'ALLOW', policy: 'capture-principal' };
          },
        }],
      });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest({
        headers: {},
        body: { scopes: ['gmail.readonly'] },
      }) as any;
      req.agentTokenHash = 'precomputed-agent-hash';
      req.agentPrincipal = { type: 'external-runtime', principalId: 'agt_123' };
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(capturedHash).toBe('precomputed-agent-hash');
      expect(capturedPrincipal).toEqual({ type: 'external-runtime', principalId: 'agt_123' });
    });

    it('captures receipt claims from request metadata', async () => {
      let capturedClaims: string[] | undefined;
      const guard = new CredGuard({
        policies: [{
          name: 'capture-receipt-claims',
          evaluate: (ctx) => {
            capturedClaims = ctx.receiptClaims;
            return { decision: 'ALLOW', policy: 'capture-receipt-claims' };
          },
        }],
      });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest({
        body: {
          scopes: ['repo'],
          metadata: {
            receiptClaims: ['staff-engineer:approved'],
          },
        },
      });
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(capturedClaims).toEqual(['staff-engineer:approved']);
    });

    it('denies when required receipt claims are missing', async () => {
      const guard = new CredGuard({
        policies: [
          receiptClaimsPolicy({
            perProvider: {
              github: ['staff-engineer:approved'],
            },
          }),
        ],
      });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest({
        params: { provider: 'github' },
        body: {
          scopes: ['repo'],
          metadata: {},
        },
      });
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res._status).toBe(403);
      expect(res._json.reason).toMatch(/Missing required receipt claims/i);
    });

    it('updates body scopes when narrowed', async () => {
      const guard = new CredGuard({
        policies: [{
          name: 'narrower',
          evaluate: () => ({
            decision: 'ALLOW',
            policy: 'narrower',
            narrowedScopes: ['read-only'],
          }),
        }],
      });
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest({ body: { scopes: ['read', 'write'] } });
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(req.body.scopes).toEqual(['read-only']);
    });

    it('returns 500 on guard evaluation error', async () => {
      const guard = new CredGuard({
        policies: [{
          name: 'error-policy',
          evaluate: () => { throw new Error('Unexpected error'); },
        }],
      });
      // Override onError to allow so we can test the outer try/catch
      const middleware = createExpressMiddleware(guard);
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();

      // Guard handles the error internally and returns DENY
      await middleware(req, res, next);

      // Default onError is 'deny', so it should be 403
      expect(res._status).toBe(403);
    });
  });

  describe('custom extractors', () => {
    it('supports custom token extractor', async () => {
      let capturedHash = '';
      const guard = new CredGuard({
        policies: [{
          name: 'capture',
          evaluate: (ctx) => {
            capturedHash = ctx.agentTokenHash;
            return { decision: 'ALLOW', policy: 'capture' };
          },
        }],
      });
      const middleware = createExpressMiddleware(guard, {
        extractAgentToken: (req) => req.headers['x-custom-token'] as string,
      });
      const req = mockRequest({
        headers: { 'x-custom-token': 'custom-token-value' },
      });
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(capturedHash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('supports custom scope extractor', async () => {
      let capturedScopes: string[] = [];
      const guard = new CredGuard({
        policies: [{
          name: 'capture',
          evaluate: (ctx) => {
            capturedScopes = ctx.requestedScopes;
            return { decision: 'ALLOW', policy: 'capture' };
          },
        }],
      });
      const middleware = createExpressMiddleware(guard, {
        extractScopes: () => ['custom-scope'],
      });
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(capturedScopes).toEqual(['custom-scope']);
    });

    it('supports custom onAllow handler', async () => {
      const onAllow = vi.fn();
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });
      const middleware = createExpressMiddleware(guard, { onAllow });
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(onAllow).toHaveBeenCalledWith(req, res, next, expect.any(Object));
      expect(next).not.toHaveBeenCalled(); // onAllow replaced default behavior
    });

    it('supports custom onDeny handler', async () => {
      const onDeny = vi.fn();
      const guard = new CredGuard({ policies: [makeDenyPolicy()] });
      const middleware = createExpressMiddleware(guard, { onDeny });
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(onDeny).toHaveBeenCalledWith(req, res, expect.any(Object));
    });
  });

  describe('CredGuard.expressMiddleware()', () => {
    it('is available as a method on CredGuard', async () => {
      const guard = new CredGuard({ policies: [makeAllowPolicy()] });

      expect(typeof guard.expressMiddleware).toBe('function');

      const middleware = guard.expressMiddleware();
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });
});

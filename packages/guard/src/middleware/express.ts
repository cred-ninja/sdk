/**
 * @credninja/guard — Express Middleware Adapter
 *
 * Wraps /api/token/:provider routes with guard policy evaluation.
 */

import { createHash } from 'node:crypto';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { CredGuard } from '../guard.js';
import type { GuardContext, GuardDecision } from '../types.js';
import { buildAuditEvent } from '../audit.js';

/** Options for express middleware */
export interface ExpressMiddlewareOptions {
  /**
   * Extract agent token from request.
   * Default: looks for Authorization header Bearer token.
   */
  extractAgentToken?: (req: Request) => string | undefined;

  /**
   * Extract requested scopes from request.
   * Default: looks for `scopes` in query or body.
   */
  extractScopes?: (req: Request) => string[];

  /**
   * Extract consented scopes.
   * Default: same as requested (assume pre-validated).
   */
  extractConsentedScopes?: (req: Request) => string[];

  /**
   * Called when guard allows the request.
   * Default: calls next().
   */
  onAllow?: (req: Request, res: Response, next: NextFunction, decision: GuardDecision) => void;

  /**
   * Called when guard denies the request.
   * Default: sends 403 with JSON error.
   */
  onDeny?: (req: Request, res: Response, decision: GuardDecision) => void;
}

/**
 * Create express middleware for guard policy evaluation.
 * Wraps /api/token/:provider style routes.
 */
export function createExpressMiddleware(
  guard: CredGuard,
  options: ExpressMiddlewareOptions = {}
): RequestHandler {
  const {
    extractAgentToken = defaultExtractAgentToken,
    extractScopes = defaultExtractScopes,
    extractConsentedScopes = defaultExtractConsentedScopes,
    onAllow = defaultOnAllow,
    onDeny = defaultOnDeny,
  } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Extract provider from route params
      const provider = req.params.provider;
      if (!provider) {
        res.status(400).json({ error: 'Missing provider parameter' });
        return;
      }

      // Extract agent token and hash it
      const agentToken = extractAgentToken(req);
      if (!agentToken) {
        res.status(401).json({ error: 'Missing agent token' });
        return;
      }
      const agentTokenHash = hashToken(agentToken);

      // Build guard context
      const requestedScopes = extractScopes(req);
      const consentedScopes = extractConsentedScopes(req) || requestedScopes;

      const ctx: GuardContext = {
        provider,
        agentTokenHash,
        requestedScopes,
        consentedScopes,
        timestamp: new Date().toISOString(),
        targetUrl: req.body?.targetUrl,
        targetMethod: req.body?.targetMethod || req.method,
        delegationId: req.body?.delegationId,
        metadata: req.body?.metadata,
      };

      // Evaluate policies
      const decision = await guard.evaluate(ctx);

      // Attach audit event to request for downstream use
      const auditEvent = buildAuditEvent(ctx, decision);
      (req as any).guardAuditEvent = auditEvent;
      (req as any).guardDecision = decision;
      (req as any).guardContext = ctx;

      if (decision.allowed) {
        // Update scopes if narrowed
        if (req.body && decision.effectiveScopes) {
          req.body.scopes = decision.effectiveScopes;
        }
        onAllow(req, res, next, decision);
      } else {
        onDeny(req, res, decision);
      }
    } catch (error) {
      // Fail-closed: deny on errors
      const message = error instanceof Error ? error.message : String(error);
      res.status(500).json({
        error: 'Guard evaluation failed',
        message,
      });
    }
  };
}

function defaultExtractAgentToken(req: Request): string | undefined {
  const auth = req.headers.authorization;
  if (auth?.startsWith('Bearer ')) {
    return auth.slice(7);
  }
  return req.query.token as string | undefined;
}

function defaultExtractScopes(req: Request): string[] {
  // Check body first, then query
  const scopes = req.body?.scopes || req.query.scopes;
  if (Array.isArray(scopes)) {
    return scopes;
  }
  if (typeof scopes === 'string') {
    return scopes.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return [];
}

function defaultExtractConsentedScopes(req: Request): string[] {
  // In practice, consented scopes come from the stored delegation
  // For middleware, we default to requested scopes
  return defaultExtractScopes(req);
}

function defaultOnAllow(
  _req: Request,
  _res: Response,
  next: NextFunction,
  _decision: GuardDecision
): void {
  next();
}

function defaultOnDeny(req: Request, res: Response, decision: GuardDecision): void {
  res.status(403).json({
    error: 'Request denied by policy',
    policy: decision.deniedBy?.policy,
    reason: decision.deniedBy?.reason,
    requestId: (req as any).id,
  });
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Extend Express middleware to CredGuard class.
 */
declare module '../guard.js' {
  interface CredGuard {
    expressMiddleware(options?: ExpressMiddlewareOptions): RequestHandler;
  }
}

// Add method to prototype
CredGuard.prototype.expressMiddleware = function (
  this: CredGuard,
  options?: ExpressMiddlewareOptions
): RequestHandler {
  return createExpressMiddleware(this, options);
};

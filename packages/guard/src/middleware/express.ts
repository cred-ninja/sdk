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
      const agentTokenHash = resolveAgentTokenHash(req, extractAgentToken);
      if (!agentTokenHash) {
        res.status(401).json({ error: 'Missing agent token' });
        return;
      }

      // Build guard context
      const requestedScopes = extractScopes(req);
      const consentedScopes = extractConsentedScopes(req) || requestedScopes;

      const principal = (req as any).agentPrincipal;
      const ctx: GuardContext = {
        provider,
        agentTokenHash,
        requestedScopes,
        consentedScopes,
        timestamp: new Date().toISOString(),
        targetUrl: req.body?.targetUrl,
        targetMethod: req.body?.targetMethod || req.method,
        delegationId: req.body?.delegationId,
        metadata: mergeMetadata(req.body?.metadata, principal),
        identitySource: inferIdentitySource(req.body),
        agentDid: typeof req.body?.agent_did === 'string' ? req.body.agent_did : undefined,
        tofuFingerprint: typeof req.body?.tofu_fingerprint === 'string' ? req.body.tofu_fingerprint : undefined,
        webBotAuthKeyId: typeof req.body?.web_bot_auth_key_id === 'string'
          ? req.body.web_bot_auth_key_id
          : (typeof req.body?.key_id === 'string' ? req.body.key_id : undefined),
        signatureAgent: typeof req.body?.signature_agent === 'string' ? req.body.signature_agent : undefined,
        receiptClaims: resolveReceiptClaims(req.body, principal),
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

function resolveAgentTokenHash(
  req: Request,
  extractAgentToken: (req: Request) => string | undefined,
): string | undefined {
  const precomputed = (req as any).agentTokenHash;
  if (typeof precomputed === 'string' && precomputed.length > 0) {
    return precomputed;
  }

  const agentToken = extractAgentToken(req);
  if (!agentToken) {
    return undefined;
  }
  return hashToken(agentToken);
}

function mergeMetadata(
  metadata: Record<string, unknown> | undefined,
  principal: unknown,
): Record<string, unknown> | undefined {
  if (!principal || typeof principal !== 'object') {
    return metadata;
  }
  return {
    ...(metadata ?? {}),
    authPrincipal: principal as Record<string, unknown>,
  };
}

function inferIdentitySource(body: Record<string, unknown> | undefined): GuardContext['identitySource'] {
  if (!body) return 'agent-token';
  if (typeof body.web_bot_auth_key_id === 'string' || typeof body.signature_agent === 'string') {
    return 'web-bot-auth';
  }
  if (typeof body.tofu_fingerprint === 'string') {
    return 'tofu';
  }
  if (typeof body.agent_did === 'string') {
    return 'did';
  }
  return 'agent-token';
}

function resolveReceiptClaims(
  body: Record<string, unknown> | undefined,
  principal: unknown,
): string[] | undefined {
  const principalClaims = getClaimsFromPrincipal(principal);
  if (principalClaims) {
    return principalClaims;
  }
  if (!body) return undefined;
  const direct = body.receipt_claims;
  if (Array.isArray(direct)) {
    const claims = direct.filter((value): value is string => typeof value === 'string' && value.trim().length > 0);
    return claims.length > 0 ? claims : undefined;
  }
  const metadataClaims = body.metadata;
  if (metadataClaims && typeof metadataClaims === 'object' && Array.isArray((metadataClaims as Record<string, unknown>).receiptClaims)) {
    const claims = ((metadataClaims as Record<string, unknown>).receiptClaims as unknown[])
      .filter((value): value is string => typeof value === 'string' && value.trim().length > 0);
    return claims.length > 0 ? claims : undefined;
  }
  return undefined;
}

function getClaimsFromPrincipal(principal: unknown): string[] | undefined {
  if (!principal || typeof principal !== 'object') {
    return undefined;
  }
  const metadata = (principal as Record<string, unknown>).metadata;
  if (!metadata || typeof metadata !== 'object') {
    return undefined;
  }
  const claims = (metadata as Record<string, unknown>).receiptClaims;
  if (!Array.isArray(claims)) {
    return undefined;
  }
  const normalized = claims.filter((value): value is string => typeof value === 'string' && value.trim().length > 0);
  return normalized.length > 0 ? normalized : undefined;
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

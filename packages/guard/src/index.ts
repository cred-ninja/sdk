/**
 * @credninja/guard — Policy engine for credential delegation guardrails
 *
 * Composable middleware for rate limiting, scope filtering, time windows,
 * URL allowlisting, and custom policies. Works with @credninja/server,
 * MCP tools, and any Express app.
 *
 * @example
 * ```ts
 * import { CredGuard, rateLimitPolicy, scopeFilterPolicy } from '@credninja/guard';
 *
 * const guard = new CredGuard({
 *   policies: [
 *     rateLimitPolicy({ maxRequests: 10, windowMs: 60_000 }),
 *     scopeFilterPolicy({
 *       allowedScopes: {
 *         google: ['gmail.readonly', 'calendar.readonly'],
 *         github: ['repo', 'read:user'],
 *       },
 *     }),
 *   ],
 * });
 *
 * // Express middleware
 * app.use('/api/token', guard.expressMiddleware());
 *
 * // MCP tool wrapper
 * const guardedHandler = guard.wrapMcpTool(handleUse);
 * ```
 */

// Core
export { CredGuard } from './guard.js';

// Types
export type {
  GuardContext,
  PolicyResult,
  CredPolicy,
  GuardConfig,
  GuardDecision,
  GuardAuditEvent,
  RateLimitPolicyConfig,
  ScopeFilterPolicyConfig,
  TimeWindowPolicyConfig,
  UrlAllowlistPolicyConfig,
  MaxTtlPolicyConfig,
  WebBotAuthPolicyConfig,
} from './types.js';

// Policies
export {
  RateLimitPolicy,
  rateLimitPolicy,
  ScopeFilterPolicy,
  scopeFilterPolicy,
  TimeWindowPolicy,
  timeWindowPolicy,
  UrlAllowlistPolicy,
  urlAllowlistPolicy,
  MaxTtlPolicy,
  maxTtlPolicy,
  webBotAuthPolicy,
} from './policies/index.js';
export type { MaxTtlPolicyResult } from './policies/index.js';

// Audit
export { buildAuditEvent, formatAuditLog } from './audit.js';

// Middleware (imports add methods to CredGuard prototype)
import './middleware/express.js';
import './middleware/mcp.js';

export type { ExpressMiddlewareOptions } from './middleware/express.js';
export { createExpressMiddleware } from './middleware/express.js';
export type { CallToolResult, McpToolContext, CredToolInput, McpWrapperOptions } from './middleware/mcp.js';
export { wrapMcpToolHandler } from './middleware/mcp.js';

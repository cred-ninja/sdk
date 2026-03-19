# @credninja/guard

Policy engine for credential delegation guardrails. Add rate limiting, scope filtering, time windows, URL allowlisting, and custom policies to control how AI agents access delegated credentials. Works as middleware for `@credninja/server`, MCP tools, or any Express app.

## Install

```bash
npm install @credninja/guard
```

## Quick Start

### Server Middleware

```typescript
import { createServer } from '@credninja/server';
import { CredGuard, rateLimitPolicy, scopeFilterPolicy } from '@credninja/guard';

const guard = new CredGuard({
  policies: [
    rateLimitPolicy({ maxRequests: 10, windowMs: 60_000 }),
    scopeFilterPolicy({
      allowedScopes: {
        google: ['gmail.readonly', 'calendar.readonly'],
        github: ['repo', 'read:user'],
      },
    }),
  ],
  onDecision: (ctx, results) => {
    console.log(`[guard] ${ctx.provider} → ${results.at(-1)?.decision}`);
  },
});

const { app } = createServer(config);
app.use('/api/token', guard.expressMiddleware());
```

### MCP Tool Wrapper

```typescript
import { CredGuard, rateLimitPolicy, urlAllowlistPolicy } from '@credninja/guard';

const guard = new CredGuard({
  policies: [
    rateLimitPolicy({ maxRequests: 20, windowMs: 60_000 }),
    urlAllowlistPolicy({
      allowedUrls: {
        github: ['https://api.github.com/repos/', 'https://api.github.com/user'],
        google: [/^https:\/\/www\.googleapis\.com\/calendar\//],
      },
    }),
  ],
});

// Wrap your MCP tool handler
const guardedUseHandler = guard.wrapMcpTool(handleUse);
```

### Custom Policy

```typescript
import type { CredPolicy, GuardContext, PolicyResult } from '@credninja/guard';

const noDeletePolicy: CredPolicy = {
  name: 'no-destructive-methods',
  evaluate(ctx: GuardContext): PolicyResult {
    if (ctx.targetMethod === 'DELETE') {
      return { decision: 'DENY', reason: 'DELETE requests are not allowed', policy: this.name };
    }
    return { decision: 'ALLOW', policy: this.name };
  },
};

const guard = new CredGuard({
  policies: [noDeletePolicy],
});
```

## Built-in Policies

| Policy | Description | Config |
|--------|-------------|--------|
| `rateLimitPolicy` | Sliding-window rate limit per agent per provider | `{ maxRequests, windowMs, perProvider? }` |
| `scopeFilterPolicy` | Restrict which scopes agents can request | `{ allowedScopes, narrowInsteadOfDeny? }` |
| `timeWindowPolicy` | Restrict when delegations can occur | `{ allowedHours, timezone?, allowedDays? }` |
| `urlAllowlistPolicy` | Restrict which URLs agents can call (cred_use) | `{ allowedUrls }` (string prefix or RegExp) |
| `maxTtlPolicy` | Cap delegation TTL | `{ maxTtlSeconds, perProvider? }` |

## Policy Chain Behavior

1. Policies execute in registration order
2. First `DENY` short-circuits (stops evaluation)
3. `SKIP` means the policy doesn't apply to this request
4. All `ALLOW`/`SKIP` = request proceeds
5. No policies registered = `ALLOW` (opt-in guardrails)
6. Policy errors = `DENY` by default (fail-closed)

## API Reference

### CredGuard

```typescript
class CredGuard {
  constructor(config: GuardConfig);
  evaluate(ctx: GuardContext): Promise<GuardDecision>;
  expressMiddleware(options?: ExpressMiddlewareOptions): RequestHandler;
  wrapMcpTool<T>(handler: (input: T, ctx: any) => Promise<CallToolResult>): (input: T, ctx: any) => Promise<CallToolResult>;
  addPolicy(policy: CredPolicy): void;
  removePolicy(name: string): boolean;
  getPolicyNames(): string[];
}
```

### GuardConfig

```typescript
interface GuardConfig {
  policies: CredPolicy[];
  onError?: 'deny' | 'allow' | 'log-and-deny';  // default: 'deny'
  onDecision?: (ctx: GuardContext, results: PolicyResult[]) => void;
}
```

### GuardContext

```typescript
interface GuardContext {
  provider: string;
  agentTokenHash: string;      // SHA-256 hash, never plaintext
  requestedScopes: string[];
  consentedScopes: string[];
  targetUrl?: string;          // For cred_use
  targetMethod?: string;       // For cred_use
  timestamp: string;           // ISO 8601
  delegationId?: string;
  metadata?: Record<string, unknown>;
}
```

### PolicyResult

```typescript
interface PolicyResult {
  decision: 'ALLOW' | 'DENY' | 'SKIP';
  reason?: string;
  policy: string;
  narrowedScopes?: string[];   // For scope narrowing
}
```

### GuardDecision

```typescript
interface GuardDecision {
  allowed: boolean;
  results: PolicyResult[];
  deniedBy?: PolicyResult;
  effectiveScopes: string[];
  evaluationMs: number;
}
```

## Audit Events

Every decision produces a `GuardAuditEvent` compatible with Cred's Ed25519 audit receipt chain:

```typescript
import { buildAuditEvent } from '@credninja/guard';

const event = buildAuditEvent(ctx, decision);
// { type: 'guard.decision', timestamp, agentTokenHash, provider, allowed, policies, ... }
```

## Full Specification

See [GUARD-SPEC.md](../../GUARD-SPEC.md) for the complete design specification.

## License

MIT

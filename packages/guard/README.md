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
| `urlAllowlistPolicy` | Restrict which URLs agents can call (cred_use) | `{ allowedUrls }` (origin-scoped string prefix or RegExp) |
| `maxTtlPolicy` | Cap delegation TTL | `{ maxTtlSeconds, perProvider? }` |
| `webBotAuthPolicy` | Require or constrain Web Bot Auth identity metadata | `{ requireKeyId?, allowedIdentitySources?, allowedSignatureAgentPrefixes? }` |
| `classificationCeilingPolicy` | Deny resources classified above the agent's ceiling | `{ levels, agentCeilings? \| resolveAgentCeiling?, resolveResourceLevel?, onMissing?, noWriteDown?, resolveFlow? }` |
| `amountLimitPolicy` | Cap monetary amounts per request and per rolling period | `{ currency, maxPerRequest?, maxPerPeriod?, periodMs?, perAgent?, resolveAmount?, onMissing?, store? }` |

### Classification Ceiling

Orders `levels` lowest first and denies a request whose level (default `ctx.metadata.classification`) is above the agent's ceiling. Ceilings come from `agentCeilings`, keyed by `agentDid` or `agentTokenHash` (the lower one applies when both match), or from `resolveAgentCeiling`. It fails closed: an unknown level, an unknown agent or a resolver error is a DENY. A request with no classification is denied unless `onMissing: 'skip'`.

With `noWriteDown: true`, `ctx.metadata.sourceClassification` and `ctx.metadata.destinationClassification` are also checked against the ceiling, and moving data to a lower level is denied.

```typescript
import { classificationCeilingPolicy } from '@credninja/guard';

classificationCeilingPolicy({
  levels: ['public', 'internal', 'confidential', 'restricted'],
  agentCeilings: { 'did:web:reports.example.com': 'confidential' },
  noWriteDown: true,
});
```

DENY codes: `classification_exceeded`, `write_down_blocked`, `classification_unknown`, `classification_missing`, `ceiling_unknown`.

### Amount Limit

Reads `ctx.metadata.amount` and `ctx.metadata.currency` (override with `resolveAmount`). Amounts are **integer minor units** (`1050` is USD 10.50); decimals, negatives and strings are denied. `maxPerPeriod` is a rolling total per `agentTokenHash` over `periodMs` (default 24 hours), and only allowed amounts count toward it. `perAgent` overrides limits by `agentTokenHash` or `agentDid`.

```typescript
import { amountLimitPolicy } from '@credninja/guard';

amountLimitPolicy({
  currency: 'USD',
  maxPerRequest: 50_00,    // $50.00
  maxPerPeriod: 200_00,    // $200.00 per 24 hours
  perAgent: { 'did:web:billing.example.com': { maxPerPeriod: 1_000_00 } },
});
```

Totals live in memory by default and reset on restart. For multiple instances, pass a `store` implementing `AmountLimitStore` (`consume` must check and record atomically). DENY codes: `amount_exceeds_per_request`, `amount_exceeds_period`, `amount_missing`, `amount_invalid`, `currency_mismatch`, `amount_store_error`.

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

## License

Apache License 2.0

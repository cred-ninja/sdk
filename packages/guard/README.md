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
| `approvalRequiredPolicy` | Hold matching requests until a human approves them | `{ when?, match?, verifyApproval?, approver?, maxApprovalTtlSeconds?, forbidSelfApproval?, resolveSponsor? }` |

## Policy Chain Behavior

1. Policies execute in registration order
2. First `DENY` short-circuits (stops evaluation)
3. `SKIP` means the policy doesn't apply to this request
4. All `ALLOW`/`SKIP` = request proceeds
5. No policies registered = `ALLOW` (opt-in guardrails)
6. Policy errors = `DENY` by default (fail-closed)
7. `REQUIRE_APPROVAL` refuses the request (`allowed: false`) but does not short-circuit, so a later `DENY` still wins. With no `DENY`, the first `REQUIRE_APPROVAL` becomes `deniedBy` and `decision.approvalRequired`

## Human Approval

`approvalRequiredPolicy` holds a request until a named human approves it, for example writes to restricted data or a payment to a new payee. A matching request is refused with `REQUIRE_APPROVAL` and the typed code `approval_required`. Callers that only check `decision.allowed` keep failing closed.

```typescript
import { CredGuard, approvalRequiredPolicy } from '@credninja/guard';

const guard = new CredGuard({
  policies: [
    approvalRequiredPolicy({
      // Any rule (or `when(ctx)`) matching means approval is needed.
      match: [{ providers: ['stripe'], methods: ['POST'], metadata: { newPayee: true } }],
      approver: { role: 'finance-approver' },
      reason: 'Payment to a new payee',
      maxApprovalTtlSeconds: 900,
      // Required: without it every approval is unverified and refused.
      verifyApproval: ({ approval, requestDigest }) => approvals.verify(approval, requestDigest),
      // Separation of duties: the agent's sponsor cannot approve its requests.
      forbidSelfApproval: true,
      resolveSponsor: (ctx) => sponsors.lookup(ctx.agentTokenHash),
    }),
  ],
});
```

The flow:

1. The agent calls without an approval. Express answers `403 { error: 'approval_required', code: 'approval_required', approval }`; the MCP wrapper returns an error result with the same `structuredContent`. `approval` carries `policy`, `reason`, `approver`, `requestDigest` and, when capped, `expiresAt`.
2. Your approval service prompts the approver (for example a CIBA-style backchannel request) and issues a signed `GuardApproval` for that `requestDigest`.
3. The agent retries the same request with `approval: { approverId, requestDigest, expiresAt, signature }` in the body (Express) or tool input (MCP).

The policy accepts the approval only if its `requestDigest` matches the request (`computeApprovalDigest`: provider, agent token hash, method, URL, scopes and the matched metadata keys), it has not expired, `verifyApproval` returns `true`, and, with `forbidSelfApproval`, the approver is not the sponsor. Anything else, including a throwing verifier, stays `REQUIRE_APPROVAL`. An approval can be presented again for the same request until it expires; enforce single use in `verifyApproval` (for example by `approval.id`) if you need it.

Pass `onApprovalRequired` to `expressMiddleware()` or `wrapMcpTool()` to shape the response. A custom `onDeny` without `onApprovalRequired` keeps handling every refusal, with `deniedBy.code` set to `approval_required`.

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
  onDecision?: (ctx: GuardContext, results: PolicyResult[], decision: GuardDecision) => void;
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
  approval?: GuardApproval;    // Presented human approval (untrusted until verified)
}
```

### PolicyResult

```typescript
interface PolicyResult {
  decision: 'ALLOW' | 'DENY' | 'SKIP' | 'REQUIRE_APPROVAL';
  reason?: string;
  policy: string;
  narrowedScopes?: string[];   // For scope narrowing
  code?: string;               // Typed code, 'approval_required' on REQUIRE_APPROVAL
  approval?: ApprovalRequirement;  // On REQUIRE_APPROVAL
}
```

### GuardDecision

```typescript
interface GuardDecision {
  allowed: boolean;
  results: PolicyResult[];
  deniedBy?: PolicyResult;     // First DENY, else first REQUIRE_APPROVAL
  approvalRequired?: ApprovalRequirement;  // Set only when approval is the sole blocker
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

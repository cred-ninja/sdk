# @credninja/guard — Design Specification

**Status:** APPROVED
**Date:** 2026-03-09
**Author:** Benito (AI) / Kieran (Architect)
**Methodology:** VSDD Phase 1 (Lean Spec)

---

## 1. Problem Statement

Cred delegates OAuth tokens to AI agents with no enforcement layer. Once an agent receives a delegated access token, it has full access to whatever scopes the user consented to — no rate limits, no spend caps, no scope narrowing, no time restrictions.

Civic's `CivicAuthGuard` middleware wraps every tool call with configurable policies, making "guardrails" their primary marketing differentiator. This is Cred's #1 competitive gap.

## 2. Design Goals

1. **Middleware, not a service.** Guard is a library that wraps credential usage, not a separate running process. Zero new infrastructure to deploy.
2. **Composable.** Works with `@credninja/server`, MCP tools, SDK, and any Express/Fastify/Hono app. Not coupled to any single integration point.
3. **Open source.** This is infrastructure, not a premium feature. Ships in `cred-ninja/sdk` as `packages/guard/`.
4. **Zero additional dependencies.** Uses Node.js built-in modules only (continuing Cred's dependency philosophy).
5. **Fail-closed.** If a policy check errors, the request is denied. Never fail-open.
6. **Auditable.** Every policy decision (allow/deny) emits a structured event. Feeds into the existing Ed25519 audit receipt chain.

## 3. Architecture

```
Agent Request
     │
     ▼
┌─────────────┐
│  Cred SDK   │  (or MCP tool, or direct /api/token call)
│  .delegate()│
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│  CredGuard       │  ← NEW: policy evaluation layer
│  .evaluate()     │
│                  │
│  ┌────────────┐  │
│  │ PolicyChain│  │  Ordered list of policies, evaluated sequentially
│  │  ┌──────┐  │  │
│  │  │Policy│──┼──┼── rate-limit, scope-filter, time-window,
│  │  │Policy│  │  │   url-allowlist, max-delegation-ttl, custom
│  │  │Policy│  │  │
│  │  └──────┘  │  │
│  └────────────┘  │
│                  │
│  Decision:       │
│  ALLOW / DENY    │
└────────┬─────────┘
         │
         ▼
   Token delegated (or rejected with reason)
```

### 3.1 Integration Points

Guard hooks into Cred at **three levels**, each optional:

| Level | Where | What it guards |
|-------|-------|----------------|
| **Server middleware** | `@credninja/server` Express routes | Wraps `/api/token/:provider` — evaluates before token leaves the server |
| **MCP tool wrapper** | `@credninja/mcp` tool handlers | Wraps `cred_delegate` and `cred_use` — evaluates before delegation or API call |
| **SDK interceptor** | `@credninja/sdk` `.delegate()` | Client-side enforcement (trust-but-verify — server-side is authoritative) |

Server middleware is the **primary enforcement point** (tokens can't bypass it). MCP and SDK layers are defense-in-depth.

### 3.2 Policy Chain Execution Model

1. Policies execute in order (first registered → last registered).
2. Each policy returns `ALLOW`, `DENY`, or `SKIP`.
3. First `DENY` short-circuits — no further policies evaluated.
4. If all policies return `ALLOW` or `SKIP`, the request proceeds.
5. If no policies are registered, behavior is **ALLOW** (opt-in guardrails, not breaking change).
6. Policy evaluation is synchronous where possible; async policies are supported but discouraged for latency.

## 4. Policy Interface

```typescript
/** Context provided to every policy evaluation */
interface GuardContext {
  /** Which provider is being accessed */
  provider: string;
  /** The agent token hash (SHA-256, never plaintext) */
  agentTokenHash: string;
  /** Scopes being requested */
  requestedScopes: string[];
  /** Scopes the user originally consented to */
  consentedScopes: string[];
  /** For cred_use: the target URL being called */
  targetUrl?: string;
  /** For cred_use: the HTTP method */
  targetMethod?: string;
  /** ISO timestamp of the request */
  timestamp: string;
  /** Delegation ID if this is a token usage (not initial delegation) */
  delegationId?: string;
  /** Arbitrary metadata from the agent request */
  metadata?: Record<string, unknown>;
}

/** Result of a single policy evaluation */
interface PolicyResult {
  decision: 'ALLOW' | 'DENY' | 'SKIP';
  /** Human-readable reason (required for DENY, optional for ALLOW/SKIP) */
  reason?: string;
  /** Policy name for audit trail */
  policy: string;
  /** Optional: modified context to pass to next policy (e.g., scope narrowing) */
  narrowedScopes?: string[];
}

/** A single policy — the core extension point */
interface CredPolicy {
  /** Unique name for this policy (used in audit events) */
  name: string;
  /** Evaluate the request against this policy */
  evaluate(ctx: GuardContext): PolicyResult | Promise<PolicyResult>;
}
```

### 4.1 Guard Configuration

```typescript
interface GuardConfig {
  /** Ordered list of policies to evaluate */
  policies: CredPolicy[];
  /** What to do if a policy throws an error. Default: 'deny' */
  onError?: 'deny' | 'allow' | 'log-and-deny';
  /** Callback for every policy decision (for audit/logging) */
  onDecision?: (ctx: GuardContext, results: PolicyResult[]) => void;
}
```

### 4.2 Guard API

```typescript
class CredGuard {
  constructor(config: GuardConfig);

  /** Evaluate all policies against a request context. Returns final decision. */
  evaluate(ctx: GuardContext): Promise<GuardDecision>;

  /** Express middleware factory — wraps token endpoints */
  expressMiddleware(): express.RequestHandler;

  /** MCP tool wrapper — wraps tool handlers */
  wrapMcpTool<T>(handler: (input: T, ctx: any) => Promise<CallToolResult>):
    (input: T, ctx: any) => Promise<CallToolResult>;

  /** Add a policy at runtime (appended to end of chain) */
  addPolicy(policy: CredPolicy): void;

  /** Remove a policy by name */
  removePolicy(name: string): boolean;
}

interface GuardDecision {
  allowed: boolean;
  /** All policy results in evaluation order */
  results: PolicyResult[];
  /** The DENY result that blocked, if any */
  deniedBy?: PolicyResult;
  /** Final scopes after any narrowing */
  effectiveScopes: string[];
  /** Duration of policy evaluation in ms */
  evaluationMs: number;
}
```

## 5. Built-in Policies

Ship with a set of configurable built-in policies that cover the most common guardrail needs. Users can also write custom policies implementing `CredPolicy`.

### 5.1 Rate Limit Policy

```typescript
/** Sliding-window rate limit per agent per provider */
interface RateLimitPolicyConfig {
  /** Max requests per window */
  maxRequests: number;
  /** Window size in milliseconds */
  windowMs: number;
  /** Optional: separate limits per provider (overrides global) */
  perProvider?: Record<string, { maxRequests: number; windowMs: number }>;
}
```

**Implementation:** In-memory sliding window counter, keyed by `agentTokenHash:provider`. No external dependencies. Resets on server restart (acceptable for v1 — persistent counters are a Cloud tier feature).

**Behavior:**
- Counts delegation requests (`/api/token/:provider`) and usage requests (`cred_use`).
- Returns `DENY` with `Retry-After` hint when limit exceeded.
- `SKIP` if the provider isn't configured in the policy.

### 5.2 Scope Filter Policy

```typescript
/** Restrict which scopes an agent can request, beyond what the user consented to */
interface ScopeFilterPolicyConfig {
  /** Allowlist of scopes per provider. Agent can only request scopes in this list. */
  allowedScopes: Record<string, string[]>;
  /** If true, silently narrow to allowed scopes instead of denying. Default: false (deny). */
  narrowInsteadOfDeny?: boolean;
}
```

**Behavior:**
- Compares `requestedScopes` against `allowedScopes[provider]`.
- If `narrowInsteadOfDeny`, removes disallowed scopes and sets `narrowedScopes` in result.
- If not narrowing and disallowed scopes found, returns `DENY`.
- Returns `SKIP` if provider not in config.

### 5.3 Time Window Policy

```typescript
/** Restrict when delegations can occur */
interface TimeWindowPolicyConfig {
  /** Allowed hours (24h format). Agent can only delegate during these hours. */
  allowedHours: { start: number; end: number };
  /** Timezone for hour evaluation (IANA, e.g. 'America/New_York'). Default: 'UTC'. */
  timezone?: string;
  /** Allowed days of week (0=Sunday, 6=Saturday). Default: all days. */
  allowedDays?: number[];
}
```

**Behavior:**
- Evaluates `ctx.timestamp` against configured window.
- `DENY` if outside allowed hours/days.
- Useful for: "agents can only access Salesforce during business hours."

### 5.4 URL Allowlist Policy

```typescript
/** For cred_use: restrict which API endpoints the agent can call */
interface UrlAllowlistPolicyConfig {
  /** Per-provider list of allowed URL patterns (string prefix or RegExp) */
  allowedUrls: Record<string, (string | RegExp)[]>;
}
```

**Behavior:**
- Only evaluates on `cred_use` calls (where `targetUrl` is present). `SKIP` otherwise.
- Checks `targetUrl` against `allowedUrls[provider]`.
- `DENY` if no pattern matches.
- This is defense-in-depth on top of the MCP server's existing SSRF allowlist.

### 5.5 Max Delegation TTL Policy

```typescript
/** Cap how long a delegated token can live */
interface MaxTtlPolicyConfig {
  /** Maximum TTL in seconds. Delegation expires after this regardless of token expiry. */
  maxTtlSeconds: number;
  /** Per-provider overrides */
  perProvider?: Record<string, number>;
}
```

**Behavior:**
- Sets `expiresAt` on the delegation to `min(token.expiresAt, now + maxTtlSeconds)`.
- Always returns `ALLOW` (it narrows, doesn't deny).

## 6. Integration Examples

### 6.1 Server Middleware

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
    console.log(`[guard] ${ctx.provider} → ${results.at(-1)?.decision}`, results);
  },
});

const { app } = createServer(config);
// Guard wraps all /api/token routes
app.use('/api/token', guard.expressMiddleware());
```

### 6.2 MCP Tool Wrapper

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

// In MCP server setup:
const guardedUseHandler = guard.wrapMcpTool(handleUse);
```

### 6.3 Custom Policy

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
```

## 7. Audit Integration

Every `GuardDecision` is structured for the existing audit pipeline:

```typescript
interface GuardAuditEvent {
  type: 'guard.decision';
  timestamp: string;
  agentTokenHash: string;
  provider: string;
  allowed: boolean;
  policies: Array<{
    name: string;
    decision: 'ALLOW' | 'DENY' | 'SKIP';
    reason?: string;
    durationMs: number;
  }>;
  requestedScopes: string[];
  effectiveScopes: string[];
  targetUrl?: string;
  targetMethod?: string;
}
```

The `onDecision` callback receives this structure. The server can:
1. Log it (structured JSON logs).
2. Feed it into the Ed25519 audit receipt chain (existing infrastructure).
3. Send it to an external SIEM/webhook (Cloud tier feature).

## 8. Error Handling

| Scenario | Behavior |
|----------|----------|
| Policy throws | `onError` config: `'deny'` (default), `'allow'`, or `'log-and-deny'` |
| No policies registered | `ALLOW` (opt-in, not breaking change) |
| All policies `SKIP` | `ALLOW` |
| Policy returns invalid result | Treated as `DENY` (fail-closed) |
| Guard not mounted | No enforcement (existing behavior preserved) |

## 9. Security Invariants

1. **Fail-closed by default.** Errors deny, not allow.
2. **No token exposure.** Guard never sees plaintext refresh tokens. It operates on delegation context, not raw credentials.
3. **Agent token never stored in plaintext.** Guard receives `agentTokenHash` (SHA-256), consistent with Cred's existing invariant.
4. **Policy evaluation is deterministic.** Same input → same output. No external network calls in built-in policies.
5. **Rate limit state is not shared across processes.** Acceptable for v1 (single-process server). Shared state (Redis) is a future Cloud feature.

## 10. Package Structure

```
packages/guard/
├── src/
│   ├── index.ts              # Public API exports
│   ├── guard.ts              # CredGuard class
│   ├── types.ts              # GuardContext, PolicyResult, GuardDecision, etc.
│   ├── policies/
│   │   ├── rate-limit.ts     # RateLimitPolicy
│   │   ├── scope-filter.ts   # ScopeFilterPolicy
│   │   ├── time-window.ts    # TimeWindowPolicy
│   │   ├── url-allowlist.ts  # UrlAllowlistPolicy
│   │   └── max-ttl.ts        # MaxTtlPolicy
│   ├── middleware/
│   │   ├── express.ts        # Express middleware adapter
│   │   └── mcp.ts            # MCP tool wrapper adapter
│   └── audit.ts              # Audit event builder
├── __tests__/
│   ├── guard.test.ts         # Core chain evaluation
│   ├── rate-limit.test.ts
│   ├── scope-filter.test.ts
│   ├── time-window.test.ts
│   ├── url-allowlist.test.ts
│   ├── max-ttl.test.ts
│   ├── express.test.ts
│   └── mcp.test.ts
├── package.json
├── tsconfig.json
└── README.md
```

## 11. What This Does NOT Cover (Future / Cloud)

| Feature | Why deferred |
|---------|-------------|
| Persistent rate limit counters (Redis) | Cloud tier — self-host gets in-memory |
| Approval workflows (human-in-the-loop) | Requires async flow + notification system |
| Monetary spend tracking | Requires pricing data per API call |
| Per-tool ACL | Phase 3 — builds on guard infrastructure but needs MCP registry |
| Dynamic policy reload (config changes without restart) | v2 quality-of-life |
| Policy DSL / JSON config files | v2 — start with TypeScript for type safety |
| Multi-process shared state | Cloud tier |

## 12. Success Criteria

1. All 5 built-in policies pass unit tests with >95% branch coverage.
2. Express middleware integration test: blocked request returns 403 with structured error.
3. MCP wrapper integration test: denied `cred_use` returns `isError: true` with policy reason.
4. Zero new dependencies added to the package.
5. Audit events are structurally compatible with existing Ed25519 receipt pipeline.
6. `npm run build` produces ESM + CJS dual output matching other packages in the monorepo.

## 13. Design Decisions (Confirmed)

All open questions resolved by Kieran (2026-03-09 21:09 ET):

1. **Policy config format: TypeScript only for v1.** No JSON/YAML. Type-safe, composable, matches monorepo DX. JSON config is a v2 convenience feature if needed.

2. **Rate limit scope: Per agent-per-provider.** Most granular useful default. Prevents one agent from starving another's quota on the same provider.

3. **Scope narrowing default: DENY.** Unlisted scopes are denied. Fail-closed. `narrowInsteadOfDeny: true` is opt-in for agents that want silent narrowing.

4. **Package name: `@credninja/guard`.** Shorter, matches the class name `CredGuard`.

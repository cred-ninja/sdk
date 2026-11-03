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
| `receiptClaimsPolicy` | Require claims on the delegation receipt chain | `{ requiredClaims?, perProvider? }` |

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
  getPolicies(): readonly CredPolicy[];
  getOnError(): 'deny' | 'allow' | 'log-and-deny';
  recentDecisions(): GuardAuditEvent[];            // with decisionHistorySize > 0
}
```

### GuardConfig

```typescript
interface GuardConfig {
  policies: CredPolicy[];
  onError?: 'deny' | 'allow' | 'log-and-deny';  // default: 'deny'
  onDecision?: (ctx: GuardContext, results: PolicyResult[]) => void;
  decisionHistorySize?: number;                  // default 0 (off); bounded ring buffer
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

Set `decisionHistorySize` on the guard to keep the last N of these in memory and read them back with `guard.recentDecisions()`. The policy diagnostics below read that buffer by default. Off (0) unless set.

## Policy diagnostics

Operators over-grant at setup (scopes, URL patterns, rate limits) and rarely revisit. This module reads a guard's policy chain as data, says what it lets each provider do, finds where the configuration disagrees with the decisions the guard actually made, and proposes the smallest configuration change for each finding, with a dry run of what that change would have decided differently. It is the guard-side equivalent of IAM Access Analyzer's unused-permission findings: evidence for a human to act on in configuration. Everything here is a pure function over a snapshot; nothing changes a running guard. Design note: `docs/design/policy-least-privilege-diagnostics.md`.

### Read and interpret

```typescript
import { CredGuard, rateLimitPolicy, scopeFilterPolicy, snapshotGuard, interpretSnapshot } from '@credninja/guard';

const guard = new CredGuard({
  policies: [
    rateLimitPolicy({ maxRequests: 100, windowMs: 60_000 }),
    scopeFilterPolicy({ allowedScopes: { github: ['repo', 'read:user', 'gist'] } }),
  ],
  decisionHistorySize: 1000,
});

const snapshot = snapshotGuard(guard);
// snapshot.hash            sha256 of the canonical chain; identifies this exact configuration
// snapshot.parameterCount  leaves across all policies
// snapshot.policies[1].descriptor
//   { kind: 'scope-filter', parameters: { allowedScopes: { github: ['repo', 'read:user', 'gist'] } } }

interpretSnapshot(snapshot).summary;
// [ '2 policies in order: rate-limit, scope-filter.',
//   'A policy that throws denies the request (fail-closed).',
//   'No URL allowlist: brokered calls may reach any URL the operation tables map.',
//   'Providers not named in any policy are only rate-limited: scope-filter and url-allowlist skip them.',
//   'github: scopes repo, read:user, gist; 100 requests per 60000ms.' ]
```

Every built-in policy serializes itself. A custom policy is recorded as `kind: 'opaque'` unless it implements `describe()` and `withParameters()` (see CONTRIBUTING.md); an opaque policy is carried over unchanged in a dry run and cannot be patched. A RegExp pattern is encoded as `{ "$regex": source, "flags": flags }`; a function such as `scopeGate` as `{ "$opaque": true }`, kept by reference.

### Diagnose against recorded decisions

```typescript
import { diagnosePolicies } from '@credninja/guard';

const diagnosis = diagnosePolicies(snapshot, guard.recentDecisions());
for (const finding of diagnosis.findings) {
  console.log(finding.code, finding.path, finding.suggestedEffect, finding.message);
}
// unused-allowed-scope /scope-filter/allowedScopes/github/2 narrowing
//   Scope "gist" is allowed for "github" but none of 412 observed requests asked for it. ...
// rate-limit-slack /rate-limit/perProvider narrowing
//   "github" peaked at 9 of 100 requests per window over 412 requests. ...
```

| Code | What it reads | Suggested patch | Effect |
|---|---|---|---|
| `unused-allowed-scope` | an allowed scope no request asked for | remove that one scope | narrowing |
| `unused-url-pattern` | a pattern no brokered call matched | remove that one pattern | narrowing |
| `unconstrained-provider-scopes` | traffic to a provider `scope-filter` does not list | add the observed scope set | narrowing |
| `unconstrained-provider-urls` | brokered calls to a provider `url-allowlist` does not list | add the observed origins | narrowing |
| `rate-limit-slack` | observed peak far under the limit | per-provider limit at twice the peak | narrowing |
| `repeated-denial` | the same denial over and over | the scope the denials asked for | widening; human decision |
| `error-fails-open` | `onError: "allow"` | set `deny` | narrowing |
| `scope-narrowing-silent` | `narrowInsteadOfDeny` | set `false` | narrowing |
| `dead-policy` | a policy that skipped every request | none, informational | |

Findings are deterministic heuristics with observation thresholds (`DiagnosisOptions`: `minObservations`, `rateLimitSlackThreshold`, `repeatedDenialThreshold`). `repeated-denial` is the one finding whose patch widens; it is offered so a reviewer can decide whether the denials describe a real workflow or an agent probing its limits.

### Dry-run a patch

```typescript
import { applyPatch, classifyPatch, diffSnapshots, replayDecisions } from '@credninja/guard';

const patch = [{ op: 'remove', path: '/scope-filter/allowedScopes/github/2' }];

classifyPatch(snapshot, patch);
// { effect: 'narrowing', magnitude: { touched: 1, total: 7, fraction: 0.14 }, ops: [...] }

const next = applyPatch(snapshot, patch);     // pure; all-or-nothing; PatchError names the failing op
diffSnapshots(snapshot, next);                // the same one op back
await replayDecisions(snapshot, next, guard.recentDecisions(), { previous: guard.getPolicies() });
// { events: 412, excludedPolicies: ['rate-limit'], unchanged: 409, newlyDenied: [...3 gist requests], newlyAllowed: [] }
```

Paths are JSON Pointers: `/onError`, `/<policy>` for a whole policy (`{ kind, parameters }`), or `/<policy>/<pointer into its parameters>`. Classification follows each kind's semantics: raising `maxRequests` widens, removing a provider key widens because the policy then skips that provider, adding a restrictive policy narrows. An op with no rule is `unknown`; treat it as widening. Replay rebuilds both chains in isolation and leaves out stateful policies (rate-limit), naming them in `excludedPolicies`. The running guard is never touched: apply an accepted patch to your configuration and redeploy.

The same report is available to operators over REST as `GET /admin/policy` on `@credninja/server`, off by default.

## License

Apache License 2.0

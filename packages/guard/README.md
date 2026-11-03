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
| `weightArtifactPolicy` | Experimental. For agents moving model weights through `cred_use`: pin artifact-store hosts, write prefixes, digests and sizes | `{ stores: { [provider]: { hosts, allowWrite?, writePathPrefixes?, pinnedDigests?, maxBytes? } } }` |

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
  replacePolicies(policies: CredPolicy[]): void;   // atomic; used by PolicyWeightSpaceEditor
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

Set `decisionHistorySize` on the guard to keep the last N of these in memory and read them back with `guard.recentDecisions()`. The weight-space diagnostics and dry runs below read that buffer by default.

## Weight-space editing

The policy chain is a small tree of parameters: scope lists, URL patterns, limits, ceilings. This module reads it as data, says what it does, finds where it disagrees with observed traffic, and patches it one leaf at a time under signed approval. The approach follows Weight-Space Programming (reading and surgically editing a network's weights); the design note is at `docs/design/weight-space-policy-editing.md`.

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
// snapshot.hash          sha256 of the canonical chain; a patch applies to exactly this state
// snapshot.parameterCount leaves across all policies
// snapshot.policies[1].descriptor
//   { kind: 'scope-filter', parameters: { allowedScopes: { github: ['repo', 'read:user', 'gist'] } } }

interpretSnapshot(snapshot).summary;
// [ '2 policies in order: rate-limit, scope-filter.',
//   'A policy that throws denies the request (fail-closed).',
//   'No URL allowlist: brokered calls may reach any URL the operation tables map.',
//   'Providers not named in any policy are only rate-limited: scope-filter and url-allowlist skip them.',
//   'github: scopes repo, read:user, gist; 100 requests per 60000ms.' ]
```

Every built-in policy serializes itself. A custom policy is recorded as `kind: 'opaque'` unless it implements `describe()` and `withParameters()` (see CONTRIBUTING.md); an opaque policy is carried over unchanged on every edit and cannot be patched. A RegExp pattern is encoded as `{ "$regex": source, "flags": flags }`; a function such as `scopeGate` as `{ "$opaque": true }`, kept by reference.

### Diagnose against traffic

```typescript
import { diagnosePolicies } from '@credninja/guard';

const diagnosis = diagnosePolicies(snapshot, guard.recentDecisions());
for (const finding of diagnosis.findings) {
  console.log(finding.code, finding.path, finding.suggestedEffect, finding.message);
}
// unused-allowed-scope /scope-filter/allowedScopes/github/2 narrowing
//   Scope "gist" is allowed for "github" but none of 412 observed requests asked for it. ...
// rate-limit-slack /rate-limit/perProvider/github narrowing
//   "github" peaked at 9 of 100 requests per window over 412 requests. ...
```

Findings are deterministic heuristics with observation thresholds (`DiagnosisOptions`). Each carries the smallest patch that addresses it and whether that patch widens or narrows the guard. `repeated-denial` is the one finding whose patch widens; it is offered so a reviewer can decide whether the denials describe a real workflow or an agent probing its limits.

### Patch one leaf

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

Paths are JSON Pointers: `/onError`, `/<policy>` for a whole policy (`{ kind, parameters }`), or `/<policy>/<pointer into its parameters>`. Classification follows each kind's semantics (raising `maxRequests` widens, removing a provider key widens because the policy then skips that provider, adding a restrictive policy narrows). An op with no rule is `unknown`, which every approval rule treats as widening.

### Apply under signed approval

```typescript
import { PolicyWeightSpaceEditor, generateApproverKeyPair, signProposal } from '@credninja/guard';

// On the operator's machine, once. The private key never goes near the agent.
const { publicKey, privateKey } = generateApproverKeyPair();

const editor = new PolicyWeightSpaceEditor(guard, {
  approvers: [{ id: 'kieran', publicKey }],
  requireApprovalFor: 'all',          // default; 'widening' lets narrowing patches apply unsigned
  onEvent: (event) => auditLog.write(event),
});

const proposal = await editor.propose({
  patch: [{ op: 'remove', path: '/scope-filter/allowedScopes/github/2' }],
  rationale: 'gist is allowed but unused in 412 requests over 30 days',
  proposer: 'did:key:z6Mk...agent',
});
// proposal.id, proposal.hash, proposal.baseHash, proposal.classification, proposal.dryRun

// The approver reviews the proposal and signs its hash, elsewhere.
const approval = signProposal(proposal, 'kieran', privateKey);

const result = await editor.apply(proposal.id, [approval]);
// { applied: true, approvers: ['kieran'], rebuilt: ['scope-filter'], kept: ['rate-limit'], snapshot }
```

`apply` refuses a proposal that is expired, tampered with, or written against a chain that has since changed (`base_mismatch`: propose again), one without enough valid approvals, and one the proposer signed for itself. It swaps the chain in one assignment and rebuilds only the policies the patch touched; the rate limit above keeps its instance and its counters. `history()` lists applied edits and `proposeRollback(id, proposer)` proposes the inverse under the same rules.

The same loop is exposed to agents over MCP (`cred_policy_inspect`, `cred_policy_propose`, `cred_policy_apply`) and to operators over REST (`/admin/policy`), each only when a `policyEditor` is configured.

## License

Apache License 2.0

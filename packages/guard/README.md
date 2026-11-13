# @credninja/guard

Policy engine for credential delegation guardrails. Add rate limiting, scope filtering, time windows, URL allowlisting, and custom policies to control how AI agents access delegated credentials. Works as middleware for `@credninja/server`, MCP tools, or any Express app.

## Install

```bash
npm install @credninja/guard
```

The package is ESM only: load it with `import`. `require('@credninja/guard')` fails with
`ERR_PACKAGE_PATH_NOT_EXPORTED`.

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

## Where identity comes from

`webBotAuthPolicy` and `receiptClaimsPolicy` judge what the adapter puts in the
context (`identitySource`, `webBotAuthKeyId`, `signatureAgent`, `receiptClaims`), so
they are only as good as where those values come from.

- **`@credninja/server`** passes verified state: the key id and Signature-Agent of a
  Web Bot Auth signature it checked, the claims of a parent receipt it verified, or
  claims an `agentRequestVerifier` attached to the caller. Values of the same name in
  the request body are ignored.
- **The Express adapter on your own app** reads `web_bot_auth_key_id`, `key_id`,
  `signature_agent`, `receipt_claims` and `metadata.receiptClaims` from the request
  body unless you pass `resolveVerifiedIdentity`. Pass it, and return only what your
  own middleware verified:

  ```typescript
  app.use('/api/token', guard.expressMiddleware({
    resolveVerifiedIdentity: (req) => ({
      webBotAuthKeyId: req.verifiedSignature?.keyId,
      signatureAgent: req.verifiedSignature?.signatureAgent,
    }),
  }));
  ```

- **The MCP adapter** has no verified channel: it reads these fields from the tool
  call's `metadata`, which the caller writes. Do not rely on `webBotAuthPolicy` or
  `receiptClaimsPolicy` there.

`agentDid` and `tofuFingerprint` follow the same rule: with
`resolveVerifiedIdentity`, only the resolver may supply them or cause the source to
be `did` or `tofu`. Return `agentDid` only after verifying proof of possession, or
when what the request issues is bound to that DID's key, and
`tofuFingerprint` only after checking the TOFU delegation proof. Returning undefined
means `agent-token` unless another verified identity was supplied. Without a resolver,
the Express adapter retains legacy body inference; `metadata` is still caller input.

The server verifies TOFU proofs for root `/api/v1/delegate` requests before Guard.
It exposes no TOFU identity on `/bc-authorize`, `/api/v1/subdelegate` or the compatibility
token route, which do not verify TOFU.

The server shows Guard an `agentDid`, and the `did` source, in three cases. On
`/api/v1/delegate` and `/bc-authorize`: when the request carries a DPoP proof for that
route signed by the key of the `agent_did` it names. With the raw-token opt-in: the
did:key the request proved, also when it names the agent by record id. On
`/api/v1/subdelegate`: the receiving agent's did:key, which the request names and the
issued token or grant is bound to. A DID a request only names is not shown, so a
policy that denies a DID is not passed by leaving the proof out: Guard then sees
`agent-token`, and the route refuses the request for its missing proof. The route
checks the proof again after Guard and is what refuses a replayed one.

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

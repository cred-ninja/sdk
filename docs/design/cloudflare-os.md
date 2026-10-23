# Cred for Cloudflare OS: Design

Status: design only, nothing built. Written against Cred `main` at `4b467cf` and Cloudflare OS `main` as of Oct 23, 2026 (the v2 early-access release, Apache 2.0). The enterprise counterpart lives in `cred-ninja/enterprise` at `docs/plans/cloudflare-os.md`.

## 1. What Cloudflare OS is, in Cred's terms

[Cloudflare OS](https://github.com/cloudflare/cloudflare-os) is an AI workspace that runs on Workers. It is not a computer operating system. Three parts matter here:

- **Gadgets.** Small per-user apps that agents write and run in a sandbox. A Gadget reaches the outside world only through bindings.
- **Gatekeepers.** One Worker per external system (GitHub, Google, Slack, Notion, any MCP server, and so on). A Gatekeeper runs that system's OAuth connect flow, holds the credential, and exposes a typed `Session` to Gadgets. Every read goes through `ApprovalQueue.authorizeObservation()` before data is returned. Every side effect goes through `ApprovalQueue.submitAction()` and runs only after it is approved.
- **The Workshop (Overseer).** The kernel. It implements `ApprovalQueue`, shows approval prompts to people, and tracks who has observed what.

The shared plumbing lives in `@gadgets/gatekeeper-kit`: connect handshakes, `CredentialCoordinator` and `CredentialSource` (token refresh, replay, expiry), an action journal, observer strategies, and an OAuth token client. Credentials are stored per Gatekeeper in Durable Object KV.

The [`cloudflare-os-starter`](https://github.com/cloudflare/cloudflare-os-starter) repository is the supported way to customize a deployment. It pins an upstream release as a submodule and lets a company add its own Gatekeepers under `packages/` without patching upstream. Upstream accepts no external PRs beyond about a dozen lines, so everything here ships as packages that a starter-based deployment adds, never as upstream changes.

## 2. Gaps Cred fills

Cloudflare already handles token refresh well inside one Gatekeeper, so "Cred vaults your tokens" is not the pitch. The gaps sit across Gatekeepers:

| Gap in Cloudflare OS | What Cred brings |
| --- | --- |
| Every company registers its own OAuth app for every service. The README calls this out as painful. | One Cred connection brokers all Cred providers. Cred Link handles the consent UI. |
| Each Gatekeeper is its own policy island. There is no shared rule for "no writes after hours" or "this agent may read the calendar but never send mail". | Guard policies evaluated in one place for every Cred-brokered call, with a seam for enterprise Cedar policy. |
| A Gadget's grant has no signed lineage. When an agent builds a Gadget that calls a sub-agent, nothing records who delegated what. | Delegation receipts and `cred_subdelegate`, with attenuation (the meet) on every hop. |
| Refresh tokens sit in each Gatekeeper's Durable Object storage. | Refresh tokens stay in the Cred vault. The Worker holds a `connection_id` and, by default, never sees a provider token. |
| Action and observation records are per Gatekeeper and not tamper-evident. | Cred's append-only audit events for every brokered call (the hash-chained, exportable version is enterprise). |

## 3. Shape

Two packages and one starter example. All Apache 2.0, in this repository.

### 3.1 `@credninja/cloudflare-os`: the Cred Gatekeeper

A Gatekeeper Worker that implements `GatekeeperVendor`, `Gatekeeper<Session>` and the connect callback, built on gatekeeper-kit leaf modules where they fit.

- **Resources.** One resource type per Cred provider (`cred:google`, `cred:github`, `cred:slack`, `cred:notion`, `cred:salesforce`, `cred:linear`, `cred:hubspot`). Resource URLs carry the requested scopes and constraints, for example `cred://google?scope=calendar.readonly`, so two grants of different breadth get distinct session types, as the MCP Gatekeeper already does with `#tool=`.
- **Connect.** `GatekeeperConnectCallback` redirects to Cred Link with a pushed request (PAR `request_uri`). On success the Gatekeeper stores only `{connection_id, grant_id, scopes}` in Durable Object KV, through gatekeeper-kit's `credential-stage` so a reconnect stays inert until the Workshop commits it. No OAuth client secrets live in the Cloudflare deployment.
- **Session.** The typed session exposes `request(method, path, body?)` plus a small typed layer per provider generated from Cred's provider metadata. Every call becomes a `cred_use` through a brokered handle. The default is brokered handle mode, so the provider token never enters the Worker. Short-lived-token mode is opt-in for providers whose SDKs need a bearer token.
- **Reads.** The session calls Cred first and then calls `authorizeObservation()` with a description built from the real response, before returning anything (the pattern the `ObservationAuthorizer` docs recommend).
- **Writes.** The session builds an `ActionDescription` with gatekeeper-kit's `action-description` (exact typed fields, so the approval prompt shows what will be sent), submits it, and runs the `cred_use` call only from `applyAction()`.
- **Delegation receipts.** When the Workshop starts a session for a Gadget, the Gatekeeper calls `cred_subdelegate` from the deployment's parent receipt, narrowed to the resource URL's scopes. The child receipt id travels with every call and appears in the audit log. This is the lineage Cloudflare OS does not record today.

### 3.2 `@credninja/cloudflare-os-policy`: the decision seam

One interface and two implementations:

```ts
interface DecisionSource {
  decide(req: {
    principal: { personId: string; agentChain: string[] };  // from Access identity and receipts
    kind: 'observation' | 'action';
    actionTag?: string;                                     // ActionDescription.actionKind.tag
    provider: string;
    scopes: string[];
    resource: string;
    context: Record<string, unknown>;
  }): Promise<{ outcome: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL'; reason: string }>;
}
```

- `GuardDecisionSource` (open source) runs `@credninja/guard` policies in-process: rate limits, scope filtering, time windows, URL allowlists, TTL caps.
- `RemoteDecisionSource` (enterprise, specified in the enterprise plan) calls the control plane's `/v1/decide`.

The outcomes map onto the existing Cloudflare OS approval model:

| Cred outcome | Observation | Action |
| --- | --- | --- |
| `ALLOW` | Call `authorizeObservation()` as normal. | Submit with `autoApprovable` only if the Gatekeeper lists that action kind in `getAutoApprovableActions()`. Otherwise it still goes to a person. |
| `REQUIRE_APPROVAL` | Throw a typed error that tells the agent to ask the user. Reads are synchronous, so there is no queue to park them in. | Submit with `autoApprovable: false`. The Workshop's normal approval prompt applies. |
| `DENY` | Throw before anything is returned. | Do not submit. Return the reason code to the Gadget. |

Cred re-decides in `applyAction()`. An action that was allowed at submit time but denied at apply time (revoked receipt, time window closed, rate limit hit) is rejected even if a person approved it. A hard DENY is never overridable by approval.

### 3.3 Wrapping the built-in Gatekeepers (spike)

Policy in 3.1 covers only Cred-brokered traffic. To cover Cloudflare's own Google, GitHub and Slack Gatekeepers without patching upstream, a `CredPolicyVendor` would wrap an inner Gatekeeper's service binding:

1. It proxies every `GatekeeperVendor` method to the inner vendor.
2. In `startSession(approvalQueue)` it passes the inner Gatekeeper a `PolicyApprovalQueue`, an `RpcTarget` that runs `DecisionSource.decide()` and then forwards to the real queue.
3. The admin disables the unwrapped connector in `/admin`, so users only reach the wrapped one.

This needs a spike before it is promised. Open questions: whether the Workshop keys Gatekeeper identity on the vendor binding so the wrapper can stand in cleanly, whether `addObserver()` and `gitPull()` pass through correctly, and how stub disposal behaves across two RPC hops. If wrapping proves fragile, the fallback is to open an upstream discussion proposing a policy service binding on `ApprovalQueueImpl` (a small, reviewable hook), and to cover only Cred-brokered traffic until then.

### 3.4 Starter example

`examples/cloudflare-os-starter/` holds the `deployment.jsonc` fragment and README steps that bind `GATEKEEPER_CRED` twice (Workshop with the `GatekeeperVendor` entrypoint, router without one, as the starter's custom-Gatekeeper docs require), plus Worker secrets for `CRED_BASE_URL` and the agent credential.

## 4. Workers compatibility

Cred packages were written for Node. What has to hold on Workers:

| Package | Node imports in `src` | Plan |
| --- | --- | --- |
| `@credninja/sdk` | `node:crypto`, `node:util` | Run with `nodejs_compat`. Verify Ed25519 signing (receipts, Web Bot Auth) under workerd; fall back to WebCrypto `Ed25519` if any call is unsupported. |
| `@credninja/guard` | `node:crypto` (the `fs` and `os` imports are test-only) | Same as above. Rate-limit state moves from memory to a Durable Object so limits hold across isolates. |
| `@credninja/attenuation` | `node:crypto` (`fs` is test-only) | Same as above. |
| `@credninja/vault`, `@credninja/server` | `fs`, SQLite, `http` | Not ported. The vault stays on the Cred server; the Gatekeeper only ever holds a `connection_id`. |

The first build step is a workerd test harness that imports the three packages and runs their existing unit tests. Nothing else starts until that passes.

## 5. Identity

The Gatekeeper needs a stable person id to look up Cred connections. Cloudflare OS deployments sign in through Cloudflare Access, and the Workshop gives Gatekeepers a `GatekeeperUserProfileSnapshot`. The design maps the Access subject (or verified email) to the Cred `userId`. Open question: whether the snapshot carries a value that is stable across email changes, or whether the Gatekeeper must verify the Access JWT itself.

## 6. Out of scope here

Cedar policy, KMS-backed signing, hash-chained evidence export, revocation fan-out with a fail-closed lease, Access-group ceilings and the self-hosted workerd bundle. Those are enterprise, in `cred-ninja/enterprise` `docs/plans/cloudflare-os.md`.

## 7. Build sequence

1. workerd compatibility harness for `sdk`, `guard`, `attenuation` (section 4).
2. `@credninja/cloudflare-os` with Google and GitHub, brokered handle mode, Cred Link connect, `GuardDecisionSource`, and the starter example. Integration test against `pnpm run-local` from a pinned Cloudflare OS release.
3. Spike for 3.3. Ship the wrapper or open the upstream discussion based on what it finds.

## 8. Risks

- **Upstream churn.** Cloudflare OS is early access and v2 is already a rewrite. Pin to tagged releases and run the integration test against each new one before bumping.
- **Cloudflare builds it natively.** Cloudflare owns Access and Zero Trust and could add cross-Gatekeeper policy itself. Cred's defense is the open standard (asor-02 and draft-sweeney receipts and constraints), multi-platform reach beyond Cloudflare, and shipping first.
- **No upstream contributions.** Anything that needs a kernel hook depends on Cloudflare's goodwill. Section 3.3 is designed to avoid needing one.

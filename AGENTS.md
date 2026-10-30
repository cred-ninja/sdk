# AGENTS.md

Machine-oriented entry point for an agent or agent framework landing on this
repository. This file lists Cred's current capability surface — every MCP
tool, REST endpoint, and framework-integration tool that exists in source —
so an agent can discover what it can do without guessing. It is generated
from source, not aspirational; if something here doesn't match the code,
the code is authoritative.

## What never goes in this repo

This repository is public. Standards-work registers, sweep reports and
anything else built from private mail live in the private
`cred-ninja/standards-private` repository, never here. Do not put the
content of private mail, mailbox message or draft identifiers, or stances
on named people into files, commit messages, or PR titles and bodies. Cite only public archives (mailarchive.ietf.org,
datatracker.ietf.org). `.github/workflows/public-leak-guard.yml` enforces
this on every PR and push to `main`.

## What this repo does

Cred is OAuth2 credential delegation middleware for AI agents. An agent
requests delegated access to a user's third-party account (Google, GitHub,
Slack, Notion, Salesforce, ...); Cred verifies the agent's identity, checks
user consent, and returns either a short-lived access token or an opaque
brokered delegation handle — never the user's long-lived refresh token. It
runs in two modes:

- **Cloud mode**: an agent (or an MCP client) talks to a hosted
  `packages/server` deployment over HTTPS with a Bearer agent token.
- **Local mode**: an MCP client talks directly to a local encrypted vault
  (`packages/vault`), no server required.

An optional policy engine, `packages/guard`, can be wired into either the
MCP tool layer or the REST server to add rate limiting, scope filtering,
TTL ceilings, time-window restrictions, and URL allowlisting on top of the
base delegation flow.

## MCP tools (`packages/mcp`)

Registered by `packages/mcp/src/server.ts` (`createCredMcpServer()` /
`startServer()`, both via the single `registerTools()` path). 11 tools:

| Tool | Purpose |
|---|---|
| `cred_delegate` | Request delegated OAuth2 access for a service on behalf of a user; returns a delegation handle (or a consent URL if the user hasn't authorized) and, when configured, a signed delegation receipt. |
| `cred_subdelegate` | Create a child delegation from a signed parent receipt, for agent-to-agent handoff. |
| `cred_use` | Make an authenticated API call through a delegation handle from `cred_delegate`; the raw token never reaches the LLM. |
| `cred_status` | Check a user's service connections and granted scopes. |
| `cred_revoke` | Revoke a user's connection to a service. |
| `cred_register_identity` | Register or import a Web Bot Auth public signing key for this agent. |
| `cred_rotate_key` | Rotate this agent's own Web Bot Auth signing key (defaults to the server's configured self agent identity). |
| `cred_revoke_identity` | Revoke this agent's own identity (emergency self-revocation). |
| `cred_audit_log` | Read the calling agent's own audit trail. Read-only; never guard-wrapped, so it survives a guard-subsystem outage. |
| `cred_capabilities` | Discover which providers are configured on this deployment and their default scopes, before calling `cred_delegate`/`cred_subdelegate`. |
| `cred_whoami` | Introspect the calling agent's own runtime permission state: active guard policy names, remaining rate-limit headroom, and (best-effort, cloud mode) its effective delegated scopes. Read-only; never guard-wrapped, so it survives a guard-subsystem outage. |

When a `CredGuard` is configured (opt-in), every tool above except
`cred_delegate`/`cred_subdelegate` in cloud mode (already enforced
server-side) and `cred_audit_log`/`cred_whoami` (read-only introspection,
kept available during a guard outage) runs through policy evaluation before
executing, and allow-path responses include the guard-computed TTL and
rate-limit headroom.

## REST endpoints (`packages/server`)

From `packages/server/src/server.ts`, current as of this plan's U9. Auth
column: `None` (no auth), `Admin` (`requireAdminAuth`, admin token/session),
`Bearer` (`requireAgentAuth`, agent Bearer token), `Bearer+VI` (Bearer plus
`requireVerifiedIdentityRegardlessOfMode`, i.e. Web Bot Auth-verified). `Link client` = Cred
Link client authentication (`client_secret_basic` or `private_key_jwt`; every
failure is the opaque `401 {"error":"access_denied"}`). The `/link/v1/*` and
`/admin/link/*` routes exist only when `LINK_ENABLED` is set.

User ids on the legacy routes: every route that acts on stored provider
tokens resolves its user id through one resolver (`requestUserId` in
server.ts). Without `user_id` it refuses with `400 user_id_required` unless
`SINGLE_USER_MODE=true`, which acts on the shared user `default`. A custom
`agentRequestVerifier` principal with `userId` binds agent requests to that
user (`403 user_id_mismatch` for another). Never add a route that falls
back to `default` on its own.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/.well-known/http-message-signatures-directory` | None | Web Bot Auth key directory |
| GET | `/health` | None | Liveness check |
| GET | `/admin/login` | None | Admin login form |
| POST | `/admin/login` | None | Create admin session cookie |
| GET | `/providers` | Admin | List configured providers |
| POST | `/admin/permissions` | Admin | Create a Permission record |
| GET | `/admin/permissions` | Admin | List/fetch Permission records |
| PATCH | `/admin/permissions/:id` | Admin | Update a Permission record |
| DELETE | `/admin/permissions/:id` | Admin | Delete a Permission record |
| GET | `/admin/audit` | Admin | Audit events across all agents (not scoped to one user) |
| GET | `/admin/agents` | Admin | List registered agent identities and status |
| DELETE | `/admin/agents/:agentId` | Admin | Revoke an agent identity as an operator |
| GET | `/connect` | Admin | Browser UI for managing provider connections |
| GET | `/connect/:provider` | Admin | Start OAuth flow (browser) from a single-use connect request (`?request=<id>`); query `user_id`/`scopes` only with the Bearer admin token |
| POST | `/connect/:provider/start` | Admin | JSON `{ user_id, scopes }`: mint a single-use connect request, answers `{ url }` |
| DELETE | `/connect/:provider` | Admin | Disconnect a provider connection |
| GET | `/connect/:provider/callback` | None | OAuth callback |
| GET | `/api/token/:provider` | Bearer | Compatibility delegation route |
| DELETE | `/api/token/:provider` | Bearer | Revoke stored credentials (compatibility route) |
| GET | `/api/v1/providers` | Bearer | List configured provider slugs |
| GET | `/api/v1/connections` | Bearer | List stored connections |
| DELETE | `/api/v1/connections/:provider` | Bearer | Revoke a stored connection |
| POST | `/api/v1/use` | Bearer + DPoP | Brokered upstream API call via a delegation handle, with a DPoP proof by the agent key the handle is bound to (handles issued under `CRED_REQUIRE_DPOP=false` and Cred Link handles take no proof) |
| DELETE | `/api/v1/delegations/:delegationId` | Bearer | Revoke a delegation and, transitively, every delegation derived from it; returns `revoked_count`, `revoked_ids`, `elapsed_ms` |
| POST | `/api/v1/delegate` | Bearer + DPoP | Primary v1 delegation endpoint; a brokered handle is issued to, and bound to the key of, the did:key agent that proves it with a DPoP proof (handle requests while `CRED_REQUIRE_DPOP` is on; raw-token requests take no proof) |
| POST | `/api/v1/subdelegate` | Bearer + actor token | Sub-delegate from a verified parent receipt; the caller proves it is the receipt's agent with an RFC 7523 `actor_token` (unless `CRED_REQUIRE_AGENT_IDENTITY=false`); always returns a brokered handle, or with `exchange: "grant"` a single-use delegation grant |
| POST | `/api/v1/token` | Bearer + actor token | RFC 8693 token exchange redeeming a delegation grant; the receiving agent proves its did:key with an RFC 7523 `actor_token` |
| POST | `/api/v1/tofu/register` | Bearer | Register a TOFU identity |
| GET | `/api/v1/web-bot-auth/keys` | Bearer | List registered Web Bot Auth identities |
| POST | `/api/v1/web-bot-auth/keys` | Bearer | Register or import a Web Bot Auth public key |
| POST | `/api/v1/web-bot-auth/keys/:agentId/rotate` | Bearer+VI | Rotate a registered Web Bot Auth key |
| POST | `/api/v1/agents/:agentId/revoke-all` | Bearer+VI | Revoke a stored agent record |
| GET | `/api/v1/audit` | Bearer | Read audit events (`since` cursor param supported) |
| GET | `/api/v1/audit/stream` | Bearer | SSE stream of `revoke` audit events for the connecting agent/user |
| POST | `/admin/link/clients` | Admin | Register a Cred Link client (secret returned once) |
| GET | `/admin/link/clients` | Admin | List Cred Link clients |
| POST | `/admin/link/clients/:client_id/disable` | Admin | Disable a Cred Link client |
| POST | `/admin/link/clients/:client_id/enable` | Admin | Re-enable a Cred Link client |
| POST | `/link/v1/par` | Link client | Pushed request for a hosted connect, update or reauth flow; returns the widget `request_uri` |
| GET | `/link/v1/authorize` | None (request_uri) | Hosted flow entry: renders the provider picker |
| POST | `/link/v1/picker` | None (envelope + binding cookie) | Picker submission; redirects to the provider |
| GET | `/link/v1/callback/:provider` | None (provider state envelope) | Provider callback; renders the scope confirmation |
| POST | `/link/v1/confirm` | None (envelope + binding cookie) | Confirm, back or cancel; delivers the result |
| GET | `/link/v1/connections` | Link client | List a subject's Link connections (`?subject=`) |
| GET | `/link/v1/connections/:id` | Link client | Connection status, provider, subject and grant |
| DELETE | `/link/v1/connections/:id` | Link client | Revoke at the provider, delete secrets, revoke the grant |
| POST | `/link/v1/connections/:id/activate` | Link client | Activate with the one-time code and the session subject |
| POST | `/link/v1/connections/:id/refresh` | Link client | Force a token refresh; returns status only |
| POST | `/link/v1/connections/:id/reauth` | Link client | Reauth pushed request for this connection |
| POST | `/link/v1/connections/:id/permissions` | Link client | Grant an agent scopes within the grant |
| POST | `/link/v1/connections/:id/narrow` | Link client | Narrow the grant to a subset of itself (no provider round trip; `enforcement` is `broker` only for Google when whole API families were removed, else `record`: family level, not read versus write) |

`GET /api/v1/audit` and `GET /admin/audit` are separate routes: the former
is scoped to the requesting agent's own `userId`; the latter is
admin-authenticated and unscoped, covering all agents.

## Framework integration tool names (`packages/integrations`)

Each of the six framework integrations wraps the same underlying delegate /
use flow, exposed under that framework's own tool-registration convention.

- **LangChain** (`cred-langchain`, `CredToolkit.get_tools()`): `cred_delegate`,
  `cred_status`, `cred_revoke` always; `cred_use` additionally when
  `token_format="handle"`.
- **CrewAI** (`cred-crewai`): `CredTool` — single-service delegate tool,
  name auto-generated as `cred_<service>_delegate` (e.g.
  `cred_google_delegate`, `cred_github_delegate`); default `name` attribute
  is `cred_delegate`. `CredUseTool` — `cred_use`, paired with
  `token_format="handle"`.
- **AutoGen** (`cred-autogen`): `cred_delegate_tool()` / `cred_use_tool()`
  factories register `cred_delegate` and `cred_use`.
- **OpenAI Agents SDK** (`cred-openai-agents`): `cred_delegate_tool()` /
  `cred_use_tool()` factories register `cred_delegate` and `cred_use`.
- **Semantic Kernel** (`cred-semantic-kernel`): a single `cred` plugin
  (`kernel.add_plugin(plugin, plugin_name="cred")`) exposing kernel
  functions `delegate` and `use` (invoked as `cred.delegate` / `cred.use`).
- **Vercel AI SDK** (`@credninja/vercel-ai`): `credDelegateTool()` /
  `credUseTool()` factories, conventionally registered under the tool keys
  `cred_delegate` and `cred_use`.

## Packages

| Package | Role |
|---|---|
| `packages/protocol` | Shared wire-protocol constants/types (version negotiation, error shapes). |
| `packages/attenuation` | Dependency-free attenuation: scope grammar, constraint ceilings, chain verification, JWS signer interface, and the draft-asor -02 `agent_delegation` token format. Re-exported by `packages/vault`. |
| `packages/oauth` | Provider OAuth adapters (Google, GitHub, Slack, Notion, Salesforce, ...). |
| `packages/tofu` | Trust-on-first-use agent identity registry (Web Bot Auth keys, DIDs). |
| `packages/vault` | Encrypted credential storage, Permission records, audit log, cumulative-constraint ledger. |
| `packages/guard` | Composable policy engine (rate limit, scope filter, TTL, time window, URL allowlist) for MCP and Express. |
| `packages/sdk` | `Cred` client class — the shared surface both `packages/mcp` and `packages/server` build on. |
| `packages/sdk-python` | Python port of the SDK client, used by the Python framework integrations. |
| `packages/server` | Hosted REST API (cloud mode) — see endpoint table above. |
| `packages/mcp` | MCP server exposing the tool surface above, in local or cloud mode. |
| `packages/integrations/*` | Framework-specific tool wrappers — see table above. |
| `packages/create-cred-app` | Project scaffold/template. |

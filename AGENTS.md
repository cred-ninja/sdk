# AGENTS.md

Machine-oriented entry point for an agent or agent framework landing on this
repository. This file lists Cred's current capability surface — every MCP
tool, REST endpoint, and framework-integration tool that exists in source —
so an agent can discover what it can do without guessing. It is generated
from source, not aspirational; if something here doesn't match the code,
the code is authoritative.

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
`requireVerifiedIdentityRegardlessOfMode`, i.e. Web Bot Auth-verified).

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
| GET | `/connect/:provider` | Admin | Start OAuth flow (browser) |
| DELETE | `/connect/:provider` | Admin | Disconnect a provider connection |
| GET | `/connect/:provider/callback` | None | OAuth callback |
| GET | `/api/token/:provider` | Bearer | Compatibility delegation route |
| DELETE | `/api/token/:provider` | Bearer | Revoke stored credentials (compatibility route) |
| GET | `/api/v1/providers` | Bearer | List configured provider slugs |
| GET | `/api/v1/connections` | Bearer | List stored connections |
| DELETE | `/api/v1/connections/:provider` | Bearer | Revoke a stored connection |
| POST | `/api/v1/use` | Bearer | Brokered upstream API call via a delegation handle |
| POST | `/api/v1/delegate` | Bearer | Primary v1 delegation endpoint |
| POST | `/api/v1/subdelegate` | Bearer | Sub-delegate from a verified parent receipt; always returns a brokered handle |
| POST | `/api/v1/tofu/register` | Bearer | Register a TOFU identity |
| GET | `/api/v1/web-bot-auth/keys` | Bearer | List registered Web Bot Auth identities |
| POST | `/api/v1/web-bot-auth/keys` | Bearer | Register or import a Web Bot Auth public key |
| POST | `/api/v1/web-bot-auth/keys/:agentId/rotate` | Bearer+VI | Rotate a registered Web Bot Auth key |
| POST | `/api/v1/agents/:agentId/revoke-all` | Bearer+VI | Revoke a stored agent record |
| GET | `/api/v1/audit` | Bearer | Read audit events (`since` cursor param supported) |
| GET | `/api/v1/audit/stream` | Bearer | SSE stream of `revoke` audit events for the connecting agent/user |

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
| `packages/oauth` | Provider OAuth adapters (Google, GitHub, Slack, Notion, Salesforce, ...). |
| `packages/tofu` | Trust-on-first-use agent identity registry (Web Bot Auth keys, DIDs). |
| `packages/vault` | Encrypted credential storage, Permission records, audit log. |
| `packages/guard` | Composable policy engine (rate limit, scope filter, TTL, time window, URL allowlist) for MCP and Express. |
| `packages/sdk` | `Cred` client class — the shared surface both `packages/mcp` and `packages/server` build on. |
| `packages/sdk-python` | Python port of the SDK client, used by the Python framework integrations. |
| `packages/server` | Hosted REST API (cloud mode) — see endpoint table above. |
| `packages/mcp` | MCP server exposing the tool surface above, in local or cloud mode. |
| `packages/integrations/*` | Framework-specific tool wrappers — see table above. |
| `packages/create-cred-app` | Project scaffold/template. |

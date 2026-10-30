# Changelog

## [Unreleased]

### BREAKING: no provider tokens, and one proof per upstream call

- `@credninja/server` no longer hands provider access tokens to callers:
  `token_format: "raw"` on `/api/v1/delegate` and `GET /api/token/:provider`
  get `403 raw_token_disabled`, and Cred Link raw tokens (Link's
  `400 invalid_request`) are refused even
  for clients with `allow_raw_tokens`. A provider token is a bearer
  credential with the connection's full scope that cannot be bound to an
  agent key or revoked per delegation. `CRED_ALLOW_RAW_TOKENS=true` restores
  raw tokens (deprecated, warns at startup). Local mode is unchanged.
- Each `/api/v1/use` DPoP proof also carries `cred_req`, base64url SHA-256 of
  the RFC 8785 (JCS) form of the whole request body (handle, URL, method,
  body, extra headers, quantities). The server recomputes it from the
  request it received, so a proof authorizes exactly one upstream call; a
  proof made for one call cannot carry another. `@credninja/sdk` `use()`
  and `cred-auth` `use()` add it.
- Cred Link, with DPoP on, issues no handle to the key-less static Bearer
  identity (`server-agent`); TOFU agents and verified principals keep their
  binding.
- Python: `cred-auth` 1.1.0 adds `agent_identity`, `create_dpop_proof()`
  and an RFC 8785 serializer (`canonical_json()`); the LangChain, CrewAI,
  OpenAI Agents, AutoGen and Semantic Kernel integrations move to 1.1.0 and
  require `cred-auth>=1.1.0`.

### BREAKING: brokered handles are bound to the agent's key (DPoP, RFC 9449)

A handle id plus the deployment's Bearer credential was enough to use a
brokered handle. Now, by default (`CRED_REQUIRE_DPOP=true`):

- `@credninja/server` issues a handle only to a did:key agent (`agent_did`;
  otherwise `400 agent_key_required`) and binds it to that key (`cnf.jkt`
  in the response, the same thumbprint the receipt's `cnf` carries).
  `/api/v1/delegate` needs a `DPoP` proof by the key; every `/api/v1/use`
  needs a fresh proof naming the request (`htm`, `htu`) and the handle
  (`ath`). Missing, stale, replayed or mismatched proofs get
  `401 invalid_dpop_proof` before any upstream call.
- Sub-delegated handles, from `/api/v1/subdelegate` or `/api/v1/token`,
  are bound to the receiving agent's key, which must be a did:key. The
  delegating agent that relays one cannot use it.
- `@credninja/sdk`: `delegateHandle()` and `use()` take `agentIdentity`
  and sign the proofs; `createDpopProof()` is exported.
- `@credninja/mcp`: cloud mode needs `CRED_AGENT_PRIVATE_KEY_HEX` for
  `cred_delegate` and `cred_use`.
- `@credninja/vercel-ai`: `credDelegateTool` and `credUseTool` take
  `agentIdentity`.
- While DPoP is on, `/api/v1/subdelegate` always requires the delegating
  agent's `actor_token`; `CRED_REQUIRE_AGENT_IDENTITY=false` is ignored
  (with a warning), so a leaked receipt cannot mint a handle bound to
  another key.
- The SDK's base URL must be the same origin and path as the server's
  `REDIRECT_BASE_URI` (`htu` is compared by scheme, host, port and path).
- The `CRED_REQUIRE_AGENT_IDENTITY=false` migration step above applies only
  with `CRED_REQUIRE_DPOP=false`.
- Python: `cred-auth` `delegate_handle()` and `use()` take `agent_identity`
  (`create_dpop_proof()` is exported), and the LangChain, CrewAI, OpenAI
  Agents, AutoGen and Semantic Kernel integrations take `agent_identity`.
- `CRED_REQUIRE_DPOP=false` keeps the old Bearer-bound handles and logs a
  deprecation warning. Raw-token delegation and Cred Link handles are
  unchanged.

### Changed: Node 26 (`@credninja/server`, CI, Docker)

- Development, CI and the server image move to Node 26 (LTS since
  2026-10-28). Node 20, which CI used, reached end of life on 2026-04-30.
  `.nvmrc` pins 26.
- BREAKING for npm consumers: every package's `engines` floor moves from
  `>=18` to `>=22`, the oldest Node release line still supported (to
  2027-04-30). CI runs the tests on Node 22 and 26.
- `@credninja/server` moves `better-sqlite3` from `^11.8.1` to `^12.6.2`,
  the range `@credninja/vault` and `@credninja/tofu` already use, so the
  workspace resolves one copy (12.11.1). 11.x has no Node 26 build.
- npm 11 asks for install scripts to be approved: `allowScripts` in the
  root `package.json` approves `better-sqlite3` (native binding) and
  `esbuild`, pinned to their locked versions. A version bump of either
  needs `npm install-scripts approve <pkg>` again.
- `packages/server/Dockerfile`: `node:26-alpine`. The image did not build
  before this change: it lacked `scripts/write-package-types.cjs`, which the
  package builds call, and the protocol, attenuation, tofu and guard
  packages the server imports. It now copies and builds all of them.

### Added: draft-02 conformance

- New package `@credninja/attenuation`, with no npm runtime dependencies: the
  scope grammar, constraint ceilings, `validateSubDelegation`,
  `verifyDelegationChain` and `parseStrictJson` move here from
  `@credninja/vault`, which re-exports them unchanged. It adds RFC 8785 JCS,
  a compact JWS signer interface (EdDSA, ES256, `kid` in the header) with a
  verifier that holds its own accepted-algorithm list, and
  `verifyAgentDelegationChain()` / `mintAgentDelegationToken()` for the
  draft-asor-wimse-agent-delegation-chain-02 Delegation Chain format. The 35
  -02 interop vectors run in CI: 35 of 35.
- `@credninja/vault`: `SqliteCumulativeLedger`, the single writer of
  `max_lifetime` and `max_subtree` running totals, debited atomically.
- `@credninja/server`: receipts signed behind the signer interface
  (`RECEIPT_SIGNING_KEY_PEM` for ES256, `RECEIPT_ACCEPTED_ALGS`); the
  cumulative ledger on `/api/v1/use` replaces the blanket deny; the
  Sub-Delegation Exchange (`exchange: "grant"` on `/api/v1/subdelegate`,
  then `POST /api/v1/token`); `token_profile: "agent_delegation"` on
  `/api/v1/delegate` and `/api/v1/subdelegate`.

### BREAKING: brokered handles by default, bound to their caller (`@credninja/server`)

- `/api/v1/delegate` returns a brokered handle when `token_format` is
  omitted. The provider token leaves the server only on an explicit
  `"token_format": "raw"`. A service with no brokered-use path answers
  `400 brokered_format_unsupported` unless `raw` is requested. The JS and
  Python `delegate()` / `tofuDelegate()` clients now send `raw` explicitly,
  so their behavior is unchanged.
- A handle from `/api/v1/delegate` or `/api/v1/token` is bound to the caller
  that minted it (agent principal, plus the Web Bot Auth key when the
  request was signed). `/api/v1/use` from any other caller answers `404`,
  the same as an unknown handle, and writes a `delegation_holder_mismatch`
  deny event. Before, any caller holding the deployment's Bearer token and a
  handle id could use it. A custom verifier caller with no `principalId`
  and no Bearer token answers `400 holder_identity_required` for a handle.
- Revoking a connection ends every live handle minted from it, instead of
  leaving them usable until their TTL (up to 900 s), and revokes the grant
  at the provider in the background. `/api/v1/use` answers
  `401 connection_revoked` when the connection behind a non-Link handle is
  gone, including after a revocation in another process.
- Permission `expiresAt`, `rateLimit` and `requiresApproval` are enforced on
  `/api/v1/delegate` (TOFU principals) and `/api/v1/subdelegate`.
  The server has no approval flow yet, so `requiresApproval: true` answers
  `403 approval_required`. `rateLimit` answers `429 rate_limited`, an expired
  permission `403 permission_expired`.

### Fixed: local mode revocation in `cred_use` (`@credninja/mcp`, `@credninja/sdk`)

- `cred_use` in local mode checks that the connection still exists before
  each call, and still holds the cached token, through the new
  `Cred.authorizeLocalUse()`, and writes an
  `access` (or `deny`) audit event. A connection revoked by any process
  sharing the vault stops the call.
- `cred_revoke` drops the cached handles for the revoked connection.

### BREAKING: caller identity on `/api/v1/subdelegate` (`@credninja/server`)

`/api/v1/subdelegate` now requires the caller to prove it is the agent the
parent receipt names, with an RFC 7523 `actor_token` signed by that agent's
did:key. Before, any caller holding the deployment's Bearer token and a
validly signed receipt could sub-delegate from it. Errors:
`401 agent_identity_required`, `403 agent_identity_mismatch`,
`403 agent_identity_unverifiable` (parent agent not a did:key).

Migration:

1. SDK callers: pass the delegating agent's identity as
   `delegatorIdentity` to `subDelegate()` / `subDelegateHandle()`; the SDK
   signs the token (`createActorToken()` is exported for other clients).
2. MCP in cloud mode: set `CRED_AGENT_PRIVATE_KEY_HEX` to the key of
   `CRED_AGENT_DID`.
3. Other clients: send `actor_token` as described in the server README.
4. Until every caller does, set `CRED_REQUIRE_AGENT_IDENTITY=false` on the
   server. That keeps the old behaviour, logs a deprecation warning at
   startup, and will be removed.

### Changed: receipt claim layout (`@credninja/server`, `@credninja/sdk` local mode)

New receipts put the principal in `sub` and the acting agent in
`client_id` and `act.sub`, with ancestors as nested `act`, plus `jti` and
`cnf`. Receipts in the old layout are still accepted everywhere, and the
SDK verifiers (TypeScript and Python) read both. A third-party verifier
that reads the agent DID from `sub` must read `act.sub` instead, or the
server can keep minting the old layout with `RECEIPT_CLAIM_LAYOUT=legacy`.
Under a cumulative constraint other than `max_calls`, `/api/v1/use` now
needs the exercise's quantity in `quantities`.

Migration: read the agent DID from `act.sub` (equal to `client_id`) and
the principal from `sub`; until every verifier does, set
`RECEIPT_CLAIM_LAYOUT=legacy`. Known downstream consumer needing the same
change: Cred Link, which is moving to `cred-ninja/link`.

### Cascading revocation (`@credninja/vault`, `@credninja/server`)

- Every delegation the server issues is recorded with its parent delegation
  (new SQLite table `vault_delegations`, created on startup; existing
  databases need no migration step). File vaults keep the records in process
  memory, like their brokered handles.
- New `DELETE /api/v1/delegations/:delegationId` revokes a delegation and,
  transitively, every delegation derived from it, and answers
  `{ revoked_count, revoked_ids, elapsed_ms, truncated }`. Agent revocation
  (`DELETE /admin/agents/:agentId`, `POST /api/v1/agents/:agentId/revoke-all`)
  now cascades the same way to every delegation issued to the agent's DID.
- `POST /api/v1/use` and `POST /api/v1/subdelegate` refuse a revoked
  delegation with `401 {"error":"delegation_revoked"}`, including a `use`
  request already in flight that has not yet gone upstream.
- One `revoke` audit event per revoked delegation, naming the revoked
  ancestor (`revokedAncestorId`) as the root cause.
- A sub-delegated handle no longer outlives its parent receipt.
- Vault: `CredVault.recordDelegation()`, `getDelegation()`,
  `revokeDelegations()`, `revokeAgentCascade()`, `writeAuditEvents()`;
  `DelegationRevokedError`; `collectDelegationSubtree()`;
  `validateSubDelegation()` takes optional `parent.expiresAt` and
  `requestedExpiresAt` and throws `expiry_escalation_denied` for a child that
  would outlive its parent.

## [2.0.0] - prepared 2026-10-13, not yet published to npm

npm only; Python package versions are unchanged. Nothing between 1.0.0 and
2.0.0 was ever published, so everything below ships in this one major. Read
the [release and migration notes](docs/releases/npm-2.0.0.md) before
upgrading.

### BREAKING: explicit user ids on the legacy routes (`@credninja/server`)

These change behavior for callers that relied on the silent fallback to the
shared `default` user. Migration, one line: set `SINGLE_USER_MODE=true` on
the server, or send `user_id` on every call.

Migration for legacy-route callers:

1. Find calls that omit `user_id` (or send it blank) to `/providers`,
   `/connect`, `DELETE /connect/:provider`, `/api/token/:provider`,
   `/api/v1/delegate`, `/api/v1/subdelegate`, `/api/v1/connections`,
   `/api/v1/audit` or `/api/v1/audit/stream`. After upgrading, they get
   `400 {"error":"user_id_required"}`. Exception: when a custom
   `agentRequestVerifier` binds the agent to a user (its principal carries
   `userId`), an omitted or blank `user_id` acts on that user, and a
   different explicit `user_id` gets `403 {"error":"user_id_mismatch"}`.
2. Single-tenant deployment that always meant the `default` user: set
   `SINGLE_USER_MODE=true` (or `singleUserMode: true` in `createServer`).
   Nothing else changes. New `create-cred-app` projects already set it.
3. Multi-user deployment: send `user_id` on every call. To keep acting on
   the old shared user, send `user_id=default` explicitly.
4. Stop building or parsing consent links by hand. Use the `consent_url`
   returned by `POST /api/v1/delegate`; it is now an opaque single-use
   `/connect/<provider>?request=<id>` link valid for 10 minutes.
5. Admin tooling that opened `/connect/<provider>?user_id=...&scopes=...`
   under the admin cookie now lands on the operator connect page. Start the
   flow there, call `POST /connect/<provider>/start`, or send the admin
   Bearer token.
6. Custom `agentRequestVerifier`: if it returns a principal with `userId`,
   requests naming a different user now get
   `403 {"error":"user_id_mismatch"}`.

- New setting `SINGLE_USER_MODE` (`singleUserMode` in `createServer`),
  default `false`. A legacy request without `user_id` (blank counts as
  missing) is now refused with `400 {"error":"user_id_required"}` instead
  of acting on `default`. With `SINGLE_USER_MODE=true` it acts on `default`
  as before. Naming `user_id`, `default` included, works in both modes. A
  request whose agent a custom `agentRequestVerifier` binds to a user
  (principal `userId`) resolves to that user instead, and a different
  explicit `user_id` gets `403 {"error":"user_id_mismatch"}`. This
  covers `/providers`, `/connect`, `DELETE /connect/:provider`,
  `/api/token/:provider`, `/api/v1/delegate`, `/api/v1/subdelegate`,
  `/api/v1/connections`, `/api/v1/audit` and `/api/v1/audit/stream`.
  `.env.example` and `create-cred-app` set `SINGLE_USER_MODE=true`.
- A custom `agentRequestVerifier` may return a principal with `userId`.
  Agent requests from it act on that user when they name none, and are
  refused with `403 {"error":"user_id_mismatch"}` when they name another.
- `consent_url` from `POST /api/v1/delegate` is now
  `/connect/<provider>?request=<id>`, a single-use connect request (10
  minutes) bound to the user id and scopes of that call. It no longer
  carries `user_id`, `scopes` or `app_client_id`; do not parse it.
- `GET /connect/<provider>?user_id=...&scopes=...` no longer starts OAuth
  under the admin session cookie: it redirects to `/connect?user_id=...`,
  where the operator starts the flow (the page uses the new
  `POST /connect/<provider>/start`, JSON `{ user_id, scopes }`, which
  answers `{ url }`). The same URL with the admin Bearer token still starts
  the flow directly.
- Links built client-side by `getConsentUrl()` (`@credninja/sdk`) and
  `get_consent_url()` (Python SDK) keep the old shape. Opened in a browser
  session they now land on the connect page for that user id, and the scopes
  in the link are not applied; prefer the `consent_url` the server returns.

### Cred Link, Phase 1 (off by default, behind `LINK_ENABLED`)

A drop-in account-connection widget and the server flow behind it. See the
Link sections of the `@credninja/server` and `@credninja/link` READMEs.

- New packages `@credninja/link` (vanilla JS) and `@credninja/link-react`.
- `@credninja/protocol`: Link contracts (wire shapes, typed error codes, the
  scope catalog, storage and policy interfaces).
- `@credninja/server`: pushed authorization requests, hosted picker and
  confirmation pages, pending-until-activate connections, the connection
  management API, and an access check on `/api/v1/delegate` and `/api/v1/use`
  that runs whether or not a Guard is configured. Requires the SQLite vault.
- `@credninja/vault`: SQLite Link store, Link token custody under reserved
  user ids, `CredVault.getStored`, connection-wide permission methods.
- `@credninja/guard`: `createLinkHooks`, `clientGrantPolicy`, and a typed
  `code` on policy results and deny responses.
- `@credninja/oauth`: `OAuthTokenError` with the parsed OAuth error code, and
  access to the raw token response for provider identity.

Polish round:

- Narrowing: `POST /link/v1/connections/:id/narrow` shrinks a grant without
  a provider round trip and intersects every permission on the connection.
  The response field `enforcement` says whether brokered calls are
  restricted too (`broker`, only when whole Google API families were
  removed) or only the records changed (`record`).
- Reconnect diff: connecting an account that is already connected shows the
  current grant next to the new one on the confirmation screen. Activation
  fails closed if the grant's scopes changed after the user confirmed.
- Popup fallback: when the popup loses its opener after the provider hop,
  the result is delivered by redirect and relayed to the waiting widget, and
  the provider is remembered as redirect-only in that browser for 30 days.
  `Cred.handleRedirect()` gains `relay` and `onRelayed`.
- Crash heal: a startup sweep resolves every activation that committed but
  never settled its token move; such a connection ends in `needs_reauth`.
- The Link SQLite schema is version 2, with a migration from version 1.
- Raw provider tokens (`allow_raw_tokens`) are refused when the delegation is
  narrower than what the provider granted.
- `@credninja/server`: the Google scope-to-endpoint table moved from
  `server.ts` to `google-scopes.ts` unchanged, so the broker and the narrow
  response share it.

### Behavior changes that apply even with Link disabled

- User ids starting with `link:` or `link-staged:` are reserved. Every route
  and every public `CredVault` method that takes a user id now refuses them.
- Brokered calls (`/api/v1/use`) refuse URLs whose path contains an encoded
  dot, slash, backslash or percent sign, dot segments, or an empty segment.
- Brokered calls to Slack `auth.revoke` and `apps.uninstall` are refused.
- Linear and HubSpot now have broker allowlist entries (Linear: the GraphQL
  endpoint only; HubSpot: the CRM, CMS, content and automation APIs).
- The OAuth callback page no longer renders provider error text or exception
  messages; it shows a generic message and a request id.
- A 2xx token response that carries an OAuth `error` and no token now throws
  instead of yielding an empty token.
- A `delegate` or `subdelegate` body that names `connection_id` is rejected
  with 400 when Link is disabled.

### npm 2.0.0 release preparation

The npm major version reflects integration changes since the public March 2026
packages; the wire-protocol version remains `0.1.0`.

- Align all twelve npm packages and internal dependency ranges at 2.0.0. Include
  the previously unpublished `@credninja/protocol`, `@credninja/tofu`,
  `@credninja/link` and `@credninja/link-react` packages.
- Publish the scaffold as `@credninja/create-app`. The unscoped npm name belongs
  to an unrelated project. Update quickstart commands and the packaged-install
  smoke test to use the scoped package.
- Add repository, homepage, and issue links to package metadata.
- Allow npm and PyPI release versions to advance independently while checking
  version consistency within each ecosystem.
- Make the release-hygiene checker work with Windows filesystem paths.

### Included changes since the public npm 1.0.0 release

- Brokered delegation handles and authenticated upstream calls through
  `delegateHandle()` / `use()`; brokered framework integration tools.
- Brokered-only server sub-delegation, signed receipt ancestry, parent-bounded
  expiry, constraint ceilings, and offline receipt-chain verification.
- Protocol-version negotiation with explicit unsupported-version errors.
- Web Bot Auth request signing and verified-identity requirements for sensitive
  agent identity operations.
- Guard policies integrated into MCP handlers, provider discovery, audit
  inspection, identity lifecycle tools, and permission introspection.
- Admin permission CRUD, incremental audit reads, and revocation-event streaming.
- Dependency updates and the fixes already merged into main through `ff00421`.


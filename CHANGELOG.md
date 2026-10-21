# Changelog

## [Unreleased]

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


# Changelog

## [Unreleased]

### Added (`@credninja/guard`)

- `classificationCeilingPolicy`: denies resources classified above the
  agent's ceiling over an ordered list of levels, with an optional
  `noWriteDown` check on source and destination levels. Fails closed on
  unknown levels and unknown agents. DENY results carry a typed `code`
  (`classification_exceeded`, `write_down_blocked`,
  `classification_unknown`, `classification_missing`, `ceiling_unknown`).
- `amountLimitPolicy`: caps monetary amounts (integer minor units) per
  request and per rolling period, in one currency, with per-agent
  overrides. Period totals live in an injectable `AmountLimitStore`
  (`InMemoryAmountLimitStore` by default) and count only allowed amounts.
  DENY codes: `amount_exceeds_per_request`, `amount_exceeds_period`,
  `amount_missing`, `amount_invalid`, `currency_mismatch`,
  `amount_store_error`.
- Both policies key agent entries by `agentTokenHash` only. DID-keyed
  entries apply only with `trustAgentDid: true`, which must be enabled only
  when `agentDid` comes from verified authentication state (the bundled
  Express and MCP adapters currently take it from request input).

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


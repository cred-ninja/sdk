# Changelog

## [Unreleased]

### Added: consent records, approvals and CIBA

- `@credninja/server`: a did:key agent's Permission is now checked at
  `/api/v1/delegate`. A Permission that requires approval names its
  approver (`approver`: `subject`, the default, `admin`, or `both`). Such a
  delegation is asked for at `POST /bc-authorize` (OpenID CIBA, poll mode;
  the request is bound to the agent's DPoP key) and redeemed at
  `/api/v1/token` with `grant_type=urn:openid:params:grant-type:ciba`. The
  subject is asked through the built-in approval page, a signed single-use
  link posted to `CRED_APPROVAL_WEBHOOK_URL`, or through an external
  OpenID Provider's CIBA endpoints (`CRED_CIBA_*`); admins decide at
  `/admin/approvals`. An approved consent (`source: "ciba"`) is reused for
  later requests it covers for `CRED_CIBA_CONSENT_TTL_SECONDS` (default one
  day); a broader request, an expired consent or a security event
  (`POST /admin/consents/revoke`) means asking again, and tokens under a
  revoked consent are refused at exercise (`401 consent_revoked`).
  Approval requests are held in process memory.
- Consent records are kept `CONSENT_RETENTION_DAYS` (at least 90, the
  default) after the later of grant and expiry, then purged daily; the
  purge is recorded in the audit chain. Consent revocations are a
  separate append-only table; records are never edited.
- `@credninja/vault`: `Permission.approver`; `revokeConsents`,
  `getConsentRevocation`, `findConsents`, `purgeConsents`.

### Changed: per-exercise ceilings, measured by the server

- `@credninja/server`: every constraint is decided from what the server
  measures; `quantities` in the `/api/v1/use` body is no longer read.
  Metered keys: `calls`/`max_calls`, `method`, `destination`,
  `request_bytes` (before the upstream call) and `response_bytes`,
  `items`/`rows`/`max_rows`/`max_results` (from the response). The
  per-exercise types `max`, `min`, `one_of`, `not_one_of`, `prefix` and
  `rank` are now enforced at exercise (`403 ceiling_exceeded`); a response
  over a bound is withheld (`withheld: true`, with the `upstream_status`
  of the call that ran, so a completed write is not retried) and audited
  with its measurement, never truncated; records are counted on the whole
  response body, in every array reachable through objects whatever the
  provider names it, not inside the records; a response whose records
  cannot be counted is withheld (`unmeasurable_response`); a request-side
  debit is given back when the upstream cannot be reached; a
  `destination` prefix holds only at a URL boundary; methods compare in
  upper case; a catalogue listing with a page-size parameter
  (`per_page`, `pageSize`) is capped at an item bound up front. A
  constraint on a key with no meter cannot be decided, so an exercise
  under it is refused (`403 unmetered_constraint`); it is still carried
  and narrowed across hops. `calls` is a running count, so a per-call
  `max` on it is refused at issuance. Method-override query parameters
  are refused in any spelling (`$httpMethod`, `_HttpMethod`, `_method`,
  `method`, ...).

### Added: capabilities and the operation catalogue

- `@credninja/server`: `/api/v1/delegate` and `/api/v1/subdelegate` accept
  `authorization_details` (RFC 9396, type `cred_delegation`). An operation
  is a granted OAuth scope, which allows what that scope allows, or a
  catalogue operation, which allows one method and URL template: GitHub
  (`github.user.get`, `github.repos.get`, `github.contents.get`,
  `github.issues.{list,get,create,comment}`, `github.pulls.{list,get}`)
  and Google Drive (`drive.files.{list,get,export,create}`). Resources
  narrow a catalogue operation: `repo:owner/name` (case-insensitive) or
  `file:<id>`. Unknown operations and resource kinds are refused at
  issuance (`400 invalid_authorization_details`) and calls outside the
  capabilities are refused at exercise (`403 capability_denied`). A child
  is held within its parent's capabilities (`403
  capability_escalation_denied`); a child that names none inherits a
  narrowed parent's. Without `authorization_details`, a token's
  capabilities are its granted scopes, as before. A token names scopes or
  catalogue operations, never both: a scope operation allows what the
  broker lets that scope do (for GitHub, the whole API), so beside a
  narrowed entry it would silently widen it. `authorization_details` is
  refused on raw-token and Cred Link requests. Brokered calls never
  forward a method override (`X-HTTP-Method-Override`, `$httpMethod`).
  Drive folder resources are not offered: holding a listing to a folder
  would mean parsing Drive's query language.
- `@credninja/sdk`: `authorizationDetails` on `delegateHandle()`,
  `subDelegateHandle()` and `subDelegateGrant()`.

### BREAKING: Delegation Tokens replace brokered handles

- `@credninja/server`: `/api/v1/delegate`, `/api/v1/subdelegate` and the
  `/api/v1/token` exchange issue a Delegation Token
  (draft-sweeney-wimse-credential-delegation-02 Section 5): a JWT (`typ`
  `dt+jwt`) carrying `iss`, `sub`, `client_id`, `act`,
  `authorization_details` (type `cred_delegation`, the granted scopes as
  operations), `delegation_constraints`, `cnf.jkt`, `consent_id`,
  `credential_handle` and `prf` (the receipts' SHA-256 content
  identifiers), with `token_type` `DPoP`. It is issued only to a did:key
  agent. `/api/v1/use` takes `Authorization: DPoP <token>` and a DPoP proof
  whose `ath` covers the token; the body no longer names a delegation.
  Bearer-bound handles, `token_format`-without-key and the
  `delegation-handle` token type are gone. The delegation state behind a
  token is recorded in the vault, so tokens survive restarts and work
  across replicas sharing one vault. `CRED_REQUIRE_DPOP=false` now affects
  Cred Link only, and `CRED_REQUIRE_AGENT_IDENTITY=false` is ignored.
  Exercise authenticates with the token alone: the deployment Bearer
  credential and a custom `agentRequestVerifier` no longer gate
  `/api/v1/use` (guard policies key on the token's agent and key).
  Revoking a connection revokes every delegation issued from it. A token
  under a cumulative constraint is refused by a process whose ledger does
  not hold its running total (a restart or another replica), unless a
  shared `cumulativeLedgerPath` is configured.
- `@credninja/vault`: delegation records carry the token's grant state;
  consent records (`recordConsent`, `getConsent`) are stored once and
  never updated.
- `@credninja/attenuation`: `mintDelegationToken`,
  `verifyDelegationToken`, `delegationTokenAth`, `receiptContentId`.
- `@credninja/sdk`: `delegateHandle()` requires `agentIdentity` and
  returns `token`; `use()` takes `token` and `agentIdentity`; new
  `subDelegateGrant()` and `redeemDelegationGrant()`. MCP and
  `@credninja/ai` keep the token in-process and show the model only an id.
- Cred Link handles are unchanged in this release step; Link moves to
  Delegation Tokens next.

### Added: tamper-evident audit log; receipts name their issuer

- `@credninja/vault` (SQLite storage): every audit row carries an HMAC-SHA256
  over the previous row's hash and its own stored fields, under a key
  derived from the vault passphrase and never stored. `verifyAuditChain()`
  reports the first missing, edited or reordered entry; `auditChainHead()`
  returns the newest entry to record outside the host, which is what shows
  a truncated tail. Rows written before this release stay unchained and are
  counted as such; their number is bound into the first chained entry, so
  an unchained row added later, or a chained row stripped of its chain
  columns, is reported as a break at entry 1. An audit write fails (and
  with it the operation) if the vault has not been initialized. The hash
  covers every column listed in `AUDIT_CHAIN_FIELDS`; a field added to
  `AuditRow` without being listed fails to compile. Exported:
  `auditChainHash`, `auditChainGenesis`, `AUDIT_CHAIN_GENESIS`,
  `AUDIT_CHAIN_FIELDS`, `AuditChainHead`, `AuditChainVerification`.
- `@credninja/vault`: `CredVault.init()` refuses a passphrase other than the
  one the vault was created with, before any read or write, instead of
  failing later at decryption (and, until now, extending the audit chain
  under the wrong key). The check value is an HMAC of the derived key in
  `<path>.check`, next to `<path>.salt`, written mode 0600 and only if
  absent, so processes creating a vault at once agree on one salt and one
  check value. It holds no key material, but with the salt it allows
  offline passphrase guessing, as the vault file does. A vault created
  before this release gets one on its first init; if that init used a
  mistaken passphrase, remove the file and start again. Removing the salt
  starts a new vault and a new check value.
- **Breaking** for code that uses `SQLiteBackend` directly: `writeAuditEvent`
  throws until `setAuditChainKey()` has been called (`CredVault.init()` does
  this). Custom `StorageBackend` implementations need no change; without the
  optional `verifyAuditChain` the verify route answers `501`. The exported
  `SQLiteAuditBackend` writes unchained rows: do not point it at a vault
  database, where verification reports its rows as tampering.
- `@credninja/server`: `GET /admin/audit/verify` (admin token) runs the
  check. Receipts now carry the Delegation Server's identifier
  (`REDIRECT_BASE_URI`) in `iss` instead of the fixed `did:key:local-cred`,
  and a parent receipt naming any other issuer is refused. The old value is
  accepted only on a receipt issued (`iat`) before the server process
  started, so the allowance ends one receipt lifetime after the upgrade.
- `@credninja/sdk` local mode: receipts name their signer, the did:key of
  the local receipt signing key, in `iss`, and a parent receipt naming any
  other issuer is refused (`invalid_parent`). The old `did:key:local-cred`
  is accepted only on a receipt issued before the `Cred` instance was
  created.

### Changed: delegation lifetimes and the draft's revocation path (`@credninja/server`)

- Receipts default to 15 minutes (was 1 hour) and `RECEIPT_TTL_SECONDS`
  above 3600 fails at startup, as Section 10.6 of
  draft-sweeney-wimse-credential-delegation requires. A brokered handle
  lives no longer than its receipt lifetime or the provider token it
  brokers. Legacy receipts minted without `exp` now age out at `iat` plus
  the same lifetime, 15 minutes by default.
- `DELETE /delegation/:delegationId`, the path the draft names, revokes
  exactly as `DELETE /api/v1/delegations/:delegationId` does. A test
  measures a single revocation under 1 second, after which the handle is
  refused.

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


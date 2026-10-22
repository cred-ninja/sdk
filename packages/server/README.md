# @credninja/server

Self-hosted credential delegation server for AI agents.

Stores OAuth tokens in an encrypted vault and can either serve delegated access tokens to authenticated agents or broker upstream API calls behind opaque delegation handles.

## Quick Start

```bash
# Install
npm install @credninja/server

# Set up configuration
cp node_modules/@credninja/server/.env.example .env
# Edit .env — set VAULT_PASSPHRASE, ADMIN_TOKEN, AGENT_TOKEN, and at least one provider

# Run
npx cred-server
```

Or from the repo:

```bash
cd packages/server
cp .env.example .env
# Edit .env
npm run dev
```

## How It Works

```
┌─────────────────┐         ┌──────────────────────┐         ┌─────────────┐
│   AI Agent      │  HTTP   │   Cred Server        │  OAuth  │  Google     │
│   (Machine B)   │────────▸│   (Machine A)        │────────▸│  GitHub     │
│                 │◂────────│                      │◂────────│  Slack ...  │
│  Bearer token   │  token  │  Encrypted vault     │  tokens │             │
└─────────────────┘         └──────────────────────┘         └─────────────┘
```

1. **Admin connects providers** — Sign in at `/admin/login`, then complete OAuth
2. **Tokens stored encrypted** — AES-256-GCM, PBKDF2-SHA256 key derivation
3. **Agent requests delegation** — `POST /api/v1/delegate` with Bearer auth
4. **Server returns a handle or access token** — Brokered handles keep provider tokens on the server; legacy token routes remain available.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | None | Liveness check |
| GET | `/.well-known/http-message-signatures-directory` | None | Web Bot Auth key directory |
| GET | `/admin/login` | None | Admin login form |
| POST | `/admin/login` | None | Create admin session cookie |
| GET | `/providers` | Admin | List configured providers + connection status |
| GET | `/connect` | Admin | Browser UI for managing provider connections |
| GET | `/connect/:provider` | Admin | Start OAuth flow (browser): `?request=<id>` from a connect request; see [User ids](#user-ids) |
| POST | `/connect/:provider/start` | Admin | JSON `{ user_id, scopes }`: mint a single-use connect request, answers `{ url }` |
| GET | `/connect/:provider/callback` | None | OAuth callback |
| POST | `/api/v1/delegate` | Bearer | Primary v1 delegation endpoint |
| POST | `/api/v1/subdelegate` | Bearer | Sub-delegate from a verified parent receipt. Always returns a brokered handle (never the raw provider token), regardless of the requested `token_format` — see note below |
| POST | `/api/v1/use` | Bearer | Broker an upstream API call with a delegation handle. Under a cumulative constraint the call is debited against the running totals first (see below) |
| POST | `/api/v1/token` | Bearer + actor token | Sub-Delegation Exchange step 2: RFC 8693 token exchange redeeming a single-use delegation grant from `/api/v1/subdelegate` with `exchange: "grant"` |
| DELETE | `/api/v1/delegations/:delegationId` | Bearer | Revoke a delegation and every delegation derived from it, see [Cascading revocation](#cascading-revocation) |
| GET | `/api/v1/connections` | Bearer | List stored connections for SDK compatibility |
| DELETE | `/api/v1/connections/:provider` | Bearer | Revoke stored credentials for SDK compatibility |
| POST | `/api/v1/tofu/register` | Bearer | Register a TOFU identity |
| GET | `/api/v1/web-bot-auth/keys` | Bearer | List registered Web Bot Auth identities |
| POST | `/api/v1/web-bot-auth/keys` | Bearer | Register or import a Web Bot Auth public key |
| POST | `/api/v1/web-bot-auth/keys/:agentId/rotate` | Bearer + verified identity | Rotate a registered Web Bot Auth key — see [Security](#security) |
| POST | `/api/v1/agents/:agentId/revoke-all` | Bearer + verified identity | Revoke a stored agent record — see [Security](#security) |
| GET | `/api/token/:provider` | Bearer | Compatibility delegation route |
| DELETE | `/api/token/:provider` | Bearer | Revoke stored credentials |
| POST | `/admin/link/clients` | Admin | Register a Cred Link client, see [Cred Link](#cred-link-phase-1) |
| GET | `/admin/link/clients` | Admin | List Cred Link clients |
| POST | `/admin/link/clients/:client_id/disable` | Admin | Disable a Cred Link client (its connections stop working) |
| POST | `/admin/link/clients/:client_id/enable` | Admin | Re-enable a Cred Link client |
| POST | `/link/v1/par` | Link client | Pushed request (connect, update, reauth); returns the widget `request_uri` |
| GET | `/link/v1/authorize` | None (request_uri) | Hosted flow entry, renders the provider picker |
| POST | `/link/v1/picker` | None (envelope + cookie) | Picker submission, redirects to the provider |
| GET | `/link/v1/callback/:provider` | None (provider state) | Provider callback, renders the scope confirmation |
| POST | `/link/v1/confirm` | None (envelope + cookie) | Confirm, back or cancel; delivers the result |
| GET | `/link/v1/connections?subject=` | Link client | List a subject's connections |
| GET | `/link/v1/connections/:id` | Link client | Connection status, provider, subject, grant |
| DELETE | `/link/v1/connections/:id` | Link client | Revoke the grant and delete secrets; revoke at the provider when safe (`provider_revoked`) |
| POST | `/link/v1/connections/:id/activate` | Link client | `{ code, subject }`: pending to active (or commit a staged update) |
| POST | `/link/v1/connections/:id/refresh` | Link client | Force a refresh, status only |
| POST | `/link/v1/connections/:id/reauth` | Link client | `{ subject }`: reauth pushed request |
| POST | `/link/v1/connections/:id/permissions` | Link client | `{ agent_id, scopes }`: grant an agent scopes within the grant |
| POST | `/link/v1/connections/:id/narrow` | Link client | `{ subject, scopes }`: narrow the grant to a subset, no provider round trip |

> **Sub-delegation is broker-only.** Scope attenuation on a raw provider access token can't be
> enforced once it has left the server, so every response from `/api/v1/subdelegate`
> (chain depth ≥ 1) is a brokered handle, even if the request sends `"token_format": "raw"`.
> A downgraded request gets `token_format_enforced: "brokered"` (and `requested_token_format`)
> in the response instead of an error. If the target service has no brokered-use path
> (`POST /api/v1/use`) at all, the request is rejected with `400 brokered_format_unsupported`
> rather than minting a handle that could never be redeemed. `/api/v1/subdelegate` also checks
> the status of *every* ancestor agent in the delegation chain — not just the immediate parent —
> before minting a child receipt, so revoking a grandparent (or any earlier ancestor) still blocks
> new descendants even if the presenting parent agent is itself still active. This is enforced via
> a signed `lineage` claim each receipt carries (extended at every hop), alongside the
> delegation records [Cascading revocation](#cascading-revocation) walks; receipts minted before this claim existed carry no
> lineage and degrade to a parent-only check for that hop until they age out under
> `RECEIPT_TTL_SECONDS`. Delegation receipts also now carry an `exp` claim (see
> `RECEIPT_TTL_SECONDS` below) — expired parent receipts are rejected.

> **Delegation receipts (draft-sweeney-wimse-credential-delegation-02).** Receipts are
> compact JWS behind a signer interface: EdDSA by default (the passphrase-derived Ed25519 key,
> as before), ES256 when `RECEIPT_SIGNING_KEY_PEM` holds a P-256 key, or any `receiptSigner`
> passed to `createServer`. The header carries `kid`. The server verifies with its own
> accepted-algorithm list (`RECEIPT_ACCEPTED_ALGS`); a receipt whose `alg` is off the list or
> differs from its key's algorithm is rejected. New receipts use the -02 claim layout: the
> principal in `sub`, the acting agent in `client_id` and `act.sub`, ancestors as nested `act`,
> the delegation id as `jti`, and `cnf.jkt` bound to the agent's did:key. Receipts in the old
> layout (agent in `sub`) are still accepted; `RECEIPT_CLAIM_LAYOUT=legacy` keeps minting them
> for verifiers that key on `sub`.
>
> **Migration.** A verifier of your own that reads the agent DID from receipt `sub` must read
> `act.sub` (equal to `client_id`) instead, and the principal from `sub`. Until it does, set
> `RECEIPT_CLAIM_LAYOUT=legacy` on the server. The SDK verifiers (`verifyDelegationReceipt`,
> Python `verify_delegation_receipt`), SDK local mode, and the server's own receipt checks already
> read both layouts. The SDK verifiers check EdDSA (Ed25519) receipts only: with a P-256
> `RECEIPT_SIGNING_KEY_PEM` the server mints ES256 receipts they reject, so keep the default EdDSA
> key while clients verify receipts with the SDK.

> **Cumulative constraints.** `max_lifetime` and `max_subtree` are enforced by this server as
> the single writer of their running totals. `/api/v1/use` debits, in one SQLite transaction, the
> delegation's own `max_lifetime` and every `max_subtree` held by it or an ancestor, right before
> the upstream call. `max_calls` is metered at one per call; any other cumulative key needs the
> exercise's quantity in `quantities` (`{"max_spend": 12}`), and a call without it is refused with
> `403 cumulative_quantity_required`. Past a bound: `403 cumulative_constraint_exceeded`. A
> delegation whose ancestors the ledger does not hold (for example after a restart with the
> in-memory default) is refused with `403 cumulative_constraint_unenforceable`, never given a
> fresh budget. Set `CUMULATIVE_LEDGER_PATH` to keep the totals across restarts.

> **Caller identity on sub-delegation.** A valid parent receipt is not authority on its own.
> `/api/v1/subdelegate` requires `actor_token`: an RFC 7523 JWT signed with the did:key of the agent
> the parent receipt names (`act.sub`, whose key the receipt's `cnf` binds), with `iss` = `sub` =
> that DID, `aud` = `<REDIRECT_BASE_URI>/api/v1/subdelegate`, `exp` at most `iat` + 300 and a fresh
> `jti`. Missing: `401 agent_identity_required`. Signed by another key or for another DID: `403
> agent_identity_mismatch`. Parent agent not a did:key: `403 agent_identity_unverifiable`. The SDK
> signs it when `subDelegate()` gets `delegatorIdentity`; the MCP server when
> `CRED_AGENT_PRIVATE_KEY_HEX` is set. `CRED_REQUIRE_AGENT_IDENTITY=false` restores the old
> behaviour (any Bearer caller holding the receipt) and logs a deprecation warning.

> **Sub-Delegation Exchange.** With `"exchange": "grant"`, `/api/v1/subdelegate` runs every hop
> check and signs the child receipt, but issues no handle: it returns a single-use
> `delegation_grant` (60 seconds by default) bound to the receiving agent's DID. The receiving
> agent redeems it at `POST /api/v1/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
> the grant as `subject_token` (`subject_token_type=urn:credninja:params:oauth:token-type:delegation-grant`),
> and as `actor_token` an RFC 7523 JWT it signed with its own did:key (`iss` = `sub` = its DID,
> `aud` = `<REDIRECT_BASE_URI>/api/v1/token`, `exp` at most `iat` + 300, a fresh `jti`). A second
> redemption is `invalid_grant`; an actor token for another DID is `401 invalid_client` and leaves
> the grant redeemable by the right agent.

> **Chain-Verifiable Profile.** `"token_profile": "agent_delegation"` on `/api/v1/delegate` or
> `/api/v1/subdelegate` (optional `audience`, and `max_depth` on a root) also returns
> `agent_delegation_token`, a token in the draft-asor-wimse-agent-delegation-chain-02 format,
> unchanged, signed with the receipt key, that a party holding only the chain verifies with
> `verifyAgentDelegationChain()` from `@credninja/attenuation`. A child needs the parent's chain,
> root first, as `agent_delegation_chain`. The agent must be an Ed25519 or P-256 did:key so the
> token can carry `cnf`. The receipt records the token's `jti` and the scope mapping
> (`chain_profile`).

## Cascading revocation

Every delegation the server issues (`/api/v1/delegate`, `/api/v1/subdelegate`)
is recorded in the vault with the id of the delegation it was derived from.
Revoking one revokes all of its descendants:

```bash
curl -X DELETE "https://cred.example.com/api/v1/delegations/del_abc?user_id=alice" \
  -H "Authorization: Bearer $CRED_AGENT_TOKEN"
# {"delegation_id":"del_abc","revoked_count":3,"revoked_ids":[...],"elapsed_ms":1.9,"truncated":false}
```

- The walk is iterative and cycle-safe, bounded at 64 hops below the revoked
  delegation (`truncated: true` if it ever stops there). On SQLite the walk
  and every write run in one transaction: the whole subtree is revoked or
  none of it is.
- `POST /api/v1/use` refuses a revoked handle with
  `401 {"error":"delegation_revoked","revoked_ancestor_id":...}`, and checks
  again right before the upstream call, so a request already in flight is
  refused too. `/api/v1/subdelegate` refuses a revoked parent the same way,
  atomically with recording the child.
- Revoking an agent (`DELETE /admin/agents/:agentId`,
  `POST /api/v1/agents/:agentId/revoke-all`) revokes every delegation issued
  to its DID and everything below them. These routes still answer `204`; the
  agent's `revoke` audit event carries `revokedCount`.
- Each revoked delegation gets its own `revoke` audit event (resource
  `service/user`) whose metadata names `delegationId`, `parentDelegationId`,
  `revokedAncestorId` (the root cause), `cascadeDepth` and `revocationTime`.
- 1,111 delegations revoke in about 12 ms on SQLite (about 90 ms for the
  whole HTTP request including the audit writes); a test holds it under 5 s.

Limits: raw provider tokens already handed out cannot be recalled and live
until they expire. Delegations issued before this release have no record, so
a cascade does not reach them; they age out under their receipt and handle
TTLs. Brokered handles live in process memory, so this holds within one
server process (the draft scopes it to one Delegation Server). Revocation
records are not garbage-collected yet.

## User ids

Every legacy route that acts on stored provider tokens (`/providers`,
`/connect`, `/api/token/:provider`, `/api/v1/delegate`,
`/api/v1/subdelegate`, `/api/v1/connections`, `/api/v1/audit` and its
stream) works for one user id, sent as `user_id` in the JSON body or the
query string. Cred Link routes are not affected.

- **Multi-user mode (the default).** A request without `user_id` (or with a
  blank one) is refused with `400 {"error":"user_id_required"}`, so a
  backend that forgets it on one call never silently acts on someone else's
  tokens. Browser pages (`/connect`, and `/providers` for a browser) answer
  with a short page saying to add `?user_id=`.
- **Single-user mode** (`SINGLE_USER_MODE=true`). A request without
  `user_id` acts on the shared user `default`, as in earlier versions. The
  quickstart `.env.example` sets this.

Naming a user id explicitly works in both modes, `default` included. The
reserved Link ids (`link:...`, `link-staged:...`) are always refused. The
server logs the mode once at startup.

**Agents bound to a user.** A custom `agentRequestVerifier` may return a
principal with `userId`. A request from that agent without `user_id` then
acts on that user (in both modes), and one that names a different
`user_id` is refused with `403 {"error":"user_id_mismatch"}`. The static
`AGENT_TOKEN` principal is never bound to a user. Admin routes are not
affected.

**Starting a connection.** `GET /connect/:provider` no longer takes the user
id and scopes from the query string when the browser is signed in with the
admin session cookie (that cookie is sent on a cross-site top-level link, so
a crafted link could otherwise connect an account under a user id and scopes
the operator did not choose). Instead:

- `POST /api/v1/delegate` answers `consent_required` with a `consent_url` of
  the form `/connect/<provider>?request=<id>`: a single-use connect request
  (random 256-bit id, 10 minutes) bound to the user id and scopes of that
  call. Open it signed in as the operator.
- The `/connect?user_id=<id>` page starts a connection with
  `POST /connect/<provider>/start` (JSON `{ user_id, scopes }`, answers
  `{ url }`, requires `Content-Type: application/json`) and then opens that
  url.
- `GET /connect/<provider>?user_id=...&scopes=...` with the admin Bearer
  token (scripts, curl) still starts the flow directly, since a Bearer
  header cannot be sent cross-site. With only the session cookie it starts
  nothing and redirects to `/connect?user_id=...`.

An unknown, expired, already used or wrong-provider request id gives a
generic error page with a request id; nothing starts.

## Cred Link (Phase 1)

Cred Link is the hosted account-connection flow behind `@credninja/link` and
`@credninja/link-react`. With `LINK_ENABLED=true` this server serves the
`/link/v1/*` routes itself (self-hosted, SQLite). Raw provider credentials
never reach the developer's code: the developer receives a `connection_id`,
and agents receive brokered handles.

**Setup**

1. Set `LINK_ENABLED=true` and `VAULT_STORAGE=sqlite`. Optionally set
   `LINK_STORE_PATH` and `LINK_BASE_URL`.
2. At every provider you offer through Link, register
   `<LINK_BASE_URL>/link/v1/callback/<provider>` as an OAuth redirect URI
   (for example `https://cred.example.com/link/v1/callback/google`). Link uses
   the same `<PROVIDER>_CLIENT_ID` / `_CLIENT_SECRET` as the admin connect UI.
3. Register each developer app as a Link client (admin auth):

   ```bash
   curl -X POST https://cred.example.com/admin/link/clients \
     -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
     -d '{"name":"Acme","redirect_uris":["https://app.example.com/cred/return"],"origins":["https://app.example.com"]}'
   ```

   The response carries `client_secret` once (only its SHA-256 is stored).
   `name` is required: it is the app name the consent pages show (unless the
   registered `theme.appName` overrides it), and the logo comes only from the
   registered `theme.logoUrl`; the browser can change only cosmetic theme
   fields. RSA client keys must be at least 2048 bits.
   For `private_key_jwt`, send `"token_endpoint_auth_method":"private_key_jwt"`
   and `"jwks":{"keys":[...]}` (public RSA, EC or Ed25519 keys). Redirect URIs
   and origins must be https (plain http only on loopback); redirect URIs may
   not carry a fragment or any Link result parameter (`cred_link`, `code`,
   `state`, ...). `"allow_raw_tokens": true` is the operator's per-client
   escape hatch for raw provider tokens (see below).

**Client authentication.** `client_secret_basic` (`Authorization: Basic`,
RFC 6749 2.3.1) or `private_key_jwt` (RFC 7523): the assertion travels as
`Authorization: Bearer <jwt>` on every route, or as `client_assertion_type` +
`client_assertion` body fields on routes with a body. `iss` = `sub` =
client_id, `aud` = `REDIRECT_BASE_URI` (or `LINK_BASE_URL`), `exp - iat` at
most 300 seconds, `jti` single use. Every client authentication failure, and
every lookup of an unknown or foreign connection, answers exactly
`401 {"error":"access_denied"}` with a `Cred-Request-Id` header.

**Flow.** The backend pushes `POST /link/v1/par` and hands the returned
`request_uri` to the widget; the user picks a provider and permissions,
consents at the provider, confirms what the provider actually granted (and
may narrow it), and the widget reports `connection_id` and a one-time `code`.
The connection stays `pending` until the backend calls
`POST /link/v1/connections/:id/activate` with that code and the `subject` of
its own current session; any mismatch revokes it. Transactions expire after
10 minutes; anything unactivated is cleaned up by a background sweep (and
revoked at the provider under the revocation rule below). Activation runs,
under the connection's token lock: the database commit, the token move, the
permission intersect for an existing grant (every agent Permission clipped to
the new grant and the previous one), and only then marks the activation
settled. If the token move fails, the connection is set to `needs_reauth`,
never left active without tokens. If that write fails, the staged
tokens are kept, the activation stays unsettled for the startup heal, and
the connection is quarantined in memory: until a later activation of it
succeeds or it is revoked, this process hands out no token for it and does
not refresh it (calls are refused with `reauth_required`), so nothing
rewrites the connection before the next start reverts it. If the intersect
fails, the client gets the opaque failure (the grant audit record is still
written) and the activation stays unsettled; the startup heal runs the
intersect again.

**Startup heal.** Every activation that is not settled (the process died
between the database commit and the settle, or a step failed) is resolved
once at the next start, before Link serves any request (the `/link/v1/*`
routes and the Link branches of `/api/v1/delegate` and `/api/v1/use` wait for
it; other routes do not). Before Link opens, only local work happens: for
every transaction whose connection still exists, the permission intersect
with the connection's current grant runs first (whatever its status; it
never widens). It stands in for the activation's own call, so it clips to
the grant's scopes from just before that activation when the transaction
recorded them (an update, reauth or reconnect), and to the current grant
otherwise. Then:

- no staged tokens left: settled. An active connection with no stored
  tokens at all becomes `needs_reauth`.
- staged tokens equal to the stored ones: settled; the leftover staged copy
  is deleted afterwards.
- the connection was written since that activation (a later reauth, update
  or narrowing, the activation's own failure handling, or the heal's own
  earlier pass; detected as a status other than active or an `updated_at`
  that is not the activation time): stale. The connection is left alone, the
  staged copy is deleted locally, nothing is revoked at the provider.
- the activation created the connection and the connection holds tokens:
  the move finished and a refresh rotated the tokens since; settled.
- a refresh token was staged and the stored one equals it: moved then
  refreshed, or never moved and the provider answered the re-consent with the
  same refresh token, which cannot be told apart. The staged refresh token is
  written onto the connection marked expired (keeping whichever access token
  expires later), so the next use refreshes with
  that refresh token (the same credential either way) and gets tokens for
  the current consent; a refresh that fails with `invalid_grant` moves the
  connection to `needs_reauth` as usual. Settled; the connection stays
  active.
- otherwise the move never happened: the connection becomes `needs_reauth`
  (`reauth_required`) and keeps its old tokens for an update or reauth.

Provider revocation of discarded staged tokens (under the revocation rule
below, bounded by the provider call timeout, never while the connection
holds tokens) and the deletion of staged copies run afterwards in the
background. A reverted or stale transaction stays unsettled until that is
done, so a restart finds it again. A transaction whose intersect or any
other step fails is logged and left unsettled for the next start; startup
never fails because of it. The first start after upgrading from a version 1
Link database re-checks every earlier activation once (that version did not
record whether the token move finished); no provider is called before Link
opens. The heal does not re-run `onActivate`: if a crash skipped the seeding
of the pushed `agent_id`'s Permission, that agent is refused until the app
adds it with `POST /link/v1/connections/:id/permissions`.

Known limits of the heal:

- Two cases fail closed (a working connection ends `needs_reauth` and the
  user reconnects): an update or reauth on a provider that rotates refresh
  tokens, a crash inside the token move, and a refresh before the next start;
  and a transaction where no refresh token was staged and the access token
  was refreshed before the heal decided (this needs an earlier start whose
  heal failed for that transaction, or a version 1 leftover).
- If the process dies after the heal marked a connection `needs_reauth` but
  before the background revocation ran, the next start treats the
  transaction as stale and only deletes the staged tokens locally; they are
  never revoked at the provider.
- A leftover staged copy whose background deletion failed after its
  transaction was settled is never swept; it is an orphan that no connection
  reads again.
- The heal's intersect with the pre-activation scopes strips a Permission
  the app set for a newly added scope between a failed-hook response and the
  restart (fails closed).
- Two missed intersects in a row (a store failure during a narrowing, then a
  store failure, not a crash, during the next widening) leave the stale
  Permission usable until the next start.
- `setAgentPermission` racing a widening activation can have its new scope
  stripped (fails closed).
- The in-memory quarantine dies with the process; the next start reverts
  the connection as long as nothing rewrote its row.

**Reconnecting an account.** When a connect flow lands on a provider account
this client and subject already have connected, the confirmation screen shows
what the app can do today and what it keeps, gains and loses on confirm.
Confirming replaces the grant with exactly the confirmed permissions; anything
unchecked or not offered in this flow is removed. The form carries which grant
and which scopes the page was rendered against (or that it showed none); if
the account's grant is different when the user confirms (another flow went
live, or its scopes changed), the page is shown again with the current
picture instead of committing. What the page showed is recorded with the
confirmation, and activation compares it with the grant's scopes at that
moment: an update, reauth or reconnect whose grant scopes changed after the
screen (a narrowing, a provider scope reduction, or another activation) is
refused, the client gets the opaque failure, the staged tokens are discarded
under the revocation rule, and the newer grant stands. A status change alone
does not refuse it: a reauth confirmed while the old token was still
working activates normally after that token died and the connection went to
`needs_reauth`.

**Narrowing without a round trip.** `POST /link/v1/connections/:id/narrow`
with `{ "subject", "scopes" }` replaces the grant with a subset of itself
(canonical scope names, non-empty, keeping every scope the provider always
grants). It answers `{ connection, changed, removed_scopes, enforcement }`;
repeating it with the same scopes answers `changed: false` and changes
nothing (it re-runs the Permission intersect). A grant that changed
underneath the request answers `503 temporarily_unavailable`; retry it.

What narrowing enforces, exactly. Narrowing never contacts the provider and
never changes the stored token, which keeps every scope the provider
granted.

- Always: the grant and every agent Permission shrink, and agents can no
  longer request or be issued the removed scopes (`/api/v1/delegate` refuses
  them, and new handles never carry them). Raw tokens are no longer issued
  for the connection (see below).
- Google: the broker tells Google API families apart (Gmail, Calendar,
  Drive, Sheets, Docs, Admin, Contacts), not single scopes, and not read
  versus write. Any remaining scope of a family unlocks every URL of that
  family. When every removed scope belongs to a family that no remaining
  scope unlocks, the response says `enforcement: "broker"` and a brokered
  call into that family is refused before it reaches Google, also through a
  handle issued before the narrowing. When a removed scope shares a family
  with a remaining one, the response says `enforcement: "record"` and the
  call still reaches Google: gmail.readonly and gmail.send, calendar.readonly
  and calendar.events, drive.file and drive, spreadsheets.readonly and
  spreadsheets, documents.readonly and documents, contacts.readonly and
  contacts are not separated. Narrowing `[gmail.readonly, gmail.send]` to
  `[gmail.readonly]` therefore still lets a handle send mail.
- GitHub, Slack, Notion, Linear, HubSpot and Salesforce (always
  `enforcement: "record"`): the broker cannot tell which scope a URL needs,
  so a still-valid handle can reach any allowlisted URL of the provider,
  including ones that need a removed scope, because the provider token is
  unchanged.

To really remove access at the provider, run an update or reauth flow that
asks the provider for fewer scopes, or delete the connection.

**Popup fallback.** In popup mode the result page posts the result to the
opener at the registered origin and waits up to 2 seconds for the widget's
`cred.link.ack`. Without an opener, or without an ack, it falls back to
redirect delivery: it navigates to the registered `redirect_uri` with the
usual result parameters plus `cred_link_via=popup` and `cred_link_flow` (the
SHA-256 hex of the flow's `request_uri`, which binds the result to the widget
that started the flow); read them with `parseLinkRedirectResult`,
`parseLinkRedirectVia` and `parseLinkRedirectFlowId` from
`@credninja/protocol`. The embedded mode's top-level window behaves the same
way, with the iframe as its opener. One case delivers twice: an opener page
that is blocked (busy, or throttled in the background) for longer than the
ack timeout still receives the postMessage after the popup already fell back
to the redirect. The activation code is single use, so one of the two
activation attempts fails; the app should treat that failure as harmless when
the connection is already active.

A provider whose consent page cut the opener is remembered in the browser
(`localStorage`, 30 days), and the next popup for it hands the flow to the
top window in redirect delivery. The memory is written only by a window that
demonstrably started the flow with an opener and lost it: the picker reports
whether the window had an opener when the user submitted, the server records
that in a short-lived, HttpOnly cookie bound to the transaction, and the
result page writes the memory only when that cookie matches. A popup-mode
link opened directly in a tab never writes it, and neither does the top
window that completes a handoff (so an entry expires after 30 days). Only
the popup picker page allows `connect-src 'self'` (for that handoff); every
other Link page sends `connect-src 'none'`. Link pages send no
Cross-Origin-Opener-Policy.

**Agents and enforcement.** Link is deny-by-default per agent: an agent can
use a connection only through a Permission, seeded on activation from the
pushed `agent_id` or added with `POST /link/v1/connections/:id/permissions`.
`POST /api/v1/delegate` with `connection_id` runs the Link check before any
vault access whether or not a Guard is configured, returns a brokered handle
by default (300 seconds, see `LINK_HANDLE_TTL_SECONDS`), and
`POST /api/v1/use` re-runs the check on every call, so a
revoked or `needs_reauth` connection is refused at once with a typed code
(`grant_revoked`, `reauth_required`, `permission_required`,
`insufficient_scope`, ...); for a narrowed one see "What narrowing enforces"
above. Raw tokens are issued only when the client has `allow_raw_tokens`, the
provider's tokens expire and refresh (never Slack, Notion or GitHub OAuth App
tokens), and the delegated scopes cover every scope the provider granted for
the connection (a raw provider token carries all of them; a narrower grant,
Permission or request gets a handle only). The check counts only scopes in
Link's catalog, so a raw token can still carry provider scopes no grant can
express (for example the app-level scopes HubSpot requires). Each raw
issuance has its own audit event.

The agent id for Link checks comes from verified request state only: a custom
`agentRequestVerifier`'s `principalId`; otherwise a signature-verified TOFU
proof or Web Bot Auth key of a local TOFU agent (`tofu:<agentId>`); otherwise
the fixed id `server-agent`. A single-agent deployment that uses the shared
`AGENT_TOKEN` passes `"agent_id": "server-agent"` in PAR.

**Provider notes.** Slack connects as a bot install (bot token, account
`<team id>/<bot user id>`). Notion has no OAuth scopes: its `content`
permission is enforced by Cred. Salesforce pins every brokered call to the
instance host captured at connect time. Brokered calls can never reach
provider revocation endpoints (Linear is limited to its GraphQL endpoint,
HubSpot to its data API paths, Slack `auth.revoke` and `apps.uninstall` are
refused).

**Provider revocation.** Every Link client on this server shares the
server's provider OAuth app, and at Google, Salesforce and Slack one
revocation ends the whole authorization for that account. Link therefore
revokes at the provider (after cancel, back, failure, expiry, a superseded
activation, or `DELETE /link/v1/connections/:id`) only when no other
non-revoked Link connection on this server, for any client or subject, uses
the same provider account and no other open flow holds staged tokens for it;
otherwise it deletes only its local tokens, and `DELETE` answers
`"provider_revoked": false`. **Limitation:** connections made through the
legacy admin `/connect` UI carry no provider account id, so Link cannot see
them; revoking a Link connection can still end a legacy connection on the
same account. Do not mix legacy and Link connections for one account if
that matters.

**Reserved user ids.** Link tokens live in the vault under the user ids
`link:<connection_id>` and `link-staged:<tid>`. Every legacy route that takes
a `user_id` rejects those ids with `400 invalid_user_id`.

## Configuration

All configuration via environment variables (or `.env` file):

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_PASSPHRASE` | Yes | Encryption passphrase for the token vault |
| `ADMIN_TOKEN` | Yes | Admin token for provider-management browser routes (must start with `cred_admin_`) |
| `AGENT_TOKEN` | Yes | Bearer token for agent API access (must start with `cred_at_`) |
| `PORT` | No | Server port (default: 3456) |
| `HOST` | No | Bind address (default: 127.0.0.1) |
| `VAULT_STORAGE` | No | `sqlite` (default, audit-capable) or `file` |
| `VAULT_PATH` | No | Path to vault file (default: `./data/vault.sqlite`) |
| `REDIRECT_BASE_URI` | No | OAuth redirect base (default: `http://localhost:3456`) |
| `SINGLE_USER_MODE` | No | `true`: legacy requests without `user_id` act on the shared user `default`. `false` (default): they are refused with `400 user_id_required`. See [User ids](#user-ids) |
| `RECEIPT_TTL_SECONDS` | No | TTL (seconds) for the `exp` claim on delegation receipts, and the max age for legacy receipts minted without one (default: `3600`) |
| `RECEIPT_AUDIENCE` | No | Audience (`aud` claim) for delegation receipts (default: `REDIRECT_BASE_URI`) |
| `RECEIPT_SIGNING_KEY_PEM` | No | PKCS#8 Ed25519 (EdDSA) or P-256 (ES256) private key for receipts (default: Ed25519 key derived from `VAULT_PASSPHRASE`) |
| `RECEIPT_ACCEPTED_ALGS` | No | Comma-separated receipt algorithms this server accepts (default: `EdDSA,ES256`) |
| `RECEIPT_CLAIM_LAYOUT` | No | `draft-02` (default: principal in `sub`, agent in `client_id` and `act.sub`) or `legacy` (agent in `sub`) |
| `CUMULATIVE_LEDGER_PATH` | No | SQLite file for cumulative-constraint running totals (default: in memory) |
| `CRED_REQUIRE_AGENT_IDENTITY` | No | `true` (default): `/api/v1/subdelegate` requires an `actor_token` proving the caller is the agent the parent receipt names. `false`: deprecated legacy behaviour, logs a warning at startup |
| `WEB_BOT_AUTH_MODE` | No | `off` (default), `optional`, or `require` for ingress Web Bot Auth verification |
| `WEB_BOT_AUTH_NONCE_STORE` | No | `memory` (default) or `sqlite` for replay defense state |
| `WEB_BOT_AUTH_NONCE_PATH` | No | SQLite path for shared Web Bot Auth nonce storage |
| `WEB_BOT_AUTH_ALLOWED_ORIGINS` | No | Comma-separated trusted remote `Signature-Agent` origins for ingress verification |
| `GOOGLE_CLIENT_ID` | No | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | No | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | No | GitHub OAuth client secret |
| `SLACK_CLIENT_ID` | No | Slack OAuth client ID |
| `SLACK_CLIENT_SECRET` | No | Slack OAuth client secret |
| ... | No | Same pattern for NOTION, SALESFORCE, LINEAR, HUBSPOT |
| `LINK_ENABLED` | No | `true` to enable Cred Link. Requires `VAULT_STORAGE=sqlite`; startup fails otherwise |
| `LINK_STORE_PATH` | No | Link SQLite file (default: `link.sqlite` next to `VAULT_PATH`) |
| `LINK_BASE_URL` | No | Public origin of the Link pages and provider callback, no path (default: `REDIRECT_BASE_URI`) |
| `LINK_HANDLE_TTL_SECONDS` | No | Lifetime of Link brokered handles (default `300`, capped at `900`) |

`ADMIN_TOKEN` and `AGENT_TOKEN` are required when you use `loadConfig()` from environment variables. For embedded/programmatic agent auth, you can instead provide a custom `agentRequestVerifier` function in `createServer(config)` and omit the static agent token entirely. Admin routes still require `adminToken`.

## Docker Deployment (Production)

```bash
cd packages/server
cp .env.example .env
# Edit .env with your credentials

# Build and run
docker compose up -d

# Verify
curl http://localhost:3456/health
```

The vault is stored in a named Docker volume (`cred-data`) — survives container restarts and rebuilds.

### HTTPS with Caddy

For production with automatic TLS:

1. Point your domain's DNS to the server
2. Edit `Caddyfile` — replace `cred.yourdomain.com` with your domain
3. Uncomment the `caddy` service in `docker-compose.yml`
4. Run `docker compose up -d`

Caddy auto-provisions Let's Encrypt certificates. Agents connect via `https://cred.yourdomain.com`.

**SSE endpoint (`GET /api/v1/audit/stream`):** this is a long-lived HTTP connection, not a request/response call. Caddy's defaults work here, but if you front this service with a different reverse proxy (ALB, nginx, k8s ingress, etc.), verify its idle/read timeouts are long enough to keep the connection open and that it doesn't buffer the response — an aggressively-timed-out or buffered proxy will silently kill or delay the stream.

### Updating

```bash
cd packages/server
git pull
docker compose build
docker compose up -d
```

Vault data is in the named volume and survives rebuilds.

## Two-Machine Setup (Production)

For true credential isolation, run the server on a separate host from your agents:

### 1. Server (Machine A)

```bash
# On your server (VPS, on-prem, etc.)
git clone https://github.com/cred-ninja/sdk.git
cd sdk/packages/server
cp .env.example .env
# Edit .env with your credentials

# Install Caddy for automatic HTTPS
sudo apt install caddy

# Configure Caddy (create /etc/caddy/Caddyfile)
echo 'cred.yourdomain.com {
    reverse_proxy localhost:3456
}' | sudo tee /etc/caddy/Caddyfile
sudo systemctl restart caddy

# Start the server
npm install && npm start
```

### 2. Agent (Machine B)

```typescript
import { Cred } from '@credninja/sdk';

const cred = new Cred({
  agentToken: process.env.CRED_AGENT_TOKEN!,
  baseUrl: 'https://cred.yourdomain.com',
});

const google = await cred.delegateHandle({
  service: 'google',
  userId: 'default',
  appClientId: 'local',
});

const events = await cred.use({
  delegationId: google.delegationId,
  url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
  method: 'GET',
});
```

Or with curl:

```bash
curl https://cred.yourdomain.com/api/v1/delegate \
  -H "Authorization: Bearer $CRED_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"service":"google","user_id":"default","appClientId":"local","token_format":"handle"}'

curl https://cred.yourdomain.com/api/v1/use \
  -H "Authorization: Bearer $CRED_AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"delegation_id":"del_...","url":"https://www.googleapis.com/calendar/v3/calendars/primary/events","method":"GET"}'
```

## Security

- **Refresh tokens never leave the server.** Brokered delegation handles also keep provider access tokens on the server.
- **Vault encrypted at rest** with AES-256-GCM (PBKDF2-SHA256, 100K iterations).
- **Agent tokens validated** using constant-time comparison (timing-attack resistant).
- **Provider-management routes require admin auth.** Browser login posts `ADMIN_TOKEN`, then sets an HttpOnly same-site session cookie.
- **Brokered upstream calls are bounded.** `/api/v1/use` enforces service URL allowlists, delegated Google scope checks, configured Guard policies, and strips caller-supplied auth, cookie, proxy, forwarding, signature, and hop-by-hop headers before forwarding.
- **Optional ingress Web Bot Auth verification** validates `Signature`, `Signature-Input`, and `Signature-Agent` on incoming agent requests and rejects replayed nonces within the signature validity window.
- **`POST /api/v1/web-bot-auth/keys/:agentId/rotate` and `POST /api/v1/agents/:agentId/revoke-all` always require a verified caller identity**, regardless of `WEB_BOT_AUTH_MODE`. A caller must present either a valid Web Bot Auth signature for the target agent, or (with a custom `agentRequestVerifier`) a `principalId` equal to the target agent's id — the shared static bearer token alone is not sufficient. Static-bearer-only deployments (`WEB_BOT_AUTH_MODE=off`, no custom `agentRequestVerifier`) will receive `403` on these two routes until one of those identity sources is configured. Requirements for each identity source:
  - **Custom `agentRequestVerifier`:** `principalId` must equal the internal id these routes compare against — the registered Web Bot Auth `agent_id` for `rotate`, or the vault `AgentRecord.id` for `revoke-all` — not merely a stable, unforgeable identifier in the verifier's own scheme.
  - **Vault `AgentRecord.fingerprint`** (used by `revoke-all`) must be provisioned as `sha256(hex(publicKey))`, matching the Web Bot Auth key's fingerprint exactly — a different encoding or digest denies every legitimate owner, not only after a key rotation.
  - There is currently no supported tool to update an `AgentRecord`'s `fingerprint` after a key rotation; an owner locked out of `revoke-all` after rotating their key needs the record refreshed via direct storage-layer access, the same way `AgentRecord`s are provisioned today.
- **Shared replay defense is available** with `WEB_BOT_AUTH_NONCE_STORE=sqlite`, allowing multiple Cred instances to reject the same nonce when they share the same nonce database.
- **Remote `Signature-Agent` fetches are origin-gated.** Cred only resolves remote directories from `WEB_BOT_AUTH_ALLOWED_ORIGINS`, requires the canonical well-known directory path, and rejects redirects during fetch.
- **HTTPS required for remote access.** The SDK refuses to send agent tokens over HTTP to non-localhost servers.
- **For production:** Always run behind a TLS reverse proxy (Caddy auto-provisions certificates).

## Web Bot Auth Validation

For local verification, run the server test suite:

```bash
npm test --workspace=packages/server
```

For a live deployed directory smoke check, run:

```bash
RUN_WEB_BOT_AUTH_LIVE_SMOKE=1 \
WEB_BOT_AUTH_LIVE_BASE_URL=https://cred.example.com \
npm test --workspace=packages/server
```

That smoke path fetches the live `/.well-known/http-message-signatures-directory` document and verifies that the response is signed and non-empty.

## Programmatic Usage

```typescript
import { createServer, loadConfig } from '@credninja/server';

const config = loadConfig(); // reads from process.env
const { app, vault } = createServer(config);
await vault.init();
app.listen(3456);
```

### Custom Agent Auth

For integrations that already have their own agent identity system, use a programmatic verifier instead of a shared static bearer token:

```typescript
import { createServer } from '@credninja/server';

const { app, vault } = createServer({
  port: 3456,
  host: '127.0.0.1',
  vaultPassphrase: process.env.VAULT_PASSPHRASE!,
  vaultStorage: 'file',
  vaultPath: './data/vault.json',
  tofuStorage: 'file',
  tofuPath: './data/tofu.json',
  adminToken: process.env.CRED_ADMIN_TOKEN!,
  redirectBaseUri: 'http://localhost:3456',
  providers: [],
  agentRequestVerifier: async (req) => {
    const assertion = req.get('X-Agent-Assertion');
    if (!assertion) {
      return { ok: false, status: 401, error: 'Missing agent assertion' };
    }

    // Verify the assertion using your own runtime's identity system.
    return {
      ok: true,
      principal: {
        type: 'external-runtime',
        principalId: 'agent_123',
        metadata: { runtime: 'external-runtime' },
      },
    };
  },
});

await vault.init();
app.listen(3456);
```

This keeps Cred core generic while letting adapters for external runtimes translate their native auth model into Cred's issuance path.

If your verifier returns a stable `principalId`, Cred can derive a stable per-agent hash for downstream Guard policies and rate limits even when no bearer token is present on the request.

## License

Apache License 2.0

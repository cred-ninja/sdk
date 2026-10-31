# npm 2.0.0 release and migration notes

Status: prepared, not published. First prepared at `ff00421` on 2026-09-24;
refreshed on 2026-10-13 at `09f9488` to cover Cred Link Phase 1 (#46, #48) and
the explicit-user-id break on the legacy routes (#47).
Release preparation refreshed on 2026-10-30 for the Delegation Token stack
and installed-package compatibility fixes. npm publication is independent
of the Python packages; this release does not publish to PyPI.

## Registry inventory

Checked against the public npm registry on 2026-10-30: none of the thirteen
packages has a published 2.0.0 version.

| Package | Public latest | Prepared |
| --- | --- | --- |
| @credninja/protocol | Not found | 2.0.0 |
| @credninja/attenuation | Not found | 2.0.0 |
| @credninja/link | Not found | 2.0.0 |
| @credninja/link-react | Not found | 2.0.0 |
| @credninja/oauth | 1.0.0 | 2.0.0 |
| @credninja/tofu | Not found | 2.0.0 |
| @credninja/vault | 1.0.0 | 2.0.0 |
| @credninja/guard | 0.1.0 | 2.0.0 |
| @credninja/sdk | 1.0.0 | 2.0.0 |
| @credninja/ai | 1.0.0 | 2.0.0 |
| @credninja/mcp | 1.0.0 | 2.0.0 |
| @credninja/server | 1.0.0 | 2.0.0 |
| @credninja/create-app | Not found | 2.0.0 |

The unscoped scaffold name is occupied by an unrelated project. Cred's new
scoped package retains the `create-cred-app` executable name; invoke it by its
scoped npm package name. Source directory names remain unchanged.

## Why a major version

Treat this as a coordinated upgrade from the public March packages. Server
authorization requirements and sub-delegation behavior changed, even where
client methods remain source-compatible. Upgrade the server, SDK, MCP adapter,
and integrations together. The npm version is separate from protocol `0.1.0`.

## Migration checklist

1. Back up the vault, identity database, and configuration using your existing
   operational process before upgrading a deployment.
2. Configure separate `ADMIN_TOKEN` and `AGENT_TOKEN` values. Use the admin token
   for management routes and the agent token for runtime delegation. Verify
   existing automation no longer assumes management endpoints are public.
3. For server sub-delegation, migrate callers expecting an access token from
   `subDelegate()` to `subDelegateHandle()` followed by `use()`. The server always
   brokers child delegations; local mode has different behavior.
4. Configure verified Web Bot Auth identity for agent key rotation and self
   revocation. A bearer token alone is insufficient for those endpoints.
5. Remint delegation receipts as appropriate. Expiry and ancestry checks are
   stricter; legacy receipts cannot retroactively acquire complete lineage.
6. Handle the explicit `protocol_version_unsupported` error when a peer selects
   an unsupported wire version. Upgrade both sides together.
7. Review Guard configuration. Permission narrowing constrains future grants;
   it does not retroactively rewrite an existing handle's permission snapshot.
8. Legacy routes now require a user id. A request to `/providers`,
   `/connect`, `DELETE /connect/:provider`, `/api/token/:provider`,
   `/api/v1/delegate`, `/api/v1/subdelegate`, `/api/v1/connections`,
   `/api/v1/audit` or `/api/v1/audit/stream` without `user_id` gets
   `400 {"error":"user_id_required"}`. Single-tenant deployments set
   `SINGLE_USER_MODE=true` and keep the old behavior; everyone else sends
   `user_id` on every call (`default` is still a valid explicit value).
   If a custom `agentRequestVerifier` binds the agent to a user (principal
   `userId`), an omitted `user_id` acts on that user and a different one
   gets `403 {"error":"user_id_mismatch"}`.
9. Treat `consent_url` from `POST /api/v1/delegate` as opaque: it is now a
   single-use `/connect/<provider>?request=<id>` link that expires after 10
   minutes. Hand-built `getConsentUrl()` / `get_consent_url()` links still
   work but land on the operator connect page and ignore their scopes.
10. User ids starting with `link:` or `link-staged:` are reserved and refused
   everywhere, whether or not Link is enabled. Rename any such users first.
11. Cred Link stays off unless `LINK_ENABLED` is set, and needs the SQLite
   vault. See the Link sections of the `@credninja/server` and
   `@credninja/link` READMEs before turning it on.
12. Outside Cred Link (whose handles are bound as in item 14), give every agent
   that uses brokered delegations a did:key identity and pass it
   to the client: `delegateHandle({ ..., agentIdentity })` and
   `use({ ..., agentIdentity })` in `@credninja/sdk`, `agent_identity=` in
   `cred-auth` and its integrations, `CRED_AGENT_DID` plus
   `CRED_AGENT_PRIVATE_KEY_HEX` for `@credninja/mcp` in cloud mode. The server
   binds each Delegation Token to that key and requires a DPoP proof (RFC 9449)
   for every use, and each `/api/v1/use` proof covers that exact request
   (`cred_req`), so a proof authorizes one upstream call. The client's base URL
   must be the same origin and path as the server's `REDIRECT_BASE_URI`. See
   item 17 for the token contract.
13. Move callers that receive provider tokens to brokered handles: the server
   no longer returns provider access tokens (`token_format: "raw"` on
   `/api/v1/delegate`, `GET /api/token/:provider`, and Cred Link raw tokens all
   get refused). `delegate()` / `tofuDelegate()` against a server, which ask
   for raw tokens, fail until callers move to `delegateHandle()` and `use()`.
   `CRED_ALLOW_RAW_TOKENS=true` restores them (deprecated); local mode, where
   the vault runs in the agent's own process, is unchanged.
14. Cred Link delegations are Delegation Tokens. A Link delegate call
   (`connection_id`) sends `agent_did` as a did:key and a DPoP proof by that
   key, and gets `access_token`, `token_type: "DPoP"` and `cnf.jkt`, plus
   `connection_id`, `grant_id` and `grant_version`. The token is issued only
   to an identified agent (a TOFU agent signing with Web Bot Auth, or a
   verified principal), not to the shared static Bearer identity
   (`server-agent`), and is exercised like any other: `Authorization: DPoP`
   at `/api/v1/use`. `delegation_id` with `Authorization: Bearer` no longer
   works for a Link delegation. Link delegations are recorded, survive a
   restart, and are still checked against the Link grant at every call.
15. Delegations are shorter-lived: receipts default to 15 minutes, and
   `RECEIPT_TTL_SECONDS` may not exceed 3600. Callers that held handles for
   longer must request new ones; legacy receipts without `exp` also expire
   after this lifetime.
16. The audit log becomes tamper-evident from the first event written after
   the upgrade; earlier rows are reported as unchained. Run
   `GET /admin/audit/verify` periodically and record the returned head outside
   the host. Receipts now name the server (`REDIRECT_BASE_URI`) in `iss`; keep
   that value stable, since a parent receipt naming another issuer is refused.
17. Brokered handles are replaced by DPoP-bound Delegation Tokens (JWTs):
   - `delegateHandle()` needs `agentIdentity` and returns `{ token, jkt,
     delegationId, receipt, expiresIn, ... }`; the server answers
     `access_token`, `token_type: "DPoP"` and `cnf.jkt`.
   - `use()` takes `{ token, agentIdentity, url, method, ... }` and sends
     `Authorization: DPoP <token>` plus a proof with `ath` = base64url SHA-256
     of the token. `delegationId` in the body, and `Authorization: Bearer`
     for an agent delegation, no longer work.
   - Sub-delegation hands off with `subDelegateGrant()` (delegating agent) and
     `redeemDelegationGrant()` (receiving agent); `/api/v1/subdelegate` always
     requires the delegator's `actor_token`.
   - `CRED_REQUIRE_DPOP` is removed (ignored, with a warning), and
     `CRED_REQUIRE_AGENT_IDENTITY=false` is ignored. Neither relaxes any
     delegation.
   - `@credninja/mcp` in brokered mode needs `CRED_AGENT_DID` and
     `CRED_AGENT_PRIVATE_KEY_HEX`.
   - Python (`cred-auth`): `delegate_handle()` needs `agent_identity` and
     returns the token, and `use()` takes the token plus `agent_identity`,
     the same way.
18. Ceilings are decided from what the server measures. `quantities` in the
   `/api/v1/use` body is no longer read. A delegation carrying a constraint on
   a key the server does not meter is refused at exercise
   (`403 unmetered_constraint`): re-issue it under a metered key (`calls`,
   `method`, `destination`, `request_bytes`, `response_bytes`, `items` and
   its aliases). A response over a bound is withheld (`withheld: true`,
   `upstream_status`), not truncated, so check `upstream_status` before
   retrying a write.
19. A Permission with `requiresApproval` is enforced, not refused. A did:key
   agent asks at `POST /bc-authorize` (OpenID CIBA, poll mode) and polls
   `/api/v1/token` with `grant_type=urn:openid:params:grant-type:ciba`. Set
   who approves per Permission (`approver`: `subject`, `admin` or `both`),
   and give the subject a channel: `CRED_APPROVAL_WEBHOOK_URL` for the
   built-in page, or an external OpenID Provider (`CRED_CIBA_*`). Without a
   channel only admin approval works (`/admin/approvals`).
20. Every Delegation Token names a consent record (`consent_id`), kept
   `CONSENT_RETENTION_DAYS` (at least 90, the default) and purged daily. A
   security event (`POST /admin/consents/revoke`) refuses the tokens under
   the revoked consents (`401 consent_revoked`). Plan storage for the
   retained records.
21. Delegations may ask for RFC 9396 `authorization_details` of type
   `cred_delegation`: granted scopes as operations, or catalogue operations
   with resources for GitHub and Google Drive. Optional: without it, a token
   carries its granted scopes as operations.
22. Exercise a full consent, delegation, brokered-use, and revocation flow on a
   test account before moving production traffic.
23. Node 22 or newer is required. CI also exercises Node 26. Both ESM import
   and CommonJS require of `@credninja/vault` and `@credninja/ai` load the same
   CommonJS implementation, so vault authenticity and AI delegation state
   remain consistent when a process mixes module formats. The private vault
   brand and agent/server binding checks remain enforced.

The [conformance map](../protocol-conformance.md) documents partial capabilities
and standards gaps. Do not describe this release as a complete implementation
of all RFCs profiled by the Internet-Draft.

## Local validation

Use Node 26 for the full checks and Node 22 for the minimum-major package smoke.

```sh
npm ci
npm run release:hygiene
npm run lint
npm run build
npm run typecheck
npm test
npm audit --omit=dev --audit-level=high
npm run smoke:npm
```

The package smoke test packs all thirteen workspaces, installs their tarballs in a
clean temporary consumer, exercises a brokered SDK call against a local server
with a mocked upstream API, and starts a generated scaffold. This is packaging
and local integration validation, not a real-provider OAuth acceptance test.
It also compiles strict NodeNext ESM/CommonJS and browser Bundler consumers
without `skipLibCheck`, checks Link imports during SSR, and verifies mixed-format
vault/AI use while rejecting forged vaults and incorrectly bound delegations.

Validation on 2026-09-24 (WSL Ubuntu, Node 22.23.3): release hygiene, lint, build,
workspace type checks, and 952 tests passed. One opt-in live Web Bot Auth test was
skipped. Fresh tarball installation, the brokered SDK/server smoke, and generated
scaffold startup also passed. The production dependency audit passed the repository's high/critical
gate and reported two existing moderate dependency findings in Hono and qs. No external
dependency versions were changed by this release preparation. Registry install
and real-provider verification remain publish-time checks.

Revalidation on 2026-10-13 at `09f9488` (Linux, Node 22.22.0): release hygiene,
lint, build, workspace type checks, and 1754 tests passed (one opt-in live Web Bot
Auth test skipped). Python packages: 133 tests passed. The twelve-package tarball
smoke, brokered SDK/server smoke, and generated scaffold startup passed. The
production dependency audit reported 0 vulnerabilities.

## Publish sequence

Complete review and validation first. Authenticate to npm using an account with
publish rights to `@credninja`. Check new-package access for protocol, link,
link-react, tofu, and create-app. Do not paste credentials into this document or source control.

Stage the release under `next` in dependency order:

```sh
npm publish --workspace packages/protocol --access public --tag next
npm publish --workspace packages/attenuation --access public --tag next
npm publish --workspace packages/link --access public --tag next
npm publish --workspace packages/link-react --access public --tag next
npm publish --workspace packages/oauth --access public --tag next
npm publish --workspace packages/tofu --access public --tag next
npm publish --workspace packages/vault --access public --tag next
npm publish --workspace packages/guard --access public --tag next
npm publish --workspace packages/sdk --access public --tag next
npm publish --workspace packages/integrations/vercel-ai --access public --tag next
npm publish --workspace packages/mcp --access public --tag next
npm publish --workspace packages/server --access public --tag next
npm publish --workspace packages/create-cred-app --access public --tag next
```

Stop on the first error. Recheck the registry after each successful publication;
package publication is not atomic. Keep a record of names, versions, and integrity
hashes. A failed later package does not undo earlier publications.

From a fresh directory outside the repository, verify registry installation of
the pinned 2.0.0 packages and run the scoped scaffold:

```sh
npx @credninja/create-app@2.0.0 cred-trial
cd cred-trial
npm start
```

Confirm `/health`, log into `/admin/login`, configure a test provider, complete
OAuth consent, then exercise delegation and revocation with the published SDK.
Run the same installed-package checks against the registry (without packing
local source) before promotion:

```sh
npm run smoke:npm -- --registry-version 2.0.0
```

Only after these checks, promote each of the thirteen packages with
`npm dist-tag add <package>@2.0.0 latest`. Update website quickstarts and publish
the announcement after the complete package set is available.

## Standards wording

Cred is an open-source implementation developed alongside the author's
[credential-delegation Internet-Draft](https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/)
and ongoing agent-auth work. That draft is an individual contribution, not an
IETF-endorsed standard. The [Datatracker references page](https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/referencedby/)
lists informative references from the Asor and HAMR delegation drafts. Those
references demonstrate standards discussion, not product adoption.

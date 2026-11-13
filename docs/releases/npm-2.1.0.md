# npm 2.1.0 and PyPI 2.0.1

Status: published 2026-11-13.

Every `@credninja` npm package moves to 2.1.0 together, and each one's range on the
others moves to `^2.1.0`. The Python packages move to 2.0.1, because the only Python
change is that `cred-crewai` now declares `<3.14`; the Python client's API is unchanged.

## What kind of release this is

2.1.0 fixes how the server enforces the limits placed on an agent. No export, type or
route is removed, and code written against 2.0.0 compiles and runs.

It is not a drop-in upgrade for a running deployment. A server that upgrades and changes
nothing else will refuse calls that worked on 2.0.0: an agent with no Permission gets
nothing, a brokered call the delegation's scopes do not cover is refused, and Salesforce
connections must be reconnected. A `^2.0.0` range picks 2.1.0 up at the next install,
so read the checklist before that install reaches production.

Two of the three have a deprecated opt-out that restores the 2.0.0 behavior for a
transition. Each warns at startup and marks the audit events it lets through.

| Change | Refusal | Opt-out |
| --- | --- | --- |
| An agent named by `agent_did` needs a Permission | `403 permission_required` | `CRED_ALLOW_AGENTS_WITHOUT_PERMISSION=true` |
| A revoked agent stays out until it is granted again | `403 agent_access_revoked` | `CRED_ALLOW_REDELEGATION_AFTER_REVOCATION=true` |
| A brokered call must be mapped, and covered by the delegation's scopes | `403 operation_not_mapped`, `403 scope_insufficient` | `CRED_ALLOW_UNCLASSIFIED_BROKER_CALLS=true` |
| A Salesforce token goes only to the connection's own instance | `400 salesforce_instance_mismatch`, `400 salesforce_instance_unknown` | none |

## Upgrade checklist

1. Back up the vault and the identity database.
2. Upgrade the server, SDK, MCP adapter and integrations together.
3. List your agents, and create a Permission for each did:key agent with
   `POST /admin/permissions`. In a generated app, `npm run grant -- <service> <scope>`.
   Without one, delegation answers `403 permission_required`.
4. Check your provider calls against the tables in `packages/server/README.md`. An
   unmapped call gets `403 operation_not_mapped`, one the grant does not cover
   `403 scope_insufficient`.
5. Reconnect Salesforce connections: the token now goes only to the stored instance,
   and connections made on 2.0.0 store none. In local mode, store Salesforce connections
   with `instanceUrl`.
6. Revocation now holds. After a delegation or agent revocation,
   `POST /admin/permissions/:id/restore` lets the agent back.
   `DELETE /admin/permissions/:id` removes the row, so restore answers `404`: grant
   again with `POST /admin/permissions`.
7. If you run `VAULT_STORAGE=file`: that backend stores no Permissions, so every agent
   is refused. Reconnect providers on a SQLite vault, or use the opt-out in the table
   for a transition.
8. If you use the deprecated raw-token opt-in: a raw token now needs a Permission
   covering every scope on the connection. A request naming a did:key in `agent_did`
   must also send a fresh DPoP proof by that key for `POST /api/v1/delegate`, checked
   before stored credentials are read or refreshed (`401 invalid_dpop_proof` when
   missing, invalid or replayed). This proves the requester at issuance; the returned
   provider token is still a bearer token. The same holds when `agent_did` is an agent
   record id whose record has a did:key. An agent with no key on record cannot be
   proved: anyone holding the agent token can name it, so give raw-token Permissions
   to did:key agents. Naming a TOFU principal (`tofu:<agentId>`) in `agent_did` on a
   raw request is refused (`401 agent_key_required`). A TOFU client using
   `tofuDelegate()` names no `agent_did`, so on 2.1.0 it is refused with
   `403 permission_required` unless `CRED_ALLOW_AGENTS_WITHOUT_PERMISSION=true` is set.
   Move TOFU clients to did:key agents with a Permission, or set that opt-out for the
   transition. Otherwise use `token_format: "handle"`.
9. Check GitHub calls: under a repository, writes to deploy keys, collaborators,
   webhooks, transfers and Actions secrets are refused, and `/user` and `/orgs` routes
   follow the scopes GitHub documents. Calendar partition scopes are unmapped, and
   metadata scopes no longer read content. Drive `$alt`/`%24alt` downloads and Gmail
   messages/threads/drafts list `q` searches need content scopes. Repeated or ambiguous
   `alt`, `format` or `q` parameters are refused for all grants. `gmail.metadata` no
   longer reaches drafts, and `userinfo.email`/`userinfo.profile` read `people/me` only.
10. Read the rate limit change: a limit now holds over any trailing window, so a client
    timed to the old clock-aligned refill will see more `429`s.
11. If a Guard judges identity: the server now shows it only checked signatures,
    verified receipt claims and, for root delegation only, a verified TOFU fingerprint.
    Naming `tofu_fingerprint` on `/bc-authorize` or another route that does not verify
    TOFU cannot satisfy a TOFU-only policy. Guard sees `agentDid` and the `did` source
    when the request carries a DPoP proof for the route by the named `agent_did`
    (`/api/v1/delegate`, `/bc-authorize`), and for the receiving agent of a
    sub-delegation. A request that only names a DID shows Guard `agent-token` and is
    then refused by the route for its missing proof. If you mount the Guard Express adapter on your own app, pass
    `resolveVerifiedIdentity` (see `packages/guard/README.md`).
12. After upgrading, delete again any connection deleted on 2.0.0 that
    `GET /api/v1/connections` still lists, and revoke its tokens at the provider. On
    2.0.0 a delete that landed during a token refresh could be undone by the refresh.
13. Check sub-delegation: a hop is now held to the delegating agent's own Permission as
    well as the receiving agent's. A grantor whose Permission is not `delegatable`, sits at
    its `maxDelegationDepth`, has expired, or no longer covers a scope the hop would grant
    is refused (`403 delegation_not_allowed`, `403 depth_exceeded`,
    `403 permission_expired`, `403 scope_insufficient`; SDK local mode `invalid_scope`).
    A grantor with no Permission row keeps the previous recipient-only behavior.
14. On `/api/v1/use`, a delegation the process has not cached (after a restart, or on
    another replica) is now checked for its DPoP proof, its agent's suspension and its
    Permission before the stored token is read or refreshed. An unproven request for a
    revoked delegation answers `401 invalid_dpop_proof` rather than
    `401 delegation_revoked`.
15. Rotate `AGENT_TOKEN`, and review the audit log for brokered writes made under
    read-only delegations and for delegations issued after a revocation.

The full list is in `CHANGELOG.md`.

## Kept from 2.0.0

- `metadata.webBotAuth` in the audit feed still holds every stored field, as 2.0.0
  returned it. It is deprecated: read an event's own fields from the new
  `metadata.details`.
- A custom `StorageBackend` written for 2.0.0 compiles and works. Its
  `revokePermission` records no revocation hold, so nothing but the missing Permission
  keeps a revoked agent out. Without `replaceIfUnchanged()`, a refresh write-back
  re-reads the row before writing, which narrows the delete race but does not close it.

## What this release does not change

Known limitation: permissions are per agent and service, and the static `AGENT_TOKEN`
carries no user. On the legacy routes the user comes from the request's `user_id`, so
`user_id` is not an authorization boundary: whoever holds the token can name any
connected user. The server warns at startup when one static token serves more than one
user, which is when `SINGLE_USER_MODE` is off and no `agentRequestVerifier` is configured.
A single-user deployment (`SINGLE_USER_MODE=true`) is not affected. To bind each caller to
one user, configure an `agentRequestVerifier` that returns `userId`.

Known limitation: whoever holds the agent token can also revoke any delegation of a user
it names (`DELETE /api/v1/delegations/:id`), and since 2.1.0 that revocation holds the
agent out until an admin restores it (`POST /admin/permissions/:id/restore`). Treat the
agent token as an operator credential.

Revocation holds, replay caches, single-use grants and pending approvals are designed
for one server process per vault database. Replay caches, grants and pending approvals
are held in process memory, so a restart forgets them.

The built-in approval page authenticates the approval link, not the person opening it.
An external provider's CIBA `id_token` is not verified. Token exchange takes no DPoP
proof. `docs/protocol-conformance.md` states each of these.

No part of this release has been exercised against a live provider.

## Release order

1. Merge the release branch to `main`, and let CI pass on the merge commit.
2. Publish npm in dependency order: `protocol`, `attenuation`, `oauth`, `tofu`, `vault`,
   `guard`, `link`, `link-react`, `sdk`, `ai`, `mcp`, `server`, `create-app`. A later
   package's `^2.1.0` range cannot resolve until the earlier ones exist. `oauth` and `sdk`
   must ship in the same release: local-mode refresh in `sdk` calls
   `toVaultRefreshAdapter`, which is new in `oauth` 2.1.0.
3. Check `npm view @credninja/server@2.1.0 dependencies`, and run `npm run smoke:npm`
   and a clean `npx @credninja/create-app` from the registry.
4. Publish PyPI: `cred-auth` first, then the five integrations. Run
   `bash scripts/smoke-python-wheels.sh` on 3.10, 3.12 and 3.13.
5. Deprecate 2.0.0 on npm with a message naming 2.1.0.

## Rollback

A published version cannot be replaced. If 2.1.0 has a defect, fix forward with 2.1.1.

For one deployment, restore the vault backup and pin 2.0.0. Going back brings back
everything 2.1.0 fixed, and 2.0.0 ignores revocation holds, so treat it as an outage
measure. New vault columns and tables are additive, and 2.0.0 does not read them.

If the operation tables wrongly refuse a call in production, prefer
`CRED_ALLOW_UNCLASSIFIED_BROKER_CALLS=true` over a downgrade, for as short a time as you
can. It keeps default deny, revocation and the Salesforce binding, but read-only grants
can write again, derived scopes such as `github.read` stop being limited to reads, and
Link narrowing isn't enforced.

After a 2.0.0 reconnect, `instance_url` can be stale when you upgrade again, so reconnect
Salesforce connections after any downgrade.

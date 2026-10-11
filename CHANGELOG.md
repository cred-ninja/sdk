# Changelog

## [Unreleased]

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

This release is prepared but not yet published. Python package versions remain
unchanged. The npm major version reflects integration changes since the public
March 2026 packages; the wire-protocol version remains `0.1.0`.

- Align all ten npm packages and internal dependency ranges at 2.0.0. Include
  the previously unpublished `@credninja/protocol` and `@credninja/tofu` packages.
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

See [release and migration notes](docs/releases/npm-2.0.0.md) before upgrading.

# Changelog

## [Unreleased]

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

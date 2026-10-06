# npm 2.0.0 release and migration notes

Status: prepared locally, not published. Baseline: `ff00421` on 2026-09-24.

## Registry inventory

Checked against the public npm registry on 2026-09-24:

| Package | Public latest | Prepared |
| --- | --- | --- |
| @credninja/protocol | Not found | 2.0.0 |
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
8. Exercise a full consent, delegation, brokered-use, and revocation flow on a
   test account before moving production traffic.

The [conformance map](../protocol-conformance.md) documents partial capabilities
and standards gaps. Do not describe this release as a complete implementation
of all RFCs profiled by the Internet-Draft.

## Local validation

Use a supported Node runtime (Node 22 is used for this release preparation).

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

The package smoke test packs all ten workspaces, installs their tarballs in a
clean temporary consumer, exercises a brokered SDK call against a local server
with a mocked upstream API, and starts a generated scaffold. This is packaging
and local integration validation, not a real-provider OAuth acceptance test.

Validation on 2026-09-24 (WSL Ubuntu, Node 22.23.3): release hygiene, lint, build,
workspace type checks, and 952 tests passed. One opt-in live Web Bot Auth test was
skipped. Fresh tarball installation, the brokered SDK/server smoke, and generated
scaffold startup also passed. The production dependency audit passed the repository's high/critical
gate and reported two existing moderate dependency findings in Hono and qs. No external
dependency versions were changed by this release preparation. Registry install
and real-provider verification remain publish-time checks.

## Publish sequence

Complete review and validation first. Authenticate to npm using an account with
publish rights to `@credninja`. Check new-package access for protocol, tofu, and
create-app. Do not paste credentials into this document or source control.

Stage the release under `next` in dependency order:

```sh
npm publish --workspace packages/protocol --access public --tag next
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
Only after these checks, promote each of the ten packages with
`npm dist-tag add <package>@2.0.0 latest`. Update website quickstarts and publish
the announcement after the complete package set is available.

## Standards wording

Cred is an open-source implementation developed alongside the author's
[credential-delegation Internet-Draft](https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/)
and ongoing agent-auth work. That draft is an individual contribution, not an
IETF-endorsed standard. The [Datatracker references page](https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/referencedby/)
lists informative references from the Asor and HAMR delegation drafts. Those
references demonstrate standards discussion, not product adoption.

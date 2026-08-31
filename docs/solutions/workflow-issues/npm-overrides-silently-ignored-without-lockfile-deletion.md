---
title: npm overrides are silently ignored unless package-lock.json is deleted
date: 2026-07-27
category: workflow-issues
module: npm workspaces overrides (root package.json)
problem_type: workflow_issue
component: tooling
severity: high
applies_when:
  - "Editing the `overrides` block in a root `package.json` within an npm workspaces monorepo"
  - "Verifying that a Dependabot or security-alert remediation actually changed the resolved dependency versions"
  - "Running `npm install` in a repo that already has a `package-lock.json` (lockfileVersion 3)"
symptoms:
  - "`npm install` exits 0 and prints a normal \"added N packages\" summary, but resolved versions in `node_modules` still match the pre-edit, vulnerable versions"
  - "`rm -rf node_modules && npm install` (package-lock.json kept) still resolves the old versions instead of the newly pinned `overrides`"
  - "`package-lock.json`'s `packages[\"\"].overrides` field stays stale/undefined after editing `package.json`'s `overrides` block"
  - "`npm audit`'s reported alert count can drop for unrelated reasons (e.g. audit database differences), giving false confidence that overrides took effect"
root_cause: missing_workflow_step
resolution_type: workflow_improvement
related_components:
  - package-lock.json
  - npm-workspaces
tags:
  - npm
  - npm-workspaces
  - package-lock
  - overrides
  - dependabot
  - security-remediation
  - monorepo
---

# npm overrides are silently ignored unless package-lock.json is deleted

## Context

While remediating 17 GitHub Dependabot alerts in an npm workspaces monorepo (npm 11.6.2, Node v25.2.1, `lockfileVersion: 3`), the fix itself was simple: bump/add entries in the root `package.json`'s `overrides` block to CVE-patched versions for 8 transitive packages (`fast-uri`, `hono`, `vite`, `esbuild`, `@hono/node-server`, `body-parser`, `form-data`, and a nested `brace-expansion` copy bundled inside `@typescript-eslint/typescript-estree`'s `minimatch@10`).

Applying it was not simple. After editing `overrides`, `npm install` exited `0` and printed an ordinary "added N packages, audited M packages" summary — no error, no warning, nothing to suggest a problem. But the actual resolved versions in `node_modules` and `package-lock.json` hadn't moved at all; they still matched the old, vulnerable pins. The only reason this surfaced was an explicit check: diffing the values in `overrides` against the versions actually recorded in `package-lock.json`, rather than trusting the install output.

Inspecting the lockfile explained why: `package-lock.json`'s `packages[""].overrides` field was `undefined`. The lockfile had never recorded an `overrides` key at all — not even for the entries that already happened to be correct (those matched by coincidence, because their previously-resolved versions already satisfied the new ranges).

## Guidance

npm decides whether an existing lockfile is still valid for a given `package.json` by diffing what the lockfile has *recorded* for fields like `overrides` against what's currently in `package.json`. If the lockfile never recorded `overrides` in the first place, that diff has nothing to compare against, and npm treats the locked tree as still current — regardless of whether `overrides` just changed, and regardless of whether `node_modules` was wiped first.

Two escalating fixes that looked reasonable both failed:

1. **`npm install`** with the existing `node_modules` + `package-lock.json` in place → no effect. Nothing to diff against, so the locked tree was reused as-is.
2. **`rm -rf node_modules && npm install`** (keeping `package-lock.json`) → still no effect. npm rebuilt `node_modules` from the *existing lockfile's* resolutions, not from a fresh resolution against `package.json`, so it reproduced the identical stale versions.

What actually worked — delete the lockfile too, forcing a full fresh resolution:

```bash
# Git Bash / macOS / Linux
rm -rf node_modules package-lock.json
npm install
```

```powershell
# PowerShell equivalent
Remove-Item -Recurse -Force node_modules, package-lock.json
npm install
```

After this, `package-lock.json`'s `packages[""].overrides` actually listed the pinned versions, and every target package resolved correctly.

Don't stop at a clean exit code. Verify by diffing resolved versions against `overrides` — checking *every* copy of a package in the lockfile, not just the top-level one, since nested/bundled copies (like the `brace-expansion` inside `typescript-estree`'s `minimatch@10` above) won't show up in a top-level-only check:

```js
// scripts/check-overrides.js
const { overrides } = require('./package.json');
const lock = require('./package-lock.json');

for (const [path, meta] of Object.entries(lock.packages)) {
  const m = path.match(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/);
  if (!m) continue;
  const want = overrides[m[1]];
  // Nested overrides (e.g. { "typescript-estree": { "brace-expansion": "..." } })
  // resolve to an object here, not a version string — check those by hand.
  if (typeof want === 'string' && meta.version !== want) {
    console.log('MISMATCH', path, meta.version, '-> want', want);
  }
}
```

```bash
node scripts/check-overrides.js   # prints nothing if every resolved copy matches
```

## Why This Matters

This failure mode is silent by construction: exit code `0`, a normal-looking summary, and — in this case — even `npm audit`'s alert count can drop for reasons unrelated to the actual fix (a different advisory database view, a newly-installed transitive dependency, etc.), producing false confidence that the remediation worked. A security-remediation PR built on this can merge, close the Dependabot alerts' associated branch, and ship, while every one of the CVEs it claimed to fix is still live in production. There's no error to catch this — only an explicit version diff will.

## When to Apply

- Editing the `overrides` block in a root `package.json` within an npm workspaces monorepo
- Verifying that a Dependabot or security-alert remediation actually changed the resolved dependency versions
- Running `npm install` in a repo that already has a `package-lock.json` (lockfileVersion 3)
- Quick check before assuming a lockfile will pick up new overrides: `jq '.packages[""].overrides' package-lock.json` — if it prints `null` or nothing, a plain `npm install` (or `rm -rf node_modules && npm install`) won't apply new overrides; go straight to deleting the lockfile too.

## Examples

Before (both attempts silently no-op — resolved versions unchanged):

```bash
$ npm install
added 327 packages, and audited 337 packages in 28s
# node_modules/hono still resolves to 4.12.23, not the 4.12.27 just set in overrides

$ rm -rf node_modules && npm install
added 323 packages, and audited 335 packages in 7s
# still 4.12.23 — deleting node_modules alone wasn't enough
```

After (lockfile deleted, forcing full re-resolution):

```bash
$ rm -rf node_modules package-lock.json && npm install
added 331 packages, removed 1 package, and audited 342 packages in 20s

$ node -e 'console.log(require("./package-lock.json").packages["node_modules/hono"].version)'
4.12.27   # matches overrides now
```

## Related

- PR: https://github.com/cred-ninja/sdk/pull/17 — "security: resolve 17 open Dependabot alerts via override bumps"

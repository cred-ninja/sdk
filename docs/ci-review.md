# CI and change review

## What this change does

CI runs build, workspace typechecking, lint, tests, package smoke, dependency
review, production dependency audit, CodeQL and the public leak guard. Python CI
runs on every PR targeting `main`, without a changed-path filter: three SDK
versions, five framework integrations, four combined environments and three
wheel-smoke versions. The existing 15 Python check names stay unchanged; no
aggregate Python gate or required-check migration is needed for that fix.

Workflow Security runs actionlint 1.7.12, offline plain-output zizmor 1.32.0 and
fully redacted Gitleaks 8.30.1. It scans a tracked-tree snapshot, including
`export-ignore` files, and tests the narrowly scoped synthetic fixture exceptions.
The pre-existing broader exclusions in `.gitleaks.toml` still apply; this is not
an assertion that every tracked byte is scanned. External Actions are pinned,
checkout credentials are not persisted, and Dependabot covers Actions, npm and
the Python packages. Dependency Review checks runtime, development and unknown
scope for new high/critical advisories; the full npm audit remains informational.

CodeQL analysis execution and the separate GitHub code-scanning result are
distinct signals. Keep both; neither a successful analyzer nor a green review
process alone establishes that a PR is ready to merge.

## Review changes, not review machinery

The [Codex migration and local fallback runbook](./codex-reviews.md) records the
current dependency audit, account setup, subscription-only local commands and
retirement order. Native Codex completed a real review on PR #157 after the root
`AGENTS.md` review rules were added. Its review remains advisory; deterministic
checks enforce merge protection. No API-backed review Action is installed.

Use native Codex and one fresh independent correctness review of the final diff.
For changes to authentication, authorization, cryptography, credential handling,
CI permissions or release tooling, include a focused security review. That can
be part of the independent review; three AI sessions are not mandatory on every
PR. Reviewers should inspect relevant source and tests, not only a bot summary.

Request native review with `@codex review`, or use the configured automatic
opening/ready-for-review trigger. Read findings and disposition them; a reaction,
successful process check or old review is not completed current-head review.
For clean diffs, inspect Codex's completed receipt and exact reviewed commit.
Neither that receipt nor a GitHub review event is a required CI status check.
Re-review material changes without repeatedly requesting unchanged diffs.

There is no custom review aggregate, check publisher, evidence expiry timer,
recovery workflow or credential-bearing model workflow. Native Codex mentions
are handled by its GitHub App, not an Actions job. Independent review and the
ChatGPT-authenticated local fallback run outside Actions; CI needs no model key.

## Manual merge

Keep PR auto-merge off. Before manually squash-merging, verify the current head,
all required checks, completed reviews, resolved findings and conversations, and
whatever native approval rules GitHub currently enforces. Never merge while a
review is running. This last condition is an operational requirement, not an
atomic guarantee provided by an asynchronous status check.

Use the existing task branch and PR for corrections; do not open another branch
for each review pass. Do not merge dependent work or publish packages merely to
clear the queue. Package releases remain a separate manual action.

## Rollout

Workflow files do not change live protection or repository settings. After native
review of PR #157 succeeded, the authorized settings migration removed only
`CodeRabbit` (producer `347564`) from Protect main. All 26 deterministic required
checks and their producers remain, as do conversation resolution, stale-review
dismissal, extra approval for unattributed changes and the separate CodeQL result.
Do not emit a dummy green replacement or require an undocumented Codex context.

The minimal `.coderabbit.yaml` explicitly disables automatic/incremental reviews,
label/description opt-in triggers, automatic verdicts and unsolicited replies.
Keep it: deleting it can restore the shared App's defaults. Its effective revision
depends on the configuration source. CodeRabbit still selected `main` on this
unmerged PR, so PR #157 was explicitly paused as well. Repository-wide config
rollout awaits an authorized maintainer merge. The shared organization App is not
removed. See the migration runbook for the precise rollout boundary.

Native approval needs an eligible reviewer other than the author; CODEOWNERS does
not create that person or grant access. For a single-maintainer repository, the
owner may explicitly authorize zero required approving reviews and disable
last-push approval. That settings decision does not waive current-head independent
review, unresolved findings, manual merging or any required CI/security check.

After publication, verify Python CI appears on a main-target PR without Python
changes and inspect the hosted Workflow Security result. Do not add a new
required context before validating its delivery. Existing PRs may need their
branches updated and CI rerun after this change lands. A stacked PR's clean merge
status against another feature branch does not establish main-branch readiness.

## Local verification

```sh
npm run test:ci
npm run build
npm run typecheck
npm run lint
npm test
npm run release:hygiene
npm run smoke:npm
npm audit --omit=dev --audit-level=high
actionlint -color
zizmor --offline --format plain .github/workflows
GITLEAKS_BIN=/path/to/gitleaks node --test scripts/ci/scanner.probe.mjs
```

Use the exact scanner versions above and have ShellCheck available for actionlint.
Local results verify source behavior, not deployed GitHub policy or review quality.

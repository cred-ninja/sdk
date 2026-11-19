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

Use CodeRabbit and one fresh independent correctness review of the final diff.
For changes to authentication, authorization, cryptography, credential handling,
CI permissions or release tooling, include a focused security review. That can
be part of the independent review; three AI sessions are not mandatory on every
PR. Reviewers should inspect relevant source and tests, not only a bot summary.

CodeRabbit is configured to submit formal approvals or change requests. Read
its findings and disposition them; a successful, neutral or skipped process check
is not evidence of a completed substantive review. Re-review changed code as
needed and tie the final review to the current head commit.

There is no custom review aggregate, check publisher, evidence expiry timer,
recovery workflow or credential-bearing Claude workflow. Interactive agent
mentions are removed too. Independent agent review can be performed outside
Actions; no model credential is needed by this CI configuration.

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

This branch does not change live protection, approvals or repository settings.
Before landing it, an authorized maintainer must coordinate retirement of the
obsolete required `claude-review` context, because its producer is removed.
Do not emit a dummy green replacement. Preserve the other required checks,
conversation resolution, stale-review/last-push handling, the extra approval for
unattributed changes and the separate CodeQL security result.

Native approval also needs an eligible reviewer other than the author. Correcting
CODEOWNERS does not create that person or grant repository access. If no eligible
approver is available, the maintainer must explicitly decide how to resolve that
setup; this change neither bypasses nor relaxes the approval rule.

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

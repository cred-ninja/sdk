# CI and review-gate operations

## Deployment status and bootstrap

These files define a candidate policy, not proof that the hosted policy has run.
The strict target workflow uses **only the PR base SHA's trusted CI scripts**.
It cannot exercise this new implementation on its own rollout PR before those
scripts are merged into `main`. Do not execute the PR version with credentials,
turn off protection, self-approve, or bypass the existing approval rule to land it.
A separately authorized maintainer must arrange a protected rollout, then verify
the checks on a non-draft canary PR before adding new required check contexts.
No releases, registry publication, live settings changes, or autonomous dispatcher
are implemented by this refresh.

The intended additional required contexts are **Workflow Security** and
**Review Gate**. Keep the existing build, test, lint, Python, leak, dependency,
CodeQL and raw CodeRabbit checks; coordinate the replacement of the old optional
Claude job context with Review Gate. Bind the aggregate to the GitHub Actions
application in branch protection rather than accepting a same-named status from
an arbitrary application. Preserve required human approval, last-push approval,
conversation resolution, branch freshness and no-bypass rules. Local tests do
not prove those server-side settings.

`CODEOWNERS` names `@kierandotai`, including CI/release/security-sensitive paths.
An author cannot approve their own PR. A single-maintainer author therefore
cannot satisfy an independent code-owner/human approval requirement alone.
Unattended merge remains **blocked** without a separate authorized reviewing
identity. Neither model output nor a blanket bot auto-approval substitutes for
that identity. Do not relax the rule or enable blanket unattended tool approval.

## What runs

- Python CI runs on every main-target PR, including documentation-only changes:
  three SDK versions, five integration jobs, four combined environments and three
  wheel-smoke versions. CrewAI's existing Python-version exclusion is unchanged.
- Build explicitly runs the root workspace typecheck after building. Lint also
  runs `npm run test:ci`, which includes behavioral policy and failure-path tests.
- Workflow Security requires actionlint **1.7.12**, offline zizmor **1.32.0** with
  **plain** output (not SARIF), and Gitleaks CLI **8.30.1** with full redaction.
  Gitleaks scans a clean `git archive HEAD` snapshot, not environment files,
  ignored local files or history. Two exact pre-existing Python test-vector
  fingerprints are excluded in `.gitleaksignore`; no test directory is exempt.
  Re-review those two locations if their data/line numbers change.
- External actions are SHA-pinned; checkout does not persist credentials.
  Dependabot covers Actions, npm and each Python package. Tool CLI version pins
  in Workflow Security need maintainer updates as well.
- Dependency Review blocks new high/critical advisories in runtime, development
  **and unknown** scope, without PR comment-write permission. The existing npm
  production high-severity gate and nonblocking full audit remain distinct.
  This does not remediate existing advisories or assert a clean dependency tree.
- Interactive `@claude` mentions are disabled. The retained manual workflow only
  states that fact; it has no model, credentials, checkout or code execution.
  Releases remain manual; there is no new publish workflow.

## The three review signals

1. **CodeRabbit** must have a real latest formal `APPROVED` review on the exact
   head SHA, submitted after the original workflow was created and after the
   linked issue requirements were last edited. All its checks must be completed;
   the newest check ID for each distinct check name must be successful, and every
   review thread must be resolved. Completed superseded failures do not poison
   successful same-SHA retries; an older still-running check still blocks.
   Neutral, skipped, rate-limited, absent, pending, failed and cancelled results
   are not approval. `request_changes_workflow: true` requests formal approvals.
2. **Claude Security Review** evaluates security-sensitive changes.
3. **Independent Diff and Issue Review** gets only the diff and linked issue
   title/body, without the PR description (which can contain bot output), another
   reviewer's answer or session. PR title/body remain freshness-bound metadata.

The last two are separate fresh runners and sessions using the **same Claude
provider/credential**; this is session independence, not independent providers.
They do not run tests, see the complete repository, or replace human review.
A repaired Claude integration is a candidate, not established reviewer quality.
The earlier observed sample (20 PRs) contained 3 successful CodeRabbit checks,
8 skipped, 6 neutral/rate-limited, 2 cancelled and 1 absent. Claude showed 16
successful and 4 failed runs, but 9 successes had no output and 7 had only a
no-issues comment, with no inline findings in that sample. Those observations
measure output/availability, **not a false-positive rate**. Retain CodeRabbit;
its real historical findings are not evidence that every successful check is a
complete review. Evaluate the repaired candidate on real labeled defects before
claiming effectiveness or authorizing unattended merge.

## Trust boundary and refusal conditions

The `pull_request_target` pipeline sparse-checks out only trusted `scripts/ci`
from the event's base SHA. No PR checkout, install, build or lifecycle hook runs
in a credential-bearing review job. Collection uses bounded GitHub API reads;
PR/issue text and patches are JSON data, never shell arguments or instructions.
The model starts in an empty directory with tools disabled, an empty strict MCP
configuration, no setting sources, slash commands disabled, hooks disabled and
no session persistence. The equals-form `--tools=""` and `--setting-sources=""`
are intentional: the pinned base action's argument parser loses quoted empty
values in space-form flags. A local probe against that exact parser and SDK
confirmed literal `--tools=` and final `--setting-sources=` reach the executable.
Explicit CLI settings disable hooks even when ordinary settings sources are off.
Do not replace these with space-form flags or use `--bare` with OAuth (that CLI
mode supports API-key authentication, not OAuth). No old comments or plugin skip
heuristics are accepted.
The narrowly annotated zizmor dangerous-trigger suppression exists only for this
base-code/data-only design. Do not copy it to a workflow that runs PR code.

Each model must return schema-constrained `pass`, `block` or `not_reviewed`, the
exact head SHA, a context digest, an exact duplicate-free reviewed-file inventory
and findings. Only a successful execution returning `pass` with no findings can
advance. Missing secret, malformed/empty output, missing files, truncation, API
failure, missing issue, drafts, forks or unsupported context sizes block. Limits
are 300 textual files, 180 KB of file inventory, 220 KB total context, at most
100 linked issues/review threads (no additional page), and bounded REST pages.
Binary/patchless changes need a policy redesign and human review, not a waiver.
A closing link to at least one issue in this same public repository is required;
cross-repository issue context is deliberately refused. Issue comments are not
supplied as requirements; put the accepted requirement in the issue body.

The publisher is a separate non-model job with `checks: write`; model jobs do not
have that permission. It creates/updates the strict aggregate on the **PR head**,
not the target workflow's base commit, and reads back publication. It re-fetches
the PR, issues, CodeRabbit checks, reviews and threads, rejects newer runs/attempts
or invalidations, and never turns a skipped/failed prerequisite into success.
A cancelled workflow can leave an in-progress aggregate, which still blocks.
PR head/title/body edits trigger fresh sessions. Same-repository issue edits,
deletions or transfers conservatively invalidate **all** open PRs; rerun reviews.
Trusted default-branch `check_run` handlers also invalidate completed green
aggregates when CodeRabbit creates, completes or re-requests a check on that SHA.
They create a separate newer failed aggregate, including while a publisher is
active. An older publisher cannot overwrite that append-only invalidation.
Publication revalidates current provider evidence and checks for newer markers
again after its write. A late-delivered event can require another complete run.
Same-event reruns retain the original workflow creation timestamp; changed PR
metadata is refused and changed issue requirements advance freshness.
GitHub events and check publication are asynchronous, not an atomic merge lock.
After a post-publication review/thread change, rerun the gate; keep GitHub's
native required-review/conversation protections enabled. The aggregate does not
replace those native protections or prove a merge-time external runner exists.

## Operating and retrying

1. Keep the PR non-draft, same-repository, targeting main with a same-repository
   closing issue link, such as `Fixes #123`. Keep requirements in that issue body.
2. Run the full trusted review workflow. Request a fresh full CodeRabbit review
   after the original run begins (for example `@coderabbitai full review`). Its
   events can invalidate the active aggregate; after the provider settles, rerun
   the complete same workflow rather than creating a new run or changing code.
   The rerun may reuse complete successful CodeRabbit evidence newer than the
   original run and current issue requirements, while both Claude sessions run
   fresh. The publisher waits up to roughly ten minutes for provider completion;
   API failures fail immediately.
3. Inspect `Claude Security Review`, `Independent Diff and Issue Review` and
   `Publish Review Gate`. A green action without validated structured output is
   not enough. Missing OAuth setup must be repaired through approved secret
   administration, never by pasting tokens into code, issues or chat.
4. For 429, runner or provider infrastructure failures, retry the complete run
   at most **two** times without code changes. A successful replacement check may
   supersede a completed failed/skipped/neutral/cancelled check of the same name;
   no currently running check or unsuccessful latest check is accepted. Do not
   request another provider review unnecessarily on each workflow rerun, or make
   empty commits to manufacture a green check. Escalate if retries cannot
   establish complete current evidence.
5. For an actual code defect, allow at most **two** fix/review cycles, with tests
   and fresh reviews on each changed SHA. Then hand off to a maintainer. A block,
   unavailable service or missing independent approval is never a bypass signal.
6. After editing PR requirements or a linked issue, rerun the entire workflow
   and request fresh CodeRabbit review. Do not rerun only the publisher: the
   security and diff outputs must come from this same workflow attempt.
7. Before merge, verify current SHA/context, all required checks and independent
   human/code-owner approval in GitHub. No worker may merge or publish merely
   because local tests or model reviews passed.

## Agent restrictions and remaining external setup

Future automation may work only in an assigned isolated branch/worktree. It may
not read credentials/wallets, modify CI/security/release policy, disable checks,
change live rules/settings, grant unattended permissions, publish packages,
deploy, approve its own work or merge without explicit maintainer authorization.
This maintenance task's authorization is not a standing exemption. Keep private
plans, correspondence, contacts and commercial data out of this public repository.

An overnight dispatcher/Linear runner is not deployed here. Repository policy,
approved runner credentials, task ownership and an independent review identity
need separate setup and explicit authorization; a connected task service alone
does not supply them. No stub pipeline is presented as a working dispatcher.

## Local verification

```sh
npm ci
npm run build
npm run typecheck
npm run lint
npm run test:ci
npm test
npm run release:hygiene
npm audit --omit=dev --audit-level=high
# After installing the exact CLI versions used in Workflow Security:
actionlint -color
zizmor --offline --format plain .github/workflows
```

Run the SDK's pytest and strict mypy checks in an isolated Python environment,
and use `npm run test:python` when exercising the combined integration matrix.
Local policy tests use synthetic API responses, not an actual hosted model run;
a hosted canary is a separate required rollout verification.

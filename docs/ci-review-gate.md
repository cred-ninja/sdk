# CI and review-gate operations

## Deployment status and bootstrap

These files define a candidate policy, not proof that the hosted policy has run.
The strict target workflow uses **only the PR base SHA's trusted CI scripts**.
It cannot exercise this new implementation on its own rollout PR before those
scripts are merged into `main`. Do not execute the PR version with credentials,
turn off protection, self-approve, or bypass the existing approval rule to land it.
A separately authorized maintainer must arrange a protected rollout, then verify
the checks on a non-draft canary PR before adding deterministic required contexts.
The canary must exercise the exact Linux native executable's version/help and
real authenticated structured-output execution, artifact tampering refusal,
post-success API faults, workflow cancellation and the completion recovery handler.
It must also show CodeRabbit check changes on an Actions-associated SHA trigger
invalidation through an independent event or scheduled fallback. Same-SHA check
precedence must be observed in GitHub's merge decision under separately authorized
canary rules: a newer failed marker refuses and a newer successful aggregate
supersedes earlier failures with all other requirements satisfied. These observations
are necessary evidence, not proof of atomic merge enforcement.
No releases, registry publication, live settings changes, or autonomous dispatcher
are implemented by this refresh.

The only intended additional required context is **Workflow Security**, after
its hosted canary. **Review Gate is ADVISORY EVIDENCE ONLY; do not make it a
required context or rely on it for autonomous merge.** Its final observation and
asynchronous invalidation cannot atomically control GitHub's merge decision. A
required aggregate is deferred until an atomic enforcement design is implemented
and proven; this repository does not implement such an engine. Keep existing
build, test, lint, Python, leak, dependency, CodeQL and raw CodeRabbit checks.
Preserve native independent human approval, last-push approval, conversation
resolution, branch freshness and no-bypass rules as the final merge wall. Local
tests do not prove those server-side settings. This is not fully unattended CI.

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
  Gitleaks scans a clean tracked-tree snapshot, including `export-ignore` files,
  not untracked environment files, ignored local files or history. Two Python
  test-vector values have rule/path/value-specific AND exceptions in
  `.gitleaks.toml`, not line-number fingerprints. The existing global config
  still excludes documented sample/test/docs/generated paths and placeholders;
  this is not exhaustive scanning of every tracked byte. Behavioral probes prove
  each new exception reports a changed matching value at the same location.
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
no session persistence. A non-model, noncredential job downloads the official
Claude **2.1.327 linux-x64** native executable, verifies its literal SHA-256
`343c744baa14bfd38286a7cb90871051f04379956da6c5b803a9e66019a76ac9`
and **372904464-byte** size, then exercises version/help without authentication.
It uploads a same-workflow immutable artifact with one-day retention and no
compression. Each model job downloads that artifact and re-verifies its bytes
before execution, including immediately before spawning. There is no Bun/npm/pip
installation, installer script or curl-to-shell chain in a model job.
A trusted preinstalled runner Node launcher (no runtime installer in either model
job) passes explicit argument-array empty values for tools and
setting sources, reads the prompt from a file into stdin, and creates a fresh cwd,
HOME and config directory. Only its CLI child receives the OAuth token in an
allowlisted environment (no GitHub token or inherited Node options). It disables
updating and nonessential traffic, hooks, MCP servers, slash commands and session
persistence. It checks native `type`, `subtype`, `is_error` and `structured_output`
and then the review policy; nonzero, malformed, absent, excessive or incomplete
output fails without logging provider text. Do not use `--bare` with OAuth.
Explicit CLI settings disable hooks even when ordinary setting sources are off.
The narrowly annotated zizmor dangerous-trigger suppression exists only for this
base-code/data-only design. Do not copy it to a workflow that runs PR code.

Each model must return schema-constrained `pass`, `block` or `not_reviewed`, the
exact head SHA, a context digest, an exact duplicate-free reviewed-file inventory
and findings. Only a successful execution returning `pass` with no findings can
advance. Missing secret, malformed/empty output, missing files, truncation, API
failure, missing issue, drafts, forks or unsupported context sizes block. Limits
are 300 textual files, 180 KB of file inventory and a stricter **less than 100 KiB**
UTF-8 serialized snapshot transport budget, including every metadata field, digest,
`SNAPSHOT=` name and NUL terminator (no truncation), at most
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
Collection errors attempt to mark the initialized check failed before returning.
After a success write, verification/API/marker failures attempt bounded restoration
and readback of failure on that same attempt's check; the job still fails. A
trusted default-branch `workflow_run` completion handler reconciles failed or
cancelled review attempts by verified run identity and external ID, without
consuming PR artifacts. If GitHub remains unavailable, recovery can also fail;
it is not an atomic guarantee and hosted fault canaries remain necessary.
PR head/title/body edits trigger fresh sessions. Issue changes conservatively
invalidate all open PRs. CodeRabbit `check_run` events are only one input:
GitHub can suppress them for Actions-associated SHAs. Independent review,
dismissal, review-comment and issue-comment events also invalidate completed
successes, and a 15-minute schedule conservatively expires successful evidence
on all open PRs. Schedule delivery itself can be delayed by GitHub; this is not a
15-minute enforcement guarantee. Rerun complete reviews after evidence expires.
Per-PR invalidations retry twice after the initial attempt and continue after a
failure; successful marker POSTs reuse their returned ID for verification.
The final publisher rechecks evidence and newer markers, but an event can still
arrive after its final observation. The aggregate cannot guarantee that a review
is not running at merge time; keep it advisory, retain native human approval and
never arm unattended merge based on its color. Same-event reruns retain the
original workflow creation timestamp; changed PR metadata is refused and changed
issue requirements advance freshness.

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
6. After a PR-body/title edit, use the **new workflow run triggered by that edit**;
   the original run's event metadata is stale and cannot be repaired by rerunning
   it. After an issue-only edit, rerun the full current PR workflow and request
   fresh CodeRabbit approval. Never rerun only the publisher: security and diff
   outputs must come from the same workflow attempt.
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

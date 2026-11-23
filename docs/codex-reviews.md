# Codex review migration and local fallback

## Rollout status

This change prepares a migration; it does not claim native Codex review is enabled.
Keep CodeRabbit operational until Codex completes a review on a real PR at its
current head, the deterministic checks run, and the maintainer verifies findings.
Never merge this migration automatically.

## Architecture and billing

| Path | Authentication and usage | Decision |
| --- | --- | --- |
| Native Codex GitHub review | Connected GitHub repository plus eligible ChatGPT account; GitHub reviews consume Code Review usage | Preferred routine reviewer, advisory |
| Local Codex CLI | `codex login` with ChatGPT; local reviews consume general Codex usage, not the GitHub Code Review allowance | Manual fallback and deeper security/correctness review |
| Official `openai/codex-action` | Provider API key stored as an Actions secret; OpenAI API usage is billed separately | Not installed; unnecessary API billing and credential-bearing public-PR execution |

Subscription usage is limited, not unlimited. Do not buy credits, enable paid
API billing or silently switch authentication when limits are reached. Check
Codex's usage dashboard (or `/status` interactively), wait for reset, or use an
eligible independent human reviewer. Keep deterministic gates running. A local
review may still work when the separate GitHub review allowance is exhausted,
but it also has limits. Never rotate identities or retry-loop to evade limits.

No custom review service, new model credential or Actions job is introduced.
Alternative open-source review services are not needed for the selected design;
a pending account authorization is not a reason to build another bot.

## Enable native review (account owner)

1. Open <https://chatgpt.com/codex/settings/code-review> using the ChatGPT account
   whose subscription should supply reviews. Sign in and complete any MFA.
2. Connect GitHub and authorize the OpenAI Codex connector for **only
   `cred-ninja/sdk`**. An organization owner may need to approve installation.
   Inspect GitHub's actual permission screen: source/metadata access enables
   reading the diff and repository; PR/issue interaction enables review comments
   and requests. Do not grant unrelated repositories. If the screen requests
   broader write access, assess it before approving; this runbook is not a
   substitute for inspecting the live requested permissions.
3. Select this repository and enable **Automatic review** under **Review code**.
   Check **Personal preferences → Automatic review → Review trigger** as well.
   Prefer opening/ready-for-review rather than every push if available; avoid
   requesting manual review while an automatic review is already running.
   Record the actual selected trigger rather than assuming the UI supports a
   particular option. Leave automatic Security Review off initially; request a
   deeper security pass only for relevant changes and when available to the plan.
4. On the migration PR, comment `@codex review`. A reaction is acknowledgment,
   not completion. Read the actual review or explicit completed no-findings
   response and confirm which head it covers. Request one new pass after material
   fixes; do not repeat requests on unchanged diffs.
5. Verify applicable root/nested `AGENTS.md` review rules. A rule citation in a
   finding or task trace can demonstrate application. A clean review without a
   trace does not prove every rule was applied. Do not fabricate a vulnerability
   merely to elicit a finding.

A GitHub CLI login and a local ChatGPT CLI login do not authorize the native
GitHub connector. No documented `gh` or Codex CLI switch configures the account's
native automatic-review settings. Use the authenticated settings UI.

### Manual native requests

```text
@codex review
@codex review for authorization, scope escalation, credential isolation and refresh-token lifecycle regressions
```

The documented additional `@codex security review` feature is a research preview;
use it only if enabled for the account. General code review also checks security.
Native GitHub review currently focuses on P0/P1 issues; use local deep review for
lower-severity correctness defects. Neither a PR comment, a GitHub review event,
nor a reaction is a CI check. The official native-review documentation does not
promise a reliable required status-check context. Keep Codex advisory; do not
invent a required `Codex` context or a dummy green substitute.

## Local fallback

From a clean, trusted checkout, verify:

```sh
codex --version
codex login status
```

The second command must report **Logged in using ChatGPT**. If missing, run
`codex login` and complete the browser flow; `codex login --device-auth` is the
supported headless alternative when enabled. Never copy an auth cache or session
credential into this repository, CI, GitHub Secrets or PR comments.

For local work using the installed CLI's built-in review command:

```sh
# Staged, unstaged and untracked changes; inspect untracked files first.
codex -s read-only -a never -c forced_login_method='"chatgpt"' review --uncommitted

# Current branch relative to current main (fetch before reviewing).
git fetch origin main
codex -s read-only -a never -c forced_login_method='"chatgpt"' review --base origin/main
```

Do not expose `.env`, credentials, private mail or unrelated sensitive untracked
files to a reviewer. Read-only mode prevents writes but is not a secret-hiding
boundary. Inspect external PRs in a separate worktree and assess any project
configuration/hooks before running a local agent; do not execute untrusted code
with inherited credentials.

Review a PR in a separate worktree without changing another developer's checkout
(replace `123` with the real PR number, and choose a new directory):

```sh
git fetch origin main
git fetch origin pull/123/head
git worktree add --detach ../sdk-pr-123-review FETCH_HEAD
cd ../sdk-pr-123-review
test "$(gh pr view 123 -R cred-ninja/sdk --json baseRefName --jq .baseRefName)" = main &&
  test "$(git rev-parse HEAD)" = "$(gh pr view 123 -R cred-ninja/sdk --json headRefOid --jq .headRefOid)" &&
  codex -s read-only -a never -c forced_login_method='"chatgpt"' review --base origin/main
```

The identity/base checks must succeed before starting review; otherwise stop and
refetch the correct head/base. Fetch the PR head separately: fetching multiple
refs together makes `FETCH_HEAD` ambiguous and can check out main instead of the
PR. The example assumes a main-target PR; for a stacked PR, fetch and review
against its actual base instead. Do not approve or merge as part of the review.

For a deeper security-focused branch review, use a custom review prompt with an
explicit comparison. The installed CLI does not allow combining a custom prompt
with `--base` or `--uncommitted`, so keep the target in the prompt:

```sh
codex -s read-only -a never -c forced_login_method='"chatgpt"' review \
  'Review git diff origin/main...HEAD. Apply applicable AGENTS.md rules. Inspect callers and tests. Focus on OAuth scope escalation, token/refresh-token leakage, cross-tenant vault access, AES-256-GCM nonces and authentication, revocation/expiry, SSRF, policy bypasses, races, retries, and Python/TypeScript divergence. Report actionable defects with severity, file/line, failure path and remediation. Distinguish verified defects from hypotheses. Do not modify files, execute repository code, read credentials or unrelated paths, or post/approve/merge anything.'
```

For unattended local execution, use the same subscription-only constraint:

```sh
codex -s read-only -a never -c forced_login_method='"chatgpt"' exec review --base origin/main
```

This is local subscription authentication, not permission to export OAuth
sessions to public runners. No wrapper is needed for these built-in paths.

## Audit baseline (2026-11-23)

Base: `6b6a81c`, repository `cred-ninja/sdk`. The existing local main checkout was
behind the remote; migration work uses its own feature branch and worktree.

- Root `AGENTS.md` is the only tracked agent instruction file; no nested override
  was found. Preserve its capability map and public-repository boundaries.
- `.coderabbit.yaml` enables formal verdicts and security-specific path guidance;
  its hosted ESLint and docstring checks are disabled because CI owns those checks.
  Preserve scope-subsumption, crypto, rotation, signed parsing and audit guidance
  when moving instructions to `AGENTS.md`.
- CodeRabbit is an organization GitHub App, ID `347564`, installation `168580483`,
  selected for all repositories. Do not uninstall this shared App. The org also
  reports `linear-code`, `claude` and `meta-muse-ai`; none is a Codex connector.
  Repository webhook inventory is empty. GitHub's user-token installation endpoint
  cannot enumerate installations using the current OAuth CLI token; the org admin
  installation endpoint supplies the inventory instead.
- Classic main-branch protection returns 404, but active ruleset **Protect main**
  (`27505472`) enforces main. Another Copilot automatic-review ruleset is disabled;
  leave it disabled rather than adding redundant reviews.
- Protect main requires PRs, linear history, no deletion/force push, strict checks,
  stale-review dismissal and resolved conversations, with no bypass actors.
  Required approving-review count is zero; this migration does not change it.
- Local `codex-cli 0.167.0` reports ChatGPT login. No login cache was opened or
  exported. No API key or billing configuration is required for this design.

### Exact required-check baseline

The required contexts and producer IDs below are the live audit baseline, not
new workflow names. Preserve all deterministic contexts and producers:

| Producer integration | Required context |
| --- | --- |
| `57789` | `CodeQL` |
| `15368` | `Review Dependencies` |
| `15368` | `Build` |
| `15368` | `Audit` |
| `15368` | `Lint` |
| `15368` | `Package Smoke` |
| `15368` | `Test (Node 22)` |
| `15368` | `Test (Node 26)` |
| `15368` | `Analyze (python)` |
| `15368` | `Analyze (javascript-typescript)` |
| `15368` | `Block Private Artifact Leakage` |
| `15368` | `SDK Python (3.9)` |
| `15368` | `SDK Python (3.10)` |
| `15368` | `SDK Python (3.12)` |
| `15368` | `Python Integration (packages/integrations/langchain)` |
| `15368` | `Python Integration (packages/integrations/crewai)` |
| `15368` | `Python Integration (packages/integrations/openai-agents)` |
| `15368` | `Python Integration (packages/integrations/autogen)` |
| `15368` | `Python Integration (packages/integrations/semantic-kernel)` |
| `15368` | `Python Combined (3.10)` |
| `15368` | `Python Combined (3.12)` |
| `15368` | `Python Combined (3.13)` |
| `15368` | `Python Combined (3.14)` |
| `15368` | `Python Wheel Smoke (3.9)` |
| `15368` | `Python Wheel Smoke (3.10)` |
| `15368` | `Python Wheel Smoke (3.12)` |
| `347564` | `CodeRabbit` (retain until native validation succeeds) |

### Deterministic verification inventory

All six workflow files remain intact:

- `ci.yml`: ESLint, CI script tests, release hygiene, production high/critical
  dependency audit, informational full audit, Node 22/26 builds and tests,
  workspace build/typechecking, scaffold pack and clean npm package smoke.
- `python-ci.yml`: SDK tests/mypy on 3.9/3.10/3.12, five framework integrations,
  combined package environments on 3.10/3.12/3.13/3.14, wheel smoke on 3.9/3.10/3.12.
  No changed-path filter; documentation-only PRs still exercise Python CI.
- `codeql.yml`: Python and JavaScript/TypeScript analysis on PRs/main and weekly;
  retain the separate GitHub code-scanning `CodeQL` result as well.
- `dependency-review.yml`: new high/critical runtime/development/unknown-scope
  advisories, no credential-bearing model execution.
- `public-leak-guard.yml`: tracked paths, internal/private correspondence markers,
  PR/commit text and package inventories. Its CodeRabbit-generated-body exemption
  remains unchanged during the transition, not a new exemption for Codex.
- `workflow-security.yml`: pinned actionlint/zizmor/Gitleaks, scanner probes and
  fully redacted tracked-snapshot secret scan. `Workflow Security` is not currently
  a required context, but still runs; do not remove or bypass it.

### Safe retirement sequence

1. Land no retirement changes until native review is connected, a current-head
   review is complete, applicable guidance is verified where observable and the
   existing required/security checks execute. Keep this migration PR open for
   maintainer merge authorization.
2. Preserve all existing `.coderabbit.yaml` security guidance in the approved
   `AGENTS.md` review section before retiring that file. Prepare the bot-disable
   configuration, but keep its producer operational until the required-context
   removal below is applied and verified.
3. Only then remove the exact required `CodeRabbit` context with producer
   `347564` from ruleset `27505472`, preserving every other writable field,
   check/producer, restriction and approval setting. Reread the live rule before
   applying the narrow delta and verify the effective branch rules afterward.
   Codex remains advisory; no synthetic replacement check.
4. After verifying the context is no longer required, land the configuration
   that explicitly disables automatic CodeRabbit reviews using its supported
   repository controls. Deleting the file alone can restore the App's defaults;
   keep a minimal disabled configuration if the shared App remains installed and
   no repository-level exclusion is available. Update current README/security/CI
   policy references and the CODEOWNERS path if obsolete configuration is removed.
   Preserve historical changelog entries.
   Remove the generated-body exemption only when its workflow change is tested;
   tightening the scan must not break existing PR metadata unexpectedly.
5. Do not uninstall the organization App: it is shared and uninstall is not
   authorized. Verify automatic CodeRabbit reviews have stopped for this repo
   after its disable configuration lands. Configuration in an unmerged PR is
   not evidence that the default branch has retired the bot.

## Official references

Verified against official documentation on 2026-11-23:

- [Codex GitHub integration](https://developers.openai.com/codex/integrations/github/)
- [Codex authentication](https://developers.openai.com/codex/auth/)
- [Codex pricing and usage](https://developers.openai.com/codex/pricing/)
- [AGENTS.md discovery and review rules](https://developers.openai.com/codex/guides/agents-md/)
- [Official Codex Action and API-key requirement](https://github.com/openai/codex-action)

Consult live settings and documentation for eligibility, triggers and limits;
this repository does not promise unlimited reviews or an automatic merge gate.

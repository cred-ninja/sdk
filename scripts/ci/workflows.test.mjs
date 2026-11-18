import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import yaml from 'js-yaml';
import { reviewerArgs } from './claude-runtime.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const load = (name) => yaml.load(readFileSync(`${root}.github/workflows/${name}.yml`, 'utf8'));

// Structural regressions complement actionlint and zizmor; they are not proof
// that a hosted review executed or that the GitHub ruleset requires it.
test('Python CI runs for every main PR, including docs-only changes', () => {
  const trigger = load('python-ci').on.pull_request;
  assert.equal(trigger.paths, undefined);
  assert.equal(trigger['paths-ignore'], undefined);
  assert.deepEqual(trigger.branches, ['main']);
  if (trigger.types) for (const event of ['opened', 'synchronize', 'reopened']) assert.ok(trigger.types.includes(event));
  const jobs = Object.values(load('python-ci').jobs);
  assert.equal(jobs.reduce((count, job) => count + Object.values(job.strategy.matrix)[0].length, 0), 15);
});

test('CI has an explicit typecheck after build and includes policy tests', () => {
  const steps = load('ci').jobs.build.steps;
  const index = steps.findIndex((step) => step.run === 'npm run typecheck');
  const build = steps.findIndex((step) => step.run?.includes('--workspace=packages/server'));
  assert.ok(build >= 0, 'server build must exist');
  assert.ok(index > build);
  assert.ok(load('ci').jobs.lint.steps.some((step) => step.run === 'npm run test:ci'));
});

test('every external action is commit-pinned and checkout credentials are not persisted', () => {
  for (const file of readdirSync(`${root}.github/workflows`).filter((p) => /\.ya?ml$/.test(p))) {
    const workflow = yaml.load(readFileSync(`${root}.github/workflows/${file}`, 'utf8'));
    assert.equal(workflow.permissions?.contents, 'read', file);
    for (const job of Object.values(workflow.jobs)) {
      for (const step of job.steps ?? []) {
        if (!step.uses || step.uses.startsWith('./')) continue;
        assert.match(step.uses, /^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/, file);
        if (step.uses.startsWith('actions/checkout@')) {
          assert.equal(step.with?.['persist-credentials'], false, file);
        }
      }
    }
  }
});

test('credential runners use only a verified native artifact and never runtime installers', () => {
  const w = load('claude-code-review');
  for (const name of ['security', 'diff']) {
    const steps = w.jobs[name].steps;
    assert.ok(steps.some((s) => s.uses?.startsWith('actions/download-artifact@')));
    assert.ok(steps.some((s) => s.run === 'node scripts/ci/claude-runtime.mjs verify'));
    assert.ok(steps.some((s) => s.id === 'review' && s.run === 'node scripts/ci/claude-runtime.mjs review'));
    assert.ok(steps.every((s) => !s.uses?.startsWith('anthropics/') && !s.uses?.startsWith('actions/setup-node@')));
  }
  assert.ok(w.jobs.runtime.steps.some((s) => s.run === 'node scripts/ci/claude-runtime.mjs fetch'));
  assert.ok(load('workflow-security').jobs['workflow-security'].steps.some((s) => s.run === 'node scripts/ci/claude-runtime.mjs fetch'));
});

test('Claude reviewer cannot hide failures or execute PR code with a credential', () => {
  const workflow = load('claude-code-review');
  assert.ok(workflow.on.pull_request_target);
  assert.equal(workflow.on.pull_request, undefined);
  for (const job of Object.values(workflow.jobs)) {
    assert.ok(job['continue-on-error'] === undefined || job['continue-on-error'] === false);
    assert.notEqual(job.permissions?.contents, 'write');
    for (const step of job.steps ?? []) {
      if (step.uses?.startsWith('actions/checkout@')) {
        assert.equal(step.with.ref, '${{ github.event.pull_request.base.sha }}');
      }
    }
  }
  for (const name of ['security', 'diff']) {
    const reviewer = workflow.jobs[name].steps.find((s) => s.id === 'review');
    assert.ok(reviewer);
    assert.ok(reviewer['continue-on-error'] === undefined || reviewer['continue-on-error'] === false);
    assert.equal(reviewer.run, 'node scripts/ci/claude-runtime.mjs review');
    const args = reviewerArgs('empty-mcp.json');
    assert.equal(args[args.indexOf('--tools') + 1], '');
    assert.equal(args[args.indexOf('--setting-sources') + 1], '');
  }
});

test('tooling gate uses exact CLI versions and offline plain zizmor', () => {
  const workflow = load('workflow-security');
  assert.ok(workflow.on.pull_request);
  const shell = workflow.jobs['workflow-security'].steps.map((s) => s.run ?? '').join('\n');
  assert.match(shell, /actionlint\/cmd\/actionlint@v1\.7\.12/);
  assert.match(shell, /zizmor==1\.32\.0/);
  assert.match(shell, /gitleaks\/v8@v8\.30\.1/);
  assert.match(shell, /--offline --format plain/);
  assert.match(shell, /--redact=100/);
  assert.doesNotMatch(shell, /format sarif/);
});

test('dependency review gates all scopes without comment permissions', () => {
  const w = load('dependency-review');
  assert.equal(w.permissions['pull-requests'], undefined);
  const step = w.jobs['dependency-review'].steps.find((s) => s.uses?.startsWith('actions/dependency-review-action@'));
  assert.equal(step.with['fail-on-severity'], 'high');
  assert.equal(step.with['fail-on-scopes'], 'runtime, development, unknown');
  assert.equal(step.with['comment-summary-in-pr'], 'never');
});

test('model jobs are isolated from check-write publishing and old sessions', () => {
  const { jobs } = load('claude-code-review');
  for (const name of ['security', 'diff']) {
    assert.equal(typeof jobs[name].permissions, 'object');
    assert.ok(jobs[name].permissions && !Array.isArray(jobs[name].permissions));
    assert.notEqual(jobs[name].permissions.checks, 'write');
    assert.ok(Object.values(jobs[name].permissions).every((p) => p === 'read' || p === 'none'));
    const action = jobs[name].steps.find((s) => s.id === 'review');
    assert.equal(action.run, 'node scripts/ci/claude-runtime.mjs review');
    assert.ok(reviewerArgs('empty.json').includes('--no-session-persistence'));
    assert.doesNotMatch(reviewerArgs('empty.json').join(' '), /--resume|--continue|bypassPermissions|dangerously-skip/);
  }
  assert.equal(jobs.publish.permissions.checks, 'write');
  assert.deepEqual(jobs.publish.needs, ['prepare', 'security', 'diff']);
});

test('advisory evidence has independent trusted event and completion recovery paths', () => {
  const evidence = load('review-evidence');
  for (const event of ['check_run', 'pull_request_review', 'pull_request_review_comment', 'issue_comment', 'schedule']) assert.ok(evidence.on[event]);
  const recovery = load('review-recovery');
  assert.deepEqual(recovery.on.workflow_run.workflows, ['Claude Code Review']);
  for (const w of [evidence, recovery]) {
    const job = Object.values(w.jobs)[0];
    const checkout = job.steps.find((s) => s.uses?.startsWith('actions/checkout@'));
    assert.equal(checkout.with.ref, '${{ github.event.repository.default_branch }}');
    assert.ok(job.steps.every((s) => !s.uses?.startsWith('actions/download-artifact@')));
  }
  const docs = readFileSync(`${root}docs/ci-review-gate.md`, 'utf8');
  assert.match(docs, /Review Gate is ADVISORY EVIDENCE ONLY/);
  assert.match(docs, /do not make it a\nrequired context/);
});

test('interactive mentions are disabled and updater covers every ecosystem', () => {
  const w = load('claude');
  assert.deepEqual(Object.keys(w.on), ['workflow_dispatch']);
  assert.doesNotMatch(readFileSync(`${root}.github/workflows/claude.yml`, 'utf8'), /secrets\.|anthropics\//);
  const d = yaml.load(readFileSync(`${root}.github/dependabot.yml`, 'utf8'));
  assert.deepEqual(d.updates.map((u) => u['package-ecosystem']).sort(), ['github-actions', 'npm', 'pip']);
  assert.equal(d.updates.find((u) => u['package-ecosystem'] === 'pip').directories.length, 6);
  const owners = readFileSync(`${root}.github/CODEOWNERS`, 'utf8');
  assert.ok(owners.split('\n').map((line) => line.replace(/#.*/, '').trim().split(/\s+/)).some(([pattern, ...tokens]) => pattern === '*' && tokens.includes('@kierandotai')));
  assert.doesNotMatch(owners, /kilroycreative/);
});

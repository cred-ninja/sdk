import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import yaml from 'js-yaml';

const root = fileURLToPath(new URL('../../', import.meta.url));
const load = (name) => yaml.load(readFileSync(`${root}.github/workflows/${name}.yml`, 'utf8'));

// Structural regressions complement actionlint and zizmor; they are not proof
// that a hosted review executed or that the GitHub ruleset requires it.
test('Python CI runs for every main PR, including docs-only changes', () => {
  const trigger = load('python-ci').on.pull_request;
  assert.equal(trigger.paths, undefined);
  assert.equal(trigger['paths-ignore'], undefined);
  assert.deepEqual(trigger.branches, ['main']);
  const jobs = Object.values(load('python-ci').jobs);
  assert.equal(jobs.reduce((count, job) => count + Object.values(job.strategy.matrix)[0].length, 0), 15);
});

test('CI has an explicit typecheck after build and includes policy tests', () => {
  const steps = load('ci').jobs.build.steps;
  const index = steps.findIndex((step) => step.run === 'npm run typecheck');
  assert.ok(index > steps.findIndex((step) => step.run?.includes('--workspace=packages/server')));
  assert.ok(load('ci').jobs.lint.steps.some((step) => step.run === 'npm run test:ci'));
});

test('every external action is commit-pinned and checkout credentials are not persisted', () => {
  for (const file of readdirSync(`${root}.github/workflows`).filter((p) => p.endsWith('.yml'))) {
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

test('Claude reviewer cannot hide failures or execute PR code with a credential', () => {
  const workflow = load('claude-code-review');
  assert.ok(workflow.on.pull_request_target);
  assert.equal(workflow.on.pull_request, undefined);
  for (const job of Object.values(workflow.jobs)) {
    assert.notEqual(job['continue-on-error'], true);
    assert.notEqual(job.permissions?.contents, 'write');
    for (const step of job.steps ?? []) {
      if (step.uses?.startsWith('actions/checkout@')) {
        assert.equal(step.with.ref, '${{ github.event.pull_request.base.sha }}');
      }
    }
  }
  const text = readFileSync(`${root}.github/workflows/claude-code-review.yml`, 'utf8');
  // The pinned action parser drops quoted empty arguments. Equals-form flags
  // survive its SDK transport as literal --tools= and --setting-sources=.
  assert.match(text, /--tools=""/);
  assert.match(text, /--setting-sources=""/);
  assert.match(text, /structured_output/);
  assert.doesNotMatch(text, /plugin_marketplaces/);
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
    assert.equal(jobs[name].permissions.checks, undefined);
    const action = jobs[name].steps.find((s) => s.uses?.startsWith('anthropics/'));
    assert.equal(action.env.CLAUDE_WORKING_DIR, '${{ runner.temp }}/review-empty');
    assert.match(action.with.claude_args, /--no-session-persistence/);
    assert.doesNotMatch(action.with.claude_args, /--resume|--continue|bypassPermissions|dangerously-skip/);
  }
  assert.equal(jobs.publish.permissions.checks, 'write');
  assert.deepEqual(jobs.publish.needs, ['prepare', 'security', 'diff']);
});

test('interactive mentions are disabled and updater covers every ecosystem', () => {
  const w = load('claude');
  assert.deepEqual(Object.keys(w.on), ['workflow_dispatch']);
  assert.doesNotMatch(readFileSync(`${root}.github/workflows/claude.yml`, 'utf8'), /secrets\.|anthropics\//);
  const d = yaml.load(readFileSync(`${root}.github/dependabot.yml`, 'utf8'));
  assert.deepEqual(d.updates.map((u) => u['package-ecosystem']).sort(), ['github-actions', 'npm', 'pip']);
  assert.equal(d.updates.find((u) => u['package-ecosystem'] === 'pip').directories.length, 6);
  const owners = readFileSync(`${root}.github/CODEOWNERS`, 'utf8');
  assert.ok(owners.includes('* @kierandotai'));
  assert.doesNotMatch(owners, /kilroycreative/);
});

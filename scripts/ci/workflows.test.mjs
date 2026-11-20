import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import * as yaml from 'js-yaml';

const root = fileURLToPath(new URL('../../', import.meta.url));
const load = (name) => yaml.load(readFileSync(`${root}.github/workflows/${name}.yml`, 'utf8'));

test('CI has no custom review lifecycle or credential-bearing model jobs', () => {
  const workflows = readdirSync(`${root}.github/workflows`).filter((p) => /\.ya?ml$/.test(p));
  for (const file of workflows) {
    assert.doesNotMatch(file, /^(?:claude|claude-code-review|review-evidence|review-invalidation|review-recovery)\.ya?ml$/);
    const source = readFileSync(`${root}.github/workflows/${file}`, 'utf8');
    assert.doesNotMatch(source, /review-gate\.mjs|claude-runtime\.mjs|CLAUDE_CODE_OAUTH_TOKEN|anthropics\//);
  }
  const scripts = readdirSync(`${root}scripts/ci`);
  assert.ok(scripts.every((file) => !/^(?:review-gate|review-policy|publication-race|claude-runtime)(?:\.|$)/.test(file)));
});

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
  const build = steps.findIndex((step) => step.run === 'npm run build');
  assert.ok(build >= 0, 'the complete workspace build must exist');
  assert.ok(index > build);
  assert.ok(load('ci').jobs.lint.steps.some((step) => step.run === 'npm run test:ci'));
});

test('the test matrix reuses the complete root build and test commands', () => {
  const steps = load('ci').jobs.test.steps;
  const build = steps.findIndex((step) => step.run === 'npm run build');
  assert.ok(build >= 0);
  assert.ok(steps.findIndex((step) => step.run === 'npm test') > build);
  const manifest = JSON.parse(readFileSync(`${root}package.json`, 'utf8'));
  for (const workspace of manifest.workspaces) {
    let pkg;
    try { pkg = JSON.parse(readFileSync(`${root}${workspace}/package.json`, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    for (const script of ['build', 'test']) {
      if (pkg.scripts?.[script]) {
        assert.ok(manifest.scripts[script].split(' && ').includes(`npm run ${script} --workspace=${workspace}`), `${workspace} must remain in the root ${script} command`);
      }
    }
  }
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

test('updater covers every ecosystem and code ownership names the maintainer', () => {
  const d = yaml.load(readFileSync(`${root}.github/dependabot.yml`, 'utf8'));
  assert.deepEqual(d.updates.map((u) => u['package-ecosystem']).sort(), ['github-actions', 'npm', 'pip']);
  assert.equal(d.updates.find((u) => u['package-ecosystem'] === 'pip').directories.length, 6);
  const owners = readFileSync(`${root}.github/CODEOWNERS`, 'utf8');
  assert.ok(owners.split('\n').map((line) => line.replace(/#.*/, '').trim().split(/\s+/)).some(([pattern, ...tokens]) => pattern === '*' && tokens.includes('@kierandotai')));
  assert.doesNotMatch(owners, /kilroycreative/);
});

import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import * as yaml from 'js-yaml';
import { readFileSync } from 'node:fs';
const steps = yaml.load(readFileSync(new URL('../../.github/workflows/public-leak-guard.yml', import.meta.url), 'utf8')).jobs['leak-guard'].steps;
function run(name, env = {}, prefix = '') {
  const step = steps.find((s) => s.name === name);
  const dir = mkdtempSync(join(tmpdir(), 'cred ci spaces-'));
  try {
    writeFileSync(join(dir, 'tracked-files.txt'), `${env.TEST_PATH ?? 'README.md'}\0`);
    const result = spawnSync('bash', ['-c', prefix + '\n' + step.run], { env: { ...process.env, RUNNER_TEMP: dir, ...env }, encoding: 'utf8' });
    if (result.error) throw result.error;
    assert.equal(typeof result.status, 'number', 'Bash must exit normally');
    return result;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
test('denylist blocks lowercase plan files and plan directories', () => {
  for (const path of ['plan.md', 'docs/plans/example.md', 'docs/PLAN.md', 'docs/release-plan.md', 'RELEASE-PLAN.MD']) {
    // Tests execute the real workflow shell, without changing tracked files.
    const result = run('Block denylisted paths', { TEST_PATH: path });
    assert.notEqual(result.status, 0, path);
  }
});
test('ordinary README path remains allowed', () => assert.equal(run('Block denylisted paths', { TEST_PATH: 'README.md' }).status, 0));
function trackedStep(filename, content, name, prefix = '') {
  const dir = mkdtempSync(join(tmpdir(), 'cred git inventory spaces-'));
  try {
    mkdirSync(dirname(join(dir, filename)), { recursive: true });
    writeFileSync(join(dir, filename), content);
    const execute = (binary, args) => {
      const result = spawnSync(binary, args, { cwd: dir, env: { ...process.env, RUNNER_TEMP: dir }, encoding: 'utf8' });
      if (result.error) throw result.error;
      assert.equal(typeof result.status, 'number');
      return result;
    };
    assert.equal(execute('git', ['init', '-q']).status, 0);
    assert.equal(execute('git', ['--literal-pathspecs', 'add', '--', filename]).status, 0);
    const collection = execute('bash', ['-c', steps.find((s) => s.name === 'Collect tracked files').run]);
    assert.equal(collection.status, 0);
    const result = execute('bash', ['-c', prefix + '\n' + steps.find((s) => s.name === name).run]);
    result.collectedOutput = collection.stdout;
    return result;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
test('tracked filenames cannot emit GitHub workflow commands in collection logs', () => {
  const result = trackedStep('::add-mask::fixture.md', 'ordinary fixture', 'Block denylisted paths');
  assert.equal(result.status, 0);
  assert.ok(!result.collectedOutput.split('\n').some((line) => line.startsWith('::')));
});
for (const filename of ['docs/é-release-plan.md', 'docs/tab\t-release-plan.md', 'docs/line\n-release-plan.md']) {
  test(`real Git inventory blocks quoted plan filename ${JSON.stringify(filename)}`, () => {
    assert.notEqual(trackedStep(filename, 'ordinary fixture', 'Block denylisted paths').status, 0);
  });
}
for (const filename of ['docs/é-notes.md', 'docs/tab\t-notes.md', 'docs/line\n-notes.md', '--notes.md']) {
  test(`real Git inventory handles every marker consumer for ${JSON.stringify(filename)}`, () => {
    assert.equal(trackedStep(filename, 'ordinary fixture', 'Block denylisted paths').status, 0);
    assert.equal(trackedStep(filename, 'ordinary fixture', 'Block internal markers in public files').status, 0);
    assert.notEqual(trackedStep(filename, ['SESSION', 'PACKAGE'].join('_'), 'Block internal markers in public files').status, 0);
    assert.equal(trackedStep(filename, 'ordinary fixture', 'Block private correspondence markers in public files').status, 0);
    assert.notEqual(trackedStep(filename, 'Stance:' + ' WATCH', 'Block private correspondence markers in public files').status, 0);
  });
}
for (const name of ['Block internal markers in public files', 'Block private correspondence markers in public files']) {
  test(`${name} refuses scanner errors instead of treating them as no match`, () => {
    assert.notEqual(trackedStep('README.md', 'ordinary fixture', name, 'function grep() { return 23; }').status, 0);
  });
}
test('commit scan fails closed when git log fails, even without a marker match', () => {
  const result = run('Block private correspondence markers in PR text and commits', { PR_TITLE: 'Clean', PR_BODY: '', BASE_SHA: 'bad', HEAD_SHA: 'bad' }, 'function git() { return 17; }');
  assert.notEqual(result.status, 0);
});
test('pack validation rejects malformed JSON instead of returning success', () => {
  const result = run('Block reports from npm packages', {}, "function npm() { printf 'not-json'; }");
  assert.notEqual(result.status, 0);
});
test('pack validation rejects empty or structurally invalid inventories', () => {
  for (const value of ['[]', '{}', '[{"name":"example"}]']) {
    const result = run('Block reports from npm packages', {}, `function npm() { printf '%s' '${value}'; }`);
    assert.notEqual(result.status, 0, value);
  }
});
test('pack validation accepts clean inventory and rejects private paths', () => {
  for (const [path, expected] of [['dist/index.js', 0], ['reports/note.txt', 1]]) {
    const result = run('Block reports from npm packages', {}, `function npm() { printf '%s' '[{"name":"example","files":[{"path":"${path}"}]}]'; }`);
    assert.equal(result.status, expected, result.stderr);
  }
});
test('commit scan accepts clean messages and rejects correspondence markers', () => {
  for (const [message, expected] of [['Ordinary change', 0], ['Stance:' + ' WATCH', 1]]) {
    const result = run('Block private correspondence markers in PR text and commits', { PR_TITLE: 'Clean', PR_BODY: '', BASE_SHA: 'base', HEAD_SHA: 'head' }, `function git() { printf '%s' '${message}'; }`);
    assert.equal(result.status, expected, result.stderr);
  }
});

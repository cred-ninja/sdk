import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import yaml from 'js-yaml';
import { readFileSync } from 'node:fs';
const steps = yaml.load(readFileSync(new URL('../../.github/workflows/public-leak-guard.yml', import.meta.url), 'utf8')).jobs['leak-guard'].steps;
function run(name, env = {}, prefix = '') {
  const step = steps.find((s) => s.name === name);
  const dir = mkdtempSync(join(tmpdir(), 'cred ci spaces-'));
  try {
    writeFileSync(join(dir, 'tracked-files.txt'), env.TEST_PATH ?? 'README.md');
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

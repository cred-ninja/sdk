import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import * as yaml from 'js-yaml';

const doc = readFileSync(new URL('../../docs/codex-reviews.md', import.meta.url), 'utf8');
const blocks = [...doc.matchAll(/```sh\n([\s\S]*?)```/g)].map((match) => match[1]);
const pr = blocks.find((block) => block.includes('pull/123/head'));
const branch = blocks.find((block) => block.includes('# Current branch'))
  .split('# Current branch relative to current main (fetch before reviewing).\n')[1];

test('CodeRabbit stays opted out while Codex guidance is present', () => {
  const config = yaml.load(readFileSync(new URL('../../.coderabbit.yaml', import.meta.url), 'utf8'));
  assert.equal(config.reviews.auto_review.enabled, false);
  assert.equal(config.reviews.auto_review.auto_incremental_review, false);
  assert.equal(config.reviews.auto_review.description_keyword, '');
  assert.deepEqual(config.reviews.auto_review.labels, []);
  assert.equal(config.reviews.auto_approvals.enabled, false);
  assert.equal(config.chat.auto_reply, false);
  assert.equal(config.reviews.path_instructions, undefined);
  const instructions = readFileSync(new URL('../../AGENTS.md', import.meta.url), 'utf8');
  assert.match(instructions, /^## Code Review Rules$/m);
});

// Exercise the published shell itself, not a second implementation of it.
const mocks = `
git() {
  case "$*" in
    'fetch origin refs/heads/main:refs/remotes/origin/main') [ "$SCENARIO" != base_fail ] ;;
    'fetch origin pull/123/head') [ "$SCENARIO" != head_fail ] ;;
    'worktree add --detach ../sdk-pr-123-review FETCH_HEAD') [ "$SCENARIO" != worktree_fail ] ;;
    'rev-parse HEAD')
      if [ "$SCENARIO" = wrong_head ]; then printf wrong; else printf expected; fi ;;
    *) return 99 ;;
  esac
}
gh() {
  case "$*" in
    *baseRefName*) if [ "$SCENARIO" = wrong_base ]; then printf feature; else printf main; fi ;;
    *headRefOid*) printf expected ;;
    *) return 99 ;;
  esac
}
cd() { [ "$SCENARIO" != cd_fail ]; }
codex() { printf 'REVIEW_STARTED\n'; }
`;

for (const [name, shell, scenarios] of [
  ['PR', pr, ['ok', 'base_fail', 'head_fail', 'worktree_fail', 'cd_fail', 'wrong_head', 'wrong_base']],
  ['branch', branch, ['ok', 'base_fail']],
]) {
  for (const scenario of scenarios) {
    test(`documented ${name} review handles ${scenario} before invoking Codex`, () => {
      const result = spawnSync('bash', ['-c', `${mocks}\n${shell}`], {
        env: { PATH: process.env.PATH, SCENARIO: scenario }, encoding: 'utf8',
      });
      if (result.error) throw result.error;
      assert.equal(result.stdout.includes('REVIEW_STARTED'), scenario === 'ok', result.stderr);
      assert.equal(result.status === 0, scenario === 'ok', result.stderr);
    });
  }
}

test('documented PR checkout refreshes main in a restricted-fetch clone and reviews the PR ref', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cred-review-docs-'));
  const env = { PATH: process.env.PATH, HOME: dir, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
  const run = (cwd, binary, args) => {
    const result = spawnSync(binary, args, { cwd, env, encoding: 'utf8' });
    if (result.error) throw result.error;
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  const commit = (cwd, message) => run(cwd, 'git', [
    '-c', 'user.name=Review Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit', '-qm', message,
  ]);
  try {
    run(dir, 'git', ['init', '-q', '-b', 'main', 'remote']);
    const remote = join(dir, 'remote');
    writeFileSync(join(remote, 'base.txt'), 'base\n');
    run(remote, 'git', ['add', 'base.txt']);
    commit(remote, 'base');
    run(remote, 'git', ['checkout', '-qb', 'fixture-pr']);
    writeFileSync(join(remote, 'pr.txt'), 'PR change\n');
    run(remote, 'git', ['add', 'pr.txt']);
    commit(remote, 'PR');
    const head = run(remote, 'git', ['rev-parse', 'HEAD']);
    run(remote, 'git', ['update-ref', 'refs/pull/123/head', head]);
    run(remote, 'git', ['checkout', '-q', 'main']);
    run(dir, 'git', ['clone', '-q', '--no-local', remote, 'checkout']);
    run(join(dir, 'checkout'), 'git', ['config', '--replace-all', 'remote.origin.fetch', '+refs/heads/fixture-pr:refs/remotes/origin/fixture-pr']);
    writeFileSync(join(remote, 'base.txt'), 'new main\n');
    run(remote, 'git', ['add', 'base.txt']);
    commit(remote, 'advance main');
    env.EXPECTED_BASE = run(remote, 'git', ['rev-parse', 'HEAD']);
    env.EXPECTED_HEAD = head;
    const output = run(join(dir, 'checkout'), 'bash', ['-c', `
      gh() {
        case "$*" in
          *baseRefName*) printf main ;;
          *headRefOid*) printf '%s' "$EXPECTED_HEAD" ;;
          *) return 99 ;;
        esac
      }
      codex() {
        test "$(git rev-parse origin/main)" = "$EXPECTED_BASE" &&
        test "$(git diff --name-only origin/main...HEAD)" = pr.txt && printf 'REVIEW_STARTED\n'
      }
      ${pr}
    `]);
    assert.ok(output.includes('REVIEW_STARTED'));
    assert.equal(run(join(dir, 'sdk-pr-123-review'), 'git', ['rev-parse', 'HEAD']), head);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { collect, main } from './review-gate.mjs';

// Exercise actual publisher and invalidator together, including an invalidation
// consumed while the publisher's original check is still in progress.
for (const boundary of ['run-read', 'success-write']) test(`CodeRabbit invalidation survives publication at ${boundary}`, async () => {
  const repo = 'example/sdk', head = 'a'.repeat(40), base = 'b'.repeat(40);
  const dir = mkdtempSync(join(tmpdir(), 'cred-publish-race-'));
  const prior = { ...process.env };
  const pr = { number: 1, draft: false, state: 'open', title: 'Change', body: 'Fixes #2', changed_files: 1, head: { sha: head, repo: { full_name: repo } }, base: { sha: base, ref: 'main' } };
  const file = { filename: 'a.ts', additions: 1, deletions: 1, patch: '@@ -1 +1 @@\n-old\n+new' };
  const issue = { number: 2, title: 'Requirement', body: 'Fix it', updatedAt: '2026-11-17T11:00:00Z', repository: { nameWithOwner: repo } };
  const gate = { id: 17, name: 'Review Gate', app: { slug: 'github-actions' }, head_sha: head, status: 'in_progress', conclusion: null, external_id: '3:1' };
  const checks = [{ id: 10, name: 'CodeRabbit', app: { slug: 'coderabbitai' }, head_sha: head, status: 'completed', conclusion: 'success' }, gate];
  let injected = false, next = 20;
  async function invalidate() {
    injected = true;
    checks.push({ ...checks[0], id: 11, conclusion: 'failure' });
    const event = process.env.GITHUB_EVENT_PATH;
    process.env.GITHUB_EVENT_PATH = join(dir, 'check.json');
    try { await main('invalidate-check', api); } finally { process.env.GITHUB_EVENT_PATH = event; }
  }
  async function api(path, body) {
    if (path.endsWith('/pulls/1')) return pr;
    if (path.includes('/files?')) return [file];
    if (path === '/graphql' && body.query.includes('closingIssuesReferences')) return { data: { repository: { pullRequest: { closingIssuesReferences: { pageInfo: { hasNextPage: false }, nodes: [issue] } } } } };
    if (path === '/graphql') return { data: { repository: { pullRequest: { reviewThreads: { pageInfo: { hasNextPage: false }, nodes: [] } } } } };
    if (path.includes('/reviews?')) return [{ id: 1, user: { login: 'coderabbitai[bot]' }, state: 'APPROVED', commit_id: head, submitted_at: '2026-11-17T12:01:00Z' }];
    if (path.includes('/check-runs?')) return { check_runs: checks.map((c) => ({ ...c })) };
    if (path.includes('/pulls?state=open')) return [pr];
    if (path.includes('/actions/workflows/')) return { workflow_runs: [] };
    if (path.endsWith('/actions/runs/3')) {
      if (!injected && boundary === 'run-read') await invalidate();
      return { id: 3, run_attempt: 1, status: 'in_progress', created_at: '2026-11-17T12:00:00Z' };
    }
    if (path.endsWith('/check-runs') && body) {
      const c = { ...body, id: next++, app: { slug: 'github-actions' } }; checks.push(c); return { ...c };
    }
    const match = path.match(/\/check-runs\/(\d+)$/);
    if (match) {
      const c = checks.find((item) => item.id === Number(match[1]));
      if (body) {
        if (!injected && boundary === 'success-write' && body.conclusion === 'success') await invalidate();
        Object.assign(c, body);
      }
      return { ...c };
    }
    throw new Error(`Unexpected API ${path}`);
  }
  try {
    writeFileSync(join(dir, 'pr.json'), JSON.stringify({ pull_request: pr }));
    writeFileSync(join(dir, 'check.json'), JSON.stringify({ check_run: { id: 11, app: { slug: 'coderabbitai' } } }));
    const s = await collect(api, repo, 1, '2026-11-17T12:00:00Z');
    Object.assign(process.env, { GITHUB_REPOSITORY: repo, GITHUB_EVENT_PATH: join(dir, 'pr.json'), GITHUB_RUN_ID: '3', GITHUB_RUN_ATTEMPT: '1', CHECK_ID: '17', SNAPSHOT: JSON.stringify(s), SECURITY_RESULT: 'success', DIFF_RESULT: 'success', SECURITY_PASSED: 'true', DIFF_PASSED: 'true' });
    await assert.rejects(main('finish', api), /blocked|superseded/i);
    assert.equal(injected, true);
    const newest = checks.filter((c) => c.name === 'Review Gate').sort((a, b) => b.id - a.id)[0];
    assert.ok(newest.id > gate.id, 'invalidation must create a separate monotonic marker');
    assert.equal(newest.conclusion, 'failure', 'older publisher must not overwrite invalidation');
  } finally { process.env = prior; rmSync(dir, { recursive: true, force: true }); }
});

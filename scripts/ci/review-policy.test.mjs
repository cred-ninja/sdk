import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateReview, validateRabbit, validateFiles } from './review-policy.mjs';
const sha = 'a'.repeat(40);
const snapshot = { head: sha, digest: 'b'.repeat(64), files: [{ filename: 'src/a.ts', additions: 1, deletions: 1, patch: '@@ -1 +1 @@\n-old\n+new' }], started: '2026-11-17T12:00:00Z' };
const output = () => ({ status: 'pass', head_sha: sha, context_digest: snapshot.digest, reviewed_files: ['src/a.ts'], findings: [] });
const rabbit = () => ({ reviews: [{ id: 1, user: { login: 'coderabbitai[bot]' }, state: 'APPROVED', commit_id: sha, submitted_at: '2026-11-17T12:01:00Z' }], checks: [{ id: 10, name: 'CodeRabbit', app: { slug: 'coderabbitai' }, status: 'completed', conclusion: 'success' }], threads: [] });
test('valid structured review is accepted', () => assert.equal(validateReview(output(), snapshot, 'success'), true));
for (const [name, mutate, conclusion] of [
  ['absent output', () => null], ['stale SHA', (o) => ({ ...o, head_sha: 'c'.repeat(40) })],
  ['wrong context', (o) => ({ ...o, context_digest: 'c'.repeat(64) })],
  ['missing reviewed file', (o) => ({ ...o, reviewed_files: [] })],
  ['duplicate inventory', (o) => ({ ...o, reviewed_files: ['src/a.ts', 'src/a.ts'] })],
  ['not reviewed', (o) => ({ ...o, status: 'not_reviewed' })],
  ['blocking finding', (o) => ({ ...o, findings: [{ file: 'src/a.ts', line: 1, severity: 'high', explanation: 'Example defect' }] })],
  ['execution failure', (o) => o, 'failure'],
]) test(`review refuses ${name}`, () => assert.throws(() => validateReview(mutate(output()), snapshot, conclusion ?? 'success')));
test('fresh approved CodeRabbit review and completed checks are accepted', () => assert.equal(validateRabbit(rabbit(), snapshot), true));
for (const conclusion of ['neutral', 'cancelled', 'skipped', 'failure']) test(`successful replacement supersedes completed ${conclusion} without a new SHA`, () => {
  const state = rabbit();
  state.checks.unshift({ ...state.checks[0], id: 9, conclusion });
  assert.equal(validateRabbit(state, snapshot), true);
});
test('successful replacement does not hide a still-running review', () => {
  const state = rabbit();
  state.checks.unshift({ ...state.checks[0], id: 9, status: 'in_progress', conclusion: null });
  assert.throws(() => validateRabbit(state, snapshot));
});
test('a separate unsuccessful CodeRabbit check name is not superseded', () => {
  const state = rabbit();
  state.checks.unshift({ ...state.checks[0], id: 9, name: 'Other review', conclusion: 'failure' });
  assert.throws(() => validateRabbit(state, snapshot));
});
test('an approval predating changed issue requirements is stale even on a retry', () => {
  assert.throws(() => validateRabbit(rabbit(), { ...snapshot, issues: [{ updatedAt: '2026-11-17T12:02:00Z' }] }));
});
test('duplicate check IDs are ambiguous, not successful replacement evidence', () => {
  const state = rabbit();
  state.checks.push({ ...state.checks[0] });
  assert.throws(() => validateRabbit(state, snapshot));
});
for (const [name, mutate] of [
  ['no formal review', (r) => { r.reviews = []; }],
  ['stale review', (r) => { r.reviews[0].commit_id = 'c'.repeat(40); }],
  ['old context review', (r) => { r.reviews[0].submitted_at = '2026-11-17T11:00:00Z'; }],
  ['neutral check', (r) => { r.checks[0].conclusion = 'neutral'; }],
  ['skipped check', (r) => { r.checks[0].conclusion = 'skipped'; }],
  ['cancelled check', (r) => { r.checks[0].conclusion = 'cancelled'; }],
  ['no checks', (r) => { r.checks = []; }],
  ['pending check', (r) => { r.checks[0].status = 'in_progress'; }],
  ['later changes requested', (r) => { r.reviews.push({ ...r.reviews[0], id: 2, state: 'CHANGES_REQUESTED' }); }],
  ['pending review', (r) => { r.reviews.push({ ...r.reviews[0], id: 2, state: 'PENDING' }); }],
  ['unresolved discussion', (r) => { r.threads.push({ isResolved: false }); }],
]) test(`CodeRabbit refuses ${name}`, () => { const r = rabbit(); mutate(r); assert.throws(() => validateRabbit(r, snapshot)); });
test('hunk body must fulfill declared context counts, not only total changes', () => {
  const f = { ...snapshot.files[0], patch: '@@ -1,20 +1,20 @@\n-old\n+new' };
  assert.throws(() => validateFiles([f], 1), /hunk|Truncated/i);
});
test('complete multi-hunk patches count context and ignore no-newline markers', () => {
  const f = { ...snapshot.files[0], additions: 2, deletions: 1, patch: '@@ -1,2 +1,2 @@\n context\n-old\n+new\n\\ No newline at end of file\n@@ -9,0 +10 @@\n+tail' };
  assert.equal(validateFiles([f], 1), true);
});
test('complete textual patches accept the standard final newline terminator', () => {
  assert.equal(validateFiles([{ ...snapshot.files[0], patch: snapshot.files[0].patch + '\n' }], 1), true);
});
for (const patch of [
  '@@ -1,2 +1 @@\n-old\n+new',
  '@@ -1 +1,2 @@\n-old\n+new',
  '@@ -1 +1 @@\n context\n-old\n+new',
  '@@ -1 +1 @@\n-old\n+new\n@@ -5,2 +5,2 @@\n context',
  '-old\n+new',
]) test(`malformed or incomplete hunk refused: ${JSON.stringify(patch)}`, () => {
  assert.throws(() => validateFiles([{ ...snapshot.files[0], patch }], 1));
});
test('complete textual file patches accepted', () => assert.equal(validateFiles(snapshot.files, 1), true));
for (const [name, files, count] of [
  ['truncated file list', snapshot.files, 2], ['empty diff', [], 0],
  ['missing patch', [{ ...snapshot.files[0], patch: undefined }], 1],
  ['truncated patch', [{ ...snapshot.files[0], additions: 2 }], 1],
]) test(`diff refuses ${name}`, () => assert.throws(() => validateFiles(files, count)));

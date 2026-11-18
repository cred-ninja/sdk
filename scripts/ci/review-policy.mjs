import { createHash } from 'node:crypto';
export const digest = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const requirePolicy = (condition, message) => { if (!condition) throw new Error(message); };
export function validateReview(output, snapshot, conclusion) {
  requirePolicy(conclusion === 'success', 'Reviewer execution did not succeed');
  requirePolicy(output && typeof output === 'object' && !Array.isArray(output), 'Missing structured output');
  requirePolicy(Object.keys(output).sort().join() === 'context_digest,findings,head_sha,reviewed_files,status', 'Unexpected output schema');
  requirePolicy(output.status === 'pass' && output.head_sha === snapshot.head && output.context_digest === snapshot.digest, 'Review blocked, missing, or stale');
  requirePolicy(Array.isArray(output.reviewed_files) && JSON.stringify([...output.reviewed_files].sort()) === JSON.stringify(snapshot.files.map((f) => f.filename).sort()), 'Incomplete reviewed-file inventory');
  requirePolicy(Array.isArray(output.findings) && output.findings.length === 0, 'Review contains findings');
  return true;
}
export function validateRabbit({ reviews, checks, threads }, snapshot) {
  const bot = reviews.filter((r) => r.user?.login === 'coderabbitai[bot]');
  requirePolicy(bot.length > 0 && !bot.some((r) => r.state === 'PENDING'), 'CodeRabbit formal review missing or pending');
  const latest = bot.reduce((a, b) => a.id > b.id ? a : b);
  const requiredSince = Math.max(Date.parse(snapshot.started), ...(snapshot.issues ?? []).map((i) => Date.parse(i.updatedAt)));
  requirePolicy(latest.state === 'APPROVED' && latest.commit_id === snapshot.head && Date.parse(latest.submitted_at) >= requiredSince, 'CodeRabbit has not approved this SHA and context');
  const relevant = checks.filter((c) => c.app?.slug === 'coderabbitai');
  requirePolicy(relevant.length > 0 && relevant.every((c) => c.status === 'completed'), 'CodeRabbit review still running or missing');
  const current = new Map();
  const ids = new Set();
  for (const check of relevant) {
    requirePolicy(Number.isSafeInteger(check.id) && check.id > 0 && !ids.has(check.id) && typeof check.name === 'string' && check.name.length > 0, 'Ambiguous CodeRabbit check identity');
    ids.add(check.id);
    if (!current.has(check.name) || current.get(check.name).id < check.id) current.set(check.name, check);
  }
  requirePolicy([...current.values()].every((c) => c.conclusion === 'success'), 'Current CodeRabbit check unsuccessful, skipped or neutral');
  requirePolicy(threads.every((t) => t.isResolved === true), 'Unresolved review threads');
  return true;
}
export function validateFiles(files, count) {
  requirePolicy(Array.isArray(files) && files.length > 0 && files.length === count && count <= 300, 'Empty or incomplete file inventory (limit 300)');
  for (const file of files) {
    requirePolicy(typeof file.filename === 'string' && typeof file.patch === 'string', 'Binary, missing or truncated patch requires manual redesign');
    const lines = file.patch.split('\n');
    requirePolicy(lines.filter((s) => s.startsWith('+')).length === file.additions && lines.filter((s) => s.startsWith('-')).length === file.deletions, 'Truncated patch');
  }
  requirePolicy(Buffer.byteLength(JSON.stringify(files)) <= 180000, 'Diff exceeds review context limit');
  return true;
}
export const reviewSchema = {
  type: 'object', additionalProperties: false,
  required: ['status', 'head_sha', 'context_digest', 'reviewed_files', 'findings'],
  properties: {
    status: { type: 'string', enum: ['pass', 'block', 'not_reviewed'] },
    head_sha: { type: 'string', pattern: '^[a-f0-9]{40}$' },
    context_digest: { type: 'string', pattern: '^[a-f0-9]{64}$' },
    reviewed_files: { type: 'array', uniqueItems: true, items: { type: 'string' } },
    findings: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['file', 'line', 'severity', 'explanation'], properties: { file: { type: 'string' }, line: { type: 'integer', minimum: 1 }, severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] }, explanation: { type: 'string' } } } },
  },
};

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { execute, isolatedOptions, parseResult, reviewerArgs, verifyRuntime } from './claude-runtime.mjs';
const snapshot = { head: 'a'.repeat(40), digest: 'b'.repeat(64), files: [{ filename: 'a.ts' }] };
const result = () => ({ type: 'result', subtype: 'success', is_error: false, structured_output: { status: 'pass', head_sha: snapshot.head, context_digest: snapshot.digest, reviewed_files: ['a.ts'], findings: [] } });
test('native result envelope and policy must both succeed', () => {
  assert.equal(parseResult(JSON.stringify(result()), snapshot).status, 'pass');
  for (const mutate of [
    (r) => { r.is_error = true; }, (r) => { delete r.is_error; },
    (r) => { r.subtype = 'error_max_turns'; }, (r) => { r.type = 'assistant'; },
    (r) => { delete r.structured_output; }, (r) => { r.structured_output.head_sha = 'c'.repeat(40); },
    (r) => { r.structured_output.findings = [{ severity: 'high' }]; },
  ]) { const r = result(); mutate(r); assert.throws(() => parseResult(JSON.stringify(r), snapshot)); }
  for (const text of ['', 'not-json', 'null', '[]']) assert.throws(() => parseResult(text, snapshot));
});
test('runtime verification refuses altered bytes even at the expected size', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cred-runtime-'));
  try {
    const file = join(dir, 'binary'); const bytes = 'synthetic executable fixture';
    const expected = { size: Buffer.byteLength(bytes), sha256: createHash('sha256').update(bytes).digest('hex') };
    writeFileSync(file, bytes); await verifyRuntime(file, expected);
    // Restore writable mode only in this synthetic fixture.
    const { chmodSync } = await import('node:fs'); chmodSync(file, 0o600);
    writeFileSync(file, bytes.replace('fixture', 'changed'));
    await assert.rejects(verifyRuntime(file, expected), /checksum/);
    writeFileSync(file, 'short'); await assert.rejects(verifyRuntime(file, expected), /size/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('real child transport preserves empty args, stdin, fresh cwd and allowlisted environment', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cred-spawn-'));
  try {
    const args = reviewerArgs(join(dir, 'empty mcp.json'));
    // This is a transport fixture, NOT a model invocation or simulated provider acceptance.
    const code = "let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>input+=c);process.stdin.on('end',()=>console.log(JSON.stringify({args:process.argv.slice(1),input,cwd:process.cwd(),env:process.env})))";
    const output = JSON.parse(await execute(process.execPath, ['-e', code, '--', ...args], isolatedOptions(dir, 'synthetic-test-value'), 'é JSON $(not-a-shell)'));
    assert.deepEqual(output.args, args);
    assert.equal(output.input, 'é JSON $(not-a-shell)');
    assert.equal(realpathSync(output.cwd), realpathSync(dir));
    assert.equal(output.env.CLAUDE_CODE_OAUTH_TOKEN, 'synthetic-test-value');
    assert.equal(output.env.GH_TOKEN, undefined);
    assert.equal(output.env.NODE_OPTIONS, undefined);
    assert.equal(output.env.DISABLE_AUTOUPDATER, '1');
    assert.equal(output.args[output.args.indexOf('--tools') + 1], '');
    assert.equal(output.args[output.args.indexOf('--setting-sources') + 1], '');
    assert.equal(isolatedOptions(dir).env.CLAUDE_CODE_OAUTH_TOKEN, undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('child output remains valid UTF-8 across chunk boundaries', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cred-utf8-'));
  try {
    const code = 'process.stdout.write(Buffer.from([0xc3]));setTimeout(()=>process.stdout.write(Buffer.from([0xa9])),30)';
    assert.equal(await execute(process.execPath, ['-e', code], isolatedOptions(dir)), 'é');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('real child nonzero, spawn failure and excessive output fail closed', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cred-spawn-refuse-'));
  try {
    await assert.rejects(execute('/definitely-not-an-executable', [], isolatedOptions(dir)));
    await assert.rejects(execute(process.execPath, ['-e', 'process.exit(7)'], isolatedOptions(dir)));
    await assert.rejects(execute(process.execPath, ['-e', 'process.stdout.write("x".repeat(1048577))'], isolatedOptions(dir)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

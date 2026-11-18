import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, copyFileSync, rmSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
const root = fileURLToPath(new URL('../../', import.meta.url));
const configRoot = process.env.SCANNER_CONFIG_ROOT || root;
const binary = process.env.GITLEAKS_BIN || 'gitleaks';
const run = (command, args, cwd, env = {}) => {
  const result = spawnSync(command, args, { cwd, env: { ...process.env, ...env }, encoding: 'utf8' });
  if (result.error) throw result.error;
  assert.equal(typeof result.status, 'number');
  return result;
};
for (const [path, lineNumber] of [['packages/sdk-python/tests/test_dpop.py', 23], ['packages/sdk-python/tests/test_identity.py', 37]]) {
  test(`exact fixture exception at ${path} does not hide another value on the same line`, () => {
    const dir = mkdtempSync(join(tmpdir(), 'cred-scanner-'));
    try {
      const original = readFileSync(join(root, path), 'utf8').split('\n')[lineNumber - 1];
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      copyFileSync(join(configRoot, '.gitleaks.toml'), join(dir, '.gitleaks.toml'));
      if (existsSync(join(configRoot, '.gitleaksignore'))) copyFileSync(join(configRoot, '.gitleaksignore'), join(dir, '.gitleaksignore'));
      for (const [line, status] of [[original, 0], [original.replace(/([A-Za-z0-9]{8})"$/, (s) => s.slice(0, 8).split('').reverse().join('') + '"'), 1]]) {
        writeFileSync(join(dir, path), '\n'.repeat(lineNumber - 1) + line + '\n');
        // Capture/redact scanner output without ever printing candidate values.
        const scan = run(binary, ['dir', '.', '--redact=100', '--no-banner'], dir);
        assert.equal(scan.status, status, `Unexpected scanner result at ${path}; values withheld; ${scan.stderr}`);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}
test('actual tracked snapshot shell includes ordinary and export-ignore files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cred-export-'));
  try {
    const repo = join(dir, 'repo'); mkdirSync(repo);
    for (const [path, content] of [['ordinary.txt', 'ordinary'], ['excluded.txt', 'still scan this'], ['.gitattributes', 'excluded.txt export-ignore\n']]) writeFileSync(join(repo, path), content);
    assert.equal(run('git', ['init', '-q'], repo).status, 0);
    assert.equal(run('git', ['add', '.'], repo).status, 0);
    assert.equal(run('git', ['-c', 'user.name=Synthetic Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], repo).status, 0);
    mkdirSync(join(dir, 'ci-tools'));
    const located = binary.startsWith('/') ? binary : run('which', [binary], repo).stdout.trim();
    symlinkSync(located, join(dir, 'ci-tools/gitleaks'));
    const workflow = readFileSync(join(configRoot, '.github/workflows/workflow-security.yml'), 'utf8');
    const section = workflow.split('      - name: Scan tracked public snapshot with redacted Gitleaks CLI\n')[1];
    const block = section?.match(/        run: \|\n((?:          .*\n?)*)/);
    assert.ok(block, 'actual snapshot run block must exist');
    const script = block[1].split('\n').map((line) => line.slice(10)).join('\n');
    assert.equal(run('bash', ['-c', script], repo, { RUNNER_TEMP: dir }).status, 0);
    assert.equal(readFileSync(join(dir, 'public-snapshot/ordinary.txt'), 'utf8'), 'ordinary');
    assert.ok(existsSync(join(dir, 'public-snapshot/excluded.txt')), 'export-ignore must not hide tracked files');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

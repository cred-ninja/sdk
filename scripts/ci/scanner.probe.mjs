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
test('public conformance exceptions are exact in value, path and rule', () => {
  const config = readFileSync(join(configRoot, '.gitleaks.toml'), 'utf8');
  const vectors = JSON.parse(readFileSync(join(root, 'conformance/wimse-419/vectors.json'), 'utf8'));
  const fixtures = Object.values(vectors.wits).map((value) => ['conformance/wimse-419/vectors.json', 'jwt', value]);
  for (const name of ['cofide', 'go-spiffe', 'spire', 'wimsey']) {
    const path = `conformance/interop/${name}-run-2026-11-13.txt`;
    const text = readFileSync(join(root, path), 'utf8');
    const values = new Set([...text.matchAll(/did:key:(z[1-9A-HJ-NP-Za-km-z]+)/g)].map((m) => m[1]));
    assert.ok(values.size > 0, 'Public identity fixture must be present');
    fixtures.push(...[...values].map((value) => [path, 'generic-api-key', value]));
  }
  const txnPath = 'conformance/interop/authgent-txn-run-2026-11-13.txt';
  const txn = readFileSync(join(root, txnPath), 'utf8').split('\n')[8].match(/\btxn=(\S+)/)?.[1];
  assert.ok(txn, 'The audited transaction correlation fixture must be present');
  fixtures.push([txnPath, 'generic-api-key', txn]);
  for (const [path, rule, value] of fixtures) {
    const dir = mkdtempSync(join(tmpdir(), 'cred-conformance-scanner-'));
    try {
      const report = join(dir, 'scan.json');
      const scan = (target, payload, policy = config) => {
        mkdirSync(dirname(join(dir, target)), { recursive: true });
        writeFileSync(join(dir, '.gitleaks.toml'), policy);
        writeFileSync(join(dir, target), payload);
        const result = run(binary, ['dir', '.', '--redact=100', '--no-banner', '--report-format', 'json', '--report-path', report], dir);
        rmSync(join(dir, target));
        const rules = JSON.parse(readFileSync(report, 'utf8')).map((finding) => finding.RuleID);
        rmSync(report);
        return { status: result.status, rules };
      };
      const payload = (text) => rule === 'jwt' ? `Workload-Identity-Token: ${text}\n` : `token = "${text}"\n`;
      assert.equal(scan(path, payload(value)).status, 0, `Known public data must pass at ${path}`);
      const changed = value.slice(0, -1) + (value.endsWith('A') ? 'B' : 'A');
      assert.equal(scan(path, payload(changed)).status, 1, `Changed value must remain reportable at ${path}`);
      assert.equal(scan(`elsewhere/${path}`, payload(value)).status, 1, `Changed path must remain reportable at ${path}`);
      const otherRule = config + '\n[[rules]]\nid = "conformance-wrong-rule-probe"\ndescription = "Exact exceptions must not cover another rule"\nregex = \'\'\'conformance_probe = ([^\\r\\n]+)\'\'\'\nsecretGroup = 1\n';
      const wrong = scan(path, `conformance_probe = ${value}\n`, otherRule);
      assert.equal(wrong.status, 1);
      assert.ok(wrong.rules.includes('conformance-wrong-rule-probe'), 'Another rule must not inherit the exception');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
  const dir = mkdtempSync(join(tmpdir(), 'cred-runtime-wit-scanner-'));
  try {
    copyFileSync(join(configRoot, '.gitleaks.toml'), join(dir, '.gitleaks.toml'));
    const path = join(dir, 'conformance/interop/cofide-run-2026-11-13.txt');
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `Workload-Identity-Token: ${Object.values(vectors.wits)[0]}\n`);
    assert.equal(run(binary, ['dir', '.', '--redact=100', '--no-banner'], dir).status, 1, 'Cofide JWTs must remain reportable');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
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

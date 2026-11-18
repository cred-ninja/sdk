import { appendFileSync, chmodSync, createReadStream, createWriteStream, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { reviewSchema, validateReview } from './review-policy.mjs';

// Official version manifest, linux-x64 native executable. No installer or package manager.
export const runtime = Object.freeze({ version: '2.1.327', sha256: '343c744baa14bfd38286a7cb90871051f04379956da6c5b803a9e66019a76ac9', size: 372904464 });
const origin = 'https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases';
export async function verifyRuntime(file, expected = runtime) {
  if (!statSync(file).isFile() || statSync(file).size !== expected.size) throw new Error('Runtime size mismatch');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  if (hash.digest('hex') !== expected.sha256) throw new Error('Runtime checksum mismatch');
  chmodSync(file, 0o500);
}
export function execute(binary, args, options, input = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { ...options, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '', bytes = 0, failed = false;
    const fail = () => { failed = true; child.kill('SIGKILL'); reject(new Error('Native reviewer execution failed')); };
    const timer = setTimeout(fail, 15 * 60 * 1000);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > 1024 * 1024) fail(); else output += chunk;
    });
    // Never echo provider output/errors: neither is trusted log content.
    child.stderr.on('data', () => {});
    child.on('error', fail);
    child.stdin.on('error', fail);
    child.on('close', (code) => { clearTimeout(timer); if (!failed && code === 0) resolve(output); else { failed = true; reject(new Error('Native reviewer execution failed')); } });
    child.stdin.end(input);
  });
}
export function isolatedOptions(dir, token) {
  return { cwd: dir, env: { PATH: '/usr/bin:/bin', HOME: dir, CLAUDE_CONFIG_DIR: join(dir, 'config'), DISABLE_AUTOUPDATER: '1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', ...(token ? { CLAUDE_CODE_OAUTH_TOKEN: token } : {}) } };
}
export function reviewerArgs(mcp) {
  return ['--print', '--output-format', 'json', '--tools', '', '--strict-mcp-config', '--mcp-config', mcp,
    '--setting-sources', '', '--settings', '{"disableAllHooks":true,"enableAllProjectMcpServers":false}',
    '--disable-slash-commands', '--no-session-persistence', '--permission-mode', 'dontAsk', '--permission-prompts', 'none',
    '--max-turns', '3', '--json-schema', JSON.stringify(reviewSchema)];
}
export function parseResult(text, snapshot) {
  const result = JSON.parse(text);
  if (result.type !== 'result' || result.subtype !== 'success' || result.is_error !== false) throw new Error('Reviewer did not complete successfully');
  validateReview(result.structured_output, snapshot, 'success');
  return result.structured_output;
}
export async function main(mode) {
  const root = process.env.RUNNER_TEMP;
  if (!root) throw new Error('Missing runner temporary directory');
  const file = join(root, 'claude-runtime', 'claude');
  if (mode === 'fetch') {
    mkdirSync(join(root, 'claude-runtime'), { recursive: true });
    const response = await fetch(`${origin}/${runtime.version}/linux-x64/claude`, { redirect: 'error', signal: AbortSignal.timeout(180000) });
    if (!response.ok) throw new Error('Runtime download failed');
    await pipeline(Readable.fromWeb(response.body), createWriteStream(file, { mode: 0o600 }));
    await verifyRuntime(file);
    const dir = mkdtempSync(join(root, 'claude-smoke-'));
    const options = isolatedOptions(dir);
    const version = await execute(file, ['--version'], options);
    if (!version.startsWith(`${runtime.version} (Claude Code)`)) throw new Error('Unexpected native runtime version');
    const help = await execute(file, ['--help'], options);
    for (const flag of reviewerArgs('empty.json').filter((arg) => arg.startsWith('--') && arg !== '--max-turns')) {
      if (!help.includes(flag)) throw new Error('Required native runtime flag unavailable');
    }
    // Exercise the actual option parser with all review flags, without starting a model.
    await execute(file, [...reviewerArgs(join(dir, 'empty-mcp.json')), '--help'], options);
    // Hosted authenticated print-mode acceptance remains a separate canary obligation.
    console.log(`Verified native Claude ${runtime.version}; version/help smoke passed.`);
  } else if (mode === 'verify') {
    await verifyRuntime(file);
  } else if (mode === 'review') {
    await verifyRuntime(file);
    const dir = mkdtempSync(join(root, 'claude-review-'));
    const mcp = join(dir, 'empty-mcp.json'); writeFileSync(mcp, '{"mcpServers":{}}');
    const token = process.env.CLAUDE_CODE_OAUTH_TOKEN;
    delete process.env.CLAUDE_CODE_OAUTH_TOKEN;
    if (!token) throw new Error('Missing reviewer credential');
    const text = await execute(file, reviewerArgs(mcp), isolatedOptions(dir, token), readFileSync(join(root, 'review-prompt.txt'), 'utf8'));
    parseResult(text, JSON.parse(process.env.SNAPSHOT));
    appendFileSync(process.env.GITHUB_OUTPUT, 'passed=true\n');
  } else throw new Error('Unknown runtime mode');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv[2]).catch(() => { console.error('Verified native reviewer failed closed.'); process.exitCode = 1; });
}

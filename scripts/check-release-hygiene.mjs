#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

const repoRoot = resolve(new URL('..', import.meta.url).pathname);
const rootPackage = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
const expectedVersion = rootPackage.version;
const failures = [];

const npmPackagePaths = [
  'packages/create-cred-app/package.json',
  'packages/guard/package.json',
  'packages/integrations/vercel-ai/package.json',
  'packages/mcp/package.json',
  'packages/oauth/package.json',
  'packages/sdk/package.json',
  'packages/server/package.json',
  'packages/tofu/package.json',
  'packages/vault/package.json',
];

for (const packagePath of npmPackagePaths) {
  const packageJson = JSON.parse(readFileSync(join(repoRoot, packagePath), 'utf8'));
  if (packageJson.version !== expectedVersion) {
    failures.push(`${packagePath}: expected version ${expectedVersion}, found ${packageJson.version}`);
  }
  const packageDir = packagePath.slice(0, -'/package.json'.length);
  for (const requiredFile of ['README.md', 'LICENSE', 'NOTICE']) {
    if (!existsSync(join(repoRoot, packageDir, requiredFile))) {
      failures.push(`${packageDir}: missing ${requiredFile}`);
    }
  }
}

const pythonPackagePaths = [
  'packages/sdk-python/pyproject.toml',
  'packages/integrations/autogen/pyproject.toml',
  'packages/integrations/crewai/pyproject.toml',
  'packages/integrations/langchain/pyproject.toml',
  'packages/integrations/openai-agents/pyproject.toml',
  'packages/integrations/semantic-kernel/pyproject.toml',
];

for (const pyprojectPath of pythonPackagePaths) {
  const source = readFileSync(join(repoRoot, pyprojectPath), 'utf8');
  const version = source.match(/^version = "([^"]+)"/m)?.[1];
  if (version !== expectedVersion) {
    failures.push(`${pyprojectPath}: expected version ${expectedVersion}, found ${version ?? 'missing'}`);
  }
  if (pyprojectPath !== 'packages/sdk-python/pyproject.toml' && !source.includes(`cred-auth>=${expectedVersion}`)) {
    failures.push(`${pyprojectPath}: expected dependency cred-auth>=${expectedVersion}`);
  }
}

const stalePatterns = [
  [/\/api\/connect/, 'stale /api/connect route'],
  [/\/api\/v1\/tofu\/rotate/, 'stale TOFU rotate route'],
  [/no auth required/i, 'stale unauthenticated route guidance'],
  [/from cred_sdk import/i, 'stale Python SDK import'],
  [/Coming Soon/i, 'stale Coming Soon copy'],
  [/waitlist/i, 'stale waitlist copy'],
  [/cred\.ninja\/waitlist/i, 'stale waitlist URL'],
  [/CRED_SERVER_URL/, 'stale server URL env var'],
  [/https:\/\/api\.cred\.ninja/i, 'stale hosted API default'],
  [/"VAULT_PASSPHRASE": "your-passphrase"/, 'stale MCP local-mode vault env var'],
];

const textRoots = ['README.md', 'SECURITY-AUDITS.md', 'docs', 'examples', 'packages'];
const textExtensions = new Set(['.md', '.mdx', '.ts', '.tsx', '.js', '.mjs', '.py', '.toml', '.json', '.example']);

function extensionOf(path) {
  const last = path.split('/').pop() ?? path;
  if (last.endsWith('.env.example')) return '.example';
  const dot = last.lastIndexOf('.');
  return dot >= 0 ? last.slice(dot) : '';
}

function walk(path, visit) {
  const stats = statSync(path);
  if (stats.isDirectory()) {
    const name = path.split('/').pop();
    if (['node_modules', 'dist', '__pycache__', '.venv'].includes(name)) return;
    for (const entry of readdirSync(path)) walk(join(path, entry), visit);
    return;
  }
  visit(path);
}

function stripAnchor(target) {
  const hashIndex = target.indexOf('#');
  return hashIndex >= 0 ? target.slice(0, hashIndex) : target;
}

for (const textRoot of textRoots) {
  const absoluteRoot = join(repoRoot, textRoot);
  if (!existsSync(absoluteRoot)) continue;
  walk(absoluteRoot, (filePath) => {
    if (!textExtensions.has(extensionOf(filePath))) return;
    const source = readFileSync(filePath, 'utf8');
    for (const [pattern, label] of stalePatterns) {
      if (pattern.test(source)) {
        failures.push(`${relative(repoRoot, filePath)}: ${label}`);
      }
    }
    if (extensionOf(filePath) === '.md') {
      for (const match of source.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
        const rawTarget = match[1].trim();
        if (
          rawTarget.startsWith('http://') ||
          rawTarget.startsWith('https://') ||
          rawTarget.startsWith('mailto:') ||
          rawTarget.startsWith('#')
        ) {
          continue;
        }
        const target = stripAnchor(rawTarget);
        if (!target) continue;
        const absoluteTarget = resolve(dirname(filePath), target);
        if (!existsSync(absoluteTarget)) {
          failures.push(`${relative(repoRoot, filePath)}: broken local markdown link ${rawTarget}`);
        }
      }
    }
  });
}

walk(repoRoot, (filePath) => {
  if (filePath.endsWith('.tgz')) {
    failures.push(`${relative(repoRoot, filePath)}: npm pack artifact must not be committed`);
  }
});

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log(`release hygiene ok (${expectedVersion})`);

#!/usr/bin/env node

import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import net from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const tmp = mkdtempSync(join(tmpdir(), 'cred-npm-smoke.'));

const workspaces = [
  'packages/protocol',
  'packages/oauth',
  'packages/tofu',
  'packages/vault',
  'packages/sdk',
  'packages/guard',
  'packages/integrations/vercel-ai',
  'packages/mcp',
  'packages/server',
  'packages/create-cred-app',
];

function run(command, args, options = {}) {
  execFileSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: { ...process.env, ...(options.env ?? {}) },
    stdio: options.stdio ?? 'inherit',
  });
}

function runOutput(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: { ...process.env, ...(options.env ?? {}) },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  });
}

function packWorkspace(workspace) {
  const output = runOutput('npm', ['pack', '--json', '--pack-destination', tmp, '--workspace', workspace]);
  const packed = JSON.parse(output);
  if (!packed[0]?.filename) {
    throw new Error(`npm pack did not return a filename for ${workspace}`);
  }
  return join(tmp, packed[0].filename);
}

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = net.createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close(() => reject(new Error('Failed to allocate a local port')));
        return;
      }
      const port = address.port;
      server.close(() => resolvePort(port));
    });
  });
}

async function waitForHealth(port, child) {
  let lastError;
  for (let i = 0; i < 80; i += 1) {
    if (child.exitCode !== null) {
      throw new Error(`server process exited before health check with code ${child.exitCode}`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) return response.json();
    } catch (error) {
      lastError = error;
    }
    await delay(100);
  }
  throw lastError ?? new Error('Timed out waiting for /health');
}

async function stopChild(child) {
  if (child.pid === undefined) return;

  const processGroup = -child.pid;
  const hasExited = () => child.exitCode !== null || child.signalCode !== null;
  const waitForExit = () => (
    hasExited()
      ? Promise.resolve()
      : new Promise((resolve) => child.once('exit', resolve))
  );
  const signalGroup = (signal) => {
    try {
      process.kill(processGroup, signal);
      return true;
    } catch (error) {
      if (error?.code === 'ESRCH') return false;
      throw error;
    }
  };

  signalGroup('SIGTERM');
  await Promise.race([
    waitForExit(),
    delay(2_000),
  ]);

  if (signalGroup(0)) {
    signalGroup('SIGKILL');
    await waitForExit();
  }
}

async function runFreshInstallSmoke(tarballsByWorkspace) {
  const consumerDir = join(tmp, 'consumer');
  run('npm', ['init', '-y'], { cwd: tmp, stdio: 'pipe' });
  run('npm', ['install', '--no-audit', '--no-fund', ...Object.values(tarballsByWorkspace)], {
    cwd: tmp,
  });

  const smokeFile = join(consumerDir, 'smoke.mjs');
  mkdirSync(consumerDir, { recursive: true });
  writeFileSync(smokeFile, `
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const require = createRequire(import.meta.url);
for (const pkg of ['@credninja/oauth', '@credninja/tofu', '@credninja/vault', '@credninja/sdk', '@credninja/ai']) {
  const mod = await import(pkg);
  if (!mod || Object.keys(mod).length === 0) throw new Error(pkg + ' ESM import exported nothing');
  const cjs = require(pkg);
  if (!cjs || Object.keys(cjs).length === 0) throw new Error(pkg + ' CJS require exported nothing');
}

const { Cred } = await import('@credninja/sdk');
const { createServer } = await import('@credninja/server');
const { createCredMcpServer } = await import('@credninja/mcp');
const dataDir = mkdtempSync(join(tmpdir(), 'cred-installed-server.'));
const config = {
  port: 0,
  host: '127.0.0.1',
  vaultPassphrase: 'test-passphrase-not-for-production',
  vaultStorage: 'sqlite',
  vaultPath: join(dataDir, 'vault.sqlite'),
  tofuStorage: 'sqlite',
  tofuPath: join(dataDir, 'tofu.sqlite'),
  adminToken: 'cred_admin_00000000000000000000000000000000',
  agentToken: 'cred_at_00000000000000000000000000000000',
  providers: [{
    slug: 'google',
    clientId: 'test-google-client-id',
    clientSecret: 'test-google-client-secret',
    defaultScopes: ['openid', 'email', 'profile'],
  }],
  redirectBaseUri: 'http://127.0.0.1:3456',
};
const { app, vault, tofu } = createServer(config);
await vault.init();
await tofu.init();
await vault.store({
  provider: 'google',
  userId: 'sdk-user',
  accessToken: 'ya29.installed-sdk-smoke',
  expiresAt: new Date(Date.now() + 60_000),
  scopes: ['calendar.readonly'],
});
const server = await new Promise((resolve) => {
  const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
});
const port = server.address().port;
try {
  const health = await fetch('http://127.0.0.1:' + port + '/health').then((res) => res.json());
  if (health.status !== 'ok') throw new Error('bad installed server health: ' + JSON.stringify(health));
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const target = typeof url === 'string' ? url : url.url;
    if (target.startsWith('http://127.0.0.1:' + port)) {
      return realFetch(url, init);
    }
    assert.equal(target, 'https://www.googleapis.com/calendar/v3/calendars/primary/events');
    assert.equal(init.headers.Authorization, 'Bearer ya29.installed-sdk-smoke');
    return new Response(JSON.stringify({ items: [{ id: 'evt_smoke' }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  try {
    const cred = new Cred({
      agentToken: config.agentToken,
      baseUrl: 'http://127.0.0.1:' + port,
    });
    const connections = await cred.getUserConnections('sdk-user');
    assert.equal(connections.length, 1);
    assert.equal(connections[0].slug, 'google');
    const handle = await cred.delegateHandle({
      service: 'google',
      userId: 'sdk-user',
      appClientId: 'app_smoke',
      scopes: ['calendar.readonly'],
    });
    assert.equal(handle.tokenType, 'Delegation');
    assert.ok(!('accessToken' in handle));
    const used = await cred.use({
      delegationId: handle.delegationId,
      url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
      method: 'GET',
    });
    assert.equal(used.ok, true);
    assert.deepEqual(used.body, { items: [{ id: 'evt_smoke' }] });
  } finally {
    globalThis.fetch = realFetch;
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
}
createCredMcpServer({
  mode: 'cloud',
  baseUrl: 'https://cred.example.com',
  agentToken: 'cred_at_00000000000000000000000000000000',
  appClientId: 'app_smoke',
});
console.log('fresh npm package import/server smoke ok');
`);
  run('node', [smokeFile], { cwd: tmp });
}

async function runCreateCredAppSmoke(tarballsByWorkspace) {
  const createDir = join(tmp, 'create-smoke');
  mkdirSync(createDir, { recursive: true });
  run('npm', ['init', '-y'], { cwd: createDir, stdio: 'pipe' });
  run('npm', ['install', '--no-audit', '--no-fund', tarballsByWorkspace['packages/create-cred-app']], {
    cwd: createDir,
  });
  run('node', ['node_modules/create-cred-app/bin/create.mjs', 'generated'], {
    cwd: createDir,
    env: { CREATE_CRED_APP_SKIP_INSTALL: '1' },
  });

  const generatedDir = join(createDir, 'generated');
  const packageJsonPath = join(generatedDir, 'package.json');
  const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  packageJson.dependencies = {
    '@credninja/server': `file:${tarballsByWorkspace['packages/server']}`,
    '@credninja/protocol': `file:${tarballsByWorkspace['packages/protocol']}`,
    '@credninja/oauth': `file:${tarballsByWorkspace['packages/oauth']}`,
    '@credninja/tofu': `file:${tarballsByWorkspace['packages/tofu']}`,
    '@credninja/vault': `file:${tarballsByWorkspace['packages/vault']}`,
    '@credninja/guard': `file:${tarballsByWorkspace['packages/guard']}`,
  };
  writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);
  run('npm', ['install', '--no-audit', '--no-fund'], { cwd: generatedDir });

  const port = await freePort();
  const child = spawn('npm', ['start'], {
    cwd: generatedDir,
    env: {
      ...process.env,
      PORT: String(port),
      HOST: '127.0.0.1',
      REDIRECT_BASE_URI: `http://127.0.0.1:${port}`,
    },
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk.toString(); });
  child.stderr.on('data', (chunk) => { output += chunk.toString(); });

  try {
    const health = await waitForHealth(port, child);
    if (health.status !== 'ok') throw new Error('bad generated app health: ' + JSON.stringify(health));
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\n${output}`);
  } finally {
    await stopChild(child);
  }
  console.log('create-cred-app generated server smoke ok');
}

try {
  run('npm', ['run', 'build']);
  const tarballsByWorkspace = Object.fromEntries(
    workspaces.map((workspace) => [workspace, packWorkspace(workspace)]),
  );
  await runFreshInstallSmoke(tarballsByWorkspace);
  await runCreateCredAppSmoke(tarballsByWorkspace);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

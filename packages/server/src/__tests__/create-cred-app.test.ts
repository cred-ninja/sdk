// A generated app, end to end: its own .env configures the server, its own grant
// script gives its agent a Permission, and that agent completes a brokered call.
import { describe, it, expect, vi, afterAll, afterEach } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import request from 'supertest';
import { importAgentIdentity } from '@credninja/sdk';
import { createServer } from '../server.js';
import { loadConfig } from '../config.js';
import { delegateAs, exerciseAs } from './token-helpers.js';

const run = promisify(execFile);
const CREATE = path.resolve(import.meta.dirname ?? __dirname, '../../../create-cred-app/bin/create.mjs');
const tmpDirs: string[] = [];
const servers: Server[] = [];

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
afterAll(async () => {
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});

function parseEnv(file: string): Record<string, string> {
  return Object.fromEntries(fs.readFileSync(file, 'utf8').split('\n')
    .filter((line) => /^[A-Z_]+=/.test(line))
    .map((line) => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]));
}

async function generate() {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-scaffold-'));
  tmpDirs.push(parent);
  const { stdout } = await run('node', [CREATE, 'app'], { cwd: parent, env: { ...process.env, CREATE_CRED_APP_SKIP_INSTALL: '1' } });
  const dir = path.join(parent, 'app');
  return { dir, stdout, env: parseEnv(path.join(dir, '.env')), agentEnv: parseEnv(path.join(dir, 'agent.env')) };
}

/** The server a generated .env configures, listening on a real port for the grant script. */
async function serve(env: Record<string, string>, dir: string) {
  for (const [key, value] of Object.entries(env)) vi.stubEnv(key, value);
  vi.stubEnv('GITHUB_CLIENT_ID', 'id');
  vi.stubEnv('GITHUB_CLIENT_SECRET', 'secret');
  const config = { ...loadConfig(), vaultPath: path.join(dir, 'data', 'vault.sqlite'), tofuPath: path.join(dir, 'data', 'tofu.sqlite') };
  fs.mkdirSync(path.join(dir, 'data'), { recursive: true });
  const server = createServer(config);
  await server.vault.init();
  await server.tofu.init();
  const listener = await new Promise<Server>((resolve) => {
    const started = server.app.listen(0, '127.0.0.1', () => resolve(started));
  });
  servers.push(listener);
  const { port } = listener.address() as { port: number };
  return { ...server, port };
}

function setEnvValues(dir: string, values: Record<string, string>) {
  const file = path.join(dir, '.env');
  let text = fs.readFileSync(file, 'utf8');
  for (const [key, value] of Object.entries(values)) {
    text = new RegExp(`^${key}=`, 'm').test(text) ? text.replace(new RegExp(`^${key}=.*$`, 'm'), `${key}=${value}`) : `${text}\n${key}=${value}\n`;
  }
  fs.writeFileSync(file, text);
}

const grant = (dir: string, port: number, ...args: string[]) => {
  setEnvValues(dir, { PORT: String(port), HOST: '127.0.0.1' });
  return run('node', ['grant-agent.mjs', ...args], { cwd: dir });
};

/** A local listener that records what reaches it. */
async function recorder(respond: (req: IncomingMessage, res: ServerResponse) => void = (_req, res) => res.writeHead(201).end('{}')) {
  const seen: Array<{ url: string | undefined; authorization: string | undefined }> = [];
  const listener = createHttpServer((req, res) => {
    seen.push({ url: req.url, authorization: req.headers.authorization });
    respond(req, res);
  });
  await new Promise<void>((resolve) => listener.listen(0, '127.0.0.1', resolve));
  servers.push(listener);
  return { seen, port: (listener.address() as { port: number }).port };
}

describe('create-cred-app', () => {
  it('generates a multi-user app and an agent identity, keeping the key out of the server config and the output', async () => {
    const { dir, stdout, env, agentEnv } = await generate();
    expect(env.SINGLE_USER_MODE).toBe('false');
    expect(agentEnv.CRED_AGENT_DID).toMatch(/^did:key:z6Mk/);
    expect(agentEnv.CRED_AGENT_PRIVATE_KEY_HEX).toMatch(/^[0-9a-f]{64}$/);
    expect(agentEnv.CRED_AGENT_TOKEN).toBe(env.AGENT_TOKEN);
    expect(env.CRED_AGENT_PRIVATE_KEY_HEX).toBeUndefined();
    expect(stdout).not.toContain(agentEnv.CRED_AGENT_PRIVATE_KEY_HEX);
    expect(stdout).not.toContain(env.ADMIN_TOKEN);
    expect(fs.statSync(path.join(dir, '.env')).mode & 0o077).toBe(0);
    expect(fs.statSync(path.join(dir, 'agent.env')).mode & 0o077).toBe(0);
    expect(fs.readFileSync(path.join(dir, '.gitignore'), 'utf8')).toContain('agent.env');
    const identity = await importAgentIdentity({ did: agentEnv.CRED_AGENT_DID!, privateKeyHex: agentEnv.CRED_AGENT_PRIVATE_KEY_HEX! });
    expect(identity.did).toBe(agentEnv.CRED_AGENT_DID);
  });

  it('a request with no user_id is refused', async () => {
    const { dir, env } = await generate();
    const { app } = await serve(env, dir);
    const res = await request(app).get('/api/v1/connections').set('Authorization', `Bearer ${env.AGENT_TOKEN}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('user_id_required');
  });

  it('its agent is refused until granted, then completes a brokered call at the limits granted', async () => {
    const { dir, env, agentEnv } = await generate();
    const { app, vault, port } = await serve(env, dir);
    await vault.store({ provider: 'github', userId: 'alice', accessToken: 'gho_generated', expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
    const identity = await importAgentIdentity({ did: agentEnv.CRED_AGENT_DID!, privateKeyHex: agentEnv.CRED_AGENT_PRIVATE_KEY_HEX! });
    const ask = () => delegateAs(app, identity, { service: 'github', user_id: 'alice' }, { bearer: env.AGENT_TOKEN!, base: env.REDIRECT_BASE_URI });

    const before = await ask();
    expect(before.status).toBe(403);
    expect(before.body.error).toBe('permission_required');

    const granted = await grant(dir, port, 'github', 'github.read');
    expect(granted.stdout).toContain('github.read');
    expect(granted.stdout).not.toContain(env.ADMIN_TOKEN);

    const after = await ask();
    expect(after.status, JSON.stringify(after.body)).toBe(200);
    expect(after.body.scopes).toEqual(['github.read']);

    const upstream = vi.fn(async (_url: unknown, _init?: unknown) => new Response('{"id":1}', { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', upstream);
    const url = 'https://api.github.com/repos/o/r';
    const used = await exerciseAs(app, identity, after.body.access_token, { url, method: 'GET' }, { base: env.REDIRECT_BASE_URI });
    expect(used.status, JSON.stringify(used.body)).toBe(200);
    expect(used.body.body).toEqual({ id: 1 });
    expect(upstream).toHaveBeenCalledTimes(1);
    expect((upstream.mock.calls[0]![1] as { headers: Record<string, string> }).headers.Authorization).toBe('Bearer gho_generated');

    const write = await exerciseAs(app, identity, after.body.access_token, { url: `${url}/issues`, method: 'POST', body: { title: 't' } }, { base: env.REDIRECT_BASE_URI });
    expect(write.status).toBe(403);
    expect(write.body.error).toBe('scope_insufficient');
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('the grant script explains its usage and reports a server it cannot reach', async () => {
    const { dir } = await generate();
    await expect(run('node', ['grant-agent.mjs'], { cwd: dir })).rejects.toMatchObject({ code: 1, stderr: expect.stringContaining('Usage') });
    setEnvValues(dir, { PORT: '1', HOST: '127.0.0.1' });
    await expect(run('node', ['grant-agent.mjs', 'github', 'repo'], { cwd: dir })).rejects.toMatchObject({ code: 1, stderr: expect.stringContaining('npm start') });
  });

  it('the grant script takes the token and address from its own .env, not the environment or the working directory', async () => {
    const { dir, env } = await generate();
    const real = await recorder();
    const decoy = await recorder();
    setEnvValues(dir, { PORT: String(real.port), HOST: '127.0.0.1' });
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-elsewhere-'));
    tmpDirs.push(elsewhere);
    fs.writeFileSync(path.join(elsewhere, '.env'), `ADMIN_TOKEN=cwd-token\nPORT=${decoy.port}\nHOST=127.0.0.1\n`);
    await run('node', [path.join(dir, 'grant-agent.mjs'), 'github', 'repo'], {
      cwd: elsewhere,
      env: { ...process.env, ADMIN_TOKEN: 'env-token', HOST: 'evil.example.com', PORT: String(decoy.port), REDIRECT_BASE_URI: 'https://evil.example.com' },
    });
    expect(real.seen).toEqual([{ url: '/admin/permissions', authorization: `Bearer ${env.ADMIN_TOKEN}` }]);
    expect(decoy.seen).toEqual([]);
  });

  it('the grant script refuses to send the admin token over http to a host that is not loopback', async () => {
    const { dir, env } = await generate();
    for (const values of [
      { HOST: 'cred.internal', REDIRECT_BASE_URI: 'http://cred.internal:3456' },
      { HOST: '10.0.0.5', REDIRECT_BASE_URI: 'http://10.0.0.5:3456' },
      { HOST: '127.0.0.1.evil.example', REDIRECT_BASE_URI: 'http://127.0.0.1.evil.example' },
      { HOST: 'localhost.evil.example', REDIRECT_BASE_URI: 'not a url' },
    ]) {
      setEnvValues(dir, values);
      const failed = await run('node', ['grant-agent.mjs', 'github', 'repo'], { cwd: dir }).then(() => null, (err: { code: number; stderr: string }) => err);
      expect(failed?.code, values.HOST).toBe(1);
      expect(failed?.stderr).toContain('Refusing to send the admin token');
      expect(failed?.stderr).not.toContain(env.ADMIN_TOKEN);
    }
  });

  it('a remote server is reached only at its https address', async () => {
    const { dir } = await generate();
    setEnvValues(dir, { HOST: 'cred.invalid', REDIRECT_BASE_URI: 'https://cred.invalid' });
    await expect(run('node', ['grant-agent.mjs', 'github', 'repo'], { cwd: dir })).rejects.toMatchObject({ code: 1, stderr: expect.stringContaining('https://cred.invalid') });
  });

  it('the grant script does not follow a redirect with the admin token', async () => {
    const { dir } = await generate();
    const target = await recorder();
    const redirector = await recorder((_req, res) => res.writeHead(307, { location: `http://127.0.0.1:${target.port}/admin/permissions` }).end());
    setEnvValues(dir, { PORT: String(redirector.port), HOST: '127.0.0.1' });
    await expect(run('node', ['grant-agent.mjs', 'github', 'repo'], { cwd: dir })).rejects.toMatchObject({ code: 1 });
    expect(redirector.seen).toHaveLength(1);
    expect(target.seen).toEqual([]);
  });

  it('says plainly that user_id is not an authorization boundary for the agent token', async () => {
    const { dir } = await generate();
    expect(fs.readFileSync(path.join(dir, '.env'), 'utf8')).toContain('user_id is NOT an authorization boundary');
    expect(fs.readFileSync(path.join(dir, 'README.md'), 'utf8')).toContain('is not an authorization boundary');
  });

  it('demonstrates that boundary: one agent token and Permission reach every user', async () => {
    const { dir, env, agentEnv } = await generate();
    const { app, vault, port } = await serve(env, dir);
    for (const userId of ['alice', 'bob']) {
      await vault.store({ provider: 'github', userId, accessToken: `gho_${userId}`, expiresAt: new Date(Date.now() + 3600_000), scopes: ['repo'] });
    }
    await grant(dir, port, 'github', 'github.read');
    const identity = await importAgentIdentity({ did: agentEnv.CRED_AGENT_DID!, privateKeyHex: agentEnv.CRED_AGENT_PRIVATE_KEY_HEX! });
    for (const userId of ['alice', 'bob']) {
      const res = await delegateAs(app, identity, { service: 'github', user_id: userId }, { bearer: env.AGENT_TOKEN!, base: env.REDIRECT_BASE_URI });
      expect(res.status, userId).toBe(200);
    }
  });
});

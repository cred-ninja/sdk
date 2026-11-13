/**
 * Known limitation in 2.x: a static agent token carries no user, so on the
 * legacy routes the user comes from the request. A server where one such token
 * serves more than one user says so at startup; a single-user server, or one
 * whose agentRequestVerifier binds principals to users, does not.
 */
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'node:crypto';
import { createServer } from '../server.js';
import type { ServerConfig } from '../config.js';

const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => vi.restoreAllMocks());

function config(overrides: Partial<ServerConfig>): ServerConfig {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-static-token-'));
  tmpDirs.push(dir);
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'sqlite',
    tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: `cred_admin_${crypto.randomBytes(16).toString('hex')}`,
    agentToken: `cred_at_${crypto.randomBytes(16).toString('hex')}`,
    providers: [],
    redirectBaseUri: 'http://localhost:3456',
    ...overrides,
  };
}

function startupWarnings(overrides: Partial<ServerConfig>): string[] {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'log').mockImplementation(() => {});
  createServer(config(overrides));
  return warn.mock.calls.map((call) => String(call[0])).filter((line) => line.includes('static AGENT_TOKEN'));
}

describe('startup warning for one static agent token serving many users', () => {
  it('warns when a static token runs in multi-user mode', () => {
    expect(startupWarnings({ singleUserMode: false })).toHaveLength(1);
  });

  it('stays quiet for a single-user server and for a verifier that binds users', () => {
    expect(startupWarnings({ singleUserMode: true })).toEqual([]);
    expect(startupWarnings({
      singleUserMode: false,
      agentRequestVerifier: () => ({ ok: false, status: 401, error: 'unauthorized' }) as never,
    })).toEqual([]);
  });
});

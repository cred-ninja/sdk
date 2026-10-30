/**
 * Per-exercise ceilings, measured by the server (Sections 5.3 and 6.1):
 * request-side bounds before the upstream call, a listing capped up front,
 * and an over-limit response withheld.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { createServer } from '../server.js';
import { newAgent, delegateAs, exerciseAs, type App, type AgentIdentity } from './token-helpers.js';

const TOKEN = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';
const DRIVE = 'https://www.googleapis.com/auth/drive.readonly';
const FILES = 'https://www.googleapis.com/drive/v3/files';
const dirs: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-meter-'));
  dirs.push(dir);
  const { app, vault } = createServer({
    port: 0, host: '127.0.0.1', vaultPassphrase: 'test-passphrase-not-for-production', vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'), tofuStorage: 'file', tofuPath: path.join(dir, 'tofu.json'),
    adminToken: `cred_admin_${crypto.randomBytes(32).toString('hex')}`, agentToken: TOKEN,
    providers: [{ slug: 'google', clientId: 'cid', clientSecret: 'secret', defaultScopes: [DRIVE] }],
    redirectBaseUri: BASE,
  });
  await vault.init();
  await vault.store({ provider: 'google', userId: 'alice', accessToken: 'ya29.meter', expiresAt: new Date(Date.now() + 3600_000), scopes: [DRIVE] });
  return app;
}

function delegate(app: App, agent: AgentIdentity, constraints: unknown[], details?: unknown) {
  return delegateAs(app, agent, {
    service: 'google', user_id: 'alice', scopes: [DRIVE], constraints, ...(details ? { authorization_details: details } : {}),
  }, { bearer: TOKEN, base: BASE });
}

function upstreamReturning(items: number) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(
    JSON.stringify({ files: Array.from({ length: items }, (_, i) => ({ id: `f${i}` })) }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  ));
}

describe('request-side ceilings', () => {
  it('refuses a call whose method or destination is outside its bounds, before the upstream call', async () => {
    const agent = await newAgent();
    const app = await setup();
    const minted = await delegate(app, agent, [
      { key: 'method', one_of: ['GET'] },
      { key: 'destination', prefix: `${FILES}/abc` },
    ]);
    expect(minted.status).toBe(200);
    const upstream = upstreamReturning(1);
    expect((await exerciseAs(app, agent, minted.body.access_token, { url: `${FILES}/abc`, method: 'GET' }, { base: BASE })).status).toBe(200);
    const other = await exerciseAs(app, agent, minted.body.access_token, { url: `${FILES}/xyz`, method: 'GET' }, { base: BASE });
    expect(other.status).toBe(403);
    expect(other.body).toMatchObject({ error: 'ceiling_exceeded', constraint: 'destination' });
    expect(upstream).toHaveBeenCalledTimes(1);
  });
});

describe('response-side ceilings', () => {
  it('withholds a response with more records than the bound, after the read', async () => {
    const agent = await newAgent();
    const app = await setup();
    const minted = await delegate(app, agent, [{ key: 'max_rows', max: 2 }]);
    const upstream = upstreamReturning(5);
    const res = await exerciseAs(app, agent, minted.body.access_token, { url: FILES, method: 'GET' }, { base: BASE });
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ error: 'ceiling_exceeded', constraint: 'max_rows', withheld: true });
    expect(JSON.stringify(res.body)).not.toContain('f4');
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it("caps a catalogue listing's page size up front, so the provider never returns more", async () => {
    const agent = await newAgent();
    const app = await setup();
    const minted = await delegate(app, agent, [{ key: 'max_rows', max: 2 }], [
      { type: 'cred_delegation', provider: 'google', operations: ['drive.files.list'] },
    ]);
    expect(minted.status).toBe(200);
    const upstream = upstreamReturning(2);
    const res = await exerciseAs(app, agent, minted.body.access_token, { url: `${FILES}?pageSize=500&q=x`, method: 'GET' }, { base: BASE });
    expect(res.status).toBe(200);
    const sent = new URL(String(upstream.mock.calls[0]![0]));
    expect(sent.searchParams.get('pageSize')).toBe('2');
    expect(sent.searchParams.get('q')).toBe('x');
  });
});

describe('issuance', () => {
  it('refuses a per-call max on a key the server meters as a running count', async () => {
    const agent = await newAgent();
    const app = await setup();
    const res = await delegate(app, agent, [{ key: 'calls', max: 5 }]);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_constraints');
  });
});

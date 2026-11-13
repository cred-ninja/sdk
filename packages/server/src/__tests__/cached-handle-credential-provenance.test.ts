/**
 * A live handle decides over the authority of the credential it forwards.
 *
 * A brokered handle holds the provider token it was issued (`upstreamToken` in
 * /api/v1/use is `delegation.accessToken`), never a fresh read. Before this
 * file, the exercise decision was taken over the connection row as it stood at
 * use time, so a row replaced narrower AFTER issuance made a wide credential
 * look narrow: /api/v1/use read `public_repo` from the row, decided the handle
 * could reach public repositories only, and then forwarded the `repo` token the
 * handle still held, which reaches private ones. The same read defeated the
 * widened-token check, which saw a public-only row and reported no wider token.
 *
 * The handle now records the stored scopes of the row its token came from, and
 * an exercise refuses rather than deciding for a credential its current row no
 * longer covers. These tests drive the real routes and assert both halves of
 * every outcome: the /use response, and the credential that actually left the
 * server (by SHA-256 digest: no test ever holds or prints a token).
 */
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'node:crypto';
import { createServer } from '../server.js';
import { actorTokenFor, delegateAs, exerciseAs, newAgent, type AgentIdentity, type App } from './token-helpers.js';
import type { ServerConfig } from '../config.js';
import type { BuiltinAdapterSlug } from '@credninja/oauth';

const BEARER = `cred_at_${crypto.randomBytes(32).toString('hex')}`;
const ADMIN = `cred_admin_${crypto.randomBytes(32).toString('hex')}`;
const BASE = 'http://localhost:3456';

/** The token of the row the handle is issued over, and of the row that replaces it. */
const WIDE_TOKEN = 'synthetic-wide-repo-token';
const NARROW_TOKEN = 'synthetic-narrow-public-repo-token';
/** A google pair, for a replacement that widens rather than narrows. */
const READ_TOKEN = 'synthetic-gmail-read-token';
const WIDER_GOOGLE_TOKEN = 'synthetic-gmail-wider-token';

const REPO_READ_URL = 'https://api.github.com/repos/synthetic-owner/synthetic-repo';
const GMAIL_READ_URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages';

const tmpDirs: string[] = [];
afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function config(dir: string, service: BuiltinAdapterSlug): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: 'test-passphrase-not-for-production',
    vaultStorage: 'sqlite',
    vaultPath: path.join(dir, 'vault.sqlite'),
    tofuStorage: 'sqlite',
    tofuPath: path.join(dir, 'tofu.sqlite'),
    adminToken: ADMIN,
    agentToken: BEARER,
    allowAgentsWithoutPermission: false,
    allowRawTokens: false,
    providers: [{ slug: service, clientId: 'id', clientSecret: 'secret', defaultScopes: [] }],
    redirectBaseUri: BASE,
  };
}

type Server = ReturnType<typeof createServer>;

/** SHA-256 of an Authorization header, so a credential is compared without being printed. */
const digest = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
const bearerDigest = (token: string) => digest(`Bearer ${token}`);

type World = { server: Server; app: App; agent: AgentIdentity; dir: string; service: BuiltinAdapterSlug; delegationId: string; token: string; receipt: string };

/**
 * A server with one stored connection and a did:key agent whose Permission
 * matches it, plus the root delegation issued over that row.
 */
async function delegated(opts: { service: BuiltinAdapterSlug; stored: string[]; allowed: string[] }): Promise<World> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-cached-handle-'));
  tmpDirs.push(dir);
  const server = createServer(config(dir, opts.service));
  await server.vault.init();
  await server.vault.store({
    provider: opts.service,
    userId: 'alice',
    accessToken: opts.service === 'github' ? WIDE_TOKEN : READ_TOKEN,
    scopes: opts.stored,
    expiresAt: new Date(Date.now() + 3_600_000),
  });
  const agent = await newAgent();
  await server.vault.createPermission!({
    agentId: agent.did,
    connectionId: opts.service,
    allowedScopes: opts.allowed,
    requiresApproval: false,
    delegatable: true,
    maxDelegationDepth: 3,
    createdBy: 'test',
  });
  const issued = await delegateAs(server.app, agent, { service: opts.service, user_id: 'alice' }, { bearer: BEARER });
  expect(issued.status, JSON.stringify(issued.body)).toBe(200);
  return { server, app: server.app, agent, dir, service: opts.service, delegationId: issued.body.delegation_id as string, token: issued.body.access_token as string, receipt: issued.body.receipt as string };
}

/** Replace the same connection, as a reconnect or another process would. */
async function replaceRow(world: World, accessToken: string, scopes: string[], expiresAt = new Date(Date.now() + 3_600_000)) {
  await world.server.vault.store({ provider: world.service, userId: 'alice', accessToken, scopes, expiresAt });
}

/**
 * Exercise the handle and report the credential each upstream call carried, as
 * a digest. `credentials` is empty when nothing was forwarded, which is what a
 * refusal must leave behind.
 */
async function exercise(world: { app: App }, agent: AgentIdentity, token: string, url: string) {
  const credentials: string[] = [];
  const upstream = vi.fn(async (_input: unknown, init?: RequestInit) => {
    credentials.push(digest(new Headers(init?.headers ?? {}).get('authorization') ?? ''));
    return new Response(JSON.stringify({ synthetic: true }), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  vi.stubGlobal('fetch', upstream);
  const response = await exerciseAs(world.app, agent, token, { url, method: 'GET' }, { base: BASE });
  return { response, credentials, upstream };
}

describe('a cached handle decides over the credential it forwards', () => {
  it('refuses once the row is replaced repo -> public_repo, and forwards nothing', async () => {
    const world = await delegated({ service: 'github', stored: ['repo'], allowed: ['repo'] });
    await replaceRow(world, NARROW_TOKEN, ['public_repo']);

    const { response, credentials } = await exercise(world, world.agent, world.token, REPO_READ_URL);

    expect(response.status, JSON.stringify(response.body)).toBe(403);
    expect(response.body.error).toBe('scope_insufficient');
    // The credential the handle holds must not leave the server on a decision
    // its current row could not have taken.
    expect(credentials).toEqual([]);
    expect(credentials).not.toContain(bearerDigest(WIDE_TOKEN));
    expect(credentials).not.toContain(bearerDigest(NARROW_TOKEN));
  });

  it('refuses a sub-delegated handle the same way: the child forwards the same credential', async () => {
    const world = await delegated({ service: 'github', stored: ['repo'], allowed: ['repo'] });
    const child = await newAgent();
    await world.server.vault.createPermission!({
      agentId: child.did,
      connectionId: 'github',
      allowedScopes: ['repo'],
      requiresApproval: false,
      delegatable: true,
      maxDelegationDepth: 3,
      createdBy: 'test',
    });
    // The parent receipt: the delegation the setup issued to the parent agent.
    const parent = world;
    const sub = await request(parent.app).post('/api/v1/subdelegate')
      .set('Authorization', `Bearer ${BEARER}`)
      .send({
        parent_receipt: parent.receipt,
        agent_did: child.did,
        service: 'github',
        user_id: 'alice',
        actor_token: actorTokenFor(parent.agent, '/api/v1/subdelegate', BASE),
      });
    expect(sub.status, JSON.stringify(sub.body)).toBe(200);

    await replaceRow(world, NARROW_TOKEN, ['public_repo']);
    const { response, credentials } = await exercise({ app: parent.app }, child, sub.body.access_token as string, REPO_READ_URL);

    expect(response.status, JSON.stringify(response.body)).toBe(403);
    expect(response.body.error).toBe('scope_insufficient');
    expect(credentials).toEqual([]);
  });

  it('still serves the unchanged control, and forwards its own credential', async () => {
    const world = await delegated({ service: 'github', stored: ['repo'], allowed: ['repo'] });

    const { response, credentials } = await exercise(world, world.agent, world.token, REPO_READ_URL);

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(response.body.ok).toBe(true);
    // The decision was taken over the wide scope the credential holds, and the
    // audit record of the forward says so.
    const access = world.server.vault.queryAuditEvents({ limit: 50 }).filter((event) => event.action === 'access');
    expect(access.at(-1)?.scopesGranted).toEqual(['repo']);
    expect(credentials).toEqual([bearerDigest(WIDE_TOKEN)]);
    expect(credentials).not.toContain(bearerDigest(NARROW_TOKEN));
  });

  it('serves a handle whose row was replaced WIDER, still with its own credential', async () => {
    const world = await delegated({ service: 'google', stored: ['gmail.readonly'], allowed: ['gmail.readonly'] });
    await replaceRow(world, WIDER_GOOGLE_TOKEN, ['gmail.readonly', 'gmail.send']);

    const { response, credentials } = await exercise(world, world.agent, world.token, GMAIL_READ_URL);

    // A wider connection does not widen the handle: the token it holds is the
    // one it was issued, so this direction stays served and stays narrow.
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    expect(credentials).toEqual([bearerDigest(READ_TOKEN)]);
    expect(credentials).not.toContain(bearerDigest(WIDER_GOOGLE_TOKEN));
  });

  it('keeps the cold-restore path coherent: it forwards and decides over the current row', async () => {
    const world = await delegated({ service: 'github', stored: ['repo'], allowed: ['repo'] });
    await replaceRow(world, NARROW_TOKEN, ['public_repo']);
    // A different process over the same vault: nothing is cached here, so the
    // handle is rebuilt from its record and its provider token is read now.
    const restarted = createServer(config(world.dir, 'github'));
    await restarted.vault.init();

    const { response, credentials } = await exercise({ app: restarted.app }, world.agent, world.token, REPO_READ_URL);

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    // The row it read is the row it decided over, and the credential it forwards.
    expect(credentials).toEqual([bearerDigest(NARROW_TOKEN)]);
    expect(credentials).not.toContain(bearerDigest(WIDE_TOKEN));
  });

  it('covers nothing for a removed row: the handle is refused as connection_revoked', async () => {
    const world = await delegated({ service: 'github', stored: ['repo'], allowed: ['repo'] });
    await world.server.vault.delete({ provider: 'github', userId: 'alice' });

    const { response, credentials } = await exercise(world, world.agent, world.token, REPO_READ_URL);

    expect(response.status).toBe(401);
    expect(response.body.error).toBe('connection_revoked');
    expect(credentials).toEqual([]);
  });

  it('covers nothing for an expired, narrower replacement row', async () => {
    const world = await delegated({ service: 'github', stored: ['repo'], allowed: ['repo'] });
    await replaceRow(world, NARROW_TOKEN, ['public_repo'], new Date(Date.now() - 60_000));

    const { response, credentials } = await exercise(world, world.agent, world.token, REPO_READ_URL);

    expect(response.status, JSON.stringify(response.body)).toBe(403);
    expect(response.body.error).toBe('scope_insufficient');
    expect(credentials).toEqual([]);
  });
});

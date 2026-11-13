/**
 * A hop must decide on one stored row and issue against that same row.
 *
 * The parent's cycle-5 concurrency probe found the defect this file pins down:
 * the hop read the connection once to decide (grantor Permission, recipient
 * Permission, recipient ceiling), then chose its credential through a second
 * read. A connection replaced from narrow to wide between the two is decided on
 * the narrow row and issued from the wide one, so the grant and the signed
 * receipt name a scope the decision never verified against the credential it
 * actually handed out.
 *
 * Here the replacement happens against the real route: the barrier sits on the
 * server's own `getStored` call, so nothing about the authorization is mocked,
 * and the receipt is the one the server signed. Every case also asserts the
 * effects a refusal or an issuance must have — one stored read, no second
 * credential read, no provider call, and exactly the child records expected.
 */
import { afterAll, describe, expect, it, vi } from 'vitest';
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
const PASSPHRASE = 'test-passphrase-not-for-production';
const ORIGINAL = 'synthetic-narrow-upstream-token';
const REPLACEMENT = 'synthetic-wide-replacement-token';
const PUBLIC_URL = 'https://api.github.com/repos/synthetic-owner/synthetic-public';
const NOTION_URL = 'https://api.notion.com/v1/pages/abc';
const tmpDirs: string[] = [];

afterAll(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});

function config(dir: string, service: BuiltinAdapterSlug): ServerConfig {
  return {
    port: 0,
    host: '127.0.0.1',
    vaultPassphrase: PASSPHRASE,
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

/** A gate is the boolean pair plus the row's own scope list. */
type Gate = { delegatable: boolean; maxDelegationDepth: number; allowedScopes?: string[] };
const PERMISSIVE: Gate = { delegatable: true, maxDelegationDepth: 5 };

type Vault = ReturnType<typeof createServer>['vault'];
type World = {
  app: App;
  vault: Vault;
  /** The directory the server's vault lives in, for a restart over the same data. */
  dir: string;
  service: BuiltinAdapterSlug;
  parent: AgentIdentity;
  child: AgentIdentity;
  parentRow: string;
  childRow: string;
  root: { body: { receipt: string; scopes: string[] } };
};

/**
 * A server with one synthetic stored credential, a grantor row and a recipient
 * row, and a root receipt genuinely minted by the direct-delegate route.
 */
async function setup(opts: {
  service: BuiltinAdapterSlug;
  storedScopes: string[];
  parent: Gate;
  child: Gate;
  ceiling?: string[];
  rootScopes: string[];
  expiresAt?: Date;
}): Promise<World> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-connection-race-'));
  tmpDirs.push(dir);
  const { app, vault } = createServer(config(dir, opts.service));
  await vault.init();
  await vault.store({
    provider: opts.service,
    userId: 'alice',
    accessToken: ORIGINAL,
    scopes: opts.storedScopes,
    expiresAt: opts.expiresAt ?? new Date(Date.now() + 3_600_000),
  });
  const parent = await newAgent();
  const child = await newAgent();
  const now = new Date().toISOString();
  for (const [role, agent, ceiling] of [['parent', parent, [] as string[]], ['child', child, opts.ceiling ?? []]] as const) {
    await vault.registerAgent!({
      id: `agt_${role}`,
      did: agent.did,
      name: role,
      fingerprint: `fp_${role}`,
      scopeCeiling: [...ceiling],
      status: 'active',
      createdBy: 'test',
      createdAt: now,
      updatedAt: now,
    });
  }
  const parentRow = await vault.createPermission!({
    agentId: 'agt_parent',
    connectionId: opts.service,
    requiresApproval: false,
    createdBy: 'test',
    ...opts.parent,
    allowedScopes: opts.parent.allowedScopes ?? opts.storedScopes,
  });
  const childRow = await vault.createPermission!({
    agentId: 'agt_child',
    connectionId: opts.service,
    requiresApproval: false,
    createdBy: 'test',
    ...opts.child,
    allowedScopes: opts.child.allowedScopes ?? opts.storedScopes,
  });

  const root = await delegateAs(
    app,
    parent,
    { service: opts.service, user_id: 'alice', appClientId: 'local', scopes: opts.rootScopes },
    { bearer: BEARER, base: BASE },
  );
  expect(root.status, JSON.stringify(root.body)).toBe(200);
  expect(root.body.scopes).toEqual(opts.rootScopes);

  return { app, vault, dir, service: opts.service, parent, child, parentRow: parentRow.id, childRow: childRow.id, root };
}

/** The claims of a receipt the server signed, as the server laid them out. */
function claimsOf(receipt: string): { scopes: string[]; delegationId: string; chainDepth: number } {
  return JSON.parse(Buffer.from(receipt.split('.')[1]!, 'base64url').toString('utf8'));
}

type Watcher = {
  storedReads: number;
  credentialReads: number;
  delegationsRecorded: number;
  storedTokens: string[];
  credentialTokens: string[];
};

/** Count (and identify) every stored and credential read the hop makes. */
function watch(vault: Vault): Watcher {
  const seen: Watcher = { storedReads: 0, credentialReads: 0, delegationsRecorded: 0, storedTokens: [], credentialTokens: [] };
  const getStored = vault.getStored.bind(vault);
  vault.getStored = (async (...args: Parameters<Vault['getStored']>) => {
    seen.storedReads += 1;
    const entry = await getStored(...args);
    if (entry) seen.storedTokens.push(entry.accessToken);
    return entry;
  }) as Vault['getStored'];
  const get = vault.get.bind(vault);
  vault.get = (async (...args: Parameters<Vault['get']>) => {
    seen.credentialReads += 1;
    const entry = await get(...args);
    if (entry) seen.credentialTokens.push(entry.accessToken);
    return entry;
  }) as Vault['get'];
  const record = vault.recordDelegation.bind(vault);
  vault.recordDelegation = (async (...args: Parameters<Vault['recordDelegation']>) => {
    seen.delegationsRecorded += 1;
    return record(...args);
  }) as Vault['recordDelegation'];
  return seen;
}

/**
 * Hold the request open from inside its first stored read until the test
 * releases it — the exact window between the decision and the issuance.
 */
function pauseAfterStoredRead(vault: Vault) {
  const read = vault.getStored.bind(vault);
  let signal!: () => void;
  let resume!: () => void;
  const reached = new Promise<void>((resolve) => { signal = resolve; });
  const held = new Promise<void>((resolve) => { resume = resolve; });
  let once = true;
  let snapshot: string[] | undefined;
  vault.getStored = (async (...args: Parameters<Vault['getStored']>) => {
    const entry = await read(...args);
    if (once) {
      once = false;
      snapshot = entry?.scopes;
      signal();
      await held;
    }
    return entry;
  }) as Vault['getStored'];
  return {
    reached,
    resume: () => resume(),
    snapshotScopes: () => snapshot,
  };
}

async function hop(app: App, receipt: string, grantor: AgentIdentity, recipient: AgentIdentity, service: string, scopes: string[]) {
  // Awaited here so the request is in flight when the returned promise is
  // raced against the barrier, not only when the caller awaits it.
  return await request(app).post('/api/v1/subdelegate')
    .set('Authorization', `Bearer ${BEARER}`)
    .send({
      parent_receipt: receipt,
      actor_token: actorTokenFor(grantor, '/api/v1/subdelegate', BASE),
      agent_did: recipient.did,
      service,
      user_id: 'alice',
      appClientId: 'local',
      scopes,
    });
}

/** Fail the test if the hop reaches the network without a stub installed. */
function noNetwork() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
    throw new Error('network disabled in this test');
  });
}

/**
 * Run the hop, replace the same connection while it is paused inside its stored
 * read, then let it continue. `replacement` of null is the unchanged control.
 */
async function hopAcrossReplacement(
  world: World,
  scopes: string[],
  replacement: { scopes: string[]; token?: string; expiresAt?: Date } | null,
) {
  const watcher = watch(world.vault);
  const pause = pauseAfterStoredRead(world.vault);
  const inFlight = hop(world.app, world.root.body.receipt, world.parent, world.child, world.service, scopes);
  const outcome = await Promise.race([
    pause.reached.then(() => 'reached' as const),
    new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), 5000)),
  ]);
  expect(outcome, 'the hop reached its stored read').toBe('reached');
  if (replacement) {
    await world.vault.store({
      provider: world.service,
      userId: 'alice',
      accessToken: replacement.token ?? REPLACEMENT,
      scopes: replacement.scopes,
      expiresAt: replacement.expiresAt ?? new Date(Date.now() + 3_600_000),
    });
  }
  pause.resume();
  const response = await inFlight;
  return { response, watcher, snapshotScopes: pause.snapshotScopes() };
}

/** The scopes the hop signed into its receipt and reported. */
function claimedScopes(response: { body: { receipt?: string } }): string[] {
  return response.body.receipt ? claimsOf(response.body.receipt).scopes : [];
}

/** The child delegation this hop recorded, or null. */
async function recordedChild(world: World, response: { body: { receipt?: string } }) {
  if (typeof response.body.receipt !== 'string') return null;
  return world.vault.getDelegation(claimsOf(response.body.receipt).delegationId);
}

/** SHA-256 of an Authorization header, so a test never holds a credential it prints. */
const digest = (value: string) => crypto.createHash('sha256').update(value).digest('hex');

/** The upstream call this /use made, as the credential digest it carried. */
async function upstreamCredential(world: { app: App; child: AgentIdentity }, token: string, url = PUBLIC_URL) {
  const seen: string[] = [];
  const stub = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input: unknown, init?: RequestInit) => {
    seen.push(digest(new Headers(init?.headers ?? {}).get('authorization') ?? ''));
    return new Response(JSON.stringify({ synthetic: true }), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  const response = await exerciseAs(world.app, world.child, token, { url, method: 'GET' }, { base: BASE });
  stub.mockRestore();
  return { response, credentials: seen };
}

type Shape = {
  name: string;
  /** A URL the selected scope may reach, used to observe the credential /use sends. */
  url: string;
  service: BuiltinAdapterSlug;
  storedScopes: string[];
  parent: Gate;
  child: Gate;
  ceiling?: string[];
  replacementScopes: string[];
  requested: string[];
};

/**
 * Four shapes, each the shape the parent probe reproduced: the connection is
 * narrow when the decision is taken, and a different operation widens it before
 * the hop picks its credential.
 */
const SHAPES: Shape[] = [
  {
    name: 'github recipient Permission',
    url: PUBLIC_URL,
    service: 'github' as const,
    storedScopes: ['public_repo'],
    parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
    child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
    replacementScopes: ['repo'],
    requested: ['github.read'],
  },
  {
    name: 'github recipient ceiling',
    url: PUBLIC_URL,
    service: 'github' as const,
    storedScopes: ['public_repo'],
    parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
    child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
    ceiling: ['public_repo'],
    replacementScopes: ['repo'],
    requested: ['github.read'],
  },
  {
    name: 'Notion recipient Permission',
    url: NOTION_URL,
    service: 'notion' as const,
    storedScopes: ['read_content'],
    parent: { ...PERMISSIVE, allowedScopes: ['content'] },
    child: { ...PERMISSIVE, allowedScopes: ['notion.read'] },
    replacementScopes: [],
    requested: ['notion.read'],
  },
  {
    name: 'Notion recipient ceiling',
    url: NOTION_URL,
    service: 'notion' as const,
    storedScopes: ['read_content'],
    parent: { ...PERMISSIVE, allowedScopes: ['content'] },
    child: { ...PERMISSIVE, allowedScopes: ['notion.read'] },
    ceiling: ['read_content'],
    replacementScopes: [],
    requested: ['notion.read'],
  },
];

describe('a connection replaced between the decision and the credential', () => {
  for (const shape of SHAPES) {
    it(`issues against the row it decided on: ${shape.name}`, async () => {
      const world = await setup({
        service: shape.service,
        storedScopes: shape.storedScopes,
        parent: shape.parent,
        child: shape.child,
        ...(shape.ceiling ? { ceiling: shape.ceiling } : {}),
        rootScopes: shape.requested,
      });
      const network = noNetwork();
      const { response, watcher, snapshotScopes } = await hopAcrossReplacement(world, shape.requested, { scopes: shape.replacementScopes });

      // The barrier saw the narrow row — this is the snapshot the decision used.
      expect(snapshotScopes).toEqual(shape.storedScopes);
      // The decision was taken once, and no second read chose the credential:
      // the entry the decision saw is the entry the hop issued against.
      expect(watcher.storedReads, 'stored reads on the hop').toBe(1);
      expect(watcher.storedTokens).toEqual([ORIGINAL]);
      expect(watcher.credentialReads, 'credential reads on the hop').toBe(0);
      expect(watcher.credentialTokens).toEqual([]);

      expect(response.status, JSON.stringify(response.body)).toBe(200);
      const claims = claimsOf(response.body.receipt);
      expect(claims.scopes).toEqual(shape.requested);
      expect(response.body.scopes).toEqual(shape.requested);
      const child = await recordedChild(world, response);
      expect(child?.status).toBe('active');
      expect(child?.grant?.scopes).toEqual(shape.requested);
      expect(watcher.delegationsRecorded).toBe(1);
      // No provider call: neither the replacement nor the decision refreshed.
      expect(network).not.toHaveBeenCalled();

      // Which credential the handle really carries, checked at the only place it
      // leaves the server. The wide replacement must never be the one sent.
      const upstream = await upstreamCredential(world, response.body.access_token, shape.url);
      expect(upstream.response.status, JSON.stringify(upstream.response.body)).toBe(200);
      expect(upstream.credentials.length).toBe(1);
      expect(upstream.credentials[0]).toBe(digest(`Bearer ${ORIGINAL}`));
      expect(upstream.credentials[0]).not.toBe(digest(`Bearer ${REPLACEMENT}`));
      network.mockRestore();
      vi.restoreAllMocks();
    });

    it(`keeps the unchanged connection control: ${shape.name}`, async () => {
      const world = await setup({
        service: shape.service,
        storedScopes: shape.storedScopes,
        parent: shape.parent,
        child: shape.child,
        ...(shape.ceiling ? { ceiling: shape.ceiling } : {}),
        rootScopes: shape.requested,
      });
      const network = noNetwork();
      const { response, watcher, snapshotScopes } = await hopAcrossReplacement(world, shape.requested, null);

      expect(snapshotScopes).toEqual(shape.storedScopes);
      expect(watcher.storedReads).toBe(1);
      expect(watcher.storedTokens).toEqual([ORIGINAL]);
      expect(watcher.credentialReads).toBe(0);
      expect(response.status, JSON.stringify(response.body)).toBe(200);
      expect(response.body.scopes).toEqual(shape.requested);
      expect(claimsOf(response.body.receipt).scopes).toEqual(shape.requested);
      const child = await recordedChild(world, response);
      expect(child?.grant?.scopes).toEqual(shape.requested);
      expect(watcher.delegationsRecorded).toBe(1);
      expect(network).not.toHaveBeenCalled();

      const upstream = await upstreamCredential(world, response.body.access_token, shape.url);
      expect(upstream.response.status, JSON.stringify(upstream.response.body)).toBe(200);
      expect(upstream.credentials[0]).toBe(digest(`Bearer ${ORIGINAL}`));
      vi.restoreAllMocks();
    });
  }

  it('fails closed when the pinned row has expired and the re-read is wider', async () => {
    // The one case the stored read cannot serve as the credential: an expired
    // row is re-read through get(), the accessor that may refresh it. That
    // result is compared against the decision, and a wider one is refused
    // rather than issued against.
    const world = await setup({
      service: 'github',
      storedScopes: ['public_repo'],
      parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
      rootScopes: ['github.read'],
    });
    // The receipt is minted while the connection is live; the connection then
    // expires, which is the state in which the hop must re-read to refresh.
    await world.vault.store({
      provider: 'github', userId: 'alice', accessToken: ORIGINAL, scopes: ['public_repo'], expiresAt: new Date(Date.now() - 60_000),
    });
    const network = noNetwork();
    const { response, watcher, snapshotScopes } = await hopAcrossReplacement(world, ['github.read'], { scopes: ['repo'] });

    expect(snapshotScopes).toEqual(['public_repo']);
    expect(watcher.storedReads).toBe(1);
    // The expired entry cannot be the credential, so exactly one re-read is
    // allowed — and its wider result must not become the issued credential.
    expect(watcher.credentialReads).toBe(1);
    expect(watcher.credentialTokens).toEqual([REPLACEMENT]);

    expect(response.status, JSON.stringify(response.body)).toBe(403);
    expect(response.body.error).toBe('scope_insufficient');
    expect(response.body.access_token).toBeUndefined();
    expect(response.body.receipt).toBeUndefined();
    expect(JSON.stringify(response.body)).not.toContain(ORIGINAL);
    expect(JSON.stringify(response.body)).not.toContain(REPLACEMENT);
    expect(watcher.delegationsRecorded).toBe(0);
    expect(network).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });

  it('keeps the expired-connection refusal when nothing replaced it', async () => {
    const world = await setup({
      service: 'github',
      storedScopes: ['public_repo'],
      parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
      rootScopes: ['github.read'],
    });
    await world.vault.store({
      provider: 'github', userId: 'alice', accessToken: ORIGINAL, scopes: ['public_repo'], expiresAt: new Date(Date.now() - 60_000),
    });
    const network = noNetwork();
    const { response, watcher } = await hopAcrossReplacement(world, ['github.read'], null);
    // Unchanged behaviour: an expired token that cannot be refreshed is no
    // credential, and the hop refuses without recording a child.
    expect(response.status, JSON.stringify(response.body)).toBe(404);
    expect(response.body.access_token).toBeUndefined();
    expect(watcher.delegationsRecorded).toBe(0);
    expect(network).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });

  it('does not share a snapshot between independent concurrent hops', async () => {
    const github = await setup({
      service: 'github',
      storedScopes: ['public_repo'],
      parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
      rootScopes: ['github.read'],
    });
    const notion = await setup({
      service: 'notion',
      storedScopes: ['read_content'],
      parent: { ...PERMISSIVE, allowedScopes: ['content'] },
      child: { ...PERMISSIVE, allowedScopes: ['notion.read'] },
      rootScopes: ['notion.read'],
    });
    const first = watch(github.vault);
    const second = watch(notion.vault);
    const network = noNetwork();
    const [one, two] = await Promise.all([
      hop(github.app, github.root.body.receipt, github.parent, github.child, 'github', ['github.read']),
      hop(notion.app, notion.root.body.receipt, notion.parent, notion.child, 'notion', ['notion.read']),
    ]);
    expect(one.status, JSON.stringify(one.body)).toBe(200);
    expect(two.status, JSON.stringify(two.body)).toBe(200);
    expect(claimsOf(one.body.receipt).scopes).toEqual(['github.read']);
    expect(claimsOf(two.body.receipt).scopes).toEqual(['notion.read']);
    expect(first).toMatchObject({ storedReads: 1, credentialReads: 0, delegationsRecorded: 1 });
    expect(second).toMatchObject({ storedReads: 1, credentialReads: 0, delegationsRecorded: 1 });
    expect(network).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });
});

/**
 * The other two routes that touch a stored connection. Neither re-reads the row
 * to pick a credential, and each keeps that property under the same
 * replacement: the direct-delegate route decides on the entry it just read, and
 * /use sends the token its handle already holds.
 */
describe('the direct-delegate route decides on the entry it read once', () => {
  it('derives the grant from the credential it read, not a later row', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-connection-race-root-'));
    tmpDirs.push(dir);
    const { app, vault } = createServer(config(dir, 'github'));
    await vault.init();
    await vault.store({
      provider: 'github', userId: 'alice', accessToken: ORIGINAL, scopes: ['public_repo'], expiresAt: new Date(Date.now() + 3_600_000),
    });
    const agent = await newAgent();
    const now = new Date().toISOString();
    await vault.registerAgent!({
      id: 'agt_root', did: agent.did, name: 'root', fingerprint: 'fp_root', scopeCeiling: [], status: 'active', createdBy: 'test', createdAt: now, updatedAt: now,
    });
    await vault.createPermission!({
      agentId: 'agt_root', connectionId: 'github', allowedScopes: ['public_repo'], requiresApproval: false, delegatable: true, maxDelegationDepth: 5, createdBy: 'test',
    });

    const watcher = watch(vault);
    const read = vault.get.bind(vault);
    let resume!: () => void;
    let signal!: () => void;
    const held = new Promise<void>((resolve) => { resume = resolve; });
    const reached = new Promise<void>((resolve) => { signal = resolve; });
    let once = true;
    let entryRead: string | undefined;
    vault.get = (async (...args: Parameters<Vault['get']>) => {
      const entry = await read(...args);
      if (once && entry) {
        once = false;
        entryRead = entry.accessToken;
        signal();
        await held;
      }
      return entry;
    }) as Vault['get'];

    // Started now, not when awaited: the barrier below has to be reached while
    // this call is in flight.
    const inFlight = (async () => await delegateAs(
      app, agent, { service: 'github', user_id: 'alice', appClientId: 'local', scopes: ['github.read'] }, { bearer: BEARER, base: BASE },
    ))();
    const outcome = await Promise.race([
      reached.then(() => 'reached' as const),
      new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), 5000)),
    ]);
    expect(outcome, 'the route reached its credential read').toBe('reached');
    await vault.store({
      provider: 'github', userId: 'alice', accessToken: REPLACEMENT, scopes: ['repo'], expiresAt: new Date(Date.now() + 3_600_000),
    });
    resume();

    const response = await inFlight;
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    // The entry already in hand is what the grant and the handle were built
    // from: one credential read, no second one after the replacement.
    expect(entryRead).toBe(ORIGINAL);
    expect(watcher.credentialReads).toBe(1);
    expect(watcher.credentialTokens).toEqual([ORIGINAL]);
    expect(response.body.scopes).toEqual(['github.read']);
    expect(claimsOf(response.body.receipt).scopes).toEqual(['github.read']);
    // The only credential this request ever obtained is the narrow one, so the
    // handle it minted can only carry that token.
    expect(watcher.credentialTokens).toEqual([ORIGINAL]);
    expect(JSON.stringify(response.body)).not.toContain(REPLACEMENT);
    vi.restoreAllMocks();
  });
});

/**
 * A handle this process did not mint — another replica, or a restart — is
 * restored from the vault, and that load is the read the forwarded token comes
 * from. It has to be the read the call's checks are taken over as well.
 */
describe('/api/v1/use decides a restored handle over the row it loaded its token from', () => {
  it('does not authorize against a second, wider read of the same connection', async () => {
    const world = await setup({
      service: 'github',
      storedScopes: ['public_repo'],
      parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      child: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      rootScopes: ['github.read'],
    });
    const issued = await hop(world.app, world.root.body.receipt, world.parent, world.child, 'github', ['github.read']);
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    expect(claimedScopes(issued)).toEqual(['github.read']);

    // A restarted server holds no handle for this token and loads it back.
    const restarted = createServer(config(world.dir, 'github'));
    await restarted.vault.init();
    const watcher = watch(restarted.vault);
    const read = restarted.vault.get.bind(restarted.vault);
    let signal!: () => void;
    let resume!: () => void;
    const reached = new Promise<void>((resolve) => { signal = resolve; });
    const held = new Promise<void>((resolve) => { resume = resolve; });
    let once = true;
    restarted.vault.get = (async (...args: Parameters<Vault['get']>) => {
      const entry = await read(...args);
      if (once && entry) {
        once = false;
        signal();
        await held;
      }
      return entry;
    }) as Vault['get'];

    const upstream = upstreamCredential({ app: restarted.app, child: world.child }, issued.body.access_token);
    expect(await new Promise<'reached' | 'timeout'>((resolve) => {
      void reached.then(() => resolve('reached'));
      setTimeout(() => resolve('timeout'), 5000);
    }), 'the restore reached its credential read').toBe('reached');
    // The connection is widened while the restored handle is paused inside the
    // read its token comes from.
    await restarted.vault.store({
      provider: 'github', userId: 'alice', accessToken: REPLACEMENT, scopes: ['repo'], expiresAt: new Date(Date.now() + 3_600_000),
    });
    resume();
    const used = await upstream;
    expect(watcher.credentialReads, 'credential reads on the restore').toBe(1);
    expect(used.response.status, JSON.stringify(used.response.body)).toBe(200);
    expect(used.credentials[0]).toBe(digest(`Bearer ${ORIGINAL}`));
    expect(used.credentials[0]).not.toBe(digest(`Bearer ${REPLACEMENT}`));
    vi.restoreAllMocks();
  });
});

describe('/api/v1/use sends the token its handle holds', () => {
  it('does not pick up a wider replacement connection', async () => {
    const world = await setup({
      service: 'github',
      storedScopes: ['public_repo'],
      parent: { ...PERMISSIVE, allowedScopes: ['public_repo'] },
      child: { ...PERMISSIVE, allowedScopes: ['github.read'] },
      rootScopes: ['github.read'],
    });
    const issued = await hop(world.app, world.root.body.receipt, world.parent, world.child, 'github', ['github.read']);
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const before = await upstreamCredential(world, issued.body.access_token);
    expect(before.response.status, JSON.stringify(before.response.body)).toBe(200);
    expect(before.credentials[0]).toBe(digest(`Bearer ${ORIGINAL}`));

    await world.vault.store({
      provider: 'github', userId: 'alice', accessToken: REPLACEMENT, scopes: ['repo'], expiresAt: new Date(Date.now() + 3_600_000),
    });
    const after = await upstreamCredential(world, issued.body.access_token);
    expect(after.response.status, JSON.stringify(after.response.body)).toBe(200);
    // The handle carries the token minted for it; a reconnect cannot widen it.
    expect(after.credentials[0]).toBe(digest(`Bearer ${ORIGINAL}`));
    expect(after.credentials[0]).not.toBe(digest(`Bearer ${REPLACEMENT}`));
    vi.restoreAllMocks();
  });
});
